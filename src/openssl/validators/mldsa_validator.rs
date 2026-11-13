// Copyright 2026 Zora Fuchs. All rights reserved.
// This file is licensed to you under the Apache License,
// Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
// or the MIT license (http://opensource.org/licenses/MIT),
// at your option.

// Unless required by applicable law or agreed to in writing,
// this software is distributed on an "AS IS" BASIS, WITHOUT
// WARRANTIES OR REPRESENTATIONS OF ANY KIND, either express or
// implied. See the LICENSE-MIT and LICENSE-APACHE files for the
// specific language governing permissions and limitations under
// each license.

use openssl::{
    pkey::{KeyType, PKey},
    sign::Verifier,
};

use crate::{RawSignatureValidationError, RawSignatureValidator, openssl::OpenSslMutex};

/// Validates raw signatures with one of the ML-DSA (FIPS 204) parameter sets.
/// Requires OpenSSL 3.5 or newer.
///
/// Expects **pure ML-DSA with an empty context string**, as produced by
/// `MlDsaSigner` and as specified for COSE.
pub(crate) enum MlDsaValidator {
    /// ML-DSA-44
    MlDsa44,

    /// ML-DSA-65
    MlDsa65,

    /// ML-DSA-87
    MlDsa87,
}

impl MlDsaValidator {
    fn key_type(&self) -> KeyType {
        match self {
            Self::MlDsa44 => KeyType::ML_DSA_44,
            Self::MlDsa65 => KeyType::ML_DSA_65,
            Self::MlDsa87 => KeyType::ML_DSA_87,
        }
    }

    fn signature_size(&self) -> usize {
        // FIPS 204, table 2. ML-DSA signatures have a fixed size.
        match self {
            Self::MlDsa44 => 2420,
            Self::MlDsa65 => 3309,
            Self::MlDsa87 => 4627,
        }
    }
}

impl RawSignatureValidator for MlDsaValidator {
    fn validate(
        &self,
        sig: &[u8],
        data: &[u8],
        public_key: &[u8],
    ) -> Result<(), RawSignatureValidationError> {
        if sig.len() != self.signature_size() {
            return Err(RawSignatureValidationError::InvalidSignature);
        }

        let _openssl = OpenSslMutex::acquire()?;

        let public_key = PKey::public_key_from_der(public_key)?;

        // `Verifier::new_without_digest` accepts any key type, so without this
        // check an Ed25519 (or other ML-DSA parameter set) key would be used
        // to validate a signature labelled as this parameter set.
        if !public_key.is_a(self.key_type()) {
            return Err(RawSignatureValidationError::InvalidPublicKey);
        }

        if Verifier::new_without_digest(&public_key)?.verify_oneshot(sig, data)? {
            Ok(())
        } else {
            Err(RawSignatureValidationError::SignatureMismatch)
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use openssl::{error::ErrorStack, sign::Signer};

    use super::*;

    const SAMPLE_DATA: &[u8] = b"some sample content to sign";

    const SEED: [u8; 32] = [7; 32];

    /// Returns `(public key SPKI DER, signature over SAMPLE_DATA)`.
    fn ml_dsa_key_and_sig(key_type: KeyType) -> (Vec<u8>, Vec<u8>) {
        fn generate(key_type: KeyType) -> Result<(Vec<u8>, Vec<u8>), ErrorStack> {
            let key = PKey::private_key_from_seed(None, key_type, None, &SEED)?;
            let sig = Signer::new_without_digest(&key)?.sign_oneshot_to_vec(SAMPLE_DATA)?;
            Ok((key.public_key_to_der()?, sig))
        }

        // Don't unwrap while holding the mutex: a panic would poison it.
        let result = {
            let _openssl = OpenSslMutex::acquire().unwrap();
            generate(key_type)
        };
        result.unwrap()
    }

    fn all_parameter_sets() -> [(MlDsaValidator, KeyType); 3] {
        [
            (MlDsaValidator::MlDsa44, KeyType::ML_DSA_44),
            (MlDsaValidator::MlDsa65, KeyType::ML_DSA_65),
            (MlDsaValidator::MlDsa87, KeyType::ML_DSA_87),
        ]
    }

    #[test]
    fn validates_each_parameter_set() {
        for (validator, key_type) in all_parameter_sets() {
            let (public_key, sig) = ml_dsa_key_and_sig(key_type);
            assert_eq!(sig.len(), validator.signature_size());

            validator.validate(&sig, SAMPLE_DATA, &public_key).unwrap();
        }
    }

    #[test]
    fn tampered_data_is_signature_mismatch() {
        for (validator, key_type) in all_parameter_sets() {
            let (public_key, sig) = ml_dsa_key_and_sig(key_type);

            let err = validator
                .validate(&sig, b"some other content", &public_key)
                .unwrap_err();

            assert_eq!(err, RawSignatureValidationError::SignatureMismatch);
        }
    }

    #[test]
    fn tampered_signature_is_signature_mismatch() {
        let (public_key, mut sig) = ml_dsa_key_and_sig(KeyType::ML_DSA_65);
        sig[10] ^= 0x01;

        let err = MlDsaValidator::MlDsa65
            .validate(&sig, SAMPLE_DATA, &public_key)
            .unwrap_err();

        assert_eq!(err, RawSignatureValidationError::SignatureMismatch);
    }

    #[test]
    fn wrong_signature_size_is_invalid_signature() {
        let (public_key, sig) = ml_dsa_key_and_sig(KeyType::ML_DSA_65);

        let err = MlDsaValidator::MlDsa65
            .validate(&sig[..sig.len() - 1], SAMPLE_DATA, &public_key)
            .unwrap_err();

        assert_eq!(err, RawSignatureValidationError::InvalidSignature);
    }

    #[test]
    fn key_of_other_parameter_set_is_invalid_public_key() {
        // The ML-DSA-65 signature has the right size for MlDsa65, but the key
        // is ML-DSA-44.
        let (public_key_44, _) = ml_dsa_key_and_sig(KeyType::ML_DSA_44);
        let (_, sig_65) = ml_dsa_key_and_sig(KeyType::ML_DSA_65);

        let err = MlDsaValidator::MlDsa65
            .validate(&sig_65, SAMPLE_DATA, &public_key_44)
            .unwrap_err();

        assert_eq!(err, RawSignatureValidationError::InvalidPublicKey);
    }

    #[test]
    fn non_ml_dsa_key_is_invalid_public_key() {
        let public_key = {
            let _openssl = OpenSslMutex::acquire().unwrap();
            PKey::generate_ed25519().and_then(|key| key.public_key_to_der())
        }
        .unwrap();
        let (_, sig) = ml_dsa_key_and_sig(KeyType::ML_DSA_65);

        let err = MlDsaValidator::MlDsa65
            .validate(&sig, SAMPLE_DATA, &public_key)
            .unwrap_err();

        assert_eq!(err, RawSignatureValidationError::InvalidPublicKey);
    }

    #[test]
    fn unparseable_public_key_is_crypto_error() {
        let (_, sig) = ml_dsa_key_and_sig(KeyType::ML_DSA_65);

        let err = MlDsaValidator::MlDsa65
            .validate(&sig, SAMPLE_DATA, &[0x00, 0x01, 0x02])
            .unwrap_err();

        assert!(matches!(
            err,
            RawSignatureValidationError::CryptoLibraryError(_)
        ));
    }
}
