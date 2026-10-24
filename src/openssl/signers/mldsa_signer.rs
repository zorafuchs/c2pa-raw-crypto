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
    pkey::{KeyType, PKey, Private},
    sign::Signer,
};

use crate::{RawSigner, RawSignerError, SigningAlg, openssl::OpenSslMutex};

enum MlDsaSigningAlg {
    MlDsa44,
    MlDsa65,
    MlDsa87,
}

impl MlDsaSigningAlg {
    fn key_type(&self) -> KeyType {
        match self {
            Self::MlDsa44 => KeyType::ML_DSA_44,
            Self::MlDsa65 => KeyType::ML_DSA_65,
            Self::MlDsa87 => KeyType::ML_DSA_87,
        }
    }
}

/// Implements [`RawSigner`] trait using OpenSSL's implementation of
/// ML-DSA (FIPS 204). Requires OpenSSL 3.5 or newer.
///
/// Signatures are **pure ML-DSA with an empty context string**, as specified
/// for COSE (`ML-DSA-44` = -48, `ML-DSA-65` = -49, `ML-DSA-87` = -50). OpenSSL
/// signs hedged (randomized) by default, so two signatures over the same data
/// differ.
///
/// The private key is held in an OpenSSL `PKey<Private>`. OpenSSL owns this key
/// material and clears it when the key is freed (`EVP_PKEY_free`), so the
/// `zeroize` crate cannot (and need not) be applied to the handle itself.
pub(crate) struct MlDsaSigner {
    alg: MlDsaSigningAlg,
    private_key: PKey<Private>,
}

impl MlDsaSigner {
    pub(crate) fn from_private_key(
        private_key: &[u8],
        alg: SigningAlg,
    ) -> Result<Self, RawSignerError> {
        let alg = match alg {
            SigningAlg::MlDsa44 => MlDsaSigningAlg::MlDsa44,
            SigningAlg::MlDsa65 => MlDsaSigningAlg::MlDsa65,
            SigningAlg::MlDsa87 => MlDsaSigningAlg::MlDsa87,
            _ => {
                return Err(RawSignerError::InternalError(
                    "MlDsaSigner should be used only for SigningAlg::MlDsa**".to_string(),
                ));
            }
        };

        let _openssl = OpenSslMutex::acquire()?;
        let private_key = PKey::private_key_from_pem(private_key)?;

        // A key of another type or parameter set would otherwise only show up
        // later as a signature that fails to validate.
        if !private_key.is_a(alg.key_type()) {
            return Err(RawSignerError::InvalidSigningCredentials(
                "private key does not match the requested ML-DSA parameter set".to_string(),
            ));
        }

        Ok(MlDsaSigner { alg, private_key })
    }
}

impl RawSigner for MlDsaSigner {
    fn sign(&self, data: &[u8]) -> Result<Vec<u8>, RawSignerError> {
        let _openssl = OpenSslMutex::acquire()?;
        let mut signer = Signer::new_without_digest(&self.private_key)?;
        Ok(signer.sign_oneshot_to_vec(data)?)
    }

    fn alg(&self) -> SigningAlg {
        match self.alg {
            MlDsaSigningAlg::MlDsa44 => SigningAlg::MlDsa44,
            MlDsaSigningAlg::MlDsa65 => SigningAlg::MlDsa65,
            MlDsaSigningAlg::MlDsa87 => SigningAlg::MlDsa87,
        }
    }

    fn max_signature_size(&self) -> usize {
        // FIPS 204, table 2. ML-DSA signatures have a fixed size.
        match self.alg {
            MlDsaSigningAlg::MlDsa44 => 2420,
            MlDsaSigningAlg::MlDsa65 => 3309,
            MlDsaSigningAlg::MlDsa87 => 4627,
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic)]
    #![allow(clippy::unwrap_used)]

    use openssl::sign::Verifier;

    use super::*;

    const SEED: [u8; 32] = [7; 32];

    fn private_key_pem(key_type: KeyType) -> Vec<u8> {
        let _openssl = OpenSslMutex::acquire().unwrap();
        PKey::private_key_from_seed(None, key_type, None, &SEED)
            .unwrap()
            .private_key_to_pem_pkcs8()
            .unwrap()
    }

    #[test]
    fn signs_and_verifies_each_parameter_set() {
        for (alg, key_type, size) in [
            (SigningAlg::MlDsa44, KeyType::ML_DSA_44, 2420),
            (SigningAlg::MlDsa65, KeyType::ML_DSA_65, 3309),
            (SigningAlg::MlDsa87, KeyType::ML_DSA_87, 4627),
        ] {
            let pem = private_key_pem(key_type);
            let signer = MlDsaSigner::from_private_key(&pem, alg).unwrap();
            assert_eq!(signer.alg(), alg);
            assert_eq!(signer.max_signature_size(), size);

            let data = b"some sample content to sign";
            let signature = signer.sign(data).unwrap();
            assert_eq!(signature.len(), size);

            let _openssl = OpenSslMutex::acquire().unwrap();
            let public_key =
                PKey::public_key_from_der(&signer.private_key.public_key_to_der().unwrap())
                    .unwrap();
            let mut verifier = Verifier::new_without_digest(&public_key).unwrap();
            assert!(verifier.verify_oneshot(&signature, data).unwrap());

            let mut verifier = Verifier::new_without_digest(&public_key).unwrap();
            assert!(!verifier.verify_oneshot(&signature, b"tampered data").unwrap());
        }
    }

    #[test]
    fn rejects_bad_pem() {
        let Err(err) = MlDsaSigner::from_private_key(b"not a PEM key", SigningAlg::MlDsa65) else {
            panic!("expected error");
        };

        assert!(matches!(err, RawSignerError::CryptoLibraryError(_)));
    }

    #[test]
    fn rejects_wrong_parameter_set() {
        let pem = private_key_pem(KeyType::ML_DSA_44);

        let Err(err) = MlDsaSigner::from_private_key(&pem, SigningAlg::MlDsa65) else {
            panic!("expected error");
        };

        assert!(matches!(err, RawSignerError::InvalidSigningCredentials(_)));
    }

    #[test]
    fn rejects_non_ml_dsa_key() {
        let pem = include_bytes!("../../../tests/fixtures/raw_signature/ed25519.priv");

        let Err(err) = MlDsaSigner::from_private_key(pem, SigningAlg::MlDsa65) else {
            panic!("expected error");
        };

        assert!(matches!(err, RawSignerError::InvalidSigningCredentials(_)));
    }

    #[test]
    fn rejects_non_ml_dsa_alg() {
        let pem = private_key_pem(KeyType::ML_DSA_65);

        let Err(err) = MlDsaSigner::from_private_key(&pem, SigningAlg::Ed25519) else {
            panic!("expected error");
        };

        assert!(matches!(err, RawSignerError::InternalError(_)));
    }
}
