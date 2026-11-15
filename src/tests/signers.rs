// Copyright 2024 Adobe. All rights reserved.
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

#[cfg(all(target_arch = "wasm32", not(target_os = "wasi")))]
use wasm_bindgen_test::wasm_bindgen_test;

use crate::{
    RawSigner, RawSignerError, SigningAlg, signer_from_private_key, validator_for_signing_alg,
};

/// Unwraps the signer when a crypto backend is compiled in.
///
/// When neither the `rust_native_crypto` nor the `openssl` feature is enabled,
/// no backend is available: asserts that the expected `NoCryptoBackend` error
/// was returned and yields `None` so the test can stop early.
fn check_signer(
    result: Result<Box<dyn RawSigner + Send + Sync>, RawSignerError>,
) -> Option<Box<dyn RawSigner + Send + Sync>> {
    #[cfg(any(feature = "rust_native_crypto", feature = "openssl"))]
    {
        Some(result.unwrap())
    }

    #[cfg(not(any(feature = "rust_native_crypto", feature = "openssl")))]
    {
        assert!(matches!(result, Err(RawSignerError::NoCryptoBackend)));
        None
    }
}

#[test]
#[cfg_attr(
    all(target_arch = "wasm32", not(target_os = "wasi")),
    wasm_bindgen_test
)]
fn es256() {
    let private_key = include_bytes!("../../tests/fixtures/raw_signature/es256.priv");

    let Some(signer) = check_signer(signer_from_private_key(private_key, SigningAlg::Es256)) else {
        return;
    };

    assert_eq!(signer.alg(), SigningAlg::Es256);

    let data = b"some sample content to sign";
    let signature = signer.sign(data).unwrap();

    println!("signature len = {}", signature.len());
    assert!(signature.len() <= signer.max_signature_size());

    let pub_key = include_bytes!("../../tests/fixtures/raw_signature/es256.pub_key");

    let validator = validator_for_signing_alg(SigningAlg::Es256).unwrap();
    validator.validate(&signature, data, pub_key).unwrap();
}

#[test]
#[cfg_attr(
    all(target_arch = "wasm32", not(target_os = "wasi")),
    wasm_bindgen_test
)]
fn es384() {
    let private_key = include_bytes!("../../tests/fixtures/raw_signature/es384.priv");

    let Some(signer) = check_signer(signer_from_private_key(private_key, SigningAlg::Es384)) else {
        return;
    };

    assert_eq!(signer.alg(), SigningAlg::Es384);

    let data = b"some sample content to sign";
    let signature = signer.sign(data).unwrap();

    println!("signature len = {}", signature.len());
    assert!(signature.len() <= signer.max_signature_size());

    let pub_key = include_bytes!("../../tests/fixtures/raw_signature/es384.pub_key");

    let validator = validator_for_signing_alg(SigningAlg::Es384).unwrap();
    validator.validate(&signature, data, pub_key).unwrap();
}

#[test]
#[cfg(all(
    feature = "openssl",
    not(all(feature = "rust_native_crypto", target_arch = "wasm32"))
))]
fn es512() {
    let private_key = include_bytes!("../../tests/fixtures/raw_signature/es512.priv");

    let Some(signer) = check_signer(signer_from_private_key(private_key, SigningAlg::Es512)) else {
        return;
    };

    assert_eq!(signer.alg(), SigningAlg::Es512);

    let data = b"some sample content to sign";
    let signature = signer.sign(data).unwrap();

    println!("signature len = {}", signature.len());
    assert!(signature.len() <= signer.max_signature_size());

    let pub_key = include_bytes!("../../tests/fixtures/raw_signature/es512.pub_key");

    let validator = validator_for_signing_alg(SigningAlg::Es512).unwrap();
    validator.validate(&signature, data, pub_key).unwrap();
}

#[test]
#[cfg_attr(
    all(target_arch = "wasm32", not(target_os = "wasi")),
    wasm_bindgen_test
)]
fn ed25519() {
    let private_key = include_bytes!("../../tests/fixtures/raw_signature/ed25519.priv");

    let Some(signer) = check_signer(signer_from_private_key(private_key, SigningAlg::Ed25519))
    else {
        return;
    };

    assert_eq!(signer.alg(), SigningAlg::Ed25519);

    let data = b"some sample content to sign";
    let signature = signer.sign(data).unwrap();

    println!("signature len = {}", signature.len());
    assert!(signature.len() <= signer.max_signature_size());

    let pub_key = include_bytes!("../../tests/fixtures/raw_signature/ed25519.pub_key");

    let validator = validator_for_signing_alg(SigningAlg::Ed25519).unwrap();
    validator.validate(&signature, data, pub_key).unwrap();
}

#[test]
#[cfg_attr(
    all(target_arch = "wasm32", not(target_os = "wasi")),
    wasm_bindgen_test
)]
fn ps256() {
    let private_key = include_bytes!("../../tests/fixtures/raw_signature/ps256.priv");

    let Some(signer) = check_signer(signer_from_private_key(private_key, SigningAlg::Ps256)) else {
        return;
    };

    assert_eq!(signer.alg(), SigningAlg::Ps256);

    let data = b"some sample content to sign";
    let signature = signer.sign(data).unwrap();

    println!("signature len = {}", signature.len());
    assert!(signature.len() <= signer.max_signature_size());

    let pub_key = include_bytes!("../../tests/fixtures/raw_signature/ps256.pub_key");

    let validator = validator_for_signing_alg(SigningAlg::Ps256).unwrap();
    validator.validate(&signature, data, pub_key).unwrap();
}

#[test]
#[cfg_attr(
    all(target_arch = "wasm32", not(target_os = "wasi")),
    wasm_bindgen_test
)]
fn ps384() {
    let private_key = include_bytes!("../../tests/fixtures/raw_signature/ps384.priv");

    let Some(signer) = check_signer(signer_from_private_key(private_key, SigningAlg::Ps384)) else {
        return;
    };

    assert_eq!(signer.alg(), SigningAlg::Ps384);

    let data = b"some sample content to sign";
    let signature = signer.sign(data).unwrap();

    println!("signature len = {}", signature.len());
    assert!(signature.len() <= signer.max_signature_size());

    let pub_key = include_bytes!("../../tests/fixtures/raw_signature/ps384.pub_key");

    let validator = validator_for_signing_alg(SigningAlg::Ps384).unwrap();
    validator.validate(&signature, data, pub_key).unwrap();
}

#[test]
#[cfg_attr(
    all(target_arch = "wasm32", not(target_os = "wasi")),
    wasm_bindgen_test
)]
fn ps512() {
    let private_key = include_bytes!("../../tests/fixtures/raw_signature/ps512.priv");

    let Some(signer) = check_signer(signer_from_private_key(private_key, SigningAlg::Ps512)) else {
        return;
    };

    assert_eq!(signer.alg(), SigningAlg::Ps512);

    let data = b"some sample content to sign";
    let signature = signer.sign(data).unwrap();

    println!("signature len = {}", signature.len());
    assert!(signature.len() <= signer.max_signature_size());

    let pub_key = include_bytes!("../../tests/fixtures/raw_signature/ps512.pub_key");

    let validator = validator_for_signing_alg(SigningAlg::Ps512).unwrap();
    validator.validate(&signature, data, pub_key).unwrap();
}

#[test]
#[cfg(all(feature = "openssl", not(feature = "rust_native_crypto")))]
fn mldsa44() {
    let private_key = include_bytes!("../../tests/fixtures/raw_signature/mldsa44.priv");

    let signer = signer_from_private_key(private_key, SigningAlg::MlDsa44).unwrap();

    assert_eq!(signer.alg(), SigningAlg::MlDsa44);

    let data = b"some sample content to sign";
    let signature = signer.sign(data).unwrap();

    assert_eq!(signature.len(), 2420);
    assert_eq!(signature.len(), signer.max_signature_size());

    let pub_key = include_bytes!("../../tests/fixtures/raw_signature/mldsa44.pub_key");

    let validator = validator_for_signing_alg(SigningAlg::MlDsa44).unwrap();
    validator.validate(&signature, data, pub_key).unwrap();
}

#[test]
#[cfg(all(feature = "openssl", not(feature = "rust_native_crypto")))]
fn mldsa65() {
    let private_key = include_bytes!("../../tests/fixtures/raw_signature/mldsa65.priv");

    let signer = signer_from_private_key(private_key, SigningAlg::MlDsa65).unwrap();

    assert_eq!(signer.alg(), SigningAlg::MlDsa65);

    let data = b"some sample content to sign";
    let signature = signer.sign(data).unwrap();

    assert_eq!(signature.len(), 3309);
    assert_eq!(signature.len(), signer.max_signature_size());

    let pub_key = include_bytes!("../../tests/fixtures/raw_signature/mldsa65.pub_key");

    let validator = validator_for_signing_alg(SigningAlg::MlDsa65).unwrap();
    validator.validate(&signature, data, pub_key).unwrap();
}

#[test]
#[cfg(all(feature = "openssl", not(feature = "rust_native_crypto")))]
fn mldsa87() {
    let private_key = include_bytes!("../../tests/fixtures/raw_signature/mldsa87.priv");

    let signer = signer_from_private_key(private_key, SigningAlg::MlDsa87).unwrap();

    assert_eq!(signer.alg(), SigningAlg::MlDsa87);

    let data = b"some sample content to sign";
    let signature = signer.sign(data).unwrap();

    assert_eq!(signature.len(), 4627);
    assert_eq!(signature.len(), signer.max_signature_size());

    let pub_key = include_bytes!("../../tests/fixtures/raw_signature/mldsa87.pub_key");

    let validator = validator_for_signing_alg(SigningAlg::MlDsa87).unwrap();
    validator.validate(&signature, data, pub_key).unwrap();
}

#[test]
#[cfg(all(feature = "openssl", not(feature = "rust_native_crypto")))]
fn mldsa65_signatures_are_hedged() {
    let private_key = include_bytes!("../../tests/fixtures/raw_signature/mldsa65.priv");
    let signer = signer_from_private_key(private_key, SigningAlg::MlDsa65).unwrap();

    let data = b"some sample content to sign";
    let signature1 = signer.sign(data).unwrap();
    let signature2 = signer.sign(data).unwrap();

    assert_ne!(signature1, signature2);

    let pub_key = include_bytes!("../../tests/fixtures/raw_signature/mldsa65.pub_key");
    let validator = validator_for_signing_alg(SigningAlg::MlDsa65).unwrap();
    validator.validate(&signature1, data, pub_key).unwrap();
    validator.validate(&signature2, data, pub_key).unwrap();
}

#[test]
#[cfg(all(feature = "openssl", not(feature = "rust_native_crypto")))]
fn mldsa65_rejects_mldsa44_key() {
    let private_key = include_bytes!("../../tests/fixtures/raw_signature/mldsa44.priv");

    let Err(err) = signer_from_private_key(private_key, SigningAlg::MlDsa65) else {
        panic!("expected error");
    };

    assert!(matches!(err, RawSignerError::InvalidSigningCredentials(_)));
}

#[test]
#[cfg(all(feature = "openssl", not(feature = "rust_native_crypto")))]
fn mldsa65_rejects_ed25519_key() {
    let private_key = include_bytes!("../../tests/fixtures/raw_signature/ed25519.priv");

    let Err(err) = signer_from_private_key(private_key, SigningAlg::MlDsa65) else {
        panic!("expected error");
    };

    assert!(matches!(err, RawSignerError::InvalidSigningCredentials(_)));
}

#[test]
#[cfg(feature = "rust_native_crypto")]
fn mldsa_not_supported_by_rust_native() {
    let private_key = include_bytes!("../../tests/fixtures/raw_signature/mldsa65.priv");

    for alg in [SigningAlg::MlDsa44, SigningAlg::MlDsa65, SigningAlg::MlDsa87] {
        let Err(err) = signer_from_private_key(private_key, alg) else {
            panic!("expected error for {alg}");
        };

        assert!(matches!(err, RawSignerError::InternalError(_)));
    }
}

