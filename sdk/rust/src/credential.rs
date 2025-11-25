use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::fmt;

type HmacSha256 = Hmac<Sha256>;

// Magic string for ID derivation - must match Go implementation
const ID_MAGIC: &[u8] = b"RDVERB_PROTOCOL_VER_01_SHA256_ID";

/// Represents a cryptographic credential with Ed25519 keypair
#[derive(Clone)]
pub struct Credential {
    signing_key: SigningKey,
    verifying_key: VerifyingKey,
    id: String,
}

impl Credential {
    /// Creates a new credential with a randomly generated Ed25519 keypair
    pub fn new() -> Result<Self, Box<dyn std::error::Error>> {
        use rand::rngs::OsRng;
        let signing_key = SigningKey::generate(&mut OsRng);
        let verifying_key = signing_key.verifying_key();
        let id = derive_id(&verifying_key);

        Ok(Self {
            signing_key,
            verifying_key,
            id,
        })
    }

    /// Creates a credential from an existing Ed25519 signing key
    pub fn from_signing_key(signing_key: SigningKey) -> Self {
        let verifying_key = signing_key.verifying_key();
        let id = derive_id(&verifying_key);
        Self {
            signing_key,
            verifying_key,
            id,
        }
    }

    /// Returns the credential ID (derived from public key)
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Returns the public key as bytes
    pub fn public_key(&self) -> &[u8] {
        self.verifying_key.as_bytes()
    }

    /// Signs data with the private key
    pub fn sign(&self, data: &[u8]) -> Vec<u8> {
        let signature = self.signing_key.sign(data);
        signature.to_bytes().to_vec()
    }

    /// Returns the signing key reference
    pub(crate) fn signing_key(&self) -> &SigningKey {
        &self.signing_key
    }

    /// Returns the verifying key reference
    pub(crate) fn verifying_key(&self) -> &VerifyingKey {
        &self.verifying_key
    }
}

impl Default for Credential {
    fn default() -> Self {
        Self::new().expect("Failed to create default credential")
    }
}

impl fmt::Debug for Credential {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Credential")
            .field("id", &self.id)
            .field("public_key", &hex::encode(self.public_key()))
            .finish()
    }
}

/// Derives an ID from a public key using HMAC-SHA256 and base32 encoding
/// This must match the Go implementation in portal/core/cryptoops/sig.go
pub fn derive_id(verifying_key: &VerifyingKey) -> String {
    let mut mac = HmacSha256::new_from_slice(ID_MAGIC)
        .expect("HMAC can take key of any size");
    mac.update(verifying_key.as_bytes());
    let result = mac.finalize();
    let bytes = result.into_bytes();

    // Use base32 encoding with the same alphabet as Go:
    // ABCDEFGHIJKLMNOPQRSTUVWXYZ234567 (RFC 4648 standard alphabet)
    base32::encode(base32::Alphabet::Rfc4648 { padding: false }, &bytes)
}

/// Verifies a signature against data and public key
pub fn verify_signature(verifying_key: &VerifyingKey, data: &[u8], signature: &[u8]) -> bool {
    if signature.len() != 64 {
        return false;
    }

    let sig_bytes: [u8; 64] = match signature.try_into() {
        Ok(b) => b,
        Err(_) => return false,
    };

    let sig = Signature::from_bytes(&sig_bytes);

    verifying_key.verify(data, &sig).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_credential_creation() {
        let cred = Credential::new().unwrap();
        assert!(!cred.id().is_empty());
        assert_eq!(cred.public_key().len(), 32);
    }

    #[test]
    fn test_sign_and_verify() {
        let cred = Credential::new().unwrap();
        let data = b"test message";
        let signature = cred.sign(data);

        assert!(verify_signature(&cred.verifying_key, data, &signature));
    }

    #[test]
    fn test_derive_id_consistency() {
        let cred = Credential::new().unwrap();
        let id1 = derive_id(&cred.verifying_key);
        let id2 = derive_id(&cred.verifying_key);
        assert_eq!(id1, id2);
    }
}
