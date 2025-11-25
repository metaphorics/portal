use crate::credential::Credential;
use crate::proto::{ClientInitPayload, Identity, ProtocolVersion, ServerInitPayload, SignedPayload};
use crate::error::{PortalError, Result};
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce,
};
use hkdf::Hkdf;
use prost::Message;
use sha2::Sha256;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tracing::{debug, error};
use x25519_dalek::{PublicKey, StaticSecret};

const NONCE_SIZE: usize = 12; // ChaCha20Poly1305 nonce size
const SESSION_KEY_SIZE: usize = 32; // X25519 shared secret size
const MAX_TIMESTAMP_SKEW: i64 = 30; // seconds
const MAX_RAW_PACKET_SIZE: usize = 1 << 26; // 64MB

// HKDF info strings for key derivation
const CLIENT_KEY_INFO: &[u8] = b"RDSEC_KEY_CLIENT";
const SERVER_KEY_INFO: &[u8] = b"RDSEC_KEY_SERVER";

/// Handshaker handles the X25519-ChaCha20Poly1305 based handshake protocol
pub struct Handshaker {
    credential: Credential,
}

impl Handshaker {
    pub fn new(credential: Credential) -> Self {
        Self { credential }
    }

    /// Performs the server-side of the handshake
    pub async fn server_handshake<S>(
        &self,
        stream: &mut S,
        alpns: &[String],
    ) -> Result<SecureConnection>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        debug!("Starting server handshake");

        // Read client init message
        let client_init_bytes = read_length_prefixed(stream).await?;

        let client_init_signed = SignedPayload::decode(&client_init_bytes[..])
            .map_err(|e| PortalError::Serialization(e.to_string()))?;

        let client_init_payload = ClientInitPayload::decode(&client_init_signed.data[..])
            .map_err(|e| PortalError::Serialization(e.to_string()))?;

        // Validate client init
        self.validate_client_init(&client_init_signed, &client_init_payload, alpns)?;

        // Generate ephemeral key pair for this session
        let ephemeral_secret = StaticSecret::random_from_rng(rand::rngs::OsRng);
        let ephemeral_public = PublicKey::from(&ephemeral_secret);

        // Create server init message
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        let mut nonce = [0u8; NONCE_SIZE];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut nonce);

        let server_init_payload = ServerInitPayload {
            version: ProtocolVersion::ProtocolVersion1 as i32,
            nonce: nonce.to_vec(),
            timestamp,
            identity: Some(Identity {
                id: self.credential.id().to_string(),
                public_key: self.credential.public_key().to_vec(),
            }),
            alpn: client_init_payload.alpn.clone(),
            session_public_key: ephemeral_public.as_bytes().to_vec(),
        };

        // Serialize and sign the payload
        let payload_bytes = server_init_payload.encode_to_vec();
        let signature = self.credential.sign(&payload_bytes);

        let server_init = SignedPayload {
            data: payload_bytes,
            signature,
        };

        // Derive session keys
        let client_session_pubkey = PublicKey::from(
            <[u8; 32]>::try_from(&client_init_payload.session_public_key[..])
                .map_err(|_| PortalError::HandshakeFailed)?,
        );

        let (server_encrypt_key, server_decrypt_key) = self.derive_server_session_keys(
            &ephemeral_secret,
            &client_session_pubkey,
            &client_init_payload.nonce,
            &nonce,
        )?;

        // Send server init message
        let server_init_bytes = server_init.encode_to_vec();
        write_length_prefixed(stream, &server_init_bytes).await?;

        debug!("Server handshake completed");

        // Create secure connection
        self.create_secure_connection(
            server_encrypt_key,
            server_decrypt_key,
            client_init_payload.identity.unwrap().id,
        )
    }

    /// Performs the client-side of the handshake
    pub async fn client_handshake<S>(
        &self,
        stream: &mut S,
        alpn: &str,
    ) -> Result<SecureConnection>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        debug!("Starting client handshake");

        // Generate ephemeral key pair for this session
        let ephemeral_secret = StaticSecret::random_from_rng(rand::rngs::OsRng);
        let ephemeral_public = PublicKey::from(&ephemeral_secret);

        // Create client init message
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        let mut nonce = vec![0u8; NONCE_SIZE];
        use rand::RngCore;
        rand::rngs::OsRng.fill_bytes(&mut nonce);

        let client_init_payload = ClientInitPayload {
            version: ProtocolVersion::ProtocolVersion1 as i32,
            nonce: nonce.clone(),
            timestamp,
            identity: Some(Identity {
                id: self.credential.id().to_string(),
                public_key: self.credential.public_key().to_vec(),
            }),
            alpn: alpn.to_string(),
            session_public_key: ephemeral_public.as_bytes().to_vec(),
        };

        // Serialize and sign the payload
        let payload_bytes = client_init_payload.encode_to_vec();
        let signature = self.credential.sign(&payload_bytes);

        let client_init = SignedPayload {
            data: payload_bytes,
            signature: signature.to_vec(),
        };

        // Send client init message
        let client_init_bytes = client_init.encode_to_vec();
        write_length_prefixed(stream, &client_init_bytes).await?;
        debug!("Sent client init message");

        // Read server init response
        let server_init_bytes = read_length_prefixed(stream).await?;

        let server_init_signed = SignedPayload::decode(&server_init_bytes[..])
            .map_err(|e| PortalError::Serialization(e.to_string()))?;

        let server_init_payload = ServerInitPayload::decode(&server_init_signed.data[..])
            .map_err(|e| PortalError::Serialization(e.to_string()))?;

        debug!("Received server init message");

        // Validate server init
        self.validate_server_init(&server_init_signed, &server_init_payload)?;

        // Derive session keys
        let server_public_key_bytes: [u8; 32] = server_init_payload
            .session_public_key
            .as_slice()
            .try_into()
            .map_err(|_| PortalError::HandshakeFailed)?;
        let server_public_key = PublicKey::from(server_public_key_bytes);

        let (client_encrypt_key, client_decrypt_key) = self.derive_client_session_keys(
            &ephemeral_secret,
            &server_public_key,
            &nonce,
            &server_init_payload.nonce,
        )?;

        debug!("Session keys derived successfully");

        // Create secure connection
        self.create_secure_connection(
            client_encrypt_key,
            client_decrypt_key,
            server_init_payload.identity.unwrap().id,
        )
    }

    fn validate_client_init(
        &self,
        client_init_signed: &SignedPayload,
        client_init_payload: &ClientInitPayload,
        expected_alpns: &[String],
    ) -> Result<()> {
        // Check protocol version
        if client_init_payload.version != ProtocolVersion::ProtocolVersion1 as i32 {
            return Err(PortalError::InvalidProtocol);
        }

        // Check timestamp
        validate_timestamp(client_init_payload.timestamp)?;

        // Check ALPN
        if !expected_alpns.contains(&client_init_payload.alpn) {
            error!("ALPN mismatch: expected {:?}, got {}", expected_alpns, client_init_payload.alpn);
            return Err(PortalError::HandshakeFailed);
        }

        // Validate identity
        let identity = client_init_payload.identity.as_ref()
            .ok_or(PortalError::InvalidIdentity)?;

        if !validate_identity(identity) {
            return Err(PortalError::InvalidIdentity);
        }

        // Verify signature
        use ed25519_dalek::{Signature, Verifier, VerifyingKey};

        let verifying_key = VerifyingKey::from_bytes(
            &<[u8; 32]>::try_from(&identity.public_key[..])
                .map_err(|_| PortalError::InvalidIdentity)?,
        )
        .map_err(|_| PortalError::InvalidSignature)?;

        let signature = Signature::from_bytes(
            &<[u8; 64]>::try_from(&client_init_signed.signature[..])
                .map_err(|_| PortalError::InvalidSignature)?,
        );

        verifying_key
            .verify(&client_init_signed.data, &signature)
            .map_err(|_| PortalError::InvalidSignature)?;

        Ok(())
    }

    fn validate_server_init(
        &self,
        server_init_signed: &SignedPayload,
        server_init_payload: &ServerInitPayload,
    ) -> Result<()> {
        // Check protocol version
        if server_init_payload.version != ProtocolVersion::ProtocolVersion1 as i32 {
            return Err(PortalError::InvalidProtocol);
        }

        // Validate timestamp (allow 30 seconds skew)
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let timestamp_diff = (now - server_init_payload.timestamp).abs();
        if timestamp_diff > MAX_TIMESTAMP_SKEW {
            error!("Timestamp validation failed: diff={}", timestamp_diff);
            return Err(PortalError::InvalidTimestamp);
        }

        // Verify signature
        let identity = server_init_payload
            .identity
            .as_ref()
            .ok_or(PortalError::InvalidIdentity)?;

        use ed25519_dalek::{Signature, Verifier, VerifyingKey};
        let public_key = VerifyingKey::from_bytes(
            &identity
                .public_key
                .as_slice()
                .try_into()
                .map_err(|_| PortalError::InvalidSignature)?,
        )
        .map_err(|_| PortalError::InvalidSignature)?;

        let signature = Signature::from_bytes(
            &server_init_signed
                .signature
                .as_slice()
                .try_into()
                .map_err(|_| PortalError::InvalidSignature)?,
        );

        public_key
            .verify(&server_init_signed.data, &signature)
            .map_err(|_| PortalError::InvalidSignature)?;

        debug!("Server init validation successful");
        Ok(())
    }

    fn derive_client_session_keys(
        &self,
        client_priv: &StaticSecret,
        server_pub: &PublicKey,
        client_nonce: &[u8],
        server_nonce: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>)> {
        // Compute shared secret
        let shared_secret = client_priv.diffie_hellman(server_pub);

        // Client encrypts, server decrypts
        let mut salt = client_nonce.to_vec();
        salt.extend_from_slice(server_nonce);
        let encrypt_key = derive_key(shared_secret.as_bytes(), &salt, CLIENT_KEY_INFO);

        // Server encrypts, client decrypts
        let mut salt = server_nonce.to_vec();
        salt.extend_from_slice(client_nonce);
        let decrypt_key = derive_key(shared_secret.as_bytes(), &salt, SERVER_KEY_INFO);

        Ok((encrypt_key, decrypt_key))
    }

    fn derive_server_session_keys(
        &self,
        server_priv: &StaticSecret,
        client_pub: &PublicKey,
        client_nonce: &[u8],
        server_nonce: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>)> {
        // Compute shared secret
        let shared_secret = server_priv.diffie_hellman(client_pub);

        // Server encrypts, client decrypts
        let mut salt = server_nonce.to_vec();
        salt.extend_from_slice(client_nonce);
        let encrypt_key = derive_key(shared_secret.as_bytes(), &salt, SERVER_KEY_INFO);

        // Client encrypts, server decrypts
        let mut salt = client_nonce.to_vec();
        salt.extend_from_slice(server_nonce);
        let decrypt_key = derive_key(shared_secret.as_bytes(), &salt, CLIENT_KEY_INFO);

        Ok((encrypt_key, decrypt_key))
    }

    fn create_secure_connection(
        &self,
        encrypt_key: Vec<u8>,
        decrypt_key: Vec<u8>,
        remote_id: String,
    ) -> Result<SecureConnection> {
        let encryptor = ChaCha20Poly1305::new_from_slice(&encrypt_key)
            .map_err(|_| PortalError::EncryptionFailed)?;

        let decryptor = ChaCha20Poly1305::new_from_slice(&decrypt_key)
            .map_err(|_| PortalError::DecryptionFailed)?;

        Ok(SecureConnection {
            local_id: self.credential.id().to_string(),
            remote_id,
            encryptor,
            decryptor,
            read_buffer: Vec::new(),
        })
    }
}

/// SecureConnection wraps a stream with encryption
pub struct SecureConnection {
    local_id: String,
    remote_id: String,
    encryptor: ChaCha20Poly1305,
    decryptor: ChaCha20Poly1305,
    read_buffer: Vec<u8>,
}

impl SecureConnection {
    pub fn local_id(&self) -> &str {
        &self.local_id
    }

    pub fn remote_id(&self) -> &str {
        &self.remote_id
    }

    /// Write encrypted data to the stream
    pub async fn write<S>(&mut self, stream: &mut S, data: &[u8]) -> Result<()>
    where
        S: AsyncWrite + Unpin,
    {
        // Generate random nonce
        let mut nonce_bytes = [0u8; NONCE_SIZE];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        // Encrypt data
        let ciphertext = self
            .encryptor
            .encrypt(nonce, data)
            .map_err(|_| PortalError::EncryptionFailed)?;

        // Calculate total size: nonce + ciphertext
        let total_size = NONCE_SIZE + ciphertext.len();

        // Write length prefix
        stream.write_u32(total_size as u32).await?;

        // Write nonce
        stream.write_all(&nonce_bytes).await?;

        // Write ciphertext
        stream.write_all(&ciphertext).await?;

        Ok(())
    }

    /// Read and decrypt data from the stream
    pub async fn read<S>(&mut self, stream: &mut S, buf: &mut [u8]) -> Result<usize>
    where
        S: AsyncRead + Unpin,
    {
        // If we have buffered data, return it first
        if !self.read_buffer.is_empty() {
            let n = std::cmp::min(buf.len(), self.read_buffer.len());
            buf[..n].copy_from_slice(&self.read_buffer[..n]);
            self.read_buffer.drain(..n);
            return Ok(n);
        }

        // Read length prefix
        let length = stream.read_u32().await? as usize;

        if length > MAX_RAW_PACKET_SIZE {
            return Err(PortalError::DecryptionFailed);
        }

        // Read encrypted message
        let mut encrypted = vec![0u8; length];
        stream.read_exact(&mut encrypted).await?;

        // Extract nonce and ciphertext
        if encrypted.len() < NONCE_SIZE {
            return Err(PortalError::DecryptionFailed);
        }

        let nonce = Nonce::from_slice(&encrypted[..NONCE_SIZE]);
        let ciphertext = &encrypted[NONCE_SIZE..];

        // Decrypt
        let plaintext = self
            .decryptor
            .decrypt(nonce, ciphertext)
            .map_err(|_| PortalError::DecryptionFailed)?;

        // Copy to output buffer
        let n = std::cmp::min(buf.len(), plaintext.len());
        buf[..n].copy_from_slice(&plaintext[..n]);

        // Buffer any remaining data
        if plaintext.len() > n {
            self.read_buffer.extend_from_slice(&plaintext[n..]);
        }

        Ok(n)
    }
}

// Helper functions

fn validate_identity(identity: &Identity) -> bool {
    use crate::credential::derive_id;
    use ed25519_dalek::VerifyingKey;

    if identity.public_key.len() != 32 {
        return false;
    }

    let Ok(verifying_key) = VerifyingKey::from_bytes(
        &<[u8; 32]>::try_from(&identity.public_key[..]).unwrap(),
    ) else {
        return false;
    };

    let derived_id = derive_id(&verifying_key);
    derived_id == identity.id
}

fn validate_timestamp(timestamp: i64) -> Result<()> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;

    let diff = now - timestamp;

    if diff < -MAX_TIMESTAMP_SKEW || diff > MAX_TIMESTAMP_SKEW {
        return Err(PortalError::InvalidTimestamp);
    }

    Ok(())
}

fn derive_key(shared_secret: &[u8], salt: &[u8], info: &[u8]) -> Vec<u8> {
    let hkdf = Hkdf::<Sha256>::new(Some(salt), shared_secret);
    let mut key = vec![0u8; SESSION_KEY_SIZE];
    hkdf.expand(info, &mut key)
        .expect("HKDF expand should never fail");
    key
}

async fn read_length_prefixed<R: AsyncRead + Unpin>(reader: &mut R) -> Result<Vec<u8>> {
    let length = reader.read_u32().await? as usize;

    if length > MAX_RAW_PACKET_SIZE {
        return Err(PortalError::HandshakeFailed);
    }

    let mut data = vec![0u8; length];
    reader.read_exact(&mut data).await?;

    Ok(data)
}

async fn write_length_prefixed<W: AsyncWrite + Unpin>(
    writer: &mut W,
    data: &[u8],
) -> Result<()> {
    writer.write_u32(data.len() as u32).await?;
    writer.write_all(data).await?;
    Ok(())
}
