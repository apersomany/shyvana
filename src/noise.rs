use crate::{
    config::Config,
    crypto::{AEAD, HASH, HKDF, HMAC, TAI64N},
    error::{Error, Result},
    packet::{HandshakeInitiation, HandshakeResponse},
};
use chacha20poly1305::aead::OsRng;
use x25519::{EphemeralSecret, PublicKey};

const CONSTRUCTION: &str = "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s";
const IDENTIFIER: &str = "WireGuard v1 zx2c4 Jason@zx2c4.com";
const LABEL_MAC1: &str = "mac1----";
const LABEL_COOKIE: &str = "cookie--";

const INITIAL_CHAINING_KEY: [u8; 0x20] = [0x00; 0x20];
const INITIAL_HASH: [u8; 0x20] = [0x00; 0x20];

pub struct HandshakeState {
    chaining_key: [u8; 0x20],
    hash: [u8; 0x20],
    ephemeral_public: PublicKey,
}

impl HandshakeState {
    pub fn send_handshake_inititation(config: &Config, buffer: &mut [u8]) -> Result<Self> {
        let message = HandshakeInitiation::wrap_mut(buffer)?;

        message.message_type = 0x01u32.to_be_bytes();

        let ephemeral_secret = EphemeralSecret::random_from_rng(OsRng::default());
        let ephemeral_public = PublicKey::from(&ephemeral_secret);

        let [chaining_key] = HKDF!(INITIAL_CHAINING_KEY, message.unencrypted_ephemeral);
        let hash = HASH!(INITIAL_HASH, config.peer_public);

        message.unencrypted_ephemeral = ephemeral_public.to_bytes();
        let hash = HASH!(hash, message.unencrypted_ephemeral);

        let [chaining_key, key] = HKDF!(
            chaining_key,
            ephemeral_secret.diffie_hellman(&config.peer_public)
        );
        message.encrypted_static = AEAD!(key, 0, config.self_public, hash);
        let hash = HASH!(hash, message.encrypted_static);

        let [chaining_key, key] = HKDF!(
            chaining_key,
            config.self_secret.diffie_hellman(&config.peer_public)
        );
        message.encrypted_timestamp = AEAD!(key, 0, TAI64N!(), hash);
        let hash = HASH!(hash, message.encrypted_timestamp);

        Ok(Self {
            chaining_key,
            hash,
            ephemeral_public,
        })
    }

    pub fn recv_handshake_inititation(config: &Config, buffer: &[u8]) -> Result<Self> {
        let message = HandshakeInitiation::wrap_ref(buffer)?;
        if u32::from_be_bytes(message.message_type) != 0x01 {
            return Err(Error::InvalidMessageType)?;
        }

        let [chaining_key] = HKDF!(INITIAL_CHAINING_KEY, message.unencrypted_ephemeral);
        let hash = HASH!(INITIAL_HASH, config.self_public);

        let ephemeral_public = PublicKey::from(message.unencrypted_ephemeral);
        let hash = HASH!(hash, message.unencrypted_ephemeral);

        let [chaining_key, key] = HKDF!(
            chaining_key,
            config.self_secret.diffie_hellman(&ephemeral_public)
        );
        let hash = HASH!(hash, message.encrypted_static);

        let [chaining_key, key] = HKDF!(
            chaining_key,
            config.self_secret.diffie_hellman(&ephemeral_public)
        );
        message.encrypted_timestamp = AEAD!(key, 0, TAI64N!(), hash);
        let hash = HASH!(hash, message.encrypted_timestamp);

        Ok(Self {
            chaining_key,
            hash,
            ephemeral_public: PublicKey::from(message.unencrypted_ephemeral),
        })
    }
    pub fn send_handshake_response(
        self,
        config: &Config,
        buffer: &mut [u8],
    ) -> Result<([u8; 32], [u8; 32])> {
        let message = HandshakeResponse::wrap_mut(buffer)?;
        Ok(todo!())
    }

    pub fn recv_handshake_response(
        self,
        config: &Config,
        buffer: &[u8],
    ) -> Result<([u8; 32], [u8; 32])> {
        let message = HandshakeResponse::wrap_ref(buffer)?;
        Ok(todo!())
    }
}
