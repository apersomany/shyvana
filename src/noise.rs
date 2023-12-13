use crate::{config::Config, crypto::HASH, error::Result, packet::HandshakeInitiation};
use chacha20poly1305::aead::OsRng;
use x25519::{EphemeralSecret, PublicKey};

pub struct HandshakeState {
    ephemeral_public: [u8; 32],
}

impl HandshakeState {
    pub fn send_handshake_inititation(config: &Config, buffer: &mut [u8]) -> Result<()> {
        let message = HandshakeInitiation::wrap(buffer)?;
        message.message_type = 0x01u32.to_be_bytes();
        let ephemeral_secret = EphemeralSecret::random_from_rng(OsRng::default());
        let ephemeral_public = PublicKey::from(&ephemeral_secret);
        message.unencrypted_ephemeral = ephemeral_public.to_bytes();

        Ok(())
    }

    pub fn recv_handshake_inititation(config: &Config, buffer: &[u8]) -> Result<()> {
        Ok(())
    }

    pub fn send_handshake_response(&mut self, config: &Config, buffer: &mut [u8]) -> Result<()> {
        Ok(())
    }

    pub fn recv_handshake_response(&mut self, config: &Config, buffer: &[u8]) -> Result<()> {
        Ok(())
    }
}
