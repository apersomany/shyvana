use std::time::Duration;
use x25519::{PublicKey, ReusableSecret, StaticSecret};

use crate::{
    crypto::{hash, kdf, mac, open, seal},
    error::Result,
    packet::{HandshakeInit, HandshakeResp},
};

pub const INITIAL_H_H: [u8; 0x20] = [
    0x22, 0x11, 0xb3, 0x61, 0x08, 0x1a, 0xc5, 0x66, 0x69, 0x12, 0x43, 0xdb, 0x45, 0x8a, 0xd5, 0x32,
    0x2d, 0x9c, 0x6c, 0x66, 0x22, 0x93, 0xe8, 0xb7, 0x0e, 0xe1, 0x9c, 0x65, 0xba, 0x07, 0x9e, 0xf3,
];

pub const INITIAL_C_K: [u8; 0x20] = [
    0x60, 0xe2, 0x6d, 0xae, 0xf3, 0x27, 0xef, 0xc0, 0x2e, 0xc3, 0x35, 0xe2, 0xa0, 0x25, 0xd2, 0xd0,
    0x16, 0xeb, 0x42, 0x06, 0xf8, 0x72, 0x77, 0xf5, 0x2d, 0x38, 0xd1, 0x98, 0x8b, 0x78, 0xcd, 0x36,
];

pub struct Initiator {
    h_h: [u8; 0x20],     // handshake hash
    c_k: [u8; 0x20],     // chaining key
    e_s: ReusableSecret, // initiator ephemeral secret
}

impl Initiator {
    pub fn send_handshake_init(
        i_i: [u8; 0x04],         // initiator index
        i_s: &StaticSecret,      // initiator static secret
        i_p: &PublicKey,         // initiator static public
        r_p: &PublicKey,         // responder static public
        e_s: ReusableSecret,     // initiator ephemeral secret
        now: Duration,           // duration since UNIX epoch
        l_c: Option<[u8; 0x20]>, // latest cookie received
        msg: &mut HandshakeInit, // destination buffer
    ) -> Result<Self> {
        // initiator.hash = HASH(HASH(initiator.chaining_key || IDENTIFIER) || responder.static_public)
        let h_h = hash(INITIAL_H_H, r_p);
        // msg.message_type = 1
        msg.m_t = 0x01;
        // msg.reserved_zero = { 0, 0, 0 }
        msg.r_0 = [0x00; 0x03];
        // msg.sender_index = little_endian(initiator.sender_index)
        msg.s_i = i_i;

        // msg.unencrypted_ephemeral = DH_PUBKEY(initiator.ephemeral_private)
        let e_p = PublicKey::from(&e_s);
        msg.u_e = e_p.to_bytes();
        // initiator.hash = HASH(initiator.hash || msg.unencrypted_ephemeral)
        let h_h = hash(h_h, msg.u_e);

        // temp = HMAC(initiator.chaining_key, msg.unencrypted_ephemeral)
        // initiator.chaining_key = HMAC(temp, 0x1)
        let [c_k] = kdf(INITIAL_C_K, msg.u_e);

        // temp = HMAC(initiator.chaining_key, DH(initiator.ephemeral_private, responder.static_public))
        // initiator.chaining_key = HMAC(temp, 0x1)
        // key = HMAC(temp, initiator.chaining_key || 0x2)
        let [c_k, key] = kdf(c_k, e_s.diffie_hellman(&r_p));

        // msg.encrypted_static = AEAD(key, 0, initiator.static_public, initiator.hash)
        let (lhs, rhs) = msg.e_s.split_at_mut(0x20);
        lhs.copy_from_slice(i_p.as_bytes());
        seal(key, 0, h_h, lhs, rhs)?;
        // initiator.hash = HASH(initiator.hash || msg.encrypted_static)
        let h_h = hash(h_h, msg.e_s);

        // temp = HMAC(initiator.chaining_key, DH(initiator.static_private, responder.static_public))
        // initiator.chaining_key = HMAC(temp, 0x1)
        // key = HMAC(temp, initiator.chaining_key || 0x2)
        let [c_k, key] = kdf(c_k, i_s.diffie_hellman(&r_p));

        // msg.encrypted_timestamp = AEAD(key, 0, TAI64N(), initiator.hash)
        let (lhs, rhs) = msg.e_t.split_at_mut(0x0c);
        lhs[0x00..0x08].copy_from_slice(&now.as_secs().to_be_bytes());
        lhs[0x08..0x0c].copy_from_slice(&now.subsec_nanos().to_be_bytes());
        seal(key, 0, h_h, lhs, rhs)?;
        // initiator.hash = HASH(initiator.hash || msg.encrypted_timestamp)
        let h_h = hash(h_h, msg.e_t);

        // msg.mac1 = MAC(HASH(LABEL_MAC1 || responder.static_public), msg[0:offsetof(msg.mac1)])
        msg.m_1 = mac(hash("mac1----", r_p), &msg[0x00..0x74]);

        // if (initiator.last_received_cookie is empty or expired)
        //     msg.mac2 = [zeros]
        // else
        //     msg.mac2 = MAC(initiator.last_received_cookie, msg[0:offsetof(msg.mac2)])
        msg.m_2 = if let Some(latest_cookie) = l_c {
            mac(latest_cookie, &msg[0x00..0x84])
        } else {
            [0x00; 0x10]
        };

        Ok(Self { c_k, h_h, e_s })
    }

    pub fn recv_handshake_resp(
        self,
        i_s: &StaticSecret,      // initiator static secret
        p_k: Option<[u8; 0x20]>, // preshared key
        src: &HandshakeResp,     // source buffer
    ) -> Result<([u8; 0x20], [u8; 0x20])> {
        let msg = HandshakeResp::wrap_ref(src)?;

        // msg.unencrypted_ephemeral = DH_PUBKEY(responder.ephemeral_private)
        let e_p = PublicKey::from(msg.u_e);
        // responder.hash = HASH(responder.hash || msg.unencrypted_ephemeral)
        let h_h = hash(self.h_h, msg.u_e);

        // temp = HMAC(responder.chaining_key, msg.unencrypted_ephemeral)
        // responder.chaining_key = HMAC(temp, 0x1)
        let [c_k] = kdf(self.c_k, msg.u_e);

        // temp = HMAC(responder.chaining_key, DH(responder.ephemeral_private, initiator.ephemeral_public))
        // responder.chaining_key = HMAC(temp, 0x1)
        let [c_k] = kdf(c_k, self.e_s.diffie_hellman(&e_p));

        // temp = HMAC(responder.chaining_key, DH(responder.ephemeral_private, initiator.static_public))
        // responder.chaining_key = HMAC(temp, 0x1)
        let [c_k] = kdf(c_k, i_s.diffie_hellman(&e_p));

        // temp = HMAC(responder.chaining_key, preshared_key)
        // responder.chaining_key = HMAC(temp, 0x1)
        // temp2 = HMAC(temp, responder.chaining_key || 0x2)
        // key = HMAC(temp, temp2 || 0x3)
        let [c_k, tau, key] = kdf(c_k, p_k.unwrap_or_default());
        // responder.hash = HASH(responder.hash || temp2)
        let h_h = hash(h_h, tau);

        // msg.encrypted_nothing = AEAD(key, 0, [empty], responder.hash)
        open(key, 0, h_h, [], &msg.e_n)?;

        // temp1 = HMAC(initiator.chaining_key, [empty])
        // temp2 = HMAC(temp1, 0x1)
        // temp3 = HMAC(temp1, temp2 || 0x2)
        // initiator.sending_key = temp2
        // initiator.receiving_key = temp3
        let [_, s_k, r_k] = kdf(c_k, []);

        Ok((s_k, r_k))
    }
}

pub struct Responder {
    h_h: [u8; 0x20], // handshake hash
    c_k: [u8; 0x20], // chaining key
    e_p: PublicKey,  // initiator ephemeral public
}

impl Responder {
    pub fn recv_handshake_init(
        r_s: &StaticSecret,  // responder static secret
        r_p: &PublicKey,     // responder static public
        i_p: &PublicKey,     // initiator public
        msg: &HandshakeInit, // source buffer
    ) -> Result<Self> {
        // initiator.hash = HASH(HASH(initiator.chaining_key || IDENTIFIER) || responder.static_public)
        let h_h = hash(INITIAL_H_H, r_p);

        // msg.unencrypted_ephemeral = DH_PUBKEY(initiator.ephemeral_private)
        let e_p = PublicKey::from(msg.u_e);
        // initiator.hash = HASH(initiator.hash || msg.unencrypted_ephemeral)
        let h_h = hash(h_h, msg.u_e);

        // temp = HMAC(initiator.chaining_key, msg.unencrypted_ephemeral)
        // initiator.chaining_key = HMAC(temp, 0x1)
        let [c_k] = kdf(INITIAL_C_K, msg.u_e);

        // temp = HMAC(initiator.chaining_key, DH(initiator.ephemeral_private, responder.static_public))
        // initiator.chaining_key = HMAC(temp, 0x1)
        // key = HMAC(temp, initiator.chaining_key || 0x2)
        let [c_k, key] = kdf(c_k, r_s.diffie_hellman(&e_p));
        // msg.encrypted_static = AEAD(key, 0, initiator.static_public, initiator.hash)

        let mut e_s = msg.e_s;
        let (lhs, rhs) = e_s.split_at_mut(0x20);
        open(key, 0, h_h, lhs, rhs)?;
        // initiator.hash = HASH(initiator.hash || msg.encrypted_static)
        let h_h = hash(h_h, msg.e_s);

        // temp = HMAC(initiator.chaining_key, DH(initiator.static_private, responder.static_public))
        // initiator.chaining_key = HMAC(temp, 0x1)
        // key = HMAC(temp, initiator.chaining_key || 0x2)
        let [c_k, key] = kdf(c_k, r_s.diffie_hellman(&i_p));

        // msg.encrypted_timestamp = AEAD(key, 0, TAI64N(), initiator.hash)
        let mut e_t = msg.e_t;
        let (lhs, rhs) = e_t.split_at_mut(0x0c);
        seal(key, 0, h_h, lhs, rhs)?;
        // initiator.hash = HASH(initiator.hash || msg.encrypted_timestamp)
        let h_h = hash(h_h, msg.e_t);

        Ok(Self { h_h, c_k, e_p })
    }

    pub fn send_handshake_resp(
        self,
        i_i: [u8; 0x04],         // initiator index
        i_p: &PublicKey,         // initiator static public
        r_i: [u8; 0x04],         // responder index
        e_s: ReusableSecret,     // responder ephemeral secret
        p_k: Option<[u8; 0x20]>, // preshared key
        l_c: Option<[u8; 0x20]>, // latest cookie received
        msg: &mut HandshakeResp,
    ) -> Result<([u8; 0x20], [u8; 0x20])> {
        // msg.message_type = 2
        msg.m_t = 0x02;
        // msg.reserved_zero = { 0, 0, 0 }
        msg.r_0 = [0x00; 0x03];
        // msg.sender_index = little_endian(responder.sender_index)
        msg.s_i = r_i;
        // msg.receiver_index = little_endian(initiator.sender_index)
        msg.r_i = i_i;

        // msg.unencrypted_ephemeral = DH_PUBKEY(responder.ephemeral_private)
        let e_p = PublicKey::from(&e_s);
        msg.u_e = e_p.to_bytes();
        // responder.hash = HASH(responder.hash || msg.unencrypted_ephemeral)
        let h_h = hash(self.h_h, msg.u_e);

        // temp = HMAC(responder.chaining_key, msg.unencrypted_ephemeral)
        // responder.chaining_key = HMAC(temp, 0x1)
        let [c_k] = kdf(self.c_k, msg.u_e);

        // temp = HMAC(responder.chaining_key, DH(responder.ephemeral_private, initiator.ephemeral_public))
        // responder.chaining_key = HMAC(temp, 0x1)
        let [c_k] = kdf(c_k, e_s.diffie_hellman(&self.e_p));

        // temp = HMAC(responder.chaining_key, DH(responder.ephemeral_private, initiator.static_public))
        // responder.chaining_key = HMAC(temp, 0x1)
        let [c_k] = kdf(c_k, e_s.diffie_hellman(i_p));

        // temp = HMAC(responder.chaining_key, preshared_key)
        // responder.chaining_key = HMAC(temp, 0x1)
        // temp2 = HMAC(temp, responder.chaining_key || 0x2)
        // key = HMAC(temp, temp2 || 0x3)
        let [c_k, tau, key] = kdf(c_k, p_k.unwrap_or_default());
        // responder.hash = HASH(responder.hash || temp2)
        let h_h = hash(h_h, tau);

        // msg.encrypted_nothing = AEAD(key, 0, [empty], responder.hash)
        seal(key, 0, h_h, [], &mut msg.e_n)?;

        // msg.mac1 = MAC(HASH(LABEL_MAC1 || initiator.static_public), msg[0:offsetof(msg.mac1)])
        msg.m_1 = mac(hash("mac1----", i_p), &msg[0x00..0x3c]);

        // if (responder.last_received_cookie is empty or expired)
        //     msg.mac2 = [zeros]
        // else
        //     msg.mac2 = MAC(responder.last_received_cookie, msg[0:offsetof(msg.mac2)])
        msg.m_2 = if let Some(latest_cookie) = l_c {
            mac(latest_cookie, &msg[0x00..0x4c])
        } else {
            [0x00; 0x10]
        };

        // temp1 = HMAC(responder.chaining_key, [empty])
        // temp2 = HMAC(temp1, 0x1)
        // temp3 = HMAC(temp1, temp2 || 0x2)
        // responder.receiving_key = temp2
        // responder.sending_key = temp3
        let [_, r_k, s_k] = kdf(c_k, []);

        Ok((s_k, r_k))
    }
}
