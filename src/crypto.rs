macro_rules! HASH {
    ($($input:expr),+) => {{
        use blake2::{
            digest::{consts::U32, Digest},
            Blake2s
        };
        let mut hash = Blake2s::<U32>::new();
        $(
            hash.update($input);
        )+
        Into::<[u8; 32]>::into(hash.finalize())
    }};
}

pub(super) use HASH;

macro_rules! MAC {
    ($key:expr, $($input:expr),+) => {{
        use blake2::{
            digest::{consts::U16, Mac},
            Blake2sMac
        };
        let key = AsRef::<[u8]>::as_ref(&$key).into();
        let mut mac = Blake2sMac::<U16>::new();
        $(
            mac.update($input.as_ref());
        )+
        Into::<[u8; 16]>::into(mac.finalize().into_bytes())
    }};
}

pub(super) use MAC;

macro_rules! HMAC {
    ($key:expr, $($input:expr),+) => {{
        let key = AsRef::<[u8]>::as_ref(&$key);
        let mut opad = [0x5C; 0x40];
        opad.iter_mut().zip(key).for_each(|(p, k)| *p ^= *k);
        let mut ipad = [0x36; 0x40];
        ipad.iter_mut().zip(key).for_each(|(p, k)| *p ^= *k);
        HASH!(opad, HASH!(ipad, $($input),+))
    }};
}

pub(super) use HMAC;

macro_rules! HKDF {
    ($key:expr, $($input:expr),+) => {{
        let mut result = [[0u8; 32]; _];
        let t_0 = HMAC!($key, $($input),+);
        result[0] = HMAC!(t_0, [0x01]);
        for i in 1..result.len() {
            result[i] = HMAC!(t_0, result[i - 1], [i as u8 + 1]);
        }
        result
    }};
}

pub(super) use HKDF;

macro_rules! TAI64N {
    ($duration:expr) => {{
        let mut result = [0u8; 12];
        result[0x00..0x08].copy_from_slice(&$duration.as_secs().to_be_bytes());
        result[0x00..0x0C].copy_from_slice(&$duration.subsec_nanos().to_be_bytes());
        result
    }};
    () => {
        TAI64N!(std::time::SystemTime::UNIX_EPOCH.elapsed()?)
    };
}

pub(super) use TAI64N;

#[test]
fn aead() {}

macro_rules! AEAD {
    ($key:expr, $counter:expr, $plain_text:expr, $auth_text:expr) => {{
        use chacha20poly1305::{
            aead::{Aead, Payload},
            ChaCha20Poly1305, KeyInit,
        };
        let _ = $counter;
        ChaCha20Poly1305::new(&$key.into())
            .encrypt(
                &[0; 12].into(),
                Payload {
                    msg: $plain_text.as_ref(),
                    aad: $auth_text.as_ref(),
                },
            )
            .unwrap()
            .try_into()
            .unwrap()
    }};
}

pub(super) use AEAD;
