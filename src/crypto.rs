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
        fn inner_impl<const N: usize>() -> [[u8; 32]; N] {
            let mut result = [[0u8; 32]; N];
            let t_0 = HMAC!($key, $($input),+);
            for i in 0..N {
                result[i] = HMAC!(t_0, [i as u8 + 1])
            }
            for i in 1..N {
                result[i] = HMAC!(t_0, result[i - 1], [i as u8 + 1]);
            }
            result
        }
        inner_impl()
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
        fn inner_impl() -> Result<[u8; 12], std::time::SystemTimeError> {
            Ok(TAI64N!(std::time::SystemTime::UNIX_EPOCH.elapsed()?))
        }
    };
}

pub(super) use TAI64N;

macro_rules! AEAD {
    ($key:expr, $counter:expr, $plain_text:expr, $auth_text:expr) => {};
}

pub(super) use AEAD;
