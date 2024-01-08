use blake2::{
    digest::{
        consts::{U16, U32},
        Digest, Mac,
    },
    Blake2s, Blake2sMac,
};
use chacha20poly1305::{AeadInPlace, ChaCha20Poly1305, KeyInit};
use hmac::SimpleHmac;

pub fn hash(one: impl AsRef<[u8]>, two: impl AsRef<[u8]>) -> [u8; 0x20] {
    let mut digest: Blake2s<U32> = Digest::new();
    digest.update(one);
    digest.update(two);
    digest.finalize().into()
}

pub fn mac(key: impl AsRef<[u8]>, txt: impl AsRef<[u8]>) -> [u8; 0x10] {
    let mut digest: Blake2sMac<U16> = Mac::new_from_slice(key.as_ref()).unwrap();
    digest.update(txt.as_ref());
    digest.finalize().into_bytes().into()
}

pub fn kdf<const N: usize>(key: impl AsRef<[u8]>, txt: impl AsRef<[u8]>) -> [[u8; 0x20]; N] {
    let mut output = [[0x00; 0x20]; N];
    let mut digest: SimpleHmac<Blake2s<U32>> = Mac::new_from_slice(key.as_ref()).unwrap();
    digest.update(txt.as_ref());
    let key = digest.finalize().into_bytes();
    for i in 0..N {
        let mut digest: SimpleHmac<Blake2s<U32>> = Mac::new_from_slice(key.as_ref()).unwrap();
        if i > 0 {
            digest.update(&output[i - 1]);
        }
        digest.update(&[i as u8 + 1]);
        output[i] = digest.finalize().into_bytes().into()
    }
    output
}

pub fn seal(
    key: impl AsRef<[u8]>,
    cnt: u64,
    aad: impl AsRef<[u8]>,
    mut txt: impl AsMut<[u8]>,
    mut tag: impl AsMut<[u8]>,
) -> Result<(), chacha20poly1305::Error> {
    let mut nonce = [0x00; 0x0c];
    nonce[0x04..0x0c].copy_from_slice(&cnt.to_le_bytes());
    tag.as_mut().copy_from_slice(
        ChaCha20Poly1305::new_from_slice(key.as_ref())
            .unwrap()
            .encrypt_in_place_detached(&nonce.into(), aad.as_ref(), txt.as_mut())?
            .as_ref(),
    );
    Ok(())
}

pub fn open(
    key: impl AsRef<[u8]>,
    cnt: u64,
    aad: impl AsRef<[u8]>,
    mut txt: impl AsMut<[u8]>,
    tag: impl AsRef<[u8]>,
) -> Result<(), chacha20poly1305::Error> {
    let mut nonce = [0x00; 0x0c];
    nonce[0x04..0x0c].copy_from_slice(&cnt.to_le_bytes());
    ChaCha20Poly1305::new_from_slice(key.as_ref())
        .unwrap()
        .decrypt_in_place_detached(
            &nonce.into(),
            aad.as_ref(),
            txt.as_mut(),
            tag.as_ref().into(),
        )
}
