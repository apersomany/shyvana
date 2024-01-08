use std::ops::{Deref, DerefMut};

use crate::{
    crypto::{open, seal},
    error::{Error, Result},
    packet::TransportData,
};

pub struct Encrypted<'a> {
    buffer: &'a mut [u8],
    length: usize,
}

impl<'a> Encrypted<'a> {
    pub fn new(buffer: &'a mut [u8]) -> Self {
        Self {
            length: buffer.len(),
            buffer,
        }
    }

    pub fn resize(&mut self, length: usize) -> bool {
        if length > self.buffer.len() {
            false
        } else {
            self.length = length;
            true
        }
    }
}

impl<'a> Deref for Encrypted<'a> {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.buffer[0x00..self.length].as_ref()
    }
}

impl<'a> DerefMut for Encrypted<'a> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.buffer[0x00..self.length].as_mut()
    }
}

pub struct Decrypted<'a> {
    buffer: &'a mut [u8],
    length: usize,
}

impl<'a> Decrypted<'a> {
    pub fn new(buffer: &'a mut [u8]) -> Self {
        Self {
            length: buffer.len() - 0x20,
            buffer,
        }
    }

    pub fn resize(&mut self, length: usize) -> bool {
        if length > self.buffer.len() - 0x20 {
            false
        } else {
            self.length = length;
            true
        }
    }
}

impl<'a> Deref for Decrypted<'a> {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.buffer[0x10..0x10 + self.length].as_ref()
    }
}

impl<'a> DerefMut for Decrypted<'a> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.buffer[0x10..0x10 + self.length].as_mut()
    }
}

pub struct Encryptor {
    r_i: [u8; 0x04], // receiver index
    key: [u8; 0x20], // sending key
    s_c: u64,        // send counter
    s_b: u64,        // send counter upper bound (exclusive)
}

impl Encryptor {
    pub fn encrypt(&mut self, buffer: Decrypted) -> Result<Encrypted> {
        todo!()
    }

    pub fn reserve(&mut self, amount: u64) -> Self {
        Self {
            key: self.key,
            s_c: self.s_c,
            s_b: {
                self.s_c = (self.s_c + amount).min(self.s_b);
                self.s_c
            },
            r_i: self.r_i,
        }
    }

    pub fn r_i(&self) -> [u8; 0x04] {
        self.r_i
    }

    pub fn key(&self) -> [u8; 0x20] {
        self.key
    }

    pub fn s_c(&self) -> u64 {
        self.s_c
    }

    pub fn s_b(&self) -> u64 {
        self.s_b
    }
}

pub struct Decryptor {
    r_i: [u8; 0x04], // receiver index
    key: [u8; 0x20], // receiving key
}

impl Decryptor {
    pub fn decrypt(&self, buffer: &mut [u8]) -> Result<()> {
        if buffer.len() < 0x20 {
            Err(Error::BufferLengthTooShort {
                expected: 0x20,
                got: buffer.len(),
            })?
        }
        // encapsulated_packet = encapsulated_packet || zero padding in order to make the length a multiple of 16
        if buffer.len() % 0x10 != 0 {
            Err(Error::BufferLengthInvalid)?
        }
        let msg = TransportData::wrap_mut(buffer)?;
        let cnt = u64::from_le_bytes(msg.cnt);
        // msg.encrypted_encapsulated_packet = AEAD(initiator.sending_key, counter, encapsulated_packet, [empty])
        let length = buffer.len();
        let (lhs, rhs) = buffer[0x10..].split_at_mut(length - 0x20);
        open(self.key, cnt, [], lhs, rhs)?;
        Ok(())
    }

    pub fn r_i(&self) -> [u8; 0x04] {
        self.r_i
    }

    pub fn key(&self) -> [u8; 0x20] {
        self.key
    }
}
