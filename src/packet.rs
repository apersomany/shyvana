use crate::error::{Error, Result};
use std::mem::size_of;

macro_rules! packet {
    ($name:ident { $($field_name:ident: $field_size:literal),+ }) => {
        #[repr(packed)]
        pub struct $name {
            $(pub $field_name: [u8; $field_size]),+
        }

        impl $name {
            pub fn wrap_ref<'a>(buffer: &'a [u8]) -> Result<&'a Self> {
                if buffer.len() < size_of::<Self>() {
                    Err(Error::BufferTooSmall)
                } else {
                    unsafe {
                        Ok(&*buffer.as_ptr().cast())
                    }
                }
            }

            pub fn wrap_mut<'a>(buffer: &'a mut [u8]) -> Result<&'a mut Self> {
                if buffer.len() < size_of::<Self>() {
                    Err(Error::BufferTooSmall)
                } else {
                    unsafe {
                        Ok(&mut *buffer.as_mut_ptr().cast())
                    }
                }
            }
        }
    };
}

packet! {
    HandshakeInitiation {
        message_type: 0x04,
        sender_index: 0x04,
        unencrypted_ephemeral: 0x20,
        encrypted_static: 0x30,
        encrypted_timestamp: 0x1c,
        mac1: 0x10,
        mac2: 0x10
    }
}

packet! {
    HandshakeResponse {
        message_type: 0x04,
        sender_index: 0x04,
        receiver_index: 0x04,
        unencrypted_ephemeral: 0x20,
        encrypted_nothing: 0x10,
        mac1: 0x10,
        mac2: 0x10
    }
}

packet! {
    CookieReply {
        message_type: 0x04,
        receiver_index: 0x08,
        nonce: 0x18,
        encrypted_cookie: 0x20
    }
}

packet! {
    TransportDataHeader {
        message_type: 0x04,
        receiver_index: 0x04,
        counter: 0x08
    }
}
