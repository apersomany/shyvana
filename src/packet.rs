use crate::error::{Error, Result};
use core::{
    mem::size_of,
    ops::{Deref, DerefMut},
    slice,
};

macro_rules! define {
    (
        $(
            $name:ident {
                $(
                    $field_name:ident: $field_size:literal
                )+
            }
        )+
    ) => {
        $(
            #[repr(packed)]
            pub struct $name {
                pub m_t: u8,
                pub r_0: [u8; 0x03],
                $(
                    pub $field_name: [u8; $field_size],
                )+
            }

            impl $name {
                pub fn wrap_mut(buffer: &mut [u8]) -> Result<&mut Self> {
                    if buffer.len() < size_of::<Self>() {
                        Err(Error::BufferLengthTooShort {
                            expected: size_of::<Self>(),
                            got: buffer.len()
                        })
                    } else {
                        unsafe {
                            Ok(&mut*(buffer as *mut _ as *mut Self))
                        }
                    }
                }

                pub fn wrap_ref(buffer: &[u8]) -> Result<&Self> {
                    if buffer.len() < size_of::<Self>() {
                        Err(Error::BufferLengthTooShort {
                            expected: size_of::<Self>(),
                            got: buffer.len()
                        })
                    } else {
                        unsafe {
                            Ok(&*(buffer as *const _ as *const Self))
                        }
                    }
                }
            }

            impl Deref for $name {
                type Target = [u8];

                fn deref(&self) -> &Self::Target {
                    unsafe { slice::from_raw_parts(self as *const _ as *const u8, size_of::<Self>()) }
                }
            }

            impl DerefMut for $name {
                fn deref_mut(&mut self) -> &mut Self::Target {
                    unsafe { slice::from_raw_parts_mut(self as *mut _ as *mut u8, size_of::<Self>()) }
                }
            }
        )+
    };
}

define! {
    HandshakeInit {
        s_i: 0x04
        u_e: 0x20
        e_s: 0x30
        e_t: 0x1c
        m_1: 0x10
        m_2: 0x10
    }
    HandshakeResp {
        s_i: 0x04
        r_i: 0x04
        u_e: 0x20
        e_n: 0x10
        m_1: 0x10
        m_2: 0x10
    }
    TransportData {
        r_i: 0x04
        cnt: 0x08
    }
}
