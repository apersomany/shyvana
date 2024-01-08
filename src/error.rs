use std::fmt::{Debug, Display, Formatter};

#[derive(Debug)]
pub enum Error {
    BufferLengthTooShort { expected: usize, got: usize },
    AeadError,
    BufferLengthInvalid,
}

impl From<chacha20poly1305::Error> for Error {
    fn from(_: chacha20poly1305::Error) -> Self {
        Self::AeadError
    }
}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        Debug::fmt(&self, f)
    }
}

impl std::error::Error for Error {}

pub type Result<T> = core::result::Result<T, Error>;
