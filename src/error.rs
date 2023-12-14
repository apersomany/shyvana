use std::fmt::Debug;

#[derive(Debug)]
pub enum Error {
    BufferTooSmall,
    InvalidMessageType,
    InvalidMessageData,
    BoxStdError(Box<dyn std::error::Error>),
    BoxDbgError(Box<dyn Debug>),
}

impl<T: std::error::Error + 'static> From<T> for Error {
    fn from(value: T) -> Self {
        Self::BoxStdError(Box::new(value))
    }
}

pub type Result<T> = std::result::Result<T, Error>;
