#[derive(Debug)]
pub enum Error {
    BufferTooSmall,
}

pub type Result<T> = std::result::Result<T, Error>;
