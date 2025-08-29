use heapless::Vec;
use thiserror::Error;

pub trait Storage<const N: usize, I: Iterator<Item = StorageBlock<N>>> {
    fn write_block(&mut self, bytes: &[u8]) -> Result<(), StorageError>;
    fn block_iter(&mut self) -> Result<I, StorageError>;
}

pub struct StorageBlock<const N: usize> {
    pub data: Vec<u8, N>,
    pub addr: usize,
}

impl<const N: usize> StorageBlock<N> {
    pub fn new(data: Vec<u8, N>, addr: usize) -> Self {
        Self { data, addr }
    }
}

#[derive(Error, Debug)]
pub enum StorageError {
    #[error("Failed to write block: {}", .0)]
    WriteFail(&'static str),
    #[error("Failed to read block: {}", .0)]
    ReadFail(&'static str),
}
