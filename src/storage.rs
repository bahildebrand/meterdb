use heapless::Vec;
use thiserror::Error;

pub trait Storage<const N: usize> {
    fn write_block(&mut self, bytes: &[u8], addr: usize) -> Result<(), StorageError>;
    fn read_block(&mut self, addr: usize) -> Result<Vec<u8, N>, StorageError>;
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

pub(crate) struct BlockIter<'a, const N: usize, S: Storage<N>> {
    storage: &'a mut S,
    end_addr: usize,
    cur_addr: usize,
}

impl<'a, const N: usize, S: Storage<N>> BlockIter<'a, N, S> {
    pub fn new(storage: &'a mut S, base_addr: usize, end_addr: usize) -> Self {
        Self {
            storage,
            end_addr,
            cur_addr: base_addr,
        }
    }
}
impl<'a, const N: usize, S: Storage<N>> Iterator for BlockIter<'a, N, S> {
    type Item = Result<StorageBlock<N>, StorageError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.cur_addr >= self.end_addr {
            return None;
        }

        let block = self
            .storage
            .read_block(self.cur_addr)
            .map(|bytes| StorageBlock::new(bytes, self.cur_addr));

        self.cur_addr += N;

        Some(block)
    }
}

#[derive(Error, Debug)]
pub enum StorageError {
    #[error("Failed to write block: {}", .0)]
    WriteFail(&'static str),
    #[error("Failed to read block: {}", .0)]
    ReadFail(&'static str),
}
