use thiserror::Error;

use crate::block::{Block, BlockError, BlockValue};

pub struct Db<const N: usize> {
    cur_block: Block<N>,
}

impl<const N: usize> Db<N> {
    pub fn new() -> Db<N> {
        let cur_block = Block::new();

        Self { cur_block }
    }

    pub fn add_reading<T: Into<BlockValue>>(&mut self, key: &str, val: T) -> Result<(), DbError> {
        self.cur_block.add_reading(key, val)?;

        Ok(())
    }
}

#[derive(Error, Debug)]
pub enum DbError {
    #[error(transparent)]
    Block(#[from] BlockError),
}
