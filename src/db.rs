use crate::block::{Block, BlockValue};

pub struct Db<const N: usize> {
    cur_block: Block<N>,
}

impl<const N: usize> Db<N> {
    pub fn new() -> Db<N> {
        let cur_block = Block::new();

        Self { cur_block }
    }

    pub fn add_reading<T: Into<BlockValue>>(&mut self, key: &str, val: T) -> Result<(), ()> {
        self.cur_block.add_reading(key, val)
    }
}
