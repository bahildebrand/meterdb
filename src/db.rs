use core::ops::AddAssign;

use thiserror::Error;

use crate::{
    Timestamp,
    block::{Block, BlockBodyError, BlockEntry, BlockError, BlockValue},
};

pub struct Db<const N: usize, W: DbWriter, T: Timestamp> {
    cur_block: Block<N>,
    writer: W,
    timestamp_provider: T,
    seq: Sequence,
}

impl<const N: usize, W: DbWriter, T: Timestamp> Db<N, W, T> {
    pub fn new(writer: W, timestamp_provider: T) -> Db<N, W, T> {
        let cur_block = Block::new();

        Self {
            cur_block,
            writer,
            timestamp_provider,
            seq: Sequence::from(0),
        }
    }

    pub fn add_reading<V: Into<BlockValue>>(&mut self, key: &str, val: V) -> Result<(), DbError> {
        let date_time = self.timestamp_provider.now().map_err(DbError::Timestamp)?;
        let block_entry = BlockEntry::new(key, val, date_time)?;
        let res = self.cur_block.add_reading(&block_entry);
        if let Err(BlockError::BlockFull) = res {
            self.flush()?;
            self.cur_block.add_reading(&block_entry)?;

            return Ok(());
        }

        res.map_err(|_| DbError::KeyWrite)
    }

    pub fn flush(&mut self) -> Result<(), DbError> {
        self.cur_block.write_header(self.seq.0)?;
        self.writer.write_block(self.cur_block.as_bytes())?;
        self.cur_block.reset();
        self.seq += 1;

        Ok(())
    }
}

pub trait DbWriter {
    fn write_block(&mut self, block: &[u8]) -> Result<(), DbError>;
}

struct Sequence(u16);

impl Sequence {
    #[allow(unused)]
    fn is_in_sequence(&self, other: &Sequence) -> bool {
        let next = self.0.overflowing_add(1).0;

        next == other.0
    }
}

impl AddAssign<u16> for Sequence {
    fn add_assign(&mut self, rhs: u16) {
        self.0 = self.0.overflowing_add(rhs).0;
    }
}

impl From<u16> for Sequence {
    fn from(value: u16) -> Self {
        Self(value)
    }
}

#[derive(Error, Debug)]
pub enum DbError {
    #[error(transparent)]
    Block(#[from] BlockError),
    #[error(transparent)]
    Body(#[from] BlockBodyError),
    #[error("failed to write key")]
    KeyWrite,
    #[error("Failed to write block")]
    BlockWrite,
    #[error("Failed to get current timestamp: {}", .0)]
    Timestamp(&'static str),
}

#[cfg(test)]
mod test {
    use chrono::{TimeZone, Utc};
    use insta::assert_binary_snapshot;

    use super::*;

    use std::sync::{Arc, Mutex};
    use std::vec::Vec;
    use std::{println, vec};

    #[test]
    fn test_block_write_and_flush() {
        const BLOCK_SIZE: usize = 64;

        let storage = TestBlockStorage::new(BLOCK_SIZE, 2);
        let storage = Arc::new(Mutex::new(storage));
        let writer = TestWriter::new(storage.clone());
        let timestamp_provider = TestTimestampProvider;
        let mut db: Db<BLOCK_SIZE, _, _> = Db::new(writer, timestamp_provider);

        let test_key = "test_key";
        let test_val = 42u32;

        db.add_reading(test_key, test_val).unwrap();
        db.flush().unwrap();

        let all_blocks = storage.lock().unwrap().dump_blocks();
        assert_binary_snapshot!(".bin", all_blocks);
    }

    #[test]
    fn test_block_overflow() {
        const BLOCK_SIZE: usize = 64;

        let storage = TestBlockStorage::new(BLOCK_SIZE, 2);
        let storage = Arc::new(Mutex::new(storage));
        let writer = TestWriter::new(storage.clone());
        let timestamp_provider = TestTimestampProvider;
        let mut db: Db<BLOCK_SIZE, _, _> = Db::new(writer, timestamp_provider);

        let test_key = "e".repeat(32);
        let test_val = 42u32;

        // write key twice, this should overflow the block
        db.add_reading(&test_key, test_val).unwrap();
        db.add_reading(&test_key, test_val).unwrap();
        db.flush().unwrap();

        let storage = storage.lock().unwrap();

        assert_eq!(storage.cur_block, 2);

        let all_blocks = storage.dump_blocks();
        assert_binary_snapshot!(".bin", all_blocks);
    }

    struct TestTimestampProvider;

    impl Timestamp for TestTimestampProvider {
        fn now(&self) -> Result<chrono::DateTime<chrono::Utc>, &'static str> {
            Ok(Utc.with_ymd_and_hms(2020, 2, 1, 0, 0, 0).unwrap())
        }
    }

    struct TestWriter {
        storage: Arc<Mutex<TestBlockStorage>>,
    }

    impl TestWriter {
        pub fn new(storage: Arc<Mutex<TestBlockStorage>>) -> Self {
            Self { storage }
        }
    }

    impl DbWriter for TestWriter {
        fn write_block(&mut self, block: &[u8]) -> Result<(), DbError> {
            let mut storage = self.storage.lock().unwrap();

            storage.write_block(block)
        }
    }

    struct TestBlockStorage {
        pub blocks: Vec<Vec<u8>>,
        pub block_size: usize,
        pub block_count: usize,
        cur_block: usize,
    }

    impl TestBlockStorage {
        pub fn new(block_size: usize, block_count: usize) -> Self {
            let blocks = (0..block_count)
                .map(|_| vec![0; block_size])
                .collect::<Vec<_>>();

            Self {
                blocks,
                block_size,
                block_count,
                cur_block: 0,
            }
        }

        pub fn dump_blocks(&self) -> Vec<u8> {
            let mut all_blocks = Vec::with_capacity(self.block_size * self.block_count);

            for block in &self.blocks {
                all_blocks.extend_from_slice(block.as_slice());
            }

            all_blocks
        }

        fn write_block(&mut self, block: &[u8]) -> Result<(), DbError> {
            let cur_block = &mut self.blocks[self.cur_block];
            self.cur_block += 1;

            cur_block.copy_from_slice(block);

            Ok(())
        }
    }
}
