use core::ops::{Add, AddAssign};

use thiserror::Error;

use crate::{
    Timestamp,
    block::{Block, BlockBodyError, BlockEntry, BlockError, BlockValue},
    storage::{BlockIter, Storage, StorageError},
};

pub struct Db<const N: usize, S, T>
where
    S: Storage<N>,
    T: Timestamp,
{
    cur_block: Block<N>,
    storage: S,
    timestamp_provider: T,
    seq: Sequence,
    base_addr: usize,
    end_addr: usize,
    cur_addr: usize,
}

impl<const N: usize, T: Timestamp, S: Storage<N>> Db<N, S, T> {
    pub fn new(
        storage: S,
        timestamp_provider: T,
        base_addr: usize,
        num_block: usize,
    ) -> Db<N, S, T> {
        let cur_block = Block::default();
        let end_addr = num_block * N + base_addr;
        let cur_addr = base_addr;

        Self {
            cur_block,
            storage,
            timestamp_provider,
            seq: Sequence::from(0),
            base_addr,
            end_addr,
            cur_addr,
        }
    }

    pub fn load(
        mut storage: S,
        timestamp_provider: T,
        base_addr: usize,
        num_block: usize,
    ) -> Result<Db<N, S, T>, DbError> {
        // TODO: cases not currently handled:
        //  1. DB Full
        //  2. Last block used, first block not
        let end_addr = N * num_block + base_addr;
        let block_iter = BlockIter::new(&mut storage, base_addr, end_addr);

        let mut prev_block: Option<(Block<N>, usize)> = None;
        for storage_block in block_iter {
            let storage_block = storage_block?;

            let block_res = Block::from_bytes(storage_block.data);
            match block_res {
                Ok(block) => {
                    if let Some((prev, _addr)) = &prev_block {
                        // TODO: Handle out of sequence valid blocks, I.E. full
                        if !prev.is_in_sequence(&block) {
                            todo!()
                        }
                    }

                    prev_block = Some((block, storage_block.addr));
                }
                Err(_) => {
                    // TODO: handle errors more granualarly here
                    if prev_block.is_some() {
                        break;
                    }

                    continue;
                }
            }
        }

        if let Some((prev, prev_addr)) = prev_block {
            let seq = prev.header.seq + 1;
            let cur_addr = prev_addr
                .checked_add(N)
                .map(|addr| if addr >= end_addr { base_addr } else { addr })
                .unwrap_or(base_addr);

            Ok(Self {
                cur_block: Block::default(),
                storage,
                timestamp_provider,
                seq,
                base_addr,
                end_addr,
                cur_addr,
            })
        } else {
            Ok(Self::new(storage, timestamp_provider, base_addr, num_block))
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
        self.cur_block.write_header(self.seq)?;
        self.storage
            .write_block(self.cur_block.as_bytes(), self.cur_addr)?;
        self.increment_addr();
        self.cur_block.reset();
        self.seq += 1;

        Ok(())
    }

    fn increment_addr(&mut self) {
        let next_addr = self.cur_addr.checked_add(N);
        if let Some(addr) = next_addr {
            if addr >= self.end_addr {
                self.cur_addr = self.base_addr
            } else {
                self.cur_addr = addr;
            }
        } else {
            self.cur_addr = self.base_addr;
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub(crate) struct Sequence(pub u16);

impl Sequence {
    #[allow(unused)]
    pub(crate) fn is_in_sequence(&self, other: &Sequence) -> bool {
        let next = self.0.overflowing_add(1).0;

        next == other.0
    }
}

impl Add<u16> for Sequence {
    type Output = Self;

    fn add(mut self, rhs: u16) -> Self::Output {
        self.0 = self.0.overflowing_add(rhs).0;
        self
    }
}

impl AddAssign<u16> for Sequence {
    fn add_assign(&mut self, rhs: u16) {
        self.0 = self.0 + rhs;
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
    #[error(transparent)]
    Storage(#[from] StorageError),
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
    use rstest::rstest;

    use crate::block::Header;

    use super::*;

    use std::sync::{Arc, Mutex};
    use std::vec;
    use std::vec::Vec;

    #[test]
    fn test_block_write_and_flush() {
        const BLOCK_SIZE: usize = 64;

        let storage = TestBlockStorage::new(2);
        let storage = Arc::new(Mutex::new(storage));
        let writer = TestStorage::new(storage.clone());
        let timestamp_provider = TestTimestampProvider;
        let mut db: Db<BLOCK_SIZE, _, _> = Db::new(writer, timestamp_provider, 0, 2);

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

        let storage = TestBlockStorage::new(2);
        let storage = Arc::new(Mutex::new(storage));
        let writer = TestStorage::new(storage.clone());
        let timestamp_provider = TestTimestampProvider;
        let mut db: Db<BLOCK_SIZE, _, _> = Db::new(writer, timestamp_provider, 0, 2);

        let test_key = "e".repeat(32);
        let test_val = 42u32;

        // write key twice, this should overflow the block
        db.add_reading(&test_key, test_val).unwrap();
        db.add_reading(&test_key, test_val).unwrap();
        db.flush().unwrap();

        let storage = storage.lock().unwrap();

        let all_blocks = storage.dump_blocks();
        assert_binary_snapshot!(".bin", all_blocks);
    }

    #[rstest]
    fn test_increment_addr() {
        const BLOCK_SIZE: usize = 64;
        const NUM_BLOCKS: usize = 4;
        let storage = TestBlockStorage::new(NUM_BLOCKS);
        let storage = Arc::new(Mutex::new(storage));
        let writer = TestStorage::new(storage.clone());
        let timestamp_provider = TestTimestampProvider;
        let mut db: Db<BLOCK_SIZE, _, _> = Db::new(writer, timestamp_provider, 0, NUM_BLOCKS);

        assert_eq!(db.cur_addr, 0);

        for i in 1..NUM_BLOCKS {
            db.increment_addr();
            assert_eq!(db.cur_addr, i * BLOCK_SIZE);
        }

        // next increment should wrap around
        db.increment_addr();
        assert_eq!(db.cur_addr, 0);
    }

    #[rstest]
    fn test_load_empty_blocks() {
        const BLOCK_SIZE: usize = 64;
        const NUM_BLOCKS: usize = 4;
        const BASE_ADDR: usize = 0;

        let storage = TestBlockStorage::new(NUM_BLOCKS);
        let storage = Arc::new(Mutex::new(storage));
        let writer = TestStorage::new(storage.clone());
        let timestamp_provider = TestTimestampProvider;
        let db: Db<BLOCK_SIZE, _, _> =
            Db::load(writer, timestamp_provider, BASE_ADDR, NUM_BLOCKS).unwrap();

        assert_eq!(db.cur_addr, BASE_ADDR);
    }

    #[rstest]
    fn test_load_block_at_start() {
        const BLOCK_SIZE: usize = 64;
        const NUM_BLOCKS: usize = 4;
        const BASE_ADDR: usize = 0;

        let initial_header = Header::default();
        let mut block: Block<BLOCK_SIZE> = Block::new(initial_header);

        block.write_header(Sequence(0)).unwrap();
        let mut blocks = vec![vec![0; BLOCK_SIZE]; NUM_BLOCKS];
        blocks[0] = block.as_bytes().to_vec();

        let storage = TestBlockStorage::new_with_state(blocks);
        let storage = Arc::new(Mutex::new(storage));
        let writer = TestStorage::new(storage.clone());
        let timestamp_provider = TestTimestampProvider;
        let db: Db<BLOCK_SIZE, _, _> =
            Db::load(writer, timestamp_provider, BASE_ADDR, NUM_BLOCKS).unwrap();

        assert_eq!(db.cur_addr, BASE_ADDR + BLOCK_SIZE);
        assert_eq!(db.seq, Sequence(1));
    }

    #[rstest]
    fn test_load_block_in_middle() {
        const BLOCK_SIZE: usize = 64;
        const NUM_BLOCKS: usize = 4;
        const BASE_ADDR: usize = 0;

        let initial_header = Header::default();
        let mut block: Block<BLOCK_SIZE> = Block::new(initial_header);

        block.write_header(Sequence(1)).unwrap();
        let mut blocks = vec![vec![0; BLOCK_SIZE]; NUM_BLOCKS];
        blocks[1] = block.as_bytes().to_vec();

        let storage = TestBlockStorage::new_with_state(blocks);
        let storage = Arc::new(Mutex::new(storage));
        let writer = TestStorage::new(storage.clone());
        let timestamp_provider = TestTimestampProvider;
        let db: Db<BLOCK_SIZE, _, _> =
            Db::load(writer, timestamp_provider, BASE_ADDR, NUM_BLOCKS).unwrap();

        assert_eq!(db.cur_addr, BASE_ADDR + 2 * BLOCK_SIZE);
        assert_eq!(db.seq, Sequence(2));
    }

    struct TestTimestampProvider;

    impl Timestamp for TestTimestampProvider {
        fn now(&self) -> Result<chrono::DateTime<chrono::Utc>, &'static str> {
            Ok(Utc.with_ymd_and_hms(2020, 2, 1, 0, 0, 0).unwrap())
        }
    }

    struct TestStorage<const N: usize> {
        storage: Arc<Mutex<TestBlockStorage<N>>>,
    }

    impl<const N: usize> TestStorage<N> {
        pub fn new(storage: Arc<Mutex<TestBlockStorage<N>>>) -> Self {
            Self { storage }
        }
    }

    impl<const N: usize> Storage<N> for TestStorage<N> {
        fn write_block(&mut self, bytes: &[u8], addr: usize) -> Result<(), StorageError> {
            let mut storage = self
                .storage
                .lock()
                .map_err(|_| StorageError::WriteFail("lock error"))?;
            storage.write_block(bytes, addr)
        }

        fn read_block(&mut self, addr: usize) -> Result<heapless::Vec<u8, N>, StorageError> {
            let mut storage = self
                .storage
                .lock()
                .map_err(|_| StorageError::WriteFail("lock error"))?;
            storage.read_block(addr)
        }
    }

    struct TestBlockStorage<const N: usize> {
        pub blocks: Vec<Vec<u8>>,
        pub block_count: usize,
    }

    impl<const N: usize> TestBlockStorage<N> {
        pub fn new(block_count: usize) -> Self {
            let blocks = (0..block_count).map(|_| vec![0; N]).collect::<Vec<_>>();

            Self {
                blocks,
                block_count,
            }
        }

        pub fn new_with_state(blocks: Vec<Vec<u8>>) -> Self {
            let block_count = blocks.len();

            Self {
                blocks,
                block_count,
            }
        }

        pub fn dump_blocks(&self) -> Vec<u8> {
            let mut all_blocks = Vec::with_capacity(N * self.block_count);

            for block in &self.blocks {
                all_blocks.extend_from_slice(block.as_slice());
            }

            all_blocks
        }

        fn write_block(&mut self, block: &[u8], addr: usize) -> Result<(), StorageError> {
            let cur_block_idx = self.addr_to_block_num(addr);
            let cur_block = &mut self.blocks[cur_block_idx];

            cur_block.copy_from_slice(block);

            Ok(())
        }

        fn read_block(&mut self, addr: usize) -> Result<heapless::Vec<u8, N>, StorageError> {
            let cur_block_idx = self.addr_to_block_num(addr);
            let mut ret_vec: heapless::Vec<u8, N> = heapless::Vec::new();
            ret_vec
                .extend_from_slice(self.blocks[cur_block_idx].as_slice())
                .expect("No capacity");

            Ok(ret_vec)
        }

        fn addr_to_block_num(&self, addr: usize) -> usize {
            addr / N
        }
    }
}
