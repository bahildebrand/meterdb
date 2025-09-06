use core::ops::{Add, AddAssign};

use heapless::Vec;
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
    head_addr: usize,
}

impl<const N: usize, T: Timestamp, S: Storage<N>> Db<N, S, T> {
    pub fn new(
        storage: S,
        timestamp_provider: T,
        base_addr: usize,
        num_block: usize,
        head_addr: usize,
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
            head_addr,
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
        let mut head_addr = None;
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

                    if head_addr.is_none() {
                        head_addr = Some(storage_block.addr);
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
                head_addr: head_addr.unwrap_or(base_addr),
            })
        } else {
            Ok(Self::new(
                storage,
                timestamp_provider,
                base_addr,
                num_block,
                base_addr,
            ))
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
        self.cur_addr = self.next_addr(self.cur_addr);
        self.cur_block.reset();
        self.seq += 1;

        Ok(())
    }

    pub fn export_block(&mut self) -> Result<Option<(Vec<u8, N>, usize)>, DbError> {
        if self.head_addr == self.cur_addr {
            return Ok(None);
        }

        let block = self.storage.read_block(self.head_addr)?;
        let addr = self.head_addr;
        self.head_addr = self.next_addr(self.head_addr);

        Ok(Some((block, addr)))
    }

    fn next_addr(&self, addr: usize) -> usize {
        addr.checked_add(N)
            .map(|a| {
                if a >= self.end_addr {
                    self.base_addr
                } else {
                    a
                }
            })
            .unwrap_or(self.base_addr)
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
        let mut db: Db<BLOCK_SIZE, _, _> = Db::new(writer, timestamp_provider, 0, 2, 0);

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
        let mut db: Db<BLOCK_SIZE, _, _> = Db::new(writer, timestamp_provider, 0, 2, 0);

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
    fn test_next_addr() {
        const BLOCK_SIZE: usize = 64;
        const NUM_BLOCKS: usize = 4;
        let storage = TestBlockStorage::new(NUM_BLOCKS);
        let storage = Arc::new(Mutex::new(storage));
        let writer = TestStorage::new(storage.clone());
        let timestamp_provider = TestTimestampProvider;
        let mut db: Db<BLOCK_SIZE, _, _> = Db::new(writer, timestamp_provider, 0, NUM_BLOCKS, 0);

        assert_eq!(db.cur_addr, 0);

        for i in 1..NUM_BLOCKS {
            db.cur_addr = db.next_addr(db.cur_addr);
            assert_eq!(db.cur_addr, i * BLOCK_SIZE);
        }

        // next increment should wrap around
        db.cur_addr = db.next_addr(db.cur_addr);
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

    #[test]
    fn test_export_block_empty_db() {
        const BLOCK_SIZE: usize = 64;

        let storage = TestBlockStorage::new(2);
        let storage = Arc::new(Mutex::new(storage));
        let writer = TestStorage::new(storage.clone());
        let timestamp_provider = TestTimestampProvider;
        let mut db: Db<BLOCK_SIZE, _, _> = Db::new(writer, timestamp_provider, 0, 2, 0);

        // When head_addr equals cur_addr, there are no blocks to export
        let result = db.export_block().unwrap();
        assert_eq!(result, None);
    }

    #[test]
    fn test_export_block_with_data() {
        const BLOCK_SIZE: usize = 64;

        let storage = TestBlockStorage::new(4);
        let storage = Arc::new(Mutex::new(storage));
        let writer = TestStorage::new(storage.clone());
        let timestamp_provider = TestTimestampProvider;
        let mut db: Db<BLOCK_SIZE, _, _> = Db::new(writer, timestamp_provider, 0, 4, 0);

        let test_key = "test_key";
        let test_val = 42u32;

        // Add data and flush to create a block
        db.add_reading(test_key, test_val).unwrap();
        db.flush().unwrap();

        // Now head_addr should be at 0 and cur_addr should be at BLOCK_SIZE
        assert_eq!(db.head_addr, 0);
        assert_eq!(db.cur_addr, BLOCK_SIZE);

        // Export the block
        let result = db.export_block().unwrap();
        assert!(result.is_some());

        let (block_data, addr) = result.unwrap();
        assert_eq!(addr, 0); // The address of the exported block
        assert_eq!(block_data.len(), BLOCK_SIZE);

        // After export, head_addr should advance
        assert_eq!(db.head_addr, BLOCK_SIZE);

        // Exporting again should return None since head_addr == cur_addr
        let result = db.export_block().unwrap();
        assert_eq!(result, None);
    }

    #[test]
    fn test_export_block_multiple_blocks() {
        const BLOCK_SIZE: usize = 64;

        let storage = TestBlockStorage::new(4);
        let storage = Arc::new(Mutex::new(storage));
        let writer = TestStorage::new(storage.clone());
        let timestamp_provider = TestTimestampProvider;
        let mut db: Db<BLOCK_SIZE, _, _> = Db::new(writer, timestamp_provider, 0, 4, 0);

        let test_key = "test_key";
        let test_val = 42u32;

        // Add data and flush to create first block
        db.add_reading(test_key, test_val).unwrap();
        db.flush().unwrap();

        // Add data and flush to create second block
        db.add_reading(test_key, test_val).unwrap();
        db.flush().unwrap();

        // Now we should have two blocks to export
        assert_eq!(db.head_addr, 0);
        assert_eq!(db.cur_addr, BLOCK_SIZE * 2);

        // Export first block
        let result1 = db.export_block().unwrap();
        assert!(result1.is_some());
        let (_, addr1) = result1.unwrap();
        assert_eq!(addr1, 0);
        assert_eq!(db.head_addr, BLOCK_SIZE);

        // Export second block
        let result2 = db.export_block().unwrap();
        assert!(result2.is_some());
        let (_, addr2) = result2.unwrap();
        assert_eq!(addr2, BLOCK_SIZE);
        assert_eq!(db.head_addr, BLOCK_SIZE * 2);

        // No more blocks to export
        let result3 = db.export_block().unwrap();
        assert_eq!(result3, None);
    }

    #[test]
    fn test_export_block_circular_buffer() {
        const BLOCK_SIZE: usize = 64;
        const NUM_BLOCKS: usize = 3;

        let storage = TestBlockStorage::new(NUM_BLOCKS);
        let storage = Arc::new(Mutex::new(storage));
        let writer = TestStorage::new(storage.clone());
        let timestamp_provider = TestTimestampProvider;
        let mut db: Db<BLOCK_SIZE, _, _> = Db::new(writer, timestamp_provider, 0, NUM_BLOCKS, 0);

        let test_key = "test_key";
        let test_val = 42u32;

        // Fill all blocks
        for _ in 0..NUM_BLOCKS {
            db.add_reading(test_key, test_val).unwrap();
            db.flush().unwrap();
        }

        // Current address should wrap around to 0
        assert_eq!(db.cur_addr, 0);
        assert_eq!(db.head_addr, 0);

        // Add one more block, which should overwrite the first block
        db.add_reading(test_key, test_val).unwrap();
        db.flush().unwrap();

        assert_eq!(db.cur_addr, BLOCK_SIZE);
        assert_eq!(db.head_addr, 0);

        // Export blocks - should get 2 blocks (the ones that weren't overwritten)
        let result1 = db.export_block().unwrap();
        assert!(result1.is_some());
        let (_, addr1) = result1.unwrap();
        assert_eq!(addr1, BLOCK_SIZE);

        let result2 = db.export_block().unwrap();
        assert!(result2.is_some());
        let (_, addr2) = result2.unwrap();
        assert_eq!(addr2, BLOCK_SIZE * 2);

        // No more blocks to export
        let result3 = db.export_block().unwrap();
        assert_eq!(result3, None);
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
