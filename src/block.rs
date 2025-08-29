use thiserror::Error;

use crate::block::header::{HEADER_LEN, Header, HeaderError};

mod body;
mod header;
mod time;

pub use body::BlockValue;
pub(crate) use body::{BlockBodyError, BlockEntry};
#[cfg(any(feature = "std", test))]
pub use time::StdTimestamp;
pub use time::Timestamp;

pub(crate) struct Block<const N: usize> {
    header: Header,
    mem: [u8; N],
}

impl<const N: usize> Block<N> {
    pub(crate) fn new() -> Self {
        let header = Header::default();

        Self {
            header,
            mem: [0xFF; N],
        }
    }

    pub(crate) fn add_reading(&mut self, block_entry: &BlockEntry) -> Result<(), BlockError> {
        let header_len = self.header.len as usize;
        if header_len + block_entry.size() > N {
            return Err(BlockError::BlockFull);
        }

        self.mem[header_len..(header_len + block_entry.size())]
            .copy_from_slice(block_entry.as_bytes());
        self.header.len += block_entry.size() as u32;

        Ok(())
    }

    pub(crate) fn write_header(&mut self, sequence: u16) -> Result<(), BlockError> {
        self.header.seq = sequence;
        self.header.calc_crc(&self.mem[HEADER_LEN..]);
        self.mem[0..HEADER_LEN].copy_from_slice(self.header.as_bytes()?.as_ref());

        Ok(())
    }

    pub(crate) fn as_bytes(&self) -> &[u8] {
        &self.mem
    }

    pub(crate) fn reset(&mut self) {
        self.header = Header::default();
        self.mem.fill(0xFF);
    }
}

#[derive(Error, Debug)]
pub enum BlockError {
    #[error("block has no room to insert key")]
    BlockFull,
    #[error(transparent)]
    Body(#[from] BlockBodyError),
    #[error(transparent)]
    Header(#[from] HeaderError),
}

#[cfg(test)]
mod test {
    use chrono::{TimeZone, Utc};

    use crate::block::header::HEADER_LEN;

    use super::*;

    #[test]
    fn test_add_reading() {
        let mut block: Block<1024> = Block::new();

        assert_eq!(block.header.len as usize, HEADER_LEN);

        let key = "test";
        let test_val = 42u32;
        let date_time = Utc.with_ymd_and_hms(2020, 2, 1, 0, 0, 0).unwrap();
        let block_entry = BlockEntry::new(key, test_val, date_time).unwrap();

        block.add_reading(&block_entry).unwrap();

        let date_time = Utc.with_ymd_and_hms(2020, 2, 1, 0, 0, 1).unwrap();
        let block_entry = BlockEntry::new(key, test_val, date_time).unwrap();
        let expected_size = block_entry.size() + HEADER_LEN;
        assert_eq!(block.header.len as usize, expected_size);
    }

    #[test]
    fn test_add_reading_overflow() {
        let mut block: Block<HEADER_LEN> = Block::new();

        let key = "test";
        let test_val = 42u32;

        // Try to add one more entry and check for overflow
        let date_time = Utc.with_ymd_and_hms(2020, 2, 1, 0, 0, 1).unwrap();
        let block_entry = BlockEntry::new(key, test_val, date_time).unwrap();
        let result = block.add_reading(&block_entry);
        assert!(result.is_err());
    }
}
