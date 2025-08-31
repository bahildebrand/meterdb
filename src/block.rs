use core::array::TryFromSliceError;

use crc_any::CRCu32;
use heapless::Vec;
use thiserror::Error;

use crate::{
    block::header::{HEADER_LEN, HeaderError},
    db::Sequence,
};

mod body;
mod header;
mod time;

pub use body::BlockValue;
pub(crate) use body::{BlockBodyError, BlockEntry};
pub(crate) use header::Header;
#[cfg(any(feature = "std", test))]
pub use time::StdTimestamp;
pub use time::Timestamp;

#[derive(Debug)]
pub(crate) struct Block<const N: usize> {
    pub(crate) header: Header,
    mem: [u8; N],
}

impl<const N: usize> Block<N> {
    #[cfg(test)]
    pub(crate) fn new(header: Header) -> Self {
        Self {
            header,
            mem: [0xFF; N],
        }
    }

    pub(crate) fn from_bytes(block: Vec<u8, N>) -> Result<Self, BlockError> {
        let header = Header::from_bytes(block[0..HEADER_LEN].try_into()?)?;

        let mut crc32 = CRCu32::crc32d();
        crc32.digest(&block[HEADER_LEN..]);
        if header.body_crc != crc32.get_crc() {
            return Err(BlockError::InvalidCrc);
        }

        // Convert heapless Vec to array
        let mem = block
            .into_array()
            .map_err(|e| BlockError::InvalidBlockLength(e.len()))?;

        Ok(Block { header, mem })
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

    pub(crate) fn write_header(&mut self, sequence: Sequence) -> Result<(), BlockError> {
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

    pub(crate) fn is_in_sequence(&self, other: &Self) -> bool {
        self.header.seq.is_in_sequence(&other.header.seq)
    }
}

impl<const N: usize> Default for Block<N> {
    fn default() -> Self {
        Self {
            header: Default::default(),
            mem: [0xFF; N],
        }
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
    #[error("invalid block length")]
    SliceInvalid(#[from] TryFromSliceError),
    #[error("invalid body crc")]
    InvalidCrc,
    #[error("invalid block length: {}", .0)]
    InvalidBlockLength(usize),
}

#[cfg(test)]
mod test {
    use chrono::{TimeZone, Utc};

    use crate::block::header::HEADER_LEN;

    use super::*;

    #[test]
    fn test_add_reading() {
        let mut block: Block<1024> = Block::default();

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
        let mut block: Block<HEADER_LEN> = Block::default();

        let key = "test";
        let test_val = 42u32;

        // Try to add one more entry and check for overflow
        let date_time = Utc.with_ymd_and_hms(2020, 2, 1, 0, 0, 1).unwrap();
        let block_entry = BlockEntry::new(key, test_val, date_time).unwrap();
        let result = block.add_reading(&block_entry);
        assert!(result.is_err());
    }

    #[test]
    fn test_from_bytes_valid_empty_block() {
        // Create a valid empty block
        let mut block: Block<64> = Block::default();
        block.write_header(Sequence(123)).unwrap();

        let block_bytes = block.as_bytes();
        let mut vec_bytes = Vec::<u8, 64>::new();
        vec_bytes.extend_from_slice(block_bytes).unwrap();

        // Test from_bytes with valid empty block
        let reconstructed_block = Block::<64>::from_bytes(vec_bytes).unwrap();
        assert_eq!(reconstructed_block.header.seq, Sequence(123));
        assert_eq!(reconstructed_block.header.len as usize, HEADER_LEN);
    }

    #[test]
    fn test_from_bytes_valid_block_with_data() {
        // Create a block with some data
        let mut block: Block<1024> = Block::default();

        let key = "temperature";
        let test_val = 255u32; // Use u32 instead of f32
        let date_time = Utc.with_ymd_and_hms(2023, 6, 15, 12, 30, 45).unwrap();
        let block_entry = BlockEntry::new(key, test_val, date_time).unwrap();

        block.add_reading(&block_entry).unwrap();
        block.write_header(Sequence(456)).unwrap();

        let block_bytes = block.as_bytes();
        let mut vec_bytes = Vec::<u8, 1024>::new();
        vec_bytes.extend_from_slice(block_bytes).unwrap();

        // Test from_bytes with block containing data
        let reconstructed_block = Block::<1024>::from_bytes(vec_bytes).unwrap();
        assert_eq!(reconstructed_block.header.seq, Sequence(456));
        assert_eq!(
            reconstructed_block.header.len as usize,
            HEADER_LEN + block_entry.size()
        );
    }

    #[test]
    fn test_from_bytes_invalid_crc() {
        // Create a valid block first
        let mut block: Block<64> = Block::default();
        block.write_header(Sequence(789)).unwrap();

        let block_bytes = block.as_bytes();
        let mut vec_bytes = Vec::<u8, 64>::new();
        vec_bytes.extend_from_slice(block_bytes).unwrap();

        // Corrupt the body data to make CRC invalid
        vec_bytes[HEADER_LEN] = 0x42; // Change first byte after header

        // Test from_bytes with invalid CRC
        let result = Block::<64>::from_bytes(vec_bytes);
        assert!(result.is_err());
        match result.unwrap_err() {
            BlockError::InvalidCrc => (), // Expected error
            _ => panic!("Expected InvalidCrc error"),
        }
    }

    #[test]
    fn test_from_bytes_multiple_entries() {
        // Create a block with multiple entries
        let mut block: Block<1024> = Block::default();

        // Add first entry
        let date_time1 = Utc.with_ymd_and_hms(2023, 1, 1, 10, 0, 0).unwrap();
        let entry1 = BlockEntry::new("temp", 200u32, date_time1).unwrap(); // Use u32
        block.add_reading(&entry1).unwrap();

        // Add second entry
        let date_time2 = Utc.with_ymd_and_hms(2023, 1, 1, 11, 0, 0).unwrap();
        let entry2 = BlockEntry::new("humidity", 65u32, date_time2).unwrap();
        block.add_reading(&entry2).unwrap();

        block.write_header(Sequence(999)).unwrap();

        let block_bytes = block.as_bytes();
        let mut vec_bytes = Vec::<u8, 1024>::new();
        vec_bytes.extend_from_slice(block_bytes).unwrap();

        // Test from_bytes with multiple entries
        let reconstructed_block = Block::<1024>::from_bytes(vec_bytes).unwrap();
        assert_eq!(reconstructed_block.header.seq, Sequence(999));
        let expected_len = HEADER_LEN + entry1.size() + entry2.size();
        assert_eq!(reconstructed_block.header.len as usize, expected_len);
    }
}
