//! Implementation of body keys for block storage.
//!
//! This module implements the key/value format used to store timeseries entries in blocks.
//! It has the following format:
//!
//! +------------+----------+-----------+----------+
//! | Key Len(2) |   Key    | TypeLen(2)| Value    |
//! +------------+----------+-----------+----------+
//! |   2 bytes  | variable |  2 bytes  | variable |
//! +------------+----------+-----------+----------+

use bytes::{BufMut, Bytes, BytesMut};

const MAX_KEY_SIZE: usize = 64;

pub(crate) struct BlockEntry {
    bytes: Bytes,
}

impl BlockEntry {
    const KEY_LEN_SIZE: usize = 2;
    const VAL_TYPE_SIZE: usize = 2;

    pub(crate) fn new<T: Into<BlockValue>>(key_str: &str, val: T) -> Result<Self, ()> {
        let key_len = key_str.as_bytes().len();
        if key_len > MAX_KEY_SIZE {
            return Err(());
        }

        let block_val = val.into();
        let block_size = Self::KEY_LEN_SIZE + Self::VAL_TYPE_SIZE + key_len + block_val.size();
        let type_len = TypeLen::from(&block_val);
        let mut entry_bytes = BytesMut::with_capacity(block_size);

        // cast to u16 is safe here, as we verified max key size above
        entry_bytes.put((block_size as u16).to_be_bytes().as_slice());
        entry_bytes.put(key_str.as_bytes());
        entry_bytes.put(type_len.as_bytes().as_slice());
        entry_bytes.put(block_val.as_bytes().as_slice());

        Ok(Self {
            bytes: entry_bytes.freeze(),
        })
    }

    pub(crate) fn size(&self) -> usize {
        self.bytes.len()
    }

    pub(crate) fn as_bytes(&self) -> &[u8] {
        self.bytes.as_ref()
    }
}

pub enum BlockValue {
    UnsignedInt(u32),
}

impl BlockValue {
    pub(crate) fn size(&self) -> usize {
        match self {
            BlockValue::UnsignedInt(_) => size_of::<u32>(),
        }
    }

    // TODO: Should not be hard coded
    pub(crate) fn as_bytes(&self) -> [u8; 4] {
        match self {
            BlockValue::UnsignedInt(v) => v.to_be_bytes(),
        }
    }
}

impl From<u32> for BlockValue {
    fn from(value: u32) -> Self {
        BlockValue::UnsignedInt(value)
    }
}

struct TypeLen {
    val_type: u8,
    size: u8,
}

impl TypeLen {
    const U32_TYPE: u8 = 0;

    fn as_bytes(&self) -> [u8; 2] {
        [self.val_type, self.size]
    }
}

impl From<&BlockValue> for TypeLen {
    fn from(value: &BlockValue) -> Self {
        let val_type = match value {
            BlockValue::UnsignedInt(_) => Self::U32_TYPE,
        };

        Self {
            val_type,
            size: value.size() as u8,
        }
    }
}

#[cfg(test)]
mod test {
    use std::vec::Vec;

    use super::*;

    use insta::assert_binary_snapshot;
    use rstest::rstest;

    #[test]
    fn test_create_block_entry() {
        let test_key = "test_key";
        let test_val = 42u32;
        let entry = BlockEntry::new(test_key, test_val);
        assert!(entry.is_ok());

        let entry = entry.unwrap();
        let entry_bytes = Vec::from(entry.as_bytes());
        let val_size = BlockValue::from(test_val).size();
        let expected_size = test_key.as_bytes().len()
            + BlockEntry::KEY_LEN_SIZE
            + BlockEntry::VAL_TYPE_SIZE
            + val_size;

        assert_eq!(entry_bytes.len(), expected_size);
        assert_binary_snapshot!(".bin", entry_bytes);
    }

    #[test]
    fn block_entry_large_key() {
        let large_key = "a".repeat(MAX_KEY_SIZE + 1);
        let entry = BlockEntry::new(&large_key, 42u32);
        assert!(entry.is_err());
    }

    #[rstest]
    #[case(BlockValue::UnsignedInt(42), size_of::<u32>())]
    fn test_block_value_size(#[case] value: BlockValue, #[case] expected_size: usize) {
        assert_eq!(value.size(), expected_size);
    }
}
