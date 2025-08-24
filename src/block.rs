use crate::block::{
    body::{BlockEntry, BlockValue},
    header::Header,
};

mod body;
mod header;

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

    pub(crate) fn add_reading<T: Into<BlockValue>>(&mut self, key: &str, val: T) -> Result<(), ()> {
        let block_entry = BlockEntry::new(key, val)?;
        let header_len = self.header.len as usize;
        if header_len + block_entry.size() > N {
            // TODO: implement block swapping/writing
            return Err(());
        }

        self.header.len += block_entry.size() as u32;
        self.mem[header_len..(header_len + block_entry.size())]
            .copy_from_slice(block_entry.as_bytes());

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use crate::block::header::HEADER_LEN;

    use super::*;

    #[test]
    fn test_add_reading() {
        let mut block: Block<1024> = Block::new();

        assert_eq!(block.header.len as usize, HEADER_LEN);

        let key = "test";
        let test_val = 42u32;

        block.add_reading(key, test_val).unwrap();

        let block_entry = BlockEntry::new(key, test_val).unwrap();
        let expected_size = block_entry.size() + HEADER_LEN;
        assert_eq!(block.header.len as usize, expected_size);
    }

    #[test]
    fn test_add_reading_overflow() {
        let mut block: Block<HEADER_LEN> = Block::new();

        let key = "test";
        let test_val = 42u32;

        // Try to add one more entry and check for overflow
        let result = block.add_reading(key, test_val);
        assert!(result.is_err());
    }
}
