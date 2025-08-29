use crc_any::{CRCu8, CRCu32};
use heapless::{CapacityError, Vec};
use thiserror::Error;

const MAGIC: u16 = 0xBEEF;
const VERSION: u8 = 0;
pub(crate) const HEADER_LEN: usize = 16;

const ERASED_FLAGS: u8 = 0xFF;
const IN_USE_FLAGS: u8 = 0xFE;
const DIRTY_FLAGS: u8 = 0xFC;

pub(crate) struct Header {
    magic: u16,
    header_crc: u8,
    version: u8,
    flags: u8,
    _reserved: u8,
    pub seq: u16,
    pub len: u32,
    body_crc: u32,
}

impl Header {
    const HEADER_CRC_OFFSET: usize = 2;

    pub(crate) fn as_bytes(&self) -> Result<Vec<u8, HEADER_LEN>, HeaderError> {
        let mut header_bytes = Vec::new();

        header_bytes.extend_from_slice(self.magic.to_be_bytes().as_slice())?;
        header_bytes.extend_from_slice(self.header_crc.to_be_bytes().as_slice())?;
        header_bytes.extend_from_slice(self.version.to_be_bytes().as_slice())?;
        header_bytes.extend_from_slice(self.flags.to_be_bytes().as_slice())?;
        header_bytes.extend_from_slice(self._reserved.to_be_bytes().as_slice())?;
        header_bytes.extend_from_slice(self.seq.to_be_bytes().as_slice())?;
        header_bytes.extend_from_slice(self.len.to_be_bytes().as_slice())?;
        header_bytes.extend_from_slice(self.body_crc.to_be_bytes().as_slice())?;

        let mut crc8 = CRCu8::crc8();
        crc8.digest(&header_bytes[(Self::HEADER_CRC_OFFSET + 1)..]);
        header_bytes[Self::HEADER_CRC_OFFSET] = crc8.get_crc();

        Ok(header_bytes)
    }

    pub(crate) fn calc_crc(&mut self, bytes: &[u8]) {
        let mut crc32 = CRCu32::crc32d();
        crc32.digest(bytes);
        self.body_crc = crc32.get_crc();
    }
}

impl Default for Header {
    fn default() -> Self {
        Self {
            magic: MAGIC,
            header_crc: 0,
            version: VERSION,
            flags: IN_USE_FLAGS,
            _reserved: 0,
            seq: 0,
            len: HEADER_LEN as u32,
            body_crc: 0,
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Flags {
    Erased,
    InUse,
    Dirty,
}

impl From<Flags> for u8 {
    fn from(flags: Flags) -> Self {
        match flags {
            Flags::Erased => ERASED_FLAGS,
            Flags::InUse => IN_USE_FLAGS,
            Flags::Dirty => DIRTY_FLAGS,
        }
    }
}

impl TryFrom<u8> for Flags {
    type Error = HeaderError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            ERASED_FLAGS => Ok(Flags::Erased),
            IN_USE_FLAGS => Ok(Flags::InUse),
            DIRTY_FLAGS => Ok(Flags::Dirty),
            _ => Err(HeaderError::InvalidFlags(value)),
        }
    }
}

#[derive(Error, Debug)]
pub enum HeaderError {
    #[error("invalid flags: {}", .0)]
    InvalidFlags(u8),
    #[error("not enough capacity for header")]
    HeaderCapacity(#[from] CapacityError),
}

#[cfg(test)]
mod tests {
    use super::*;

    use rstest::rstest;

    #[rstest]
    #[case(Flags::Erased, ERASED_FLAGS)]
    #[case(Flags::InUse, IN_USE_FLAGS)]
    #[case(Flags::Dirty, DIRTY_FLAGS)]
    fn test_int_to_flags(#[case] flags: Flags, #[case] flags_raw: u8) {
        assert_eq!(Flags::try_from(flags_raw).unwrap(), flags);
    }

    #[test]
    fn test_int_to_flags_failure() {
        for flags_raw in 0..=255 {
            if flags_raw != ERASED_FLAGS && flags_raw != IN_USE_FLAGS && flags_raw != DIRTY_FLAGS {
                assert!(Flags::try_from(flags_raw).is_err());
            }
        }
    }

    #[rstest]
    #[case(ERASED_FLAGS, Flags::Erased)]
    #[case(IN_USE_FLAGS, Flags::InUse)]
    #[case(DIRTY_FLAGS, Flags::Dirty)]
    fn test_flags_to_int(#[case] flags_raw: u8, #[case] flags: Flags) {
        assert_eq!(u8::from(flags), flags_raw);
    }

    #[test]
    fn test_header_as_bytes() {
        let expected = [
            0xBE, 0xEF, // magic
            0x02, // header_crc
            0x00, // version
            0xFE, // flags
            0x00, // _reserved
            0x00, 0x01, // seq
            0x00, 0x00, 0x04, 0x00, // len
            0x00, 0x01, 0xE2, 0x40, // body_crc
        ];

        let header = Header {
            seq: 1,
            len: 1024,
            body_crc: 123456,
            ..Default::default()
        };
        let bytes = header.as_bytes().unwrap();
        assert_eq!(bytes.len(), HEADER_LEN);
        assert_eq!(bytes.as_slice(), &expected);
    }

    #[test]
    fn test_crc32() {
        let mut header = Header::default();
        let data = b"hello world";
        header.calc_crc(data);
        assert_eq!(header.body_crc, 0x56C8F614);
    }
}
