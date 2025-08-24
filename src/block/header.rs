use bytes::{BufMut, Bytes, BytesMut};
use thiserror::Error;

const MAGIC: u16 = 0xBEEF;
const VERSION: u8 = 0;
pub(crate) const HEADER_LEN: usize = 16;

const ERASED_FLAGS: u8 = 0xFF;
const IN_USE_FLAGS: u8 = 0xFE;
const DIRTY_FLAGS: u8 = 0xFC;

pub(crate) struct Header {
    magic: u16,
    version: u8,
    flags: u8,
    _reserved: u16,
    seq: u16,
    pub len: u32,
    crc32: u32,
}

impl Header {
    pub(crate) fn new(seq: u16, len: u32, crc32: u32) -> Self {
        Header {
            magic: MAGIC,
            version: VERSION,
            flags: Flags::InUse.into(),
            _reserved: 0,
            seq,
            len,
            crc32,
        }
    }

    pub(crate) fn size() -> usize {
        HEADER_LEN
    }

    pub(crate) fn as_bytes(&self) -> Bytes {
        let mut header_bytes = BytesMut::with_capacity(HEADER_LEN);

        header_bytes.put(self.magic.to_be_bytes().as_slice());
        header_bytes.put(self.version.to_be_bytes().as_slice());
        header_bytes.put(self.flags.to_be_bytes().as_slice());
        header_bytes.put(self._reserved.to_be_bytes().as_slice());
        header_bytes.put(self.seq.to_be_bytes().as_slice());
        header_bytes.put(self.len.to_be_bytes().as_slice());
        header_bytes.put(self.crc32.to_be_bytes().as_slice());

        header_bytes.freeze()
    }
}

impl Default for Header {
    fn default() -> Self {
        Self {
            magic: MAGIC,
            version: VERSION,
            flags: IN_USE_FLAGS,
            _reserved: 0,
            seq: 0,
            len: HEADER_LEN as u32,
            crc32: 0,
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
    // TODO: Actual error type
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

#[derive(Error, Debug, PartialEq, Eq)]
pub enum HeaderError {
    #[error("invalid flags: {}", .0)]
    InvalidFlags(u8),
}

#[cfg(test)]
mod tests {
    use super::*;

    use rstest::rstest;

    #[rstest]
    #[case(Ok(Flags::Erased), ERASED_FLAGS)]
    #[case(Ok(Flags::InUse), IN_USE_FLAGS)]
    #[case(Ok(Flags::Dirty), DIRTY_FLAGS)]
    #[case(Err(HeaderError::InvalidFlags(0x0)), 0x0)]
    fn test_int_to_flags(#[case] flags: Result<Flags, HeaderError>, #[case] flags_raw: u8) {
        assert_eq!(Flags::try_from(flags_raw), flags);
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
            0x00, // version
            0xFE, // flags
            0x00, 0x00, // _reserved
            0x00, 0x01, // seq
            0x00, 0x00, 0x04, 0x00, // len
            0x00, 0x01, 0xE2, 0x40, // crc32
        ];

        let header = Header::new(1, 1024, 123456);
        let bytes = header.as_bytes();
        assert_eq!(bytes.len(), HEADER_LEN);
        assert_eq!(bytes.as_ref(), &expected);
    }
}
