use core::array::TryFromSliceError;

use crc_any::{CRCu8, CRCu32};
use heapless::{CapacityError, Vec};
use thiserror::Error;

use crate::db::Sequence;

const MAGIC: u16 = 0xBEEF;
const VERSION: u8 = 0;
pub(crate) const HEADER_LEN: usize = 16;

const ERASED_FLAGS: u8 = 0xFF;
const IN_USE_FLAGS: u8 = 0xFE;
const DIRTY_FLAGS: u8 = 0xFC;

#[derive(Debug)]
pub(crate) struct Header {
    magic: u16,
    header_crc: u8,
    version: u8,
    flags: u8,
    _reserved: u8,
    pub seq: Sequence,
    pub len: u32,
    pub body_crc: u32,
}

impl Header {
    const HEADER_CRC_OFFSET: usize = 2;
    const VERSION_OFFSET: usize = 3;
    const FLAGS_OFFSET: usize = 4;
    const RESERVED_OFFSET: usize = 5;
    const SEQ_OFFSET: usize = 6;
    const LEN_OFFSET: usize = 8;
    const BODY_CRC_OFFSET: usize = 12;

    pub(crate) fn as_bytes(&self) -> Result<Vec<u8, HEADER_LEN>, HeaderError> {
        let mut header_bytes = Vec::new();

        header_bytes.extend_from_slice(self.magic.to_be_bytes().as_slice())?;
        header_bytes.extend_from_slice(self.header_crc.to_be_bytes().as_slice())?;
        header_bytes.extend_from_slice(self.version.to_be_bytes().as_slice())?;
        header_bytes.extend_from_slice(self.flags.to_be_bytes().as_slice())?;
        header_bytes.extend_from_slice(self._reserved.to_be_bytes().as_slice())?;
        header_bytes.extend_from_slice(self.seq.0.to_be_bytes().as_slice())?;
        header_bytes.extend_from_slice(self.len.to_be_bytes().as_slice())?;
        header_bytes.extend_from_slice(self.body_crc.to_be_bytes().as_slice())?;

        let mut crc8 = CRCu8::crc8();
        crc8.digest(&header_bytes[(Self::HEADER_CRC_OFFSET + 1)..]);
        header_bytes[Self::HEADER_CRC_OFFSET] = crc8.get_crc();

        Ok(header_bytes)
    }

    pub(crate) fn from_bytes(bytes: &[u8; HEADER_LEN]) -> Result<Header, HeaderError> {
        let mut header = Header::default();

        header.magic = u16::from_be_bytes(bytes[0..Self::HEADER_CRC_OFFSET].try_into()?);
        header.header_crc = bytes[Self::HEADER_CRC_OFFSET];
        header.version = bytes[Self::VERSION_OFFSET];
        header.flags = bytes[Self::FLAGS_OFFSET];
        header._reserved = bytes[Self::RESERVED_OFFSET];
        header.seq = Sequence(u16::from_be_bytes(
            bytes[Self::SEQ_OFFSET..Self::LEN_OFFSET].try_into()?,
        ));
        header.len = u32::from_be_bytes(bytes[Self::LEN_OFFSET..Self::BODY_CRC_OFFSET].try_into()?);
        header.body_crc = u32::from_be_bytes(bytes[Self::BODY_CRC_OFFSET..HEADER_LEN].try_into()?);

        if header.magic != MAGIC {
            return Err(HeaderError::InvalidMagic(header.magic));
        }

        let mut crc8 = CRCu8::crc8();
        crc8.digest(&bytes[Header::VERSION_OFFSET..]);
        if header.header_crc != crc8.get_crc() {
            return Err(HeaderError::InvalidHeaderCrc);
        }

        Ok(header)
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
            seq: Sequence(0),
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
    #[error("Header CRC invalid")]
    InvalidHeaderCrc,
    #[error("Header CRC invalid")]
    InvalidBodyCrc,
    #[error("Invalid magic: {}", .0)]
    InvalidMagic(u16),
    #[error("Failed to convert from intput bytes")]
    InvalidArrayIndex(#[from] TryFromSliceError),
    #[error("Header invalid")]
    InvalidHeader,
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
            seq: Sequence(1),
            len: 1024,
            body_crc: 123456,
            ..Default::default()
        };
        let bytes = header.as_bytes().unwrap();
        assert_eq!(bytes.len(), HEADER_LEN);
        assert_eq!(bytes.as_slice(), &expected);
    }

    #[test]
    fn test_header_from_bytes() {
        let bytes: [u8; HEADER_LEN] = [
            0xBE, 0xEF, // magic
            0x02, // header_crc
            0x00, // version
            0xFE, // flags
            0x00, // _reserved
            0x00, 0x01, // seq
            0x00, 0x00, 0x04, 0x00, // len
            0x00, 0x01, 0xE2, 0x40, // body_crc
        ];
        let header = Header::from_bytes(&bytes).unwrap();
        assert_eq!(header.magic, 0xBEEF);
        assert_eq!(header.header_crc, 0x02);
        assert_eq!(header.version, 0x00);
        assert_eq!(header.flags, 0xFE);
        assert_eq!(header._reserved, 0x00);
        assert_eq!(header.seq, Sequence(1));
        assert_eq!(header.len, 1024);
        assert_eq!(header.body_crc, 123456);
    }

    #[test]
    fn test_crc32() {
        let mut header = Header::default();
        let data = b"hello world";
        header.calc_crc(data);
        assert_eq!(header.body_crc, 0x56C8F614);
    }

    #[test]
    fn test_from_bytes_invalid_magic() {
        let mut bytes: [u8; HEADER_LEN] = [
            0xDE, 0xAD, // Invalid magic (should be 0xBEEF)
            0x02, // header_crc
            0x00, // version
            0xFE, // flags
            0x00, // _reserved
            0x00, 0x01, // seq
            0x00, 0x00, 0x04, 0x00, // len
            0x00, 0x01, 0xE2, 0x40, // body_crc
        ];

        // Calculate correct CRC for the invalid magic header
        let mut crc8 = CRCu8::crc8();
        crc8.digest(&bytes[Header::VERSION_OFFSET..]);
        bytes[Header::HEADER_CRC_OFFSET] = crc8.get_crc();

        let result = Header::from_bytes(&bytes);
        assert!(result.is_err());
        match result.unwrap_err() {
            HeaderError::InvalidMagic(magic) => assert_eq!(magic, 0xDEAD),
            _ => panic!("Expected InvalidMagic error"),
        }
    }

    #[test]
    fn test_from_bytes_invalid_header_crc() {
        let bytes: [u8; HEADER_LEN] = [
            0xBE, 0xEF, // magic
            0xFF, // Invalid header_crc (should be calculated)
            0x00, // version
            0xFE, // flags
            0x00, // _reserved
            0x00, 0x01, // seq
            0x00, 0x00, 0x04, 0x00, // len
            0x00, 0x01, 0xE2, 0x40, // body_crc
        ];

        let result = Header::from_bytes(&bytes);
        assert!(result.is_err());
        match result.unwrap_err() {
            HeaderError::InvalidHeaderCrc => {} // Expected
            _ => panic!("Expected InvalidHeaderCrc error"),
        }
    }

    #[test]
    fn test_from_bytes_boundary_values() {
        // Test with maximum values for each field
        let mut bytes: [u8; HEADER_LEN] = [
            0xBE, 0xEF, // magic
            0x00, // header_crc (will be calculated)
            0xFF, // version (max u8)
            0xFF, // flags (max u8)
            0xFF, // _reserved (max u8)
            0xFF, 0xFF, // seq (max u16)
            0xFF, 0xFF, 0xFF, 0xFF, // len (max u32)
            0xFF, 0xFF, 0xFF, 0xFF, // body_crc (max u32)
        ];

        // Calculate correct CRC
        let mut crc8 = CRCu8::crc8();
        crc8.digest(&bytes[Header::VERSION_OFFSET..]);
        bytes[Header::HEADER_CRC_OFFSET] = crc8.get_crc();

        let result = Header::from_bytes(&bytes);
        assert!(result.is_ok());
        let header = result.unwrap();
        assert_eq!(header.magic, 0xBEEF);
        assert_eq!(header.version, 0xFF);
        assert_eq!(header.flags, 0xFF);
        assert_eq!(header._reserved, 0xFF);
        assert_eq!(header.seq, Sequence(0xFFFF));
        assert_eq!(header.len, 0xFFFFFFFF);
        assert_eq!(header.body_crc, 0xFFFFFFFF);
    }

    #[test]
    fn test_from_bytes_minimum_values() {
        // Test with minimum values (all zeros except magic)
        let mut bytes: [u8; HEADER_LEN] = [
            0xBE, 0xEF, // magic
            0x00, // header_crc (will be calculated)
            0x00, // version
            0x00, // flags
            0x00, // _reserved
            0x00, 0x00, // seq
            0x00, 0x00, 0x00, 0x00, // len
            0x00, 0x00, 0x00, 0x00, // body_crc
        ];

        // Calculate correct CRC
        let mut crc8 = CRCu8::crc8();
        crc8.digest(&bytes[Header::VERSION_OFFSET..]);
        bytes[Header::HEADER_CRC_OFFSET] = crc8.get_crc();

        let result = Header::from_bytes(&bytes);
        assert!(result.is_ok());
        let header = result.unwrap();
        assert_eq!(header.magic, 0xBEEF);
        assert_eq!(header.version, 0x00);
        assert_eq!(header.flags, 0x00);
        assert_eq!(header._reserved, 0x00);
        assert_eq!(header.seq, Sequence(0));
        assert_eq!(header.len, 0);
        assert_eq!(header.body_crc, 0);
    }

    #[rstest]
    #[case([0x00, 0x00], 0x0000)] // All zeros
    #[case([0xFF, 0xFF], 0xFFFF)] // All ones
    #[case([0x12, 0x34], 0x1234)] // Arbitrary values
    #[case([0xAB, 0xCD], 0xABCD)] // More arbitrary values
    fn test_from_bytes_magic_variations(#[case] magic_bytes: [u8; 2], #[case] expected_magic: u16) {
        let mut bytes: [u8; HEADER_LEN] = [
            magic_bytes[0],
            magic_bytes[1], // magic
            0x00,           // header_crc (will be calculated)
            0x00,           // version
            0xFE,           // flags
            0x00,           // _reserved
            0x00,
            0x01, // seq
            0x00,
            0x00,
            0x04,
            0x00, // len
            0x00,
            0x01,
            0xE2,
            0x40, // body_crc
        ];

        // Calculate correct CRC
        let mut crc8 = CRCu8::crc8();
        crc8.digest(&bytes[Header::VERSION_OFFSET..]);
        bytes[Header::HEADER_CRC_OFFSET] = crc8.get_crc();

        let result = Header::from_bytes(&bytes);

        if expected_magic == MAGIC {
            // Should succeed if magic is correct
            assert!(result.is_ok());
            let header = result.unwrap();
            assert_eq!(header.magic, expected_magic);
        } else {
            // Should fail if magic is incorrect
            assert!(result.is_err());
            match result.unwrap_err() {
                HeaderError::InvalidMagic(magic) => assert_eq!(magic, expected_magic),
                _ => panic!("Expected InvalidMagic error"),
            }
        }
    }

    #[test]
    fn test_from_bytes_crc_validation_comprehensive() {
        // Create a valid header first
        let mut bytes: [u8; HEADER_LEN] = [
            0xBE, 0xEF, // magic
            0x00, // header_crc (will be calculated)
            0x01, // version
            0xFE, // flags
            0x00, // _reserved
            0x00, 0x42, // seq
            0x00, 0x00, 0x10, 0x00, // len
            0x12, 0x34, 0x56, 0x78, // body_crc
        ];

        // Calculate correct CRC
        let mut crc8 = CRCu8::crc8();
        crc8.digest(&bytes[Header::VERSION_OFFSET..]);
        let correct_crc = crc8.get_crc();
        bytes[Header::HEADER_CRC_OFFSET] = correct_crc;

        // Verify it works with correct CRC
        let result = Header::from_bytes(&bytes);
        assert!(result.is_ok());

        // Test with each possible incorrect CRC value
        for invalid_crc in 0u8..=255u8 {
            if invalid_crc != correct_crc {
                let mut test_bytes = bytes;
                test_bytes[Header::HEADER_CRC_OFFSET] = invalid_crc;

                let result = Header::from_bytes(&test_bytes);
                assert!(result.is_err(), "CRC {} should have failed", invalid_crc);
                match result.unwrap_err() {
                    HeaderError::InvalidHeaderCrc => {} // Expected
                    _ => panic!("Expected InvalidHeaderCrc error for CRC {}", invalid_crc),
                }
            }
        }
    }
}
