//! Handles weird string-like wrapper over LMCP messages, it is used by OpenAMASE
//! and the Tcp bridge from OpenUxAS. See UxAS_SentinelSerialBuffer.h for details/

/// The error type for sentinel stream processing
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    SentinelNotFound,
    ChecksumVerifyError,
}

pub struct LmcpSentinelizer;

impl LmcpSentinelizer {
    /// The structure is:
    /// (getSerialSentinelBeforePayloadSize() + std::to_string(data.size())
    ///         + getSerialSentinelAfterPayloadSize() + data + getSerialSentinelBeforeChecksum()
    ///         + std::to_string(calculateChecksum(data)) + getSerialSentinelAfterChecksum());
    const BEFORE_PAYLOAD_SIZE: [u8; 8] = [43, 61, 43, 61, 43, 61, 43, 61]; // +=+=+=+=
    const AFTER_PAYLOAD_SIZE: [u8; 8] = [35, 64, 35, 64, 35, 64, 35, 64]; // #@#@#@#@
    const BEFORE_CHECKSUM: [u8; 8] = [33, 37, 33, 37, 33, 37, 33, 37]; // !%!%!%!%
    const AFTER_CHECKSUM: [u8; 8] = [63, 94, 63, 94, 63, 94, 63, 94]; // ?^?^?^?^
    const SENTINEL_LEN: usize = 8;
    const NUM_AS_STRING_LEN: usize = 5;

    /// 4*8 for sentinels, 5 bytes for a typical string value of checksum
    /// 5 bytes for a typical string value of a payload length
    const SENTINEL_OVERHEAD: usize = 4 * Self::SENTINEL_LEN + 2 * Self::NUM_AS_STRING_LEN;

    /// Calculate checksum over data
    fn calculate_checksum(data: &[u8]) -> u32 {
        data.iter().fold(0, |mut sum, &x| {
            sum += x as u32;
            sum
        })
    }

    /// Add sentinel strings to the payload
    pub fn create_sentinelized_stream(data: &[u8]) -> Vec<u8> {
        let mut msg = Vec::with_capacity(data.len() + Self::SENTINEL_OVERHEAD);

        let checksum = Self::calculate_checksum(data).to_string();
        let checksum = checksum.as_bytes();

        msg.extend_from_slice(&Self::BEFORE_PAYLOAD_SIZE);
        msg.extend_from_slice(data.len().to_string().as_bytes());
        msg.extend_from_slice(&Self::AFTER_PAYLOAD_SIZE);
        msg.extend_from_slice(data);
        msg.extend_from_slice(&Self::BEFORE_CHECKSUM);
        msg.extend_from_slice(&checksum);
        msg.extend_from_slice(&Self::AFTER_CHECKSUM);

        msg
    }

    /// Process sentinelized data and return payload
    pub fn parse_sentinelized_stream(data: Vec<u8>) -> Result<Vec<u8>, Error> {
        let mut data = data; // add mutability
        data = Self::check_sentinel(data, &Self::BEFORE_PAYLOAD_SIZE)?;
        let (len, mut data) = Self::get_numeric_val(data)?;
        data = Self::check_sentinel(data, &Self::AFTER_PAYLOAD_SIZE)?;
        let (payload, mut data) = Self::get_payload(data, len as usize);
        data = Self::check_sentinel(data, &Self::BEFORE_CHECKSUM)?;
        let (checksum, data) = Self::get_numeric_val(data)?;
        Self::check_sentinel(data, &Self::AFTER_CHECKSUM)?;
        Self::verify_checksum(&payload, checksum)?;
        Ok(payload)
    }
    
    /// Calculate checksu
    fn verify_checksum(payload: &[u8], chksum: u32) -> Result<(),Error> {
        if chksum == Self::calculate_checksum(payload) {
            Ok(())
        } else {
            Err(Error::ChecksumVerifyError)
        }
    } 

    /// Check if the sentinel is at the beginning of the data
    fn check_sentinel(mut data: Vec<u8>, sentinel: &[u8]) -> Result<Vec<u8>, Error> {
        if &data[..sentinel.len()] == sentinel{
            data.drain(..sentinel.len());
            Ok(data)
        } else {
            Err(Error::SentinelNotFound)
        }
    }

    /// Return payload bytes and the rest of the buffer
    fn get_payload(mut data: Vec<u8>, len: usize) -> (Vec<u8>, Vec<u8>) {
        let payload: Vec<_> = data.drain(..len).collect();
        (payload, data)
    }

    /// Find numeric value, encoded between sentinel bytes
    fn get_numeric_val(mut data: Vec<u8>) -> Result<(u32, Vec<u8>), Error> {
        let mut val = vec![];
        while !data.is_empty() {
            let c = data.remove(0);
            if char::is_numeric(c as char) {
                val.push(c);
            } else {
                data.insert(0, c); // return the last element
                break;
            }
        }
        let val = String::from_utf8(val).unwrap();
        let val = val.parse::<u32>().unwrap();
        Ok((val, data))
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use std::iter::FromIterator;

    const TEST_DATA: &str = "+=+=+=+=25#@#@#@#@ABCDEFGHIJKLMNOPQRSTUVWXY!%!%!%!%1925?^?^?^?^";
    const TEST_PAYLOAD: &str = "ABCDEFGHIJKLMNOPQRSTUVWXY";

    #[test]
    fn test_parse_sentinelized_stream() {
        let payload =
            LmcpSentinelizer::parse_sentinelized_stream(TEST_DATA.as_bytes().to_vec()).unwrap();
        assert_eq!(payload, TEST_PAYLOAD.as_bytes().to_vec());
    }

    #[test]
    fn test_create_sentinelized_stream() {
        let sentinel = LmcpSentinelizer::create_sentinelized_stream(TEST_PAYLOAD.as_bytes());
        assert_eq!(sentinel, TEST_DATA.as_bytes().to_vec());
    }
}
