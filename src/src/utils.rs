
use crypto::digest::Digest;
use crypto::sha1;
use crypto::sha2;
use crypto::ripemd160;

pub struct IntUtils;

use time;

impl IntUtils {
    fn get_bytes(u: u64) -> [u8; 8] {
        [((u & 0x00000000000000ff) / 0x1)               as u8,
         ((u & 0x000000000000ff00) / 0x100)             as u8,
         ((u & 0x0000000000ff0000) / 0x10000)           as u8,
         ((u & 0x00000000ff000000) / 0x1000000)         as u8,
         ((u & 0x000000ff00000000) / 0x100000000)       as u8,
         ((u & 0x0000ff0000000000) / 0x10000000000)     as u8,
         ((u & 0x00ff000000000000) / 0x1000000000000)   as u8,
         ((u & 0x7f00000000000000) / 0x100000000000000) as u8]
    }

    fn get_raw_result(x: i64, padded: bool) -> (Vec<u8>, u8) {
        let u: u64 = x.abs() as u64;
        let bytes: [u8; 8] = IntUtils::get_bytes(u);
        let sign = if u == x as u64 { 0x00 } else { 0x80 };

        let mut response = vec![];
        response.extend(bytes.iter().cloned());

        if !padded {
            if u == 0 {
                response.truncate(0);
            } else if u <= 0x7f {
                response.truncate(1);
            } else if u <= 0x7fff {
                response.truncate(2);
            } else if u <= 0x7fffff {
                response.truncate(3);
            } else if u <= 0x7fffffff {
                response.truncate(4);
            } else if u <= 0x7fffffffff {
                response.truncate(5);
            } else if u <= 0x7fffffffffff {
                response.truncate(6);
            } else if u <= 0x7fffffffffffff {
                response.truncate(7);
            };
        };

        (response, sign)
    }

    fn to_vec_u8_base(x: i64, padded: bool) -> Vec<u8> {
        let (mut response, sign) = IntUtils::get_raw_result(x, padded);

        if x != 0 {
            response = IntUtils::add_sign(response, sign);
        }

        response
    }

    pub fn to_vec_u8(x: i64) -> Vec<u8> {
        IntUtils::to_vec_u8_base(x, false)
    }

    pub fn to_vec_u8_padded(x: i64) -> Vec<u8> {
        IntUtils::to_vec_u8_base(x, true)
    }

    pub fn u16_to_be_vec_u8_padded(x: u16) -> Vec<u8> {
        let bytes = IntUtils::get_bytes(x as u64);
        vec![bytes[1], bytes[0]]
    }

    pub fn u32_to_vec_u8_padded(x: u32) -> Vec<u8> {
        let bytes = IntUtils::get_bytes(x as u64);
        vec![bytes[0], bytes[1], bytes[2], bytes[3]]
    }

    pub fn u64_to_vec_u8_padded(x: u64) -> Vec<u8> {
        let bytes = IntUtils::get_bytes(x as u64);
        vec![bytes[0], bytes[1], bytes[2], bytes[3],
             bytes[4], bytes[5], bytes[6], bytes[7]]
    }

    fn add_sign(bytes_: Vec<u8>, sign: u8) -> Vec<u8> {
        let mut bytes = bytes_;
        let value = bytes.pop().unwrap();
        bytes.push(value | sign);

        bytes
    }

    pub fn i32_to_vec_u8_padded(x: i32) -> Vec<u8> {
        let (mut bytes, sign) = IntUtils::get_raw_result(x as i64, true);
        bytes.truncate(4);

        IntUtils::add_sign(bytes, sign)
    }

    pub fn to_u64(x: &Vec<u8>) -> u64 {
        assert!(x.len() <= 8);

        let mut result = 0;
        let mut multiplier: u64 = 1;
        for i in 0..x.len() {
            if i != 0 { multiplier *= 0x100 };
            result += *x.get(i).unwrap() as u64 * multiplier;
        }

        result as u64
    }

    pub fn to_variable_length_int(data: u64) -> Vec<u8> {
        let bytes = IntUtils::get_bytes(data);

        match data {
            0x00000...0x0000000fd => vec![bytes[0]],
            0x000fd...0x000010000 => vec![0xfd, bytes[0], bytes[1]],
            0x10000...0x100000000 => vec![0xfe, bytes[0], bytes[1], bytes[2], bytes[3]],
            _                     => vec![0xff, bytes[0], bytes[1], bytes[2], bytes[3],
                                                bytes[4], bytes[5], bytes[6], bytes[7]],
        }
    }

    pub fn to_u32(x: &Vec<u8>) -> u32 {
        assert!(x.len() <= 4);

        IntUtils::to_u64(x) as u32
    }

    fn exp(x: i64, exponent: u8) -> i64 {
        let mut result = 1;
        for _ in 0 .. exponent {
            result *= x;
        }

        result
    }

    pub fn to_i32(x: &Vec<u8>) -> i32 {
        assert!(x.len() <= 4);

        let unsigned = IntUtils::to_u32(x) as i64;
        if unsigned == 0 {
            return 0;
        }

        let last = match x.last() {
            Some(x) => *x,
            None => 0
        };

        let mut sign = (last & 0x80) as i64;
        sign *= IntUtils::exp(0x100, (x.len() - 1) as u8);

        let mut result = unsigned as i64;
        if sign != 0 {
            result = sign - result;
        }

        result as i32
    }
}

pub struct ParserUtils;

impl ParserUtils {
    pub fn get_be_fixed(data: &mut Vec<u8>, bytes: u8) -> u64 {
        assert!(bytes == 2 || bytes == 4 || bytes == 8);
        assert!(data.len() >= bytes as usize);

        let mut bytes = ParserUtils::get_bytes(data, bytes as u64);
        bytes.reverse();

        IntUtils::to_u64(&bytes)
    }

    pub fn get_fixed_i32(data: &mut Vec<u8>) -> i32 {
        assert!(data.len() >= 4 as usize);

        IntUtils::to_i32(&ParserUtils::get_bytes(data, 4))
    }

    pub fn get_fixed(data: &mut Vec<u8>, bytes: u8) -> u64 {
        assert!(bytes == 2 || bytes == 4 || bytes == 8);
        assert!(data.len() >= bytes as usize);

        IntUtils::to_u64(&ParserUtils::get_bytes(data, bytes as u64))
    }

    pub fn get_time(data: &mut Vec<u8>) -> time::Tm {
        // TODO: fix the case when u64 is too big for i64
        let sec = ParserUtils::get_fixed_u64(data) as i64;
        time::at_utc(time::Timespec::new(sec, 0))
    }

    pub fn serialize_time(timestamp: time::Tm) -> Vec<u8> {
        IntUtils::to_vec_u8_padded(timestamp.to_timespec().sec)
    }

    pub fn get_bytes(data: &mut Vec<u8>, bytes: u64) -> Vec<u8> {
        assert!(data.len() >= bytes as usize);
        let mut bytes_data = vec![];

        for _ in 0..bytes {
            bytes_data.push(data.pop().unwrap());
        }

        bytes_data
    }

    pub fn get_be_fixed_u16(data: &mut Vec<u8>) -> u16 {
        ParserUtils::get_be_fixed(data, 2) as u16
    }

    pub fn get_fixed_u32(data: &mut Vec<u8>) -> u32 {
        ParserUtils::get_fixed(data, 4) as u32
    }

    pub fn get_bool(data: &mut Vec<u8>) -> bool {
        let bytes = ParserUtils::get_bytes(data, 1);

        if bytes[0] == 0 {
            false
        } else {
            true
        }
    }

    pub fn get_fixed_string(data: &mut Vec<u8>, length: u64) -> String {
        let bytes = ParserUtils::get_bytes(data, length);
        // TODO: return error
        String::from_utf8(bytes).unwrap()
    }

    pub fn to_string(data: &str) -> Vec<u8> {
        let length = data.len() as u64;

        let mut result = vec![];
        result.extend(IntUtils::u64_to_vec_u8_padded(length));
        result.extend(data.as_bytes().iter().cloned());

        result
    }

    pub fn get_string(data: &mut Vec<u8>) -> String {
        let length = ParserUtils::get_variable_length_int(data);
        ParserUtils::get_fixed_string(data, length)
    }

    pub fn get_fixed_u64(data: &mut Vec<u8>) -> u64 {
        ParserUtils::get_fixed(data, 8)
    }

    pub fn get_variable_length_int(data: &mut Vec<u8>) -> u64 {
        let last = data.pop().unwrap();

        if last < 0xfd {
            return last as u64;
        }

        let bytes = match last {
            0xfd => 2,
            0xfe => 4,
            0xff => 8,
            _ => unreachable!(),
        };

        IntUtils::to_u64(&ParserUtils::get_bytes(data, bytes))
    }
}

pub struct CryptoUtils;

impl CryptoUtils {
    pub fn ripemd160(input: Vec<u8>) -> Vec<u8> {
        let mut ripemd160 = ripemd160::Ripemd160::new();
        ripemd160.input(&input[..]);

        let mut result = [0u8;20];
        ripemd160.result(&mut result[0..20]);

        let mut result_array = Vec::new();
        result_array.extend(result.iter().cloned());

        result_array
    }

    pub fn sha1(input: Vec<u8>) -> Vec<u8> {
        let mut sha1 = sha1::Sha1::new();
        sha1.input(&input[..]);

        let mut result = [0u8;20];
        sha1.result(&mut result[0..20]);

        let mut result_array = Vec::new();
        result_array.extend(result.iter().cloned());

        result_array
    }

    pub fn sha256(input: Vec<u8>) -> Vec<u8> {
        let mut sha256 = sha2::Sha256::new();
        sha256.input(&input[..]);

        let mut result = [0u8;32];
        sha256.result(&mut result[0..32]);

        let mut result_array = Vec::new();
        result_array.extend(result.iter().cloned());

        result_array
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustc_serialize::base64::FromBase64;

    #[test]
    fn test_to_i32() {
        assert_eq!(IntUtils::to_i32(&vec![0x01]), 1);
        assert_eq!(IntUtils::to_i32(&vec![0x81]), -1);

        assert_eq!(IntUtils::to_i32(&vec![0x7f]), 127);
        assert_eq!(IntUtils::to_i32(&vec![0xff]), -127);

        assert_eq!(IntUtils::to_i32(&vec![0x80, 0x00]), 128);
        assert_eq!(IntUtils::to_i32(&vec![0x80, 0x80]), -128);

        assert_eq!(IntUtils::to_i32(&vec![0xff, 0x7f]), 32767);
        assert_eq!(IntUtils::to_i32(&vec![0xff, 0xff]), -32767);

        assert_eq!(IntUtils::to_i32(&vec![0x00, 0x80, 0x00]), 32768);
        assert_eq!(IntUtils::to_i32(&vec![0x00, 0x80, 0x80]), -32768);

        assert_eq!(IntUtils::to_i32(&vec![0xff, 0xff, 0x7f]), 8388607);
        assert_eq!(IntUtils::to_i32(&vec![0xff, 0xff, 0xff]), -8388607);

        assert_eq!(IntUtils::to_i32(&vec![0x00, 0x00, 0x80, 0x00]), 8388608);
        assert_eq!(IntUtils::to_i32(&vec![0x00, 0x00, 0x80, 0x80]), -8388608);

        assert_eq!(IntUtils::to_i32(&vec![0xff, 0xff, 0xff, 0x7f]), 2147483647);
        assert_eq!(IntUtils::to_i32(&vec![0xff, 0xff, 0xff, 0xff]), -2147483647);
    }

    #[test]
    fn test_to_vec_u8() {
        assert_eq!(vec![0x01], IntUtils::to_vec_u8(1));
        assert_eq!(vec![0x81], IntUtils::to_vec_u8(-1));

        assert_eq!(vec![0x7f], IntUtils::to_vec_u8(127));
        assert_eq!(vec![0xff], IntUtils::to_vec_u8(-127));

        assert_eq!(vec![0x80, 0x00], IntUtils::to_vec_u8(128));
        assert_eq!(vec![0x80, 0x80], IntUtils::to_vec_u8(-128));

        assert_eq!(vec![0xff, 0x7f], IntUtils::to_vec_u8(32767));
        assert_eq!(vec![0xff, 0xff], IntUtils::to_vec_u8(-32767));

        assert_eq!(vec![0x00, 0x80, 0x00], IntUtils::to_vec_u8(32768));
        assert_eq!(vec![0x00, 0x80, 0x80], IntUtils::to_vec_u8(-32768));

        assert_eq!(vec![0xff, 0xff, 0x7f], IntUtils::to_vec_u8(8388607));
        assert_eq!(vec![0xff, 0xff, 0xff], IntUtils::to_vec_u8(-8388607));

        assert_eq!(vec![0x00, 0x00, 0x80, 0x00], IntUtils::to_vec_u8(8388608));
        assert_eq!(vec![0x00, 0x00, 0x80, 0x80], IntUtils::to_vec_u8(-8388608));

        assert_eq!(vec![0xff, 0xff, 0xff, 0x7f], IntUtils::to_vec_u8(2147483647));
        assert_eq!(vec![0xff, 0xff, 0xff, 0xff], IntUtils::to_vec_u8(-2147483647));
    }

    #[test]
    fn test_i32_to_vec_u8_padded() {
        assert_eq!(vec![0x00, 0x00, 0x00, 0x00], IntUtils::i32_to_vec_u8_padded(0x0000));
        assert_eq!(vec![0x01, 0x00, 0x00, 0x00], IntUtils::i32_to_vec_u8_padded(0x0001));
        assert_eq!(vec![0xfe, 0xff, 0x00, 0x00], IntUtils::i32_to_vec_u8_padded(0xfffe));
        assert_eq!(vec![0xff, 0xff, 0xff, 0x7f],
                   IntUtils::i32_to_vec_u8_padded(0x7fffffff));
        assert_eq!(vec![0x01, 0x00, 0x00, 0x80], IntUtils::i32_to_vec_u8_padded(-0x1));
    }

    #[test]
    fn test_u16_to_be_vec_u8_padded() {
        assert_eq!(vec![0x00, 0x00], IntUtils::u16_to_be_vec_u8_padded(0x0000));
        assert_eq!(vec![0x00, 0x01], IntUtils::u16_to_be_vec_u8_padded(0x0001));
        assert_eq!(vec![0xff, 0xfe], IntUtils::u16_to_be_vec_u8_padded(0xfffe));
        assert_eq!(vec![0xff, 0xff], IntUtils::u16_to_be_vec_u8_padded(0xffff));
    }

    fn test_hash(hash: &Fn(Vec<u8>) -> Vec<u8>, input: &str, expected: &str) {
        let output = hash(input.from_base64().unwrap());
        assert_eq!(output, expected.from_base64().unwrap());
    }

    #[test]
    fn test_ripemd160() {
        test_hash(&CryptoUtils::ripemd160, "MQ==", "xHkHq9KoBJLKk4iwXA44JRj/OWA=");
        test_hash(&CryptoUtils::ripemd160, "dGVzdA==", "XlL+5H5rBwVl90NyRozcaZ3okQc=");
        test_hash(&CryptoUtils::ripemd160, "dGVzdF8y", "rwwVga+QLGzlz74RtoOwUT/L6Bw=");
    }

    #[test]
    fn test_sha256() {
        test_hash(&CryptoUtils::sha256, "MQ==", "a4ayc/80/OGda4BO/1o/V0etpOqiLx1JwB5S3beHW0s=");
        test_hash(&CryptoUtils::sha256, "dGVzdA==", "n4bQgYhMfWWaL+qgxVrQFaO/TxsrC4Is0V1sFbDwCgg=");
        test_hash(&CryptoUtils::sha256, "dGVzdF8y", "oQnb2DKAEyn4QJvuKEUCStTOqfAz+lwr0XfG/T54ZYc=");
    }
}
