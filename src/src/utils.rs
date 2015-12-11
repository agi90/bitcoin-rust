use crypto::digest::Digest;
use crypto::sha1;
use crypto::sha2;
use crypto::ripemd160;

pub struct IntUtils;

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

    fn add_sign(bytes_: Vec<u8>, sign: u8) -> Vec<u8> {
        let mut bytes = bytes_;
        let value = bytes.pop().unwrap();
        bytes.push(value | sign);

        bytes
    }

    pub fn to_vec_u8(x: i64) -> Vec<u8> {
        IntUtils::to_vec_u8_base(x, false)
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

#[allow(dead_code)]
pub struct Debug;

#[allow(dead_code)]
impl Debug {
    pub fn print_bytes(data: &[u8]) {
        for d in data {
            print!("{:02X} ", d);
        }
        print!("\n");
    }
}

pub struct CryptoUtils;

impl CryptoUtils {
    pub fn ripemd160(input: &[u8]) -> [u8;20] {
        let mut ripemd160 = ripemd160::Ripemd160::new();
        ripemd160.input(input);

        let mut result = [0u8;20];
        ripemd160.result(&mut result[0..20]);

        result
    }

    pub fn sha1(input: &[u8]) -> [u8;20] {
        let mut sha1 = sha1::Sha1::new();
        sha1.input(input);

        let mut result = [0u8;20];
        sha1.result(&mut result[0..20]);

        result
    }

    pub fn sha256(input: &[u8]) -> [u8;32] {
        let mut sha256 = sha2::Sha256::new();
        sha256.input(input);

        let mut result = [0u8;32];
        sha256.result(&mut result[0..32]);

        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustc_serialize::base64::FromBase64;

    fn test_hash(hash: &Fn(&[u8]) -> [u8;20], input: &str, expected: &str) {
        let output = hash(&input.from_base64().unwrap());
        assert_eq!(&output, &expected.from_base64().unwrap()[..]);
    }

    #[test]
    fn test_ripemd160() {
        test_hash(&CryptoUtils::ripemd160, "MQ==", "xHkHq9KoBJLKk4iwXA44JRj/OWA=");
        test_hash(&CryptoUtils::ripemd160, "dGVzdA==", "XlL+5H5rBwVl90NyRozcaZ3okQc=");
        test_hash(&CryptoUtils::ripemd160, "dGVzdF8y", "rwwVga+QLGzlz74RtoOwUT/L6Bw=");
    }
}
