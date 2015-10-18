pub struct IntUtils;

impl IntUtils {
    pub fn to_vec_u8(x: i32) -> Vec<u8> {
        let u = x.abs();
        let sign: u8 = if u == x { 0x00 } else { 0x80 };

        let byte0 = (u  & 0x000000ff)              as u8;
        let byte1 = ((u & 0x0000ff00) / 0x100)     as u8;
        let byte2 = ((u & 0x00ff0000) / 0x10000)   as u8;
        let byte3 = ((u & 0x7f000000) / 0x1000000) as u8;

        if u == 0 {
            vec![]
        } else if u <= 0x7f {
            vec![u as u8 | sign]
        } else if u <= 0x7fff {
            vec![byte0, byte1 | sign]
        } else if u <= 0x7fffff {
            vec![byte0, byte1, byte2 | sign]
        } else {
            vec![byte0, byte1, byte2, byte3 | sign]
        }
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

#[cfg(test)]
mod tests {
    use super::*;

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
}
