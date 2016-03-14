use time;

use std::io::Read;

use super::{Deserialize, Deserializer, VarInt};

impl Deserialize for i32 {
    fn deserialize(deserializer: &mut Deserializer) -> Result<Self, String> {
        deserializer.to_i(4).map(|r| r as i32)
    }
}

impl Deserialize for i64 {
    fn deserialize(deserializer: &mut Deserializer) -> Result<Self, String> {
        deserializer.to_i(8)
    }
}

impl Deserialize for u8 {
    fn deserialize(deserializer: &mut Deserializer) -> Result<Self, String> {
        deserializer.to_u(1).map(|r| r as u8)
    }
}

impl Deserialize for u16 {
    fn deserialize(deserializer: &mut Deserializer) -> Result<Self, String> {
        deserializer.to_u(2).map(|r| r as u16)
    }
}

impl Deserialize for u32 {
    fn deserialize(deserializer: &mut Deserializer) -> Result<Self, String> {
        deserializer.to_u(4).map(|r| r as u32)
    }
}

impl Deserialize for u64 {
    fn deserialize(deserializer: &mut Deserializer) -> Result<Self, String> {
        deserializer.to_u(8).map(|r| r as u64)
    }
}

impl Deserialize for time::Tm {
    fn deserialize(deserializer: &mut Deserializer) -> Result<Self, String> {
        let sec = try!(deserializer.to_i(8));
        // Somewhere around 2033 this will break
        // unfortunately time::Tm crashes with an invalid time :-(
        // so we need to do some validation.
        // TODO: switch to a better library
        if sec < 0 || sec > 2000000000 {
            panic!();
            // Err(format!("Invalid time sec={}", sec))
        } else {
            Ok(time::at_utc(time::Timespec::new(sec, 0)))
        }
    }
}

impl Deserialize for bool {
    fn deserialize(deserializer: &mut Deserializer) -> Result<Self, String> {
        let data = try!(deserializer.to_u_fixed(1));
        Ok(data != 0)
    }
}

impl Deserialize for String {
    fn deserialize(deserializer: &mut Deserializer) -> Result<Self, String> {
        let length = try!(VarInt::deserialize(deserializer)).as_u64() as usize;

        if length > 1024 {
            return Err(format!("String is too long, length={}", length));
        }

        let mut bytes = [0; 1024];
        try!(deserializer.read_ex(&mut bytes[0..length]));

        let mut bytes_vector = vec![];
        bytes_vector.extend(bytes[0..length].into_iter());

        String::from_utf8(bytes_vector).map_err(|e| format!("Error: {:?}", e))
    }
}

impl<U: Deserialize> Deserialize for Vec<U> {
    fn deserialize(deserializer: &mut Deserializer) -> Result<Self, String> {
        let length = try!(VarInt::deserialize(deserializer)).as_u64() as usize;

        let mut result = vec![];
        for _ in 0..length {
            result.push(try!(U::deserialize(deserializer)));
        }

        Ok(result)
    }
}

impl<U:Deserialize, K: Deserialize> Deserialize for (U, K) {
    fn deserialize(deserializer: &mut Deserializer) -> Result<Self, String> {
        let first  = try!(U::deserialize(deserializer));
        let second = try!(K::deserialize(deserializer));

        Ok((first, second))
    }
}

// TODO: figure out a way to generalize this
// probably related to https://github.com/rust-lang/rfcs/issues/1038
impl<U: Deserialize + Default + Copy> Deserialize for [U; 4] {
    fn deserialize(deserializer: &mut Deserializer) -> Result<Self, String> {
        let mut result = [U::default(); 4];
        for i in 0..4 {
            result[i] = try!(U::deserialize(deserializer));
        }

        Ok(result)
    }
}

impl<U: Deserialize + Default + Copy> Deserialize for [U; 32] {
    fn deserialize(deserializer: &mut Deserializer) -> Result<Self, String> {
        let mut result = [U::default(); 32];
        for i in 0..32 {
            result[i] = try!(U::deserialize(deserializer));
        }

        Ok(result)
    }
}

impl<T: Read> Deserializer for T {
    fn to_u_slice(&self, data: &[u8]) -> u64 {
        let mut result = 0;
        let mut multiplier: u64 = 1;

        for i in 0..data.len() {
            if i != 0 { multiplier *= 0x100 };
            result += data[i] as u64 * multiplier;
        }

        result
    }

    fn read_ex(&mut self, out: &mut [u8]) -> Result<(), String> {
        self.read_exact(out).map_err(|e| format!("Error: {:?}", e))
    }

    fn to_i(&mut self, size: usize) -> Result<i64, String> {
        assert!(size == 1 || size == 2 || size == 4 || size == 8);

        let mut data = [0; 8];
        try!(self.read_ex(&mut data[0..size]));

        let sign     = data[size-1] & 0x80;
        data[size-1] = data[size-1] & 0x7F;

        let unsigned = self.to_u_slice(&data[0..size]) as i64;

        if sign > 0 {
            Ok(unsigned * -1)
        } else {
            Ok(unsigned)
        }
    }

    fn to_u_fixed(&mut self, size: usize) -> Result<u64, String> {
        assert!(size == 1 || size == 2 || size == 4 || size == 8);

        let mut data = [0; 8];
        try!(self.read_ex(&mut data[0..size]));

        Ok(self.to_u_slice(&data[0..size]))
    }

    fn to_u(&mut self, size: usize) -> Result<u64, String> {
        self.to_u_fixed(size)
    }
}
