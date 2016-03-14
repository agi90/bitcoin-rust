use time;
use std::io::Write;

use super::{Serialize, Serializer, VarInt};

impl<T: Write> Serializer for T {
    fn push(&mut self, byte: u8) {
        self.write_all(&[byte]).unwrap();
    }

    fn push_bytes(&mut self, data: &[u8]) {
        self.write_all(&data).unwrap();
    }

    fn u_to_fixed(&mut self, x: u64, bytes: usize) {
        let data = self.to_bytes(x);
        self.push_bytes(&data[0..bytes]);
    }

    fn serialize_u(&mut self, x: u64, bytes: usize) {
        self.u_to_fixed(x, bytes);
    }

    fn to_bytes(&self, u: u64) -> [u8; 8] {
        [((u & 0x00000000000000ff) / 0x1)               as u8,
         ((u & 0x000000000000ff00) / 0x100)             as u8,
         ((u & 0x0000000000ff0000) / 0x10000)           as u8,
         ((u & 0x00000000ff000000) / 0x1000000)         as u8,
         ((u & 0x000000ff00000000) / 0x100000000)       as u8,
         ((u & 0x0000ff0000000000) / 0x10000000000)     as u8,
         ((u & 0x00ff000000000000) / 0x1000000000000)   as u8,
         ((u & 0xff00000000000000) / 0x100000000000000) as u8]
    }

    fn i_to_fixed(&mut self, x: i64, bytes: usize) {
        let u: u64 = x.abs() as u64;
        let mut data: [u8; 8] = self.to_bytes(u);
        let sign = if u == x as u64 { 0x00 } else { 0x80 };

        data[bytes-1] = data[bytes-1] | sign;

        for i in 0..bytes {
            self.push(data[i]);
        }
    }
}

impl Serialize for bool {
    fn serialize(&self, serializer: &mut Serializer) {
        serializer.push(if *self { 1 } else { 0 });
    }
}

impl Serialize for i16 {
    fn serialize(&self, serializer: &mut Serializer) {
        serializer.i_to_fixed(*self as i64, 2);
    }
}

impl Serialize for i32 {
    fn serialize(&self, serializer: &mut Serializer) {
        serializer.i_to_fixed(*self as i64, 4);
    }
}

impl Serialize for i64 {
    fn serialize(&self, serializer: &mut Serializer) {
        serializer.i_to_fixed(*self, 8);
    }
}

impl Serialize for u8 {
    fn serialize(&self, serializer: &mut Serializer) {
        serializer.push(*self);
    }
}

impl Serialize for u16 {
    fn serialize(&self, serializer: &mut Serializer) {
        serializer.u_to_fixed(*self as u64, 2);
    }
}

impl Serialize for u32 {
    fn serialize(&self, serializer: &mut Serializer) {
        serializer.serialize_u(*self as u64, 4);
    }
}

impl Serialize for u64 {
    fn serialize(&self, serializer: &mut Serializer) {
        serializer.serialize_u(*self, 8);
    }
}

impl Serialize for time::Tm {
    fn serialize(&self, serializer: &mut Serializer) {
        serializer.i_to_fixed(self.to_timespec().sec, 8);
    }
}

impl Serialize for String {
    fn serialize(&self, serializer: &mut Serializer) {
        let length = VarInt::new(self.as_bytes().len() as u64);
        length.serialize(serializer);
        serializer.push_bytes(&self.as_bytes());
    }
}

impl<U: Serialize> Serialize for Vec<U> {
    fn serialize(&self, serializer: &mut Serializer) {
        let length = VarInt::new(self.len() as u64);
        length.serialize(serializer);

        for x in self {
            x.serialize(serializer);
        }
    }
}

impl <U: Serialize, V: Serialize> Serialize for (U,V) {
    fn serialize(&self, serializer: &mut Serializer) {
        self.0.serialize(serializer);
        self.1.serialize(serializer);
    }
}

impl <U: Serialize> Serialize for [U] {
    fn serialize(&self, serializer: &mut Serializer) {
        for x in self {
            x.serialize(serializer);
        }
    }
}

impl <U: Serialize> Serialize for [U; 4] {
    fn serialize(&self, serializer: &mut Serializer) {
        for x in self {
            x.serialize(serializer);
        }
    }
}

impl <U: Serialize> Serialize for [U; 32] {
    fn serialize(&self, serializer: &mut Serializer) {
        for x in self {
            x.serialize(serializer);
        }
    }
}

