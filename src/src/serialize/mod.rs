mod serialize;
mod deserialize;
mod var_int;

pub trait Serialize {
    fn serialize(&self, serializer: &mut Serializer);
    fn size() -> usize where Self: Sized;
}

pub trait Deserialize: Sized {
    fn deserialize(deserializer: &mut Deserializer) -> Result<Self, String>;
}

pub trait Serializer {
    fn push(&mut self, byte: u8);
    fn push_bytes(&mut self, data: &[u8]);
    fn u_to_fixed(&mut self, x: u64, bytes: usize);
    fn serialize_u(&mut self, x: u64, bytes: usize);
    fn to_bytes(&self, u: u64) -> [u8; 8];
    fn i_to_fixed(&mut self, x: i64, bytes: usize);
}

pub trait Deserializer {
    fn read_ex(&mut self, out: &mut [u8]) -> Result<(), String>;
    fn to_i(&mut self, size: usize) -> Result<i64, String>;
    fn to_u_fixed(&mut self, size: usize) -> Result<u64, String>;
    fn to_u(&mut self, size: usize) -> Result<u64, String>;
    fn to_u_slice(&self, data: &[u8]) -> u64;
}

#[derive(PartialEq, Debug, Clone, Copy)]
pub struct VarInt {
    data: u64,
}

