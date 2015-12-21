extern crate rand;

use super::IPAddress;
use super::Services;
use utils::CryptoUtils;

use std::ops::Deref;

use std::io::{Cursor, SeekFrom, Seek, Read, Write};
use std::net::Ipv6Addr;

use std::hash::{Hash, Hasher};

use std::fmt;
use std::str;

use time;

#[derive(PartialEq, Copy, Clone, Debug)]
pub enum NetworkType {
    Main,
    TestNet,
    TestNet3,
    NameCoin,
    Unknown,
}

#[derive(PartialEq, Copy, Clone, Debug)]
pub enum Command {
    Addr,
    GetAddr,
    Version,
    Verack,
    Inv,
    Tx,
    NotFound,
    GetData,
    Ping,
    Pong,
    Reject,
    GetHeaders,
    GetBlocks,
    Headers,
    Block,
    Unknown,
}

type Bytes = Vec<u8>;
type BlockLocators = Vec<Bytes>;

pub trait Serialize {
    fn serialize(&self, serializer: &mut Serializer);

    fn serialize_hash(&self) -> (Vec<u8>, BitcoinHash) {
        let mut buffer = Cursor::new(vec![]);
        self.serialize(&mut buffer);

        let hash = CryptoUtils::sha256(&CryptoUtils::sha256(buffer.get_ref()));
        (buffer.into_inner(), BitcoinHash::new(hash))
    }

    fn hash(&self) -> BitcoinHash {
        self.serialize_hash().1
    }
}

pub trait Serializer {
    fn push(&mut self, byte: u8);
    fn push_bytes(&mut self, data: &[u8]);
    fn u_to_fixed(&mut self, x: u64, bytes: usize);
    fn serialize_u(&mut self, x: u64, bytes: usize);
    fn to_bytes(&self, u: u64) -> [u8; 8];
    fn i_to_fixed(&mut self, x: i64, bytes: usize);
}

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

impl Serialize for Ipv6Addr {
    fn serialize(&self, serializer: &mut Serializer) {
        for x in self.segments().iter() {
            let bytes = serializer.to_bytes(*x as u64);
            // Ip are encoded with big-endian integers
            serializer.push(bytes[1]);
            serializer.push(bytes[0]);
        }
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

impl Serialize for Services {
    fn serialize(&self, serializer: &mut Serializer) {
        let data = if self.node_network { 1 } else { 0 };
        serializer.serialize_u(data, 8);
    }
}

impl Deserialize for IPAddress {
    fn deserialize(deserializer: &mut Deserializer) -> Result<Self, String> {
        let services: Services = try!(Deserialize::deserialize(deserializer));
        let address: Ipv6Addr  = try!(Deserialize::deserialize(deserializer));

        // The port is encoded in big endian
        let mut data = [0; 2];
        try!(deserializer.read_ex(&mut data));

        let port = deserializer.to_u_slice(&[data[1], data[0]]) as u16;

        Ok(IPAddress::new(services, address, port))
    }
}

impl Serialize for IPAddress {
    fn serialize(&self, serializer: &mut Serializer) {
        self.services.serialize(serializer);
        self. address.serialize(serializer);

        // The port is encoded in big endian
        let data = serializer.to_bytes(self.port as u64);
        serializer.push(data[1]);
        serializer.push(data[0]);
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

pub trait Deserialize: Sized {
    fn deserialize(deserializer: &mut Deserializer) -> Result<Self, String>;
}

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

impl Deserialize for Ipv6Addr {
    fn deserialize(deserializer: &mut Deserializer) -> Result<Self, String> {
        let mut data = [0; 16];
        try!(deserializer.read_ex(&mut data));

        let mut s = [0u16; 8];
        for i in 0..8 {
            // IPs are big-endian so we need to swap the bytes
            s[i] = deserializer.to_u_slice(&[data[2*i + 1], data[2*i]]) as u16;
        }

        Ok(Ipv6Addr::new(s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7]))
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

impl Deserialize for Services {
    fn deserialize(deserializer: &mut Deserializer) -> Result<Self, String> {
        let data = try!(u64::deserialize(deserializer));
        Ok(Services::new(data == 1))
    }
}

pub trait Deserializer {
    fn read_ex(&mut self, out: &mut [u8]) -> Result<(), String>;
    fn to_i(&mut self, size: usize) -> Result<i64, String>;
    fn to_u_fixed(&mut self, size: usize) -> Result<u64, String>;
    fn to_u(&mut self, size: usize) -> Result<u64, String>;
    fn to_u_slice(&self, data: &[u8]) -> u64;
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

#[derive(PartialEq, Debug, Clone, Copy)]
pub struct ShortFormatTm {
    data: time::Tm,
}

impl ShortFormatTm {
    pub fn new(data: time::Tm) -> ShortFormatTm {
        ShortFormatTm {
            data: data,
        }
    }

    pub fn as_tm(&self) -> time::Tm {
        self.data
    }
}

impl Deref for ShortFormatTm {
    type Target = time::Tm;

    fn deref(&self) -> &time::Tm {
        &self.data
    }
}

impl Serialize for ShortFormatTm {
    fn serialize(&self, serializer: &mut Serializer) {
        serializer.serialize_u(self.data.to_timespec().sec as u64, 4);
    }
}

impl Deserialize for ShortFormatTm {
    fn deserialize(deserializer: &mut Deserializer) -> Result<Self, String> {
        let sec = try!(deserializer.to_u_fixed(4));
        Ok(ShortFormatTm::new(time::at_utc(time::Timespec::new(sec as i64, 0))))
    }
}

#[derive(PartialEq, Debug, Clone, Copy)]
pub struct VarInt {
    data: u64,
}

impl VarInt {
    pub fn new(data: u64) -> VarInt {
        VarInt {
            data: data,
        }
    }

    pub fn as_u64(&self) -> u64 {
        self.data
    }
}

impl Deref for VarInt {
    type Target = u64;

    fn deref(&self) -> &u64 {
        &self.data
    }
}

impl Serialize for VarInt {
    fn serialize(&self, serializer: &mut Serializer) {
        let data = serializer.to_bytes(self.data);

        match self.data {
            0x00000...0x0000000fc => {
                serializer.push(data[0])
            },
            0x000fd...0x00000ffff => {
                serializer.push(0xfd);
                serializer.push_bytes(&data[0..2]);
            },
            0x10000...0x0ffffffff => {
                serializer.push(0xfe);
                serializer.push_bytes(&data[0..4]);
            },
            _ => {
                serializer.push(0xff);
                serializer.push_bytes(&data[0..8]);
            },
        };
    }
}

impl Deserialize for VarInt {
    fn deserialize(deserializer: &mut Deserializer) -> Result<Self, String> {
        let mut data = [0; 1];
        try!(deserializer.read_ex(&mut data));

        if data[0] < 0xfd {
            return Ok(VarInt::new(data[0] as u64));
        }

        let bytes = match data[0] {
            0xfd => 2,
            0xfe => 4,
            0xff => 8,
            _    => 0,
        };

        Ok(VarInt::new(try!(deserializer.to_u_fixed(bytes))))
    }
}

#[derive(PartialEq, Eq, Clone, Copy)]
pub struct BitcoinHash {
    data: [u8; 32],
}

impl BitcoinHash {
    pub fn new(data: [u8; 32]) -> BitcoinHash {
        BitcoinHash {
            data: data,
        }
    }
}

impl Deref for BitcoinHash {
    type Target = [u8; 32];

    fn deref(&self) -> &[u8; 32] {
        &self.data
    }
}

impl Hash for BitcoinHash {
    fn hash<H: Hasher>(&self, state: &mut H) {
        Hash::hash(&self.data, state);
    }
}

impl fmt::Debug for BitcoinHash {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        for i in 0..32 {
            // Let's print the hash in the canonical form (i.e. big endian)
            let result = write!(f, "{:02X}", self[31 - i]);
            if result.is_err() {
                return result;
            }
        }

        Ok(())
    }
}

impl Serialize for BitcoinHash {
    fn serialize(&self, serializer: &mut Serializer) {
        self.data.serialize(serializer);
    }
}

impl Deserialize for BitcoinHash {
    fn deserialize(deserializer: &mut Deserializer) -> Result<Self, String> {
        Ok(BitcoinHash {
            data: try!(Deserialize::deserialize(deserializer)),
        })
    }
}

impl Deserialize for Command {
    fn deserialize(deserializer: &mut Deserializer) -> Result<Self, String> {
        let mut bytes = [0; 12];
        try!(deserializer.read_ex(&mut bytes));

        match &bytes {
            b"version\0\0\0\0\0"      => Ok(Command::Version),
            b"verack\0\0\0\0\0\0"     => Ok(Command::Verack),
            b"tx\0\0\0\0\0\0\0\0\0\0" => Ok(Command::Tx),
            b"inv\0\0\0\0\0\0\0\0\0"  => Ok(Command::Inv),
            b"ping\0\0\0\0\0\0\0\0"   => Ok(Command::Ping),
            b"pong\0\0\0\0\0\0\0\0"   => Ok(Command::Pong),
            b"getaddr\0\0\0\0\0"      => Ok(Command::GetAddr),
            b"notfound\0\0\0\0"       => Ok(Command::NotFound),
            b"addr\0\0\0\0\0\0\0\0"   => Ok(Command::Addr),
            b"reject\0\0\0\0\0\0"     => Ok(Command::Reject),
            b"getblocks\0\0\0"        => Ok(Command::GetBlocks),
            b"getheaders\0\0"         => Ok(Command::GetHeaders),
            b"getdata\0\0\0\0\0"      => Ok(Command::GetData),
            b"headers\0\0\0\0\0"      => Ok(Command::Headers),
            b"block\0\0\0\0\0\0\0"    => Ok(Command::Block),
            command                   => {
                println!("Warning: unknown command `{:?}`", str::from_utf8(command));
                Ok(Command::Unknown)
            },
        }
    }
}

impl Serialize for Command {
    fn serialize(&self, serializer: &mut Serializer) {
        let bytes = match self {
            &Command::Addr        => b"addr\0\0\0\0\0\0\0\0",
            &Command::GetAddr     => b"getaddr\0\0\0\0\0",
            &Command::Version     => b"version\0\0\0\0\0",
            &Command::Verack      => b"verack\0\0\0\0\0\0",
            &Command::Tx          => b"tx\0\0\0\0\0\0\0\0\0\0",
            &Command::Inv         => b"inv\0\0\0\0\0\0\0\0\0",
            &Command::Ping        => b"ping\0\0\0\0\0\0\0\0",
            &Command::Pong        => b"pong\0\0\0\0\0\0\0\0",
            &Command::Reject      => b"reject\0\0\0\0\0\0",
            &Command::NotFound    => b"notfound\0\0\0\0",
            &Command::GetData     => b"getdata\0\0\0\0\0",
            &Command::GetHeaders  => b"getheaders\0\0",
            &Command::Block       => b"block\0\0\0\0\0\0\0",
            &Command::GetBlocks   => b"getblocks\0\0\0",
            &Command::Headers     => b"headers\0\0\0\0\0",
            &Command::Unknown     => unimplemented!(),
        };

        assert_eq!(bytes.len(), 12);
        serializer.push_bytes(bytes);
    }
}

impl Deserialize for NetworkType {
    fn deserialize(deserializer: &mut Deserializer) -> Result<Self, String> {
        let data = try!(u32::deserialize(deserializer));
        match data {
            0xD9B4BEF9 => Ok(NetworkType::Main),
            0xDAB5BFFA => Ok(NetworkType::TestNet),
            0x0709110B => Ok(NetworkType::TestNet3),
            0xFEB4BEF9 => Ok(NetworkType::NameCoin),
            _          => Err(format!("Unrecognized magic number {}", data)),
        }
    }
}

impl Serialize for NetworkType {
    fn serialize(&self, serializer: &mut Serializer) {
        let magic = match self {
            &NetworkType::Main      => 0xD9B4BEF9,
            &NetworkType::TestNet   => 0xDAB5BFFA,
            &NetworkType::TestNet3  => 0x0709110B,
            &NetworkType::NameCoin  => 0xFEB4BEF9,
            // Uknown is only used internally and should
            // never be sent accross the network
            &NetworkType::Unknown   => unimplemented!(),
        };

        serializer.serialize_u(magic, 4);
    }
}

#[allow(non_camel_case_types)]
#[derive(Debug, PartialEq)]
pub enum InventoryVectorType {
    ERROR,
    MSG_TX,
    MSG_BLOCK,
    MSG_FILTERED_BLOCK,
}

impl Serialize for InventoryVectorType {
    fn serialize(&self, serializer: &mut Serializer) {
        let index: u32 = match self {
            &InventoryVectorType::ERROR              => 0,
            &InventoryVectorType::MSG_TX             => 1,
            &InventoryVectorType::MSG_BLOCK          => 2,
            &InventoryVectorType::MSG_FILTERED_BLOCK => 3,
        };

        index.serialize(serializer);
    }
}

impl Deserialize for InventoryVectorType {
    fn deserialize(deserializer: &mut Deserializer) -> Result<Self, String> {
        let index = try!(u32::deserialize(deserializer));

        match index {
            0 => Ok(InventoryVectorType::ERROR),
            1 => Ok(InventoryVectorType::MSG_TX),
            2 => Ok(InventoryVectorType::MSG_BLOCK),
            3 => Ok(InventoryVectorType::MSG_FILTERED_BLOCK),
            vector_type => Err(format!("Unexpected inventory vector type = {}", vector_type)),
        }
    }
}

macro_rules! message {
    ($name:ident ; $($element: ident: $ty: ty),*) => {
        #[derive(Debug, PartialEq)]
        pub struct $name { $(pub $element: $ty),* }

        impl $name {
            pub fn new($($element: $ty),*) -> $name {
                $name {
                    $($element: $element),*
                }
            }
        }

        impl Serialize for $name {
            fn serialize(&self, serializer: &mut Serializer) {
                $(self.$element.serialize(serializer));*
            }
        }

        impl Deserialize for $name {
            fn deserialize(deserializer: &mut Deserializer) -> Result<Self, String> {
                Ok($name {
                    $($element: try!(Deserialize::deserialize(deserializer))),*
                })
            }
        }
    }
}

message!(MessageHeader;
    network_type: NetworkType,
    command: Command,
    length: u32,
    checksum: [u8; 4]
);

message!(VersionMessage;
    version: i32,
    services: Services,
    timestamp: time::Tm,
    addr_recv: IPAddress,
    addr_from: IPAddress,
    nonce: u64,
    user_agent: String,
    start_height: i32,
    relay: bool
);

message!(PingMessage;
    nonce: u64
);

message!(AddrMessage;
    addr_list: Vec<(ShortFormatTm, IPAddress)>
);

message!(RejectMessage;
    message: String,
    ccode: u8,
    reason: String
);

message!(HeadersMessage;
    headers: Vec<(BlockMetadata, u64)>
);

message!(GetHeadersMessage;
    version: u32,
    block_locators: Vec<BitcoinHash>,
    hash_stop: BitcoinHash
);

message!(InventoryVector;
    type_: InventoryVectorType,
    hash: BitcoinHash
);

message!(InvMessage;
    inventory: Vec<InventoryVector>
);

message!(OutPoint;
    hash: BitcoinHash,
    index: u32
);

message!(TxIn;
    previous_output: OutPoint,
    script: Vec<u8>,
    sequence: u32
);

message!(TxOut;
    value: i64,
    pk_script: Vec<u8>
);

message!(TxMessage;
    version: u32,
    tx_in: Vec<TxIn>,
    tx_out: Vec<TxOut>,
    lock_time: u32
);

message!(BlockMetadata;
    version: i32,
    prev_block: BitcoinHash,
    merkle_root: BitcoinHash,
    timestamp: ShortFormatTm,
    bits: u32,
    nonce: u32
);

pub struct BlockMessage {
    pub metadata: BlockMetadata,
    pub txns: Vec<TxMessage>,
}

impl BlockMessage {
    pub fn prev_block(&self) -> &BitcoinHash { &self.metadata.prev_block }
    pub fn into_metadata(self) -> BlockMetadata { self.metadata }
}

impl Serialize for BlockMessage {
    fn serialize(&self, serializer: &mut Serializer) {
        self.metadata.serialize(serializer);
        self.txns    .serialize(serializer);
    }

    fn serialize_hash(&self) -> (Vec<u8>, BitcoinHash) {
        let (serialized, hash) = self.metadata.serialize_hash();
        let mut buffer = Cursor::new(serialized);
        buffer.seek(SeekFrom::End(0)).unwrap();
        self.txns.serialize(&mut buffer);

        (buffer.into_inner(), hash)
    }
}

impl Deserialize for BlockMessage {
    fn deserialize(deserializer: &mut Deserializer) -> Result<Self, String> {
        Ok(BlockMessage {
            metadata: try!(Deserialize::deserialize(deserializer)),
            txns:     try!(Deserialize::deserialize(deserializer)),
        })
    }
}

pub fn get_serialized_message(network_type: NetworkType,
                              command: Command,
                              message: Option<Box<Serialize>>) -> Vec<u8> {
    let mut buffer = Cursor::new(vec![]);
    message.map(|m| m.serialize(&mut buffer));

    let checksum = CryptoUtils::sha256(&CryptoUtils::sha256(buffer.get_ref()));

    let header = MessageHeader {
        network_type: network_type,
        command: command,
        length: buffer.get_ref().len() as u32,
        checksum: [checksum[0], checksum[1], checksum[2], checksum[3]],
    };

    let mut header_buffer = Cursor::new(vec![]);
    header.serialize(&mut header_buffer);

    let mut result = header_buffer.into_inner();
    result.extend(buffer.into_inner());

    result
}

#[cfg(test)]
mod tests {
    use rustc_serialize::hex::FromHex;
    use std::io::Cursor;
    use super::*;
    use utils::Debug;

    #[test]
    fn test_real_tx_fd_length_script() {
        let tx = "0100000004462d18011de1ff68d8b5ebaf91a166fb11473987f61a93b85095065fae88ef8701000000fdfd0000483045022100c660a5b274b6f16befc5c9097a3a6bcd70f28d7bbacd6a38546a51e8219f10310220024475046dd15b01be75e9871ab60d725591b8174712faffa46ac7d4a35b0ed70147304402202c665edd73b2bb379ea78a1846df6573f52d9bf47bd584e40349c8643161c57602202a578c359014e9fe9b19c69f266d32b5bc838fc09f63d4cd5e3108def98bb053014c69522102ca2a810ab17249b6033a038de563983881b4069270183f3c0aba945653e442162103f480f1b648d0d5167804ad4d586e0e757cc33fde0e133fd036e45d60d2db59e12103c18131d8de99d45fb72a774cab0ccc258cd2abd9605610da20b9a232c88a3cb653aeffffffffb6a3c919fc8bab89329df0e41dd58017e59d5fec4076c4746573b7922e8fd427010000006b4830450220082991a84213115e3a718730dc0e0e248e6d429bb0b86065e23fed39be03fabe022100eb4c66f29293f0b90c0847aaca1fe37ab0afab6d47b7f1c308f309c4d63def43012103f480f1b648d0d5167804ad4d586e0e757cc33fde0e133fd036e45d60d2db59e1ffffffff3f1af8aefe6ed159cb94062d8e50ac5d9c24843899ff3bc88e6a5316f7cf7def010000006a473044022062032061b3fe964555ca785a6b08312c0db6f891eeda36721889b7bb189417d802203c129734bffe6d444aa60f17e9dcead44a8cc94a9a2d07e6227788748955481c012103223850b5215f24bbf8159783918f70f7d5b13039bffb48dda6d048d1bac2bc59ffffffff6b10231eace272420820d0379630d5ab743f9e18371dc5d5648ab7abe9ed39b3000000006a473044022036192198d39e55b73c6ab96f9e578525a368edf624471a9d9bbc15cc31cc1d2502205cef889543d938f2ac7def02ea2cc48e360dc05638a8ac6058342a726498045d0121038306b58a51ad7a6b97a02d8736676b0567e1addfd90106c8fe703663005bd20dffffffff0229520f00000000001976a914a10a4da7d425923f7296b4b9b6dc4fe2564a3ba688ac57bf0100000000001976a9143380a752d3314b80542a721a7dced925a2f5fbf488ac00000000".from_hex().unwrap();

        let mut cursor = Cursor::new(tx.clone());
        let tx_obj = TxMessage::deserialize(&mut cursor).unwrap();

        let mut buffer = vec![];
        tx_obj.serialize(&mut buffer);

        Debug::print_bytes(&buffer);
        Debug::print_bytes(&tx);

        assert_eq!(buffer, tx);
    }

    #[test]
    fn test_real_tx_value_0() {
        let tx = "0100000002abf3a7e5bb08d828d9facb5f43e89437c8db8eb37e47ef590abe1040b8074cc3000000006a47304402201adc73cb90a42440a83f590e7a5309b611924c603c195da956ddbee1a024599e02205bd1b89ab89d8496c6ee8ae89bd98d725541137e9e044bc87a6f2d0cb53248e901210371196e03bfa6fdff8a4f2d9d4ba705ddbf40b062d2c0113253129d3230045f3bffffffffabf3a7e5bb08d828d9facb5f43e89437c8db8eb37e47ef590abe1040b8074cc3010000006b483045022100a16379ef6976f74c697beca71c79008f64a547fd856fe89c2ee08082ed4ba56002205c5f58ed92ad00c04395fa2bef655a99e2602e87212c1ba6499610a2ffc1f30a0121038966fb63c2c52b9d6c948029cf0d1e125944d5129e913565dcd6adf71355a0a4ffffffff03a0860100000000001976a914231709007241b6f638859d47384fe60f0f6a26ef88acc18d0ed2050000001976a9148c38e68d20d575f421f044a5995e1e18070b290f88ac0000000000000000056a0379657300000000".from_hex().unwrap();

        let mut cursor = Cursor::new(tx.clone());
        let tx_obj = TxMessage::deserialize(&mut cursor).unwrap();

        println!("{:?}", tx_obj);
    }
}
