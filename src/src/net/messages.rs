extern crate rand;

use super::IPAddress;
use super::Services;
use utils::CryptoUtils;

use std::io::{Cursor, SeekFrom, Seek, Read, Write};
use std::net::Ipv6Addr;

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

#[derive(Debug, PartialEq, Copy, Clone)]
pub enum Flag {
    // applicable to i16 for now
    BigEndian,
    // applicable to unsigned types, strings, arrays
    VariableSize,
    FixedSize(usize),
    // applicable to time::Tm
    ShortFormat,
}

type Hash = [u8; 32];
type Bytes = Vec<u8>;
type BlockLocators = Vec<Bytes>;
type BlockHeaders = Vec<BlockHeader>;
type AddrList = Vec<(time::Tm, IPAddress)>;

pub trait Serialize {
    fn serialize(&self, serializer: &mut Serializer, flag: &[Flag]);

    fn serialize_hash(&self) -> (Vec<u8>, [u8; 32]) {
        let mut buffer = Cursor::new(vec![]);
        self.serialize(&mut buffer, &[]);

        let hash = CryptoUtils::sha256(&CryptoUtils::sha256(buffer.get_ref()));
        (buffer.into_inner(), hash)
    }

    fn hash(&self) -> [u8; 32] {
        self.serialize_hash().1
    }
}

pub trait Serializer {
    fn push(&mut self, byte: u8);
    fn push_bytes(&mut self, data: &[u8], bytes: usize);
    fn u_to_fixed(&mut self, x: u64, bytes: usize);
    fn serialize_u(&mut self, x: u64, bytes: usize, flags: &[Flag]);
    fn var_int(&mut self, x: u64);
    fn to_bytes(&self, u: u64) -> [u8; 8];
    fn i_to_fixed(&mut self, x: i64, bytes: usize);
}

impl<T: Write> Serializer for T {
    fn push(&mut self, byte: u8) {
        self.write_all(&[byte]).unwrap();
    }

    fn push_bytes(&mut self, data: &[u8], bytes: usize) {
        self.write_all(&data[0..bytes]).unwrap();
    }

    fn u_to_fixed(&mut self, x: u64, bytes: usize) {
        let data = self.to_bytes(x);
        self.push_bytes(&data, bytes);
    }

    fn serialize_u(&mut self, x: u64, bytes: usize, flags: &[Flag]) {
        if flags.contains(&Flag::VariableSize) {
            self.var_int(x);
        } else {
            self.u_to_fixed(x, bytes);
        }
    }

    fn var_int(&mut self, x: u64) {
        let data = self.to_bytes(x);

        match x {
            0x00000...0x0000000fd => {
                self.push(data[0])
            },
            0x000fd...0x000010000 => {
                self.push(0xfd);
                self.push_bytes(&data, 2);
            },
            0x10000...0x100000000 => {
                self.push(0xfe);
                self.push_bytes(&data, 4);
            },
            _ => {
                self.push(0xff);
                self.push_bytes(&data, 8);
            },
        };
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
    fn serialize(&self, serializer: &mut Serializer, _: &[Flag]) {
        serializer.push(if *self { 1 } else { 0 });
    }
}

impl Serialize for i16 {
    fn serialize(&self, serializer: &mut Serializer, _: &[Flag]) {
        serializer.i_to_fixed(*self as i64, 2);
    }
}

impl Serialize for i32 {
    fn serialize(&self, serializer: &mut Serializer, _: &[Flag]) {
        serializer.i_to_fixed(*self as i64, 4);
    }
}

impl Serialize for i64 {
    fn serialize(&self, serializer: &mut Serializer, _: &[Flag]) {
        serializer.i_to_fixed(*self, 8);
    }
}

impl Serialize for u8 {
    fn serialize(&self, serializer: &mut Serializer, _: &[Flag]) {
        serializer.push(*self);
    }
}

impl Serialize for u16 {
    fn serialize(&self, serializer: &mut Serializer, flags: &[Flag]) {
        if flags.contains(&Flag::BigEndian) {
            let data = serializer.to_bytes(*self as u64);
            serializer.push(data[1]);
            serializer.push(data[0]);
        } else {
            serializer.u_to_fixed(*self as u64, 2);
        }
    }
}

impl Serialize for u32 {
    fn serialize(&self, serializer: &mut Serializer, flag: &[Flag]) {
        serializer.serialize_u(*self as u64, 4, flag);
    }
}

impl Serialize for u64 {
    fn serialize(&self, serializer: &mut Serializer, flag: &[Flag]) {
        serializer.serialize_u(*self, 8, flag);
    }
}

impl Serialize for Ipv6Addr {
    fn serialize(&self, serializer: &mut Serializer, _: &[Flag]) {
        for x in self.segments().iter() {
            let bytes = serializer.to_bytes(*x as u64);
            // Ip are encoded with big-endian integers
            serializer.push(bytes[1]);
            serializer.push(bytes[0]);
        }
    }
}

impl Serialize for time::Tm {
    fn serialize(&self, serializer: &mut Serializer, flags: &[Flag]) {
        if flags.contains(&Flag::ShortFormat) {
            serializer.serialize_u(self.to_timespec().sec as u64, 4, &[]);
        } else {
            serializer.i_to_fixed(self.to_timespec().sec, 8);
        }
    }
}

impl Serialize for String {
    fn serialize(&self, serializer: &mut Serializer, flags: &[Flag]) {
        let length = self.as_bytes().len();

        if flags.contains(&Flag::VariableSize) {
            serializer.var_int(length as u64);
        }

        serializer.push_bytes(&self.as_bytes(), length);
    }
}

impl<U: Serialize> Serialize for Vec<U> {
    fn serialize(&self, serializer: &mut Serializer, flags: &[Flag]) {
        let length = self.len();

        if flags.get(0) == Some(&Flag::VariableSize) {
            serializer.var_int(length as u64);
        }

        for x in self {
            if flags.len() > 1 {
                x.serialize(serializer, &flags[1..]);
            } else {
                x.serialize(serializer, &[]);
            }
        }
    }
}

impl Serialize for Services {
    fn serialize(&self, serializer: &mut Serializer, _: &[Flag]) {
        let data = if self.node_network { 1 } else { 0 };
        serializer.serialize_u(data, 8, &[]);
    }
}

impl<T: Read> Deserialize<T> for IPAddress {
    fn deserialize(deserializer: &mut Deserializer<T>, _: &[Flag]) -> Result<Self, String> {
        Ok(IPAddress::new(
            try!(Services::deserialize(deserializer, &[])),
            try!(Ipv6Addr::deserialize(deserializer, &[])),
                 try!(u16::deserialize(deserializer, &[Flag::BigEndian])),
        ))
    }
}

impl Serialize for IPAddress {
    fn serialize(&self, serializer: &mut Serializer, _: &[Flag]) {
        self.services.serialize(serializer, &[]);
        self. address.serialize(serializer, &[]);
        self.    port.serialize(serializer, &[Flag::BigEndian]);
    }
}

impl <U: Serialize, V: Serialize> Serialize for (U,V) {
    fn serialize(&self, serializer: &mut Serializer, flag: &[Flag]) {
        self.0.serialize(serializer, flag);
        self.1.serialize(serializer, flag);
    }
}

impl <U: Serialize> Serialize for [U] {
    fn serialize(&self, serializer: &mut Serializer, flag: &[Flag]) {
        for x in self {
            x.serialize(serializer, flag);
        }
    }
}

impl <U: Serialize> Serialize for [U; 32] {
    fn serialize(&self, serializer: &mut Serializer, flag: &[Flag]) {
        for x in self {
            x.serialize(serializer, flag);
        }
    }
}

pub trait Deserialize<T: Read>: Sized {
    fn deserialize(deserializer: &mut Deserializer<T>, flag: &[Flag]) -> Result<Self, String>;
}

#[derive(Debug)]
pub struct Deserializer<T: Read> {
    buffer: T,
    pos: usize,
}

impl<T: Read> Deserialize<T> for i32 {
    fn deserialize(deserializer: &mut Deserializer<T>, _: &[Flag]) -> Result<Self, String> {
        deserializer.to_i(4).map(|r| r as i32)
    }
}

impl<T: Read> Deserialize<T> for i64 {
    fn deserialize(deserializer: &mut Deserializer<T>, _: &[Flag]) -> Result<Self, String> {
        deserializer.to_i(8)
    }
}

impl<T: Read> Deserialize<T> for u8 {
    fn deserialize(deserializer: &mut Deserializer<T>, _: &[Flag]) -> Result<Self, String> {
        deserializer.to_u(1, &[]).map(|r| r as u8)
    }
}

impl<T: Read> Deserialize<T> for u16 {
    fn deserialize(deserializer: &mut Deserializer<T>, flags: &[Flag]) -> Result<Self, String> {
        if flags.contains(&Flag::BigEndian) {
            deserializer.get_be_u16()
        } else {
            deserializer.to_u(2, flags).map(|r| r as u16)
        }
    }
}

impl<T: Read> Deserialize<T> for u32 {
    fn deserialize(deserializer: &mut Deserializer<T>, flag: &[Flag]) -> Result<Self, String> {
        deserializer.to_u(4, flag).map(|r| r as u32)
    }
}

impl<T: Read> Deserialize<T> for u64 {
    fn deserialize(deserializer: &mut Deserializer<T>, flag: &[Flag]) -> Result<Self, String> {
        deserializer.to_u(8, flag).map(|r| r as u64)
    }
}

impl<T: Read> Deserialize<T> for Ipv6Addr {
    fn deserialize(deserializer: &mut Deserializer<T>, _: &[Flag]) -> Result<Self, String> {
        deserializer.to_ip()
    }
}

impl<T: Read> Deserialize<T> for time::Tm {
    fn deserialize(deserializer: &mut Deserializer<T>, flags: &[Flag]) -> Result<Self, String> {
        if flags.contains(&Flag::ShortFormat) {
            deserializer.to_short_time()
        } else {
            deserializer.to_time()
        }
    }
}

impl<T: Read> Deserialize<T> for bool {
    fn deserialize(deserializer: &mut Deserializer<T>, _: &[Flag]) -> Result<Self, String> {
        deserializer.to_bool()
    }
}

impl<T: Read> Deserialize<T> for String {
    fn deserialize(deserializer: &mut Deserializer<T>, flag: &[Flag]) -> Result<Self, String> {
        deserializer.to_string(flag)
    }
}

fn extract_fixed_size(flags: &[Flag]) -> Option<usize> {
    for flag in flags {
        if let &Flag::FixedSize(n) = flag {
            return Some(n);
        };
    };

    None
}

impl<T: Read, U: Deserialize<T>> Deserialize<T> for Vec<U> {
    fn deserialize(deserializer: &mut Deserializer<T>, flags: &[Flag]) -> Result<Self, String> {
        let length = try!(deserializer.get_array_size(flags));
        let mut result = vec![];
        for _ in 0..length {
            if flags.len() > 1 {
                result.push(try!(U::deserialize(deserializer, &flags[1..])));
            } else {
                result.push(try!(U::deserialize(deserializer, &[])));
            }
        }

        Ok(result)
    }
}

impl<T: Read, U:Deserialize<T>, K: Deserialize<T>> Deserialize<T> for (U, K) {
    fn deserialize(deserializer: &mut Deserializer<T>, flag: &[Flag]) -> Result<Self, String> {
        let first  = try!(U::deserialize(deserializer, flag));
        let second = try!(K::deserialize(deserializer, flag));

        Ok((first, second))
    }
}

// TODO: figure out a way to generalize this
// probably related to https://github.com/rust-lang/rfcs/issues/1038
impl<T: Read, U: Deserialize<T> + Default + Copy> Deserialize<T> for [U; 32] {
    fn deserialize(deserializer: &mut Deserializer<T>, flags: &[Flag]) -> Result<Self, String> {
        let mut result = [U::default(); 32];
        for i in 0..32 {
            result[i] = try!(U::deserialize(deserializer, flags));
        }

        Ok(result)
    }
}

impl<T: Read> Deserialize<T> for Services {
    fn deserialize(deserializer: &mut Deserializer<T>, _: &[Flag]) -> Result<Self, String> {
        let data = try!(u64::deserialize(deserializer, &[]));
        Ok(Services::new(data == 1))
    }
}

impl<T: Read> Deserializer<T> {
    pub fn new(buffer: T) -> Deserializer<T> {
        Deserializer {
            buffer: buffer,
            pos: 0,
        }
    }

    pub fn into_inner(self) -> T { self.buffer }

    pub fn pos(&self) -> usize { self.pos }

    pub fn get_array_size(&mut self, flags: &[Flag]) -> Result<usize, String> {
        let flag = flags.get(0)
            .and_then(|f| if let &Flag::FixedSize(n) = f { Some(n) } else { None });

        Ok(match flag {
            Some(n) => n,
            None => try!(self.to_var_int_any()).1 as usize,
        })
    }

    fn read(&mut self, out: &mut [u8]) -> Result<(), String> {
        self.pos += out.len();
        self.buffer.read_exact(out).map_err(|e| format!("Error: {:?}", e))
    }

    pub fn to_i(&mut self, size: usize) -> Result<i64, String> {
        assert!(size == 1 || size == 2 || size == 4 || size == 8);

        let mut data = [0; 8];
        try!(self.read(&mut data[0..size]));

        let sign     = data[size-1] & 0x80;
        data[size-1] = data[size-1] & 0x7F;

        let unsigned = self.to_u_slice(&data[0..size]) as i64;

        if sign > 0 {
            Ok(unsigned * -1)
        } else {
            Ok(unsigned)
        }
    }

    fn to_u_slice(&self, data: &[u8]) -> u64 {
        let mut result = 0;
        let mut multiplier: u64 = 1;

        for i in 0..data.len() {
            if i != 0 { multiplier *= 0x100 };
            result += data[i] as u64 * multiplier;
        }

        result
    }

    pub fn to_u_fixed(&mut self, size: usize) -> Result<u64, String> {
        assert!(size == 1 || size == 2 || size == 4 || size == 8);

        let mut data = [0; 8];
        try!(self.read(&mut data[0..size]));

        Ok(self.to_u_slice(&data[0..size]))
    }

    pub fn to_u(&mut self, size: usize, flags: &[Flag]) -> Result<u64, String> {
        if flags.contains(&Flag::VariableSize) {
            self.to_var_int(size)
        } else {
            self.to_u_fixed(size)
        }
    }

    pub fn to_var_int_any(&mut self) -> Result<(usize, u64), String> {
        let mut data = [0; 1];
        try!(self.read(&mut data));

        if data[0] < 0xfd {
            return Ok((1, data[0] as u64));
        }

        let bytes = match data[0] {
            0xfd => 2,
            0xfe => 4,
            0xff => 8,
            _    => 0,
        };

        Ok((bytes, try!(self.to_u_fixed(bytes))))
    }

    pub fn to_var_int(&mut self, size: usize) -> Result<u64, String> {
        let (bytes, result) = try!(self.to_var_int_any());

        if size >= bytes {
            Ok(result)
        } else {
            // TODO: make this an error
            println!("Wrong size var_int: was {}, expected {}", bytes, size);
            panic!();
        }
    }

    pub fn get_be_u16(&mut self) -> Result<u16, String> {
        let mut data = [0; 2];
        try!(self.read(&mut data));

        let result = self.to_u_slice(&[data[1], data[0]]);
        Ok(result as u16)
    }

    fn to_ip(&mut self) -> Result<Ipv6Addr, String> {
        let mut data = [0; 16];
        try!(self.read(&mut data));

        let mut s = [0u16; 8];
        for i in 0..8 {
            // IPs are big-endian so we need to swap the bytes
            s[i] = self.to_u_slice(&[data[2*i + 1], data[2*i]]) as u16;
        }

        Ok(Ipv6Addr::new(s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7]))
    }

    pub fn to_short_time(&mut self) -> Result<time::Tm, String> {
        let sec = try!(self.to_u_fixed(4));
        Ok(time::at_utc(time::Timespec::new(sec as i64, 0)))
    }

    pub fn to_time(&mut self) -> Result<time::Tm, String> {
        let sec = try!(self.to_i(8));
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

    pub fn to_bool(&mut self) -> Result<bool, String> {
        let data = try!(self.to_u_fixed(1));
        Ok(data != 0)
    }

    fn to_string(&mut self, flags: &[Flag]) -> Result<String, String> {
        let length_ = extract_fixed_size(flags);

        let length = match length_ {
            Some(x) => x,
            None    => try!(self.to_var_int_any()).1 as usize,
        };

        if length > 1024 {
            return Err(format!("String is too long, length={}", length));
        }

        let mut bytes = [0; 1024];
        try!(self.read(&mut bytes[0..length]));

        let mut bytes_vector = vec![];
        bytes_vector.extend(bytes[0..length].into_iter());

        String::from_utf8(bytes_vector).map_err(|e| format!("Error: {:?}", e))
    }
}

impl<T: Read> Deserialize<T> for Command {
    fn deserialize(deserializer: &mut Deserializer<T>, _: &[Flag]) -> Result<Self, String> {
        let data = try!(String::deserialize(deserializer, &[Flag::FixedSize(12)]));
        match data.as_str() {
            "version\0\0\0\0\0"      => Ok(Command::Version),
            "verack\0\0\0\0\0\0"     => Ok(Command::Verack),
            "tx\0\0\0\0\0\0\0\0\0\0" => Ok(Command::Tx),
            "inv\0\0\0\0\0\0\0\0\0"  => Ok(Command::Inv),
            "ping\0\0\0\0\0\0\0\0"   => Ok(Command::Ping),
            "pong\0\0\0\0\0\0\0\0"   => Ok(Command::Pong),
            "getaddr\0\0\0\0\0"      => Ok(Command::GetAddr),
            "notfound\0\0\0\0"       => Ok(Command::NotFound),
            "addr\0\0\0\0\0\0\0\0"   => Ok(Command::Addr),
            "reject\0\0\0\0\0\0"     => Ok(Command::Reject),
            "getblocks\0\0\0"        => Ok(Command::GetBlocks),
            "getheaders\0\0"         => Ok(Command::GetHeaders),
            "getdata\0\0\0\0\0"      => Ok(Command::GetData),
            "headers\0\0\0\0\0"      => Ok(Command::Headers),
            "block\0\0\0\0\0\0\0"    => Ok(Command::Block),
            command                  => {
                println!("Warning: unknown command `{}`", command);
                Ok(Command::Unknown)
            },
        }
    }
}

impl Serialize for Command {
    fn serialize(&self, serializer: &mut Serializer, _: &[Flag]) {
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

        serializer.push_bytes(bytes, 12);
    }
}

impl<T: Read> Deserialize<T> for NetworkType {
    fn deserialize(deserializer: &mut Deserializer<T>, _: &[Flag]) -> Result<Self, String> {
        let data = try!(u32::deserialize(deserializer, &[]));
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
    fn serialize(&self, serializer: &mut Serializer, _: &[Flag]) {
        let magic = match self {
            &NetworkType::Main      => 0xD9B4BEF9,
            &NetworkType::TestNet   => 0xDAB5BFFA,
            &NetworkType::TestNet3  => 0x0709110B,
            &NetworkType::NameCoin  => 0xFEB4BEF9,
            // Uknown is only used internally and should
            // never be sent accross the network
            &NetworkType::Unknown   => unimplemented!(),
        };

        serializer.serialize_u(magic, 4, &[]);
    }
}

#[derive(PartialEq, Debug)]
pub struct MessageHeader {
    pub network_type: NetworkType,
    pub command: Command,
    pub length: u32,
    pub checksum: Vec<u8>,
}

impl MessageHeader {
    pub fn len(&self) -> u32 { self.length }
    pub fn magic(&self) -> &NetworkType { &self.network_type }
    pub fn command(&self) -> &Command { &self.command }
}

impl Serialize for MessageHeader {
    fn serialize(&self, serializer: &mut Serializer, _: &[Flag]) {
        self.network_type.serialize(serializer, &[]);
        self.     command.serialize(serializer, &[]);
        self.      length.serialize(serializer, &[]);
        self.    checksum.serialize(serializer, &[]);
    }
}

impl<T: Read> Deserialize<T> for MessageHeader {
    fn deserialize(deserializer: &mut Deserializer<T>, _: &[Flag]) -> Result<Self, String> {
        Ok(MessageHeader {
            network_type: try!(NetworkType::deserialize(deserializer, &[])),
            command:          try!(Command::deserialize(deserializer, &[])),
            length:               try!(u32::deserialize(deserializer, &[])),
            checksum: try!(Bytes::deserialize(deserializer, &[Flag::FixedSize(4)])),
        })
    }
}

#[derive(Debug, PartialEq)]
pub struct VersionMessage {
    pub version: i32,
    pub services: Services,
    pub timestamp: time::Tm,
    pub addr_recv: IPAddress,
    pub addr_from: IPAddress,
    pub nonce: u64,
    pub user_agent: String,
    pub start_height: i32,
    pub relay: bool,
}

impl Serialize for VersionMessage {
    fn serialize(&self, serializer: &mut Serializer, _: &[Flag]) {
        self.     version.serialize(serializer, &[]);
        self.    services.serialize(serializer, &[]);
        self.   timestamp.serialize(serializer, &[]);
        self.   addr_recv.serialize(serializer, &[]);
        self.   addr_from.serialize(serializer, &[]);
        self.       nonce.serialize(serializer, &[]);
        self.  user_agent.serialize(serializer, &[Flag::VariableSize]);
        self.start_height.serialize(serializer, &[]);

        if self.version > 70001 {
            self.relay.serialize(serializer, &[]);
        }
    }
}

impl<T: Read> Deserialize<T> for VersionMessage {
    fn deserialize(deserializer: &mut Deserializer<T>, _: &[Flag]) -> Result<Self, String> {
        let version =           try!(i32::deserialize(deserializer, &[]));
        let services =     try!(Services::deserialize(deserializer, &[]));
        let timestamp =    try!(time::Tm::deserialize(deserializer, &[]));
        let addr_recv =   try!(IPAddress::deserialize(deserializer, &[]));
        let addr_from =   try!(IPAddress::deserialize(deserializer, &[]));
        let nonce =             try!(u64::deserialize(deserializer, &[]));
        let user_agent =     try!(String::deserialize(deserializer, &[Flag::VariableSize]));
        let start_height =      try!(i32::deserialize(deserializer, &[]));

        let relay = if version > 70001 {
            try!(bool::deserialize(deserializer, &[]))
        } else {
            false
        };

        Ok(VersionMessage {
            version: version,
            services: services,
            timestamp: timestamp,
            addr_recv: addr_recv,
            addr_from: addr_from,
            nonce: nonce,
            user_agent: user_agent,
            start_height: start_height,
            relay: relay,
        })
    }
}

#[derive(Debug)]
pub struct PingMessage {
    pub nonce: u64,
}

impl Serialize for PingMessage {
    fn serialize(&self, serializer: &mut Serializer, _: &[Flag]) {
        self.nonce.serialize(serializer, &[]);
    }
}

impl<T: Read> Deserialize<T> for PingMessage {
    fn deserialize(deserializer: &mut Deserializer<T>, _: &[Flag]) -> Result<Self, String> {
        Ok(PingMessage {
            nonce: try!(u64::deserialize(deserializer, &[])),
        })
    }
}

impl PingMessage {
    pub fn nonce(&self) -> u64 { self.nonce }
    pub fn new() -> PingMessage {
        PingMessage {
            nonce: rand::random(),
        }
    }
}

#[derive(Debug)]
pub struct AddrMessage {
    pub addr_list: Vec<(time::Tm, IPAddress)>,
}

impl Serialize for AddrMessage {
    fn serialize(&self, serializer: &mut Serializer, _: &[Flag]) {
        self.addr_list.serialize(serializer, &[Flag::VariableSize, Flag::ShortFormat]);
    }
}

impl<T: Read> Deserialize<T> for AddrMessage {
    fn deserialize(deserializer: &mut Deserializer<T>, _: &[Flag]) -> Result<Self, String> {
        Ok(AddrMessage {
            addr_list: try!(AddrList::deserialize(deserializer, &[Flag::VariableSize, Flag::ShortFormat])),
        })
    }
}

impl AddrMessage {
    pub fn new(addr_list: Vec<(time::Tm, IPAddress)>) -> AddrMessage {
        AddrMessage {
            addr_list: addr_list,
        }
    }
}

#[derive(Debug)]
pub struct RejectMessage {
    message: String,
    ccode: u8,
    reason: String,
}

impl Serialize for RejectMessage {
    fn serialize(&self, serializer: &mut Serializer, _: &[Flag]) {
        self.message.serialize(serializer, &[Flag::VariableSize]);
        self  .ccode.serialize(serializer, &[]);
        self .reason.serialize(serializer, &[Flag::VariableSize]);
    }
}

impl<T: Read> Deserialize<T> for RejectMessage {
    fn deserialize(deserializer: &mut Deserializer<T>, _: &[Flag]) -> Result<Self, String> {
        Ok(RejectMessage {
            message: try!(String::deserialize(deserializer, &[Flag::VariableSize])),
            ccode:       try!(u8::deserialize(deserializer, &[])),
            reason:  try!(String::deserialize(deserializer, &[Flag::VariableSize])),
        })
    }
}

#[derive(Debug)]
pub struct BlockHeader {
    pub version: i32,
    pub prev_block: Vec<u8>,
    pub merkle_root: Vec<u8>,
    pub timestamp: time::Tm,
    pub bits: u32,
    pub nonce: u32,
    pub txn_count: u64,
}

impl Serialize for BlockHeader {
    fn serialize(&self, serializer: &mut Serializer, _: &[Flag]) {
        self.    version.serialize(serializer, &[]);
        self. prev_block.serialize(serializer, &[]);
        self.merkle_root.serialize(serializer, &[]);
        self.  timestamp.serialize(serializer, &[Flag::ShortFormat]);
        self.       bits.serialize(serializer, &[]);
        self.      nonce.serialize(serializer, &[]);
        self.  txn_count.serialize(serializer, &[Flag::VariableSize]);
    }
}

impl<T: Read> Deserialize<T> for BlockHeader {
    fn deserialize(deserializer: &mut Deserializer<T>, _: &[Flag]) -> Result<Self, String> {
        Ok(BlockHeader {
            version:        try!(i32::deserialize(deserializer, &[])),
            prev_block:   try!(Bytes::deserialize(deserializer, &[Flag::FixedSize(32)])),
            merkle_root:  try!(Bytes::deserialize(deserializer, &[Flag::FixedSize(32)])),
            timestamp: try!(time::Tm::deserialize(deserializer, &[Flag::ShortFormat])),
            bits:           try!(u32::deserialize(deserializer, &[])),
            nonce:          try!(u32::deserialize(deserializer, &[])),
            txn_count:      try!(u64::deserialize(deserializer, &[Flag::VariableSize])),
        })
    }
}

#[derive(Debug)]
pub struct HeadersMessage {
    pub headers: Vec<BlockHeader>,
}

impl HeadersMessage {
    pub fn new(headers: Vec<BlockHeader>) -> HeadersMessage {
        HeadersMessage {
            headers: headers,
        }
    }
}

impl Serialize for HeadersMessage {
    fn serialize(&self, serializer: &mut Serializer, _: &[Flag]) {
        self.headers.serialize(serializer, &[Flag::VariableSize]);
    }
}

impl<T: Read> Deserialize<T> for HeadersMessage {
    fn deserialize(deserializer: &mut Deserializer<T>, _: &[Flag]) -> Result<Self, String> {
        Ok(HeadersMessage {
            headers: try!(BlockHeaders::deserialize(deserializer, &[Flag::VariableSize])),
        })
    }
}

#[derive(Debug)]
pub struct GetHeadersMessage {
    pub version: u32,
    pub block_locators: Vec<Vec<u8>>,
    pub hash_stop: Vec<u8>,
}

impl Serialize for GetHeadersMessage {
    fn serialize(&self, serializer: &mut Serializer, _: &[Flag]) {
        self.       version.serialize(serializer, &[]);
        self.block_locators.serialize(serializer, &[Flag::VariableSize, Flag::FixedSize(32)]);
        self.     hash_stop.serialize(serializer, &[Flag::FixedSize(32)]);
    }
}

impl<T: Read> Deserialize<T> for GetHeadersMessage {
    fn deserialize(deserializer: &mut Deserializer<T>, _: &[Flag]) -> Result<Self, String> {
        Ok(GetHeadersMessage {
            version: try!(u32::deserialize(deserializer, &[])),
            block_locators: try!(BlockLocators::deserialize(deserializer, &[Flag::VariableSize,
                                                            Flag::FixedSize(32)])),
            hash_stop: try!(Bytes::deserialize(deserializer, &[Flag::FixedSize(32)])),
        })
    }
}

#[allow(non_camel_case_types)]
#[derive(Debug)]
pub enum InventoryVectorType {
    ERROR,
    MSG_TX,
    MSG_BLOCK,
    MSG_FILTERED_BLOCK,
}

impl Serialize for InventoryVectorType {
    fn serialize(&self, serializer: &mut Serializer, _: &[Flag]) {
        let index: u32 = match self {
            &InventoryVectorType::ERROR              => 0,
            &InventoryVectorType::MSG_TX             => 1,
            &InventoryVectorType::MSG_BLOCK          => 2,
            &InventoryVectorType::MSG_FILTERED_BLOCK => 3,
        };

        index.serialize(serializer, &[]);
    }
}

impl<T: Read> Deserialize<T> for InventoryVectorType {
    fn deserialize(deserializer: &mut Deserializer<T>, _: &[Flag]) -> Result<Self, String> {
        let index = try!(u32::deserialize(deserializer, &[]));

        match index {
            0 => Ok(InventoryVectorType::ERROR),
            1 => Ok(InventoryVectorType::MSG_TX),
            2 => Ok(InventoryVectorType::MSG_BLOCK),
            3 => Ok(InventoryVectorType::MSG_FILTERED_BLOCK),
            vector_type => Err(format!("Unexpected inventory vector type = {}", vector_type)),
        }
    }
}

#[derive(Debug)]
pub struct InventoryVector {
    pub type_: InventoryVectorType,
    pub hash: [u8; 32],
}

impl Serialize for InventoryVector {
    fn serialize(&self, serializer: &mut Serializer, _: &[Flag]) {
        self.type_.serialize(serializer, &[]);
        self.hash .serialize(serializer, &[]);
    }
}

impl<T: Read> Deserialize<T> for InventoryVector {
    fn deserialize(deserializer: &mut Deserializer<T>, _: &[Flag]) -> Result<Self, String> {
        Ok(InventoryVector {
            type_: try!(Deserialize::deserialize(deserializer, &[])),
            hash:  try!(Deserialize::deserialize(deserializer, &[])),
        })
    }
}

impl InventoryVector {
    pub fn new(type_: InventoryVectorType, hash: [u8; 32]) -> InventoryVector {
        InventoryVector {
            type_: type_,
            hash: hash,
        }
    }
}

type Inventory = Vec<InventoryVector>;

#[derive(Debug)]
pub struct InvMessage {
    pub inventory: Vec<InventoryVector>,
}

impl Serialize for InvMessage {
    fn serialize(&self, serializer: &mut Serializer, _: &[Flag]) {
        self.inventory.serialize(serializer, &[Flag::VariableSize]);
    }
}

impl<T: Read> Deserialize<T> for InvMessage {
    fn deserialize(deserializer: &mut Deserializer<T>, _: &[Flag]) -> Result<Self, String> {
        Ok(InvMessage {
            inventory: try!(Inventory::deserialize(deserializer, &[Flag::VariableSize])),
        })
    }
}

impl InvMessage {
    pub fn new(inventory: Vec<InventoryVector>) -> InvMessage {
        InvMessage {
            inventory: inventory,
        }
    }
}

#[derive(Debug)]
pub struct OutPoint {
    hash: [u8; 32],
    index: u32,
}

impl Serialize for OutPoint {
    fn serialize(&self, serializer: &mut Serializer, _: &[Flag]) {
        self.hash .serialize(serializer, &[]);
        self.index.serialize(serializer, &[]);
    }
}

impl<T: Read> Deserialize<T> for OutPoint {
    fn deserialize(deserializer: &mut Deserializer<T>, _: &[Flag]) -> Result<Self, String> {
        Ok(OutPoint {
            hash:  try!(Hash::deserialize(deserializer, &[])),
            index: try!( u32::deserialize(deserializer, &[])),
        })
    }
}

#[derive(Debug)]
pub struct TxIn {
    previous_output: OutPoint,
    script: Vec<u8>,
    sequence: u32,
}

impl Serialize for TxIn {
    fn serialize(&self, serializer: &mut Serializer, _: &[Flag]) {
        self.previous_output.serialize(serializer, &[]);
        self.script         .serialize(serializer, &[Flag::VariableSize]);
        self.sequence       .serialize(serializer, &[]);
    }
}

impl<T: Read> Deserialize<T> for TxIn {
    fn deserialize(deserializer: &mut Deserializer<T>, _: &[Flag]) -> Result<Self, String> {
        Ok(TxIn {
            previous_output: try!(Deserialize::deserialize(deserializer, &[])),
            script:          try!(Deserialize::deserialize(deserializer, &[Flag::VariableSize])),
            sequence:        try!(Deserialize::deserialize(deserializer, &[])),
        })
    }
}

#[derive(Debug)]
pub struct TxOut {
    value: i64,
    pk_script: Vec<u8>,
}

impl Serialize for TxOut {
    fn serialize(&self, serializer: &mut Serializer, _: &[Flag]) {
        self.value    .serialize(serializer, &[]);
        self.pk_script.serialize(serializer, &[Flag::VariableSize]);
    }
}

impl<T: Read> Deserialize<T> for TxOut {
    fn deserialize(deserializer: &mut Deserializer<T>, _: &[Flag]) -> Result<Self, String> {
        Ok(TxOut {
            value:     try!(Deserialize::deserialize(deserializer, &[])),
            pk_script: try!(Deserialize::deserialize(deserializer, &[Flag::VariableSize])),
        })
    }
}

#[derive(Debug)]
pub struct TxMessage {
    version: u32,
    tx_in: Vec<TxIn>,
    tx_out: Vec<TxOut>,
    lock_time: u32,
}

impl Serialize for TxMessage {
    fn serialize(&self, serializer: &mut Serializer, _: &[Flag]) {
        self.version  .serialize(serializer, &[]);
        self.tx_in    .serialize(serializer, &[Flag::VariableSize]);
        self.tx_out   .serialize(serializer, &[Flag::VariableSize]);
        self.lock_time.serialize(serializer, &[]);
    }
}

impl<T: Read> Deserialize<T> for TxMessage {
    fn deserialize(deserializer: &mut Deserializer<T>, _: &[Flag]) -> Result<Self, String> {
        Ok(TxMessage {
            version:   try!(Deserialize::deserialize(deserializer, &[])),
            tx_in:     try!(Deserialize::deserialize(deserializer, &[Flag::VariableSize])),
            tx_out:    try!(Deserialize::deserialize(deserializer, &[Flag::VariableSize])),
            lock_time: try!(Deserialize::deserialize(deserializer, &[])),
        })
    }
}

#[derive(Debug)]
pub struct BlockMetadata {
    version: i32,
    prev_block: [u8; 32],
    merkle_root: [u8; 32],
    timestamp: time::Tm,
    bits: u32,
    nonce: u32,
}

impl Serialize for BlockMetadata {
    fn serialize(&self, serializer: &mut Serializer, _: &[Flag]) {
        self.version    .serialize(serializer, &[]);
        self.prev_block .serialize(serializer, &[]);
        self.merkle_root.serialize(serializer, &[]);
        self.timestamp  .serialize(serializer, &[Flag::ShortFormat]);
        self.bits       .serialize(serializer, &[]);
        self.nonce      .serialize(serializer, &[]);
    }
}

impl<T: Read> Deserialize<T> for BlockMetadata {
    fn deserialize(deserializer: &mut Deserializer<T>, _: &[Flag]) -> Result<Self, String> {
        Ok(BlockMetadata {
            version:     try!(Deserialize::deserialize(deserializer, &[])),
            prev_block:  try!(Deserialize::deserialize(deserializer, &[])),
            merkle_root: try!(Deserialize::deserialize(deserializer, &[])),
            timestamp:   try!(Deserialize::deserialize(deserializer, &[Flag::ShortFormat])),
            bits:        try!(Deserialize::deserialize(deserializer, &[])),
            nonce:       try!(Deserialize::deserialize(deserializer, &[])),
        })
    }
}

#[derive(Debug)]
pub struct BlockMessage {
    metadata: BlockMetadata,
    txns: Vec<TxMessage>,
}

impl Serialize for BlockMessage {
    fn serialize(&self, serializer: &mut Serializer, _: &[Flag]) {
        self.metadata.serialize(serializer, &[]);
        self.txns    .serialize(serializer, &[Flag::VariableSize]);
    }

    fn serialize_hash(&self) -> (Vec<u8>, [u8; 32]) {
        let (serialized, hash) = self.metadata.serialize_hash();
        let mut buffer = Cursor::new(serialized);
        buffer.seek(SeekFrom::End(0)).unwrap();
        self.txns.serialize(&mut buffer, &[Flag::VariableSize]);

        println!("Hash = {:?}", hash);

        (buffer.into_inner(), hash)
    }
}

impl<T: Read> Deserialize<T> for BlockMessage {
    fn deserialize(deserializer: &mut Deserializer<T>, _: &[Flag]) -> Result<Self, String> {
        Ok(BlockMessage {
            metadata: try!(Deserialize::deserialize(deserializer, &[])),
            txns:     try!(Deserialize::deserialize(deserializer, &[Flag::VariableSize])),
        })
    }
}

pub fn get_serialized_message(network_type: NetworkType,
                              command: Command,
                              message: Option<Box<Serialize>>) -> Vec<u8> {
    let mut buffer = Cursor::new(vec![]);
    message.map(|m| m.serialize(&mut buffer, &[]));

    let checksum = CryptoUtils::sha256(&CryptoUtils::sha256(buffer.get_ref()));

    let header = MessageHeader {
        network_type: network_type,
        command: command,
        length: buffer.get_ref().len() as u32,
        checksum: checksum[0..4].to_vec(),
    };

    let mut header_buffer = Cursor::new(vec![]);
    header.serialize(&mut header_buffer, &[]);

    let mut result = header_buffer.into_inner();
    result.extend(buffer.into_inner());

    result
}
