use super::IPAddress;
use super::Services;
use utils::CryptoUtils;

use std::io::Cursor;
use std::io::Read;
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
    Ping,
    Pong,
    Reject,
    GetHeaders,
    Unknown,
}

#[derive(PartialEq, Copy, Clone)]
pub enum Flag {
    // applicable to i16 for now
    BigEndian,
    // applicable to unsigned types, strings, arrays
    VariableSize,
    FixedSize(usize),
    // applicable to time::Tm
    ShortFormat,
    NoFlag,
}

pub trait Serialize {
    fn serialize(&self, serializer: &mut Serializer, flag: Flag);
}

pub struct Serializer {
    buffer: Vec<u8>,
}

impl Serializer {
    pub fn new() -> Serializer {
        Serializer {
            buffer: vec![],
        }
    }

    pub fn inner(&self) -> &Vec<u8> {
        &self.buffer
    }

    pub fn into_inner(self) -> Vec<u8> {
        self.buffer
    }

    pub fn push(&mut self, byte: u8) {
        self.buffer.push(byte);
    }

    pub fn push_bytes(&mut self, data: &[u8], bytes: usize) {
        for i in 0..bytes {
            self.buffer.push(data[i]);
        }
    }

    pub fn u_to_fixed(&mut self, x: u64, bytes: usize) {
        let data = self.to_bytes(x);
        self.push_bytes(&data, bytes);
    }

    pub fn serialize_u(&mut self, x: u64, bytes: usize, flag: Flag) {
        if flag == Flag::VariableSize {
            self.var_int(x);
        } else {
            self.u_to_fixed(x, bytes);
        }
    }

    pub fn var_int(&mut self, x: u64) {
        let data = self.to_bytes(x);

        match x {
            0x00000...0x0000000fd => {
                self.buffer.push(data[0])
            },
            0x000fd...0x000010000 => {
                self.buffer.push(0xfd);
                self.push_bytes(&data, 2);
            },
            0x10000...0x100000000 => {
                self.buffer.push(0xfe);
                self.push_bytes(&data, 4);
            },
            _ => {
                self.buffer.push(0xff);
                self.push_bytes(&data, 8);
            },
        };
    }

    pub fn to_bytes(&self, u: u64) -> [u8; 8] {
        [((u & 0x00000000000000ff) / 0x1)               as u8,
         ((u & 0x000000000000ff00) / 0x100)             as u8,
         ((u & 0x0000000000ff0000) / 0x10000)           as u8,
         ((u & 0x00000000ff000000) / 0x1000000)         as u8,
         ((u & 0x000000ff00000000) / 0x100000000)       as u8,
         ((u & 0x0000ff0000000000) / 0x10000000000)     as u8,
         ((u & 0x00ff000000000000) / 0x1000000000000)   as u8,
         ((u & 0xff00000000000000) / 0x100000000000000) as u8]
    }

    pub fn i_to_fixed(&mut self, x: i64, bytes: usize) {
        let u: u64 = x.abs() as u64;
        let mut data: [u8; 8] = self.to_bytes(u);
        let sign = if u == x as u64 { 0x00 } else { 0x80 };

        data[bytes-1] = data[bytes-1] | sign;

        for i in 0..bytes {
            self.buffer.push(data[i]);
        }
    }
}

impl Serialize for bool {
    fn serialize(&self, serializer: &mut Serializer, _: Flag) {
        serializer.push(if *self { 1 } else { 0 });
    }
}

impl Serialize for i16 {
    fn serialize(&self, serializer: &mut Serializer, _: Flag) {
        serializer.i_to_fixed(*self as i64, 2);
    }
}

impl Serialize for i32 {
    fn serialize(&self, serializer: &mut Serializer, _: Flag) {
        serializer.i_to_fixed(*self as i64, 4);
    }
}

impl Serialize for u8 {
    fn serialize(&self, serializer: &mut Serializer, _: Flag) {
        serializer.push(*self);
    }
}

impl Serialize for u16 {
    fn serialize(&self, serializer: &mut Serializer, flag: Flag) {
        if flag == Flag::BigEndian {
            let data = serializer.to_bytes(*self as u64);
            serializer.push(data[1]);
            serializer.push(data[0]);
        } else {
            serializer.u_to_fixed(*self as u64, 2);
        }
    }
}

impl Serialize for u32 {
    fn serialize(&self, serializer: &mut Serializer, flag: Flag) {
        serializer.serialize_u(*self as u64, 4, flag);
    }
}

impl Serialize for u64 {
    fn serialize(&self, serializer: &mut Serializer, flag: Flag) {
        serializer.serialize_u(*self, 8, flag);
    }
}

impl Serialize for Ipv6Addr {
    fn serialize(&self, serializer: &mut Serializer, _: Flag) {
        for x in self.segments().iter() {
            let bytes = serializer.to_bytes(*x as u64);
            // Ip are encoded with big-endian integers
            serializer.push(bytes[1]);
            serializer.push(bytes[0]);
        }
    }
}

impl Serialize for time::Tm {
    fn serialize(&self, serializer: &mut Serializer, flag: Flag) {
        if flag == Flag::ShortFormat {
            serializer.serialize_u(self.to_timespec().sec as u64, 4, Flag::NoFlag);
        } else {
            serializer.i_to_fixed(self.to_timespec().sec, 8);
        }
    }
}

impl Serialize for String {
    fn serialize(&self, serializer: &mut Serializer, flag: Flag) {
        let length = self.as_bytes().len();

        if flag == Flag::VariableSize {
            serializer.var_int(length as u64);
        }

        serializer.push_bytes(&self.as_bytes(), length);
    }
}

impl<T: Serialize> Serialize for Vec<T> {
    fn serialize(&self, serializer: &mut Serializer, flag: Flag) {
        let length = self.len();

        if flag == Flag::VariableSize {
            serializer.var_int(length as u64);
        }

        for x in self {
            x.serialize(serializer, Flag::NoFlag);
        }
    }
}

impl Serialize for Services {
    fn serialize(&self, serializer: &mut Serializer, _: Flag) {
        let data = if self.node_network { 1 } else { 0 };
        serializer.serialize_u(data, 8, Flag::NoFlag);
    }
}

impl Deserialize for IPAddress {
    fn deserialize(deserializer: &mut Deserializer, _:Flag) -> Result<Self, String> {
        Ok(IPAddress::new(
            try!(Services::deserialize(deserializer, Flag::NoFlag)),
            try!(Ipv6Addr::deserialize(deserializer, Flag::NoFlag)),
                 try!(u16::deserialize(deserializer, Flag::BigEndian)),
        ))
    }
}

impl Serialize for IPAddress {
    fn serialize(&self, serializer: &mut Serializer, _: Flag) {
        self.services.serialize(serializer, Flag::NoFlag);
        self. address.serialize(serializer, Flag::NoFlag);
        self.    port.serialize(serializer, Flag::BigEndian);
    }
}

impl <T: Serialize, V: Serialize> Serialize for (T,V) {
    fn serialize(&self, serializer: &mut Serializer, flag: Flag) {
        self.0.serialize(serializer, flag);
        self.1.serialize(serializer, flag);
    }
}

impl <T: Serialize> Serialize for [T] {
    fn serialize(&self, serializer: &mut Serializer, flag: Flag) {
        for x in self {
            x.serialize(serializer, flag);
        }
    }
}

pub trait Deserialize: Sized {
    fn deserialize(deserializer: &mut Deserializer, flag: Flag) -> Result<Self, String>;
}

#[derive(Debug)]
pub struct Deserializer<'a> {
    buffer: Cursor<&'a [u8]>,
}

impl Deserialize for i32 {
    fn deserialize(deserializer: &mut Deserializer, _: Flag) -> Result<Self, String> {
        deserializer.to_i(4).map(|r| r as i32)
    }
}

impl Deserialize for i64 {
    fn deserialize(deserializer: &mut Deserializer, _: Flag) -> Result<Self, String> {
        deserializer.to_i(8)
    }
}

impl Deserialize for u8 {
    fn deserialize(deserializer: &mut Deserializer, _: Flag) -> Result<Self, String> {
        deserializer.to_u(1, Flag::NoFlag).map(|r| r as u8)
    }
}

impl Deserialize for u16 {
    fn deserialize(deserializer: &mut Deserializer, flag: Flag) -> Result<Self, String> {
        if flag == Flag::BigEndian {
            deserializer.get_be_u16()
        } else {
            deserializer.to_u(2, flag).map(|r| r as u16)
        }
    }
}

impl Deserialize for u32 {
    fn deserialize(deserializer: &mut Deserializer, flag: Flag) -> Result<Self, String> {
        deserializer.to_u(4, flag).map(|r| r as u32)
    }
}

impl Deserialize for u64 {
    fn deserialize(deserializer: &mut Deserializer, flag: Flag) -> Result<Self, String> {
        deserializer.to_u(8, flag).map(|r| r as u64)
    }
}

impl Deserialize for Ipv6Addr {
    fn deserialize(deserializer: &mut Deserializer, _: Flag) -> Result<Self, String> {
        deserializer.to_ip()
    }
}

impl Deserialize for time::Tm {
    fn deserialize(deserializer: &mut Deserializer, flag: Flag) -> Result<Self, String> {
        if flag == Flag::ShortFormat {
            deserializer.to_short_time()
        } else {
            deserializer.to_time()
        }
    }
}

impl Deserialize for bool {
    fn deserialize(deserializer: &mut Deserializer, _: Flag) -> Result<Self, String> {
        deserializer.to_bool()
    }
}

impl Deserialize for String {
    fn deserialize(deserializer: &mut Deserializer, flag: Flag) -> Result<Self, String> {
        deserializer.to_string(flag)
    }
}

impl<T: Deserialize> Deserialize for Vec<T> {
    fn deserialize(deserializer: &mut Deserializer, flag: Flag) -> Result<Self, String> {
        let length = match flag {
            Flag::FixedSize(n) => n,
            _                  => try!(deserializer.to_var_int_any()).1 as usize,
        };

        let mut result = vec![];
        for _ in 0..length {
            result.push(try!(T::deserialize(deserializer, Flag::NoFlag)));
        }

        Ok(result)
    }
}

impl<T:Deserialize, U: Deserialize> Deserialize for (T, U) {
    fn deserialize(deserializer: &mut Deserializer, flag: Flag) -> Result<Self, String> {
        let first  = try!(T::deserialize(deserializer, flag));
        let second = try!(U::deserialize(deserializer, flag));

        Ok((first, second))
    }
}


impl Deserialize for Services {
    fn deserialize(deserializer: &mut Deserializer, _:Flag) -> Result<Self, String> {
        let data = try!(u64::deserialize(deserializer, Flag::NoFlag));
        Ok(Services::new(data == 1))
    }
}

impl<'a> Deserializer<'a> {
    pub fn into_inner(self) -> &'a [u8] {
        self.buffer.into_inner()
    }

    pub fn new(buffer: &[u8]) -> Deserializer {
        Deserializer {
            buffer: Cursor::new(buffer),
        }
    }

    fn read(&mut self, out: &mut [u8]) -> Result<(), String> {
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

    pub fn to_u(&mut self, size: usize, flag: Flag) -> Result<u64, String> {
        if flag == Flag::VariableSize {
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

        if size == bytes {
            Ok(result)
        } else {
            Err(format!("Wrong size var_int: was {}, expected {}", bytes, size))
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
            Err(format!("Invalid time sec={}", sec))
        } else {
            Ok(time::at_utc(time::Timespec::new(sec, 0)))
        }
    }

    pub fn to_bool(&mut self) -> Result<bool, String> {
        let data = try!(self.to_u_fixed(1));
        Ok(data != 0)
    }

    fn to_string(&mut self, flag: Flag) -> Result<String, String> {
        let length = match flag {
            Flag::FixedSize(n) => n,
            _                  => try!(self.to_var_int_any()).1 as usize,
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

impl Deserialize for Command {
    fn deserialize(deserializer: &mut Deserializer, _: Flag) -> Result<Self, String> {
        let data = try!(String::deserialize(deserializer, Flag::FixedSize(12)));
        match data.as_str() {
            "version\0\0\0\0\0"    => Ok(Command::Version),
            "verack\0\0\0\0\0\0"   => Ok(Command::Verack),
            "ping\0\0\0\0\0\0\0\0" => Ok(Command::Ping),
            "pong\0\0\0\0\0\0\0\0" => Ok(Command::Pong),
            "getaddr\0\0\0\0\0"    => Ok(Command::GetAddr),
            "addr\0\0\0\0\0\0\0\0" => Ok(Command::Addr),
            "reject\0\0\0\0\0\0"   => Ok(Command::Reject),
            "getheaders\0\0"       => Ok(Command::GetHeaders),
            _                      => Err(format!("Unknown command: {}", data)),
        }
    }
}

impl Serialize for Command {
    fn serialize(&self, serializer: &mut Serializer, _: Flag) {
        let bytes = match self {
            &Command::Addr        => b"addr\0\0\0\0\0\0\0\0",
            &Command::GetAddr     => b"getaddr\0\0\0\0\0",
            &Command::Version     => b"version\0\0\0\0\0",
            &Command::Verack      => b"verack\0\0\0\0\0\0",
            &Command::Ping        => b"ping\0\0\0\0\0\0\0\0",
            &Command::Pong        => b"pong\0\0\0\0\0\0\0\0",
            &Command::Reject      => b"reject\0\0\0\0\0\0",
            &Command::GetHeaders  => b"getheaders\0\0",
            &Command::Unknown     => unimplemented!(),
        };

        serializer.push_bytes(bytes, 12);
    }
}

impl Deserialize for NetworkType {
    fn deserialize(deserializer: &mut Deserializer, _: Flag) -> Result<Self, String> {
        let data = try!(u32::deserialize(deserializer, Flag::NoFlag));
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
    fn serialize(&self, serializer: &mut Serializer, _: Flag) {
        let magic = match self {
            &NetworkType::Main      => 0xD9B4BEF9,
            &NetworkType::TestNet   => 0xDAB5BFFA,
            &NetworkType::TestNet3  => 0x0709110B,
            &NetworkType::NameCoin  => 0xFEB4BEF9,
            // Uknown is only used internally and should
            // never be sent accross the network
            &NetworkType::Unknown   => unimplemented!(),
        };

        serializer.serialize_u(magic, 4, Flag::NoFlag);
    }
}

#[derive(PartialEq, Debug)]
pub struct MessageHeader {
    network_type: NetworkType,
    command: Command,
    length: u32,
    checksum: Vec<u8>,
}

impl MessageHeader {
    pub fn len(&self) -> u32 { self.length }
    pub fn magic(&self) -> &NetworkType { &self.network_type }
    pub fn command(&self) -> &Command { &self.command }
}

impl Serialize for MessageHeader {
    fn serialize(&self, serializer: &mut Serializer, _: Flag) {
        self.network_type.serialize(serializer, Flag::NoFlag);
        self.     command.serialize(serializer, Flag::NoFlag);
        self.      length.serialize(serializer, Flag::NoFlag);
        self.    checksum.serialize(serializer, Flag::NoFlag);
    }
}

impl Deserialize for MessageHeader {
    fn deserialize(deserializer: &mut Deserializer, _: Flag) -> Result<Self, String> {
        Ok(MessageHeader {
            network_type: try!(NetworkType::deserialize(deserializer, Flag::NoFlag)),
            command:          try!(Command::deserialize(deserializer, Flag::NoFlag)),
            length:               try!(u32::deserialize(deserializer, Flag::NoFlag)),
            checksum: try!(<Vec<u8> as Deserialize>::deserialize(deserializer, Flag::FixedSize(4))),
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
    fn serialize(&self, serializer: &mut Serializer, _: Flag) {
        self.     version.serialize(serializer, Flag::NoFlag);
        self.    services.serialize(serializer, Flag::NoFlag);
        self.   timestamp.serialize(serializer, Flag::NoFlag);
        self.   addr_recv.serialize(serializer, Flag::NoFlag);
        self.   addr_from.serialize(serializer, Flag::NoFlag);
        self.       nonce.serialize(serializer, Flag::NoFlag);
        self.  user_agent.serialize(serializer, Flag::VariableSize);
        self.start_height.serialize(serializer, Flag::NoFlag);
        self.       relay.serialize(serializer, Flag::NoFlag);
    }
}

impl Deserialize for VersionMessage {
    fn deserialize(deserializer: &mut Deserializer, _: Flag) -> Result<Self, String> {
        Ok(VersionMessage {
            version:            try!(i32::deserialize(deserializer, Flag::NoFlag)),
            services:      try!(Services::deserialize(deserializer, Flag::NoFlag)),
            timestamp:     try!(time::Tm::deserialize(deserializer, Flag::NoFlag)),
            addr_recv:    try!(IPAddress::deserialize(deserializer, Flag::NoFlag)),
            addr_from:    try!(IPAddress::deserialize(deserializer, Flag::NoFlag)),
            nonce:              try!(u64::deserialize(deserializer, Flag::NoFlag)),
            user_agent:      try!(String::deserialize(deserializer, Flag::VariableSize)),
            start_height:       try!(i32::deserialize(deserializer, Flag::NoFlag)),
            relay:             try!(bool::deserialize(deserializer, Flag::NoFlag)),
        })
    }
}

#[derive(Debug)]
pub struct PingMessage {
    nonce: u64,
}

impl Serialize for PingMessage {
    fn serialize(&self, serializer: &mut Serializer, _: Flag) {
        self.nonce.serialize(serializer, Flag::NoFlag);
    }
}

impl Deserialize for PingMessage {
    fn deserialize(deserializer: &mut Deserializer, _: Flag) -> Result<Self, String> {
        Ok(PingMessage {
            nonce: try!(u64::deserialize(deserializer, Flag::NoFlag)),
        })
    }
}

impl PingMessage {
    pub fn nonce(&self) -> u64 { self.nonce }
}

pub struct AddrMessage {
    pub addr_list: Vec<(time::Tm, IPAddress)>,
}

type AddrList = Vec<(time::Tm, IPAddress)>;

impl Deserialize for AddrMessage {
    fn deserialize(deserializer: &mut Deserializer, _: Flag) -> Result<Self, String> {
        Ok(AddrMessage {
            addr_list: try!(AddrList::deserialize(deserializer, Flag::ShortFormat)),
        })
    }
}

impl Serialize for AddrMessage {
    fn serialize(&self, serializer: &mut Serializer, _: Flag) {
        self.addr_list.serialize(serializer, Flag::ShortFormat);
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
    fn serialize(&self, serializer: &mut Serializer, _: Flag) {
        self.message.serialize(serializer, Flag::VariableSize);
        self  .ccode.serialize(serializer, Flag::NoFlag);
        self .reason.serialize(serializer, Flag::VariableSize);
    }
}

impl Deserialize for RejectMessage {
    fn deserialize(deserializer: &mut Deserializer, _: Flag) -> Result<Self, String> {
        Ok(RejectMessage {
            message: try!(String::deserialize(deserializer, Flag::VariableSize)),
            ccode:       try!(u8::deserialize(deserializer, Flag::NoFlag)),
            reason:  try!(String::deserialize(deserializer, Flag::VariableSize)),
        })
    }
}

pub fn get_serialized_message(network_type: NetworkType,
                              command: Command,
                              message: Option<Box<Serialize>>) -> Vec<u8> {
    let mut serializer = Serializer::new();
    message.map(|m| m.serialize(&mut serializer, Flag::NoFlag));

    let checksum = CryptoUtils::sha256(&CryptoUtils::sha256(serializer.inner()));

    let header = MessageHeader {
        network_type: network_type,
        command: command,
        length: serializer.inner().len() as u32,
        checksum: checksum[28..32].to_vec(),
    };

    let mut header_serializer = Serializer::new();
    header.serialize(&mut header_serializer, Flag::NoFlag);

    let mut result = header_serializer.into_inner();
    result.extend(serializer.into_inner());

    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::*;
    use utils::Debug;

    #[test]
    fn test() {
        let buffer =
            vec![// version
                 0x62, 0xEA, 0x00, 0x00,
                 // services
                 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                 // timestamp
                 0x11, 0xB2, 0xD0, 0x50, 0x00, 0x00, 0x00, 0x00,
                 // addr_recv
                 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF,
                 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                 // addr_from
                 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF,
                 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                 // nonce
                 0x3B, 0x2E, 0xB3, 0x5D, 0x8C, 0xE6, 0x17, 0x65,
                 // user-agent string
                 0x0F, 0x2F, 0x53, 0x61, 0x74, 0x6F, 0x73, 0x68, 0x69, 0x3A,
                 0x30, 0x2E, 0x37, 0x2E, 0x32, 0x2F,
                 // last block id
                 0xC0, 0x3E, 0x03, 0x00,
                 // relay
                 0x01];

        let mut deserializer = Deserializer::new(&buffer[..]);
        let message = VersionMessage::deserialize(&mut deserializer, Flag::NoFlag).unwrap();

        assert_eq!(message.version, 60002);
        assert_eq!(message.services, Services::new(true));
        assert_eq!(message.user_agent, "/Satoshi:0.7.2/");
        assert_eq!(message.start_height, 212672);
        assert_eq!(message.relay, true);

        let mut serializer = Serializer::new();
        message.serialize(&mut serializer, Flag::NoFlag);

        let result = serializer.into_inner();
        Debug::print_bytes(&result);

        assert_eq!(result, buffer);
    }
}
