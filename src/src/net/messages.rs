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

#[derive(Debug)]
pub enum BasicType {
    Bool,
    FixedU8,
    FixedU16,
    // Big endian to use with IPs
    FixedBEU16,
    FixedU32,
    FixedU64,
    FixedI32,
    FixedI64,
    // size less than 256
    Bytes(usize),
    Ip,
    Time,
    ShortTime,
    VarString,
    VarInt,
}

#[derive(Debug, Clone)]
pub enum Data {
    Bool(bool),
    Unsigned(u64),
    Signed(i64),
    Bytes(Vec<u8>),
    Ip(Ipv6Addr),
    Time(time::Tm),
    VarString(String),
}

#[derive(PartialEq, Copy, Clone)]
pub enum Flag {
    // applicable to i16 for now
    BigEndian,
    // applicable to unsigned types
    VariableSize,
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

impl Data {
    pub fn deserialize(basic_type: &BasicType, buffer: &mut Cursor<Vec<u8>>) -> Result<Data, String> {
        match basic_type {
            &BasicType::Bool        => Data::get_bool(buffer),
            &BasicType::FixedU8     => Data::get_u8(buffer),
            &BasicType::FixedU16    => Data::get_u16(buffer),
            &BasicType::FixedBEU16  => Data::get_be_u16(buffer),
            &BasicType::FixedU32    => Data::get_u32(buffer),
            &BasicType::FixedU64    => Data::get_u64(buffer),
            &BasicType::FixedI32    => Data::get_i32(buffer),
            &BasicType::FixedI64    => Data::get_i64(buffer),
            &BasicType::Bytes(size) => Data::get_bytes(size, buffer),
            &BasicType::Ip          => Data::get_ip(buffer),
            &BasicType::Time        => Data::get_time(buffer),
            &BasicType::ShortTime   => Data::get_short_time(buffer),
            &BasicType::VarString   => Data::get_var_string(buffer),
            &BasicType::VarInt      => Data::get_var_int(buffer),
        }
    }

    fn read(buffer: &mut Cursor<Vec<u8>>, out: &mut [u8]) -> Result<(), String> {
        buffer.read_exact(out).map_err(|e| format!("Error: {:?}", e))
    }

    fn get_bytes(size: usize, buffer: &mut Cursor<Vec<u8>>) -> Result<Data, String> {
        assert!(size < 256);

        let mut buff = [0; 256];
        try!(Data::read(buffer, &mut buff[0..size]));

        let mut result = vec![];
        result.extend(buff[0..size].into_iter());

        Ok(Data::Bytes(result))
    }

    fn to_u_slice(data: &[u8]) -> u64 {
        let mut result = 0;
        let mut multiplier: u64 = 1;

        for i in 0..data.len() {
            if i != 0 { multiplier *= 0x100 };
            result += data[i] as u64 * multiplier;
        }

        result
    }

    fn to_u(buffer: &mut Cursor<Vec<u8>>, size: usize) -> Result<u64, String> {
        assert!(size == 1 || size == 2 || size == 4 || size == 8);

        let mut data = [0; 8];
        try!(Data::read(buffer, &mut data[0..size]));

        Ok(Data::to_u_slice(&data[0..size]))
    }

    fn get_ip(buffer: &mut Cursor<Vec<u8>>) -> Result<Data, String> {
        let mut data = [0; 16];
        try!(Data::read(buffer, &mut data));

        let mut s = [0u16; 8];
        for i in 0..8 {
            // IPs are big-endian so we need to swap the bytes
            s[i] = Data::to_u_slice(&[data[2*i + 1], data[2*i]]) as u16;
        }

        let ip = Ipv6Addr::new(s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7]);

        Ok(Data::Ip(ip))
    }

    fn to_var_int(buffer: &mut Cursor<Vec<u8>>) -> Result<u64, String> {
        let mut data = [0; 1];
        try!(Data::read(buffer, &mut data));

        if data[0] < 0xfd {
            return Ok(data[0] as u64);
        }

        let bytes = match data[0] {
            0xfd => 2,
            0xfe => 4,
            0xff => 8,
            _ => unreachable!(),
        };

        Data::to_u(buffer, bytes)
    }


    fn get_be_u16(buffer: &mut Cursor<Vec<u8>>) -> Result<Data, String> {
        let mut data = [0; 2];
        try!(Data::read(buffer, &mut data));

        let result = Data::to_u_slice(&[data[1], data[0]]);
        Ok(Data::Unsigned(result))
    }

    fn get_var_int(buffer: &mut Cursor<Vec<u8>>) -> Result<Data, String> {
        let data = try!(Data::to_var_int(buffer));
        Ok(Data::Unsigned(data))
    }

    fn to_var_string(buffer: &mut Cursor<Vec<u8>>) -> Result<String, String> {
        let length = try!(Data::to_var_int(buffer)) as usize;
        if length > 1024 {
            return Err(format!("String is too long, length={}", length));
        }

        let mut bytes = [0; 1024];
        try!(Data::read(buffer, &mut bytes[0..length]));

        let mut bytes_vector = vec![];
        bytes_vector.extend(bytes[0..length].into_iter());

        String::from_utf8(bytes_vector).map_err(|e| format!("Error: {:?}", e))
    }

    fn get_var_string(buffer: &mut Cursor<Vec<u8>>) -> Result<Data, String> {
        let data = try!(Data::to_var_string(buffer));
        Ok(Data::VarString(data))
    }

    fn get_short_time(buffer: &mut Cursor<Vec<u8>>) -> Result<Data, String> {
        let sec = try!(Data::to_u(buffer, 4));
        Ok(Data::Time(time::at_utc(time::Timespec::new(sec as i64, 0))))
    }

    fn get_time(buffer: &mut Cursor<Vec<u8>>) -> Result<Data, String> {
        let sec = try!(Data::to_i(buffer, 8));
        // Somewhere around 2033 this will break
        // unfortunately time::Tm crashes with an invalid time :-(
        // so we need to do some validation.
        // TODO: switch to a better library
        if sec < 0 || sec > 2000000000 {
            Err(format!("Invalid time sec={}", sec))
        } else {
            Ok(Data::Time(time::at_utc(time::Timespec::new(sec, 0))))
        }
    }

    fn to_i(buffer: &mut Cursor<Vec<u8>>, size: usize) -> Result<i64, String> {
        assert!(size == 1 || size == 2 || size == 4 || size == 8);

        let mut data = [0; 8];
        try!(Data::read(buffer, &mut data[0..size]));

        let sign     = data[size-1] & 0x80;
        data[size-1] = data[size-1] & 0x7F;

        let unsigned = Data::to_u_slice(&data[0..size]) as i64;

        if sign > 0 {
            Ok(unsigned * -1)
        } else {
            Ok(unsigned)
        }
    }

    fn get_i64(buffer: &mut Cursor<Vec<u8>>) -> Result<Data, String> {
        let data = try!(Data::to_i(buffer, 8));
        Ok(Data::Signed(data))
    }

    fn get_i32(buffer: &mut Cursor<Vec<u8>>) -> Result<Data, String> {
        let data = try!(Data::to_i(buffer, 4));
        Ok(Data::Signed(data))
    }

    fn get_u64(buffer: &mut Cursor<Vec<u8>>) -> Result<Data, String> {
        let data = try!(Data::to_u(buffer, 8));
        Ok(Data::Unsigned(data))
    }

    fn get_u32(buffer: &mut Cursor<Vec<u8>>) -> Result<Data, String> {
        let data = try!(Data::to_u(buffer, 4));
        Ok(Data::Unsigned(data))
    }

    fn get_u16(buffer: &mut Cursor<Vec<u8>>) -> Result<Data, String> {
        let data = try!(Data::to_u(buffer, 2));
        Ok(Data::Unsigned(data))
    }

    fn get_bool(buffer: &mut Cursor<Vec<u8>>) -> Result<Data, String> {
        let data = try!(Data::to_u(buffer, 1));
        Ok(Data::Bool(data != 0))
    }

    fn get_u8(buffer: &mut Cursor<Vec<u8>>) -> Result<Data, String> {
        let data = try!(Data::to_u(buffer, 1));
        Ok(Data::Unsigned(data))
    }

    pub fn value_u(&self) -> Result<u64, String> {
        match self {
            &Data::Unsigned(x) => Ok(x),
            _                  => Err(format!("{:?} is not an unsigned.", self)),
        }
    }

    pub fn value_i(&self) -> Result<i64, String> {
        match self {
            &Data::Signed(x) => Ok(x),
            _                => Err(format!("{:?} is not a signed.", self)),
        }
    }

    pub fn value_time(&self) -> Result<time::Tm, String> {
        match self {
            &Data::Time(x) => Ok(x),
            _              => Err(format!("{:?} is not a time.", self)),
        }
    }

    pub fn value_bytes(&self) -> Result<&Vec<u8>, String> {
        match self {
            &Data::Bytes(ref x) => Ok(x),
            _                   => Err(format!("{:?} is not bytes.", self)),
        }
    }

    pub fn value_string(&self) -> Result<&str, String> {
        match self {
            &Data::VarString(ref x) => Ok(x),
            _                       => Err(format!("{:?} is not bytes.", self)),
        }
    }

    pub fn value_bool(&self) -> Result<bool, String> {
        match self {
            &Data::Bool(x) => Ok(x),
            _              => Err(format!("{:?} is not a bool.", self)),
        }
    }

    pub fn value_ip(&self) -> Result<&Ipv6Addr, String> {
        match self {
            &Data::Ip(ref x) => Ok(x),
            _                => Err(format!("{:?} is not an ip.", self)),
        }
    }
}

#[derive(Debug)]
pub enum ContainerType {
    Base(BasicType),
    Struct(&'static [BasicType]),
    // The index must be an unsigned type
    VarArray(BasicType, &'static [BasicType]),
    FixedArray(usize, &'static [BasicType]),
}

#[derive(Debug)]
pub enum ContainerData {
    Base(Data),
    Struct(Vec<Data>),
    Array(Vec<Vec<Data>>),
}

impl ContainerData {
    pub fn unwrap(&self) -> Result<&Data, String> {
        match self {
            &ContainerData::Base(ref x) => Ok(x),
            _                           => Err(format!("{:?} is not a base", self)),
        }
    }

    pub fn unwrap_struct(&self) -> Result<&Vec<Data>, String> {
        match self {
            &ContainerData::Struct(ref x) => Ok(x),
            _                             => Err(format!("{:?} is not a struct", self)),
        }
    }

    pub fn unwrap_array(&self) -> Result<&Vec<Vec<Data>>, String> {
        match self {
            &ContainerData::Array(ref x) => Ok(x),
            _                            => Err(format!("{:?} is not an array", self)),
        }
    }

    fn get_array(definition: &[BasicType], size: usize,
                 buffer: &mut Cursor<Vec<u8>>) -> Result<Vec<Vec<Data>>, String> {
        let mut data = vec![];
        for _ in 0..size {
            let mut struct_data = vec![];
            for type_ in definition {
                let el = try!(Data::deserialize(type_, buffer));
                struct_data.push(el);
            }

            data.push(struct_data);
        }

        Ok(data)
    }

    pub fn deserialize(container_type: &ContainerType,
                       buffer: &mut Cursor<Vec<u8>>) -> Result<ContainerData, String> {
        match container_type {
            &ContainerType::Base(ref x) => {
                let data = try!(Data::deserialize(x, buffer));
                Ok(ContainerData::Base(data))
            },
            &ContainerType::VarArray(ref index_type, ref types) => {
                let size_wrapped = try!(Data::deserialize(index_type, buffer));

                let size = match size_wrapped {
                    Data::Unsigned(x) => x as usize,
                    _                 => unreachable!() // only unsigned is allowed
                };

                let data = try!(ContainerData::get_array(types, size, buffer));
                Ok(ContainerData::Array(data))
            },
            &ContainerType::FixedArray(size, ref types) => {
                let data = try!(ContainerData::get_array(types, size, buffer));
                Ok(ContainerData::Array(data))
            },
            &ContainerType::Struct(ref element_type) => {
                let data = try!(ContainerData::get_array(element_type, 1, buffer))
                    .swap_remove(0);

                Ok(ContainerData::Struct(data))
            }
        }
    }
}

#[derive(Debug)]
struct Message {
    definition: &'static [ContainerType],
    data: Vec<ContainerData>,
}

impl Message {
    fn deserialize(buffer: &mut Cursor<Vec<u8>>,
                   definition: &'static [ContainerType]) -> Result<Message, String> {
        let mut data = vec![];
        for el in definition.iter() {
            let el_data = try!(ContainerData::deserialize(&el, buffer));
            data.push(el_data);
        }

        Ok(Message {
            definition: definition,
            data: data,
        })
    }

    fn get(&self, index: usize) -> Result<&ContainerData, String> {
        self.data.get(index).ok_or(format!("There's no data at {}", index))
    }

    pub fn get_array(&self, index: usize) -> Result<&Vec<Vec<Data>>, String> {
        self.get(index).and_then(|s| s.unwrap_array())
    }

    pub fn unwrap_at(&self, index: usize) -> Result<&Data, String> {
        self.get(index).and_then(|d| d.unwrap())
    }

    pub fn get_struct(&self, index: usize) -> Result<&Vec<Data>, String> {
        self.get(index).and_then(|s| s.unwrap_struct())
    }

    pub fn get_string(&self, index: usize) -> Result<String, String> {
        self.unwrap_at(index).and_then(|d| d.value_string())
                             .and_then(|d| Ok(d.to_string()))
    }

    pub fn get_bool(&self, index: usize) -> Result<bool, String> {
        self.unwrap_at(index).and_then(|d| d.value_bool())
    }

    pub fn get_time(&self, index: usize) -> Result<time::Tm, String> {
        self.unwrap_at(index).and_then(|d| d.value_time())
    }

    pub fn get_u8(&self, index: usize) -> Result<u8, String> {
        self.unwrap_at(index).and_then(|d| d.value_u())
            .and_then(|d| Ok(d as u8))
    }

    pub fn get_u32(&self, index: usize) -> Result<u32, String> {
        self.unwrap_at(index).and_then(|d| d.value_u())
            .and_then(|d| Ok(d as u32))
    }

    pub fn get_u64(&self, index: usize) -> Result<u64, String> {
        self.unwrap_at(index).and_then(|d| d.value_u())
    }

    pub fn get_i32(&self, index: usize) -> Result<i32, String> {
        self.unwrap_at(index).and_then(|d| d.value_i())
            .and_then(|d| Ok(d as i32))
    }

    pub fn get_bytes(&self, index: usize) -> Result<&Vec<u8>, String> {
        self.unwrap_at(index).and_then(|d| d.value_bytes())
    }
}

impl Command {
    pub fn from_bytes(data: &[u8]) -> Command {
        match data {
            b"version\0\0\0\0\0"    => Command::Version,
            b"verack\0\0\0\0\0\0"   => Command::Verack,
            b"ping\0\0\0\0\0\0\0\0" => Command::Ping,
            b"pong\0\0\0\0\0\0\0\0" => Command::Pong,
            b"getaddr\0\0\0\0\0"    => Command::GetAddr,
            b"addr\0\0\0\0\0\0\0\0" => Command::Addr,
            b"reject\0\0\0\0\0\0"   => Command::Reject,
            b"getheaders\0\0"       => Command::GetHeaders,
            _                       => Command::Unknown,
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

impl NetworkType {
    pub fn from_magic(data: u32) -> NetworkType {
        match data {
            0xD9B4BEF9 => NetworkType::Main,
            0xDAB5BFFA => NetworkType::TestNet,
            0x0709110B => NetworkType::TestNet3,
            0xFEB4BEF9 => NetworkType::NameCoin,
            _          => NetworkType::Unknown,
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

const MESSAGE_HEADER: &'static [ContainerType; 4]  = &[
     ContainerType::Base(BasicType::FixedU32),
     ContainerType::Base(BasicType::Bytes(12)),
     ContainerType::Base(BasicType::FixedU32),
     ContainerType::Base(BasicType::Bytes(4)),
];

#[derive(PartialEq, Debug)]
pub struct MessageHeader {
    network_type: NetworkType,
    command: Command,
    length: u32,
    checksum: Vec<u8>,
}

impl Serialize for MessageHeader {
    fn serialize(&self, serializer: &mut Serializer, _: Flag) {
        self.network_type.serialize(serializer, Flag::NoFlag);
        self.     command.serialize(serializer, Flag::NoFlag);
        self.      length.serialize(serializer, Flag::NoFlag);
        self.    checksum.serialize(serializer, Flag::NoFlag);
    }
}

impl MessageHeader {
    pub fn deserialize(buffer: &mut Cursor<Vec<u8>>) -> Result<MessageHeader, String> {
        let message = try!(Message::deserialize(buffer, MESSAGE_HEADER));

        Ok(MessageHeader {
            network_type: NetworkType::from_magic(try!(message.get_u32(0))),
            command:      Command::from_bytes(try!(message.get_bytes(1))),
            length:       try!(message.get_u32(2)),
            checksum:     try!(message.get_bytes(3)).clone(),
        })
    }

    pub fn len(&self) -> u32 { self.length }
    pub fn magic(&self) -> &NetworkType { &self.network_type }
    pub fn command(&self) -> &Command { &self.command }
}


const IP_STRUCT_TIME: &'static [BasicType; 4] =
&[
    BasicType::ShortTime,
    BasicType::FixedU64,
    BasicType::Ip,
    BasicType::FixedBEU16
];

const IP_STRUCT: &'static [BasicType; 3] =
&[
    BasicType::FixedU64,
    BasicType::Ip,
    BasicType::FixedBEU16
];

const VERSION_MESSAGE: &'static [ContainerType; 9]  = &[
     ContainerType::Base(BasicType::FixedI32),
     ContainerType::Base(BasicType::FixedU64),
     ContainerType::Base(BasicType::Time),
     ContainerType::Struct(IP_STRUCT),
     ContainerType::Struct(IP_STRUCT),
     ContainerType::Base(BasicType::FixedU64),
     ContainerType::Base(BasicType::VarString),
     ContainerType::Base(BasicType::FixedI32),
     ContainerType::Base(BasicType::Bool),
];

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

impl VersionMessage {
    pub fn deserialize(buffer: &mut Cursor<Vec<u8>>) -> Result<VersionMessage, String> {
        let message = try!(Message::deserialize(buffer, VERSION_MESSAGE));
        Ok(VersionMessage {
            version:      try!(message.get_i32(0)),
            services:     try!(Services::from_data(try!(message.unwrap_at(1)))),
            timestamp:    try!(message.get_time(2)),
            addr_recv:    try!(IPAddress::from_data(try!(message.get_struct(3)))),
            addr_from:    try!(IPAddress::from_data(try!(message.get_struct(4)))),
            nonce:        try!(message.get_u64(5)),
            user_agent:   try!(message.get_string(6)),
            start_height: try!(message.get_i32(7)),
            relay:        try!(message.get_bool(8)),
        })
    }
}

const PING_MESSAGE: &'static [ContainerType; 1]  = &[
     ContainerType::Base(BasicType::FixedU64),
];

#[derive(Debug)]
pub struct PingMessage {
    nonce: u64,
}

impl Serialize for PingMessage {
    fn serialize(&self, serializer: &mut Serializer, _: Flag) {
        self.nonce.serialize(serializer, Flag::NoFlag);
    }
}

impl PingMessage {
    pub fn deserialize(buffer: &mut Cursor<Vec<u8>>) -> Result<PingMessage, String> {
        let message = try!(Message::deserialize(buffer, PING_MESSAGE));
        Ok(PingMessage {
            nonce: try!(message.get_u64(0)),
        })
    }

    pub fn nonce(&self) -> u64 { self.nonce }
}

const ADDR_MESSAGE: &'static [ContainerType; 1] = &[
    ContainerType::VarArray(BasicType::VarInt, IP_STRUCT_TIME),
];

pub struct AddrMessage {
    pub addr_list: Vec<(time::Tm, IPAddress)>,
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

    pub fn deserialize(buffer: &mut Cursor<Vec<u8>>) -> Result<AddrMessage, String> {
        let message = try!(Message::deserialize(buffer, ADDR_MESSAGE));
        let data = try!(message.get_array(0));

        let mut addr_list = vec![];
        for el in data {
            if el.len() != 4 {
                return Err(format!("Not a valid address {:?}", el));
            }

            addr_list.push((
                    try!(el.get(0).unwrap().value_time()),
                    IPAddress::new(
                        try!(Services::from_data(el.get(1).unwrap())),
                        *try!(el.get(2).unwrap().value_ip()),
                        try!(el.get(3).unwrap().value_u()) as u16)));
        }

        Ok(AddrMessage {
            addr_list: addr_list,
        })
    }
}

const REJECT_MESSAGE: &'static [ContainerType; 3] = &[
    ContainerType::Base(BasicType::VarString),
    ContainerType::Base(BasicType::FixedU8),
    ContainerType::Base(BasicType::VarString),
];

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

impl RejectMessage {
    pub fn deserialize(buffer: &mut Cursor<Vec<u8>>) -> Result<RejectMessage, String> {
        let message = try!(Message::deserialize(buffer, REJECT_MESSAGE));

        Ok(RejectMessage {
            message: try!(message.get_string(0)),
            ccode:   try!(message.get_u8(1)),
            reason:  try!(message.get_string(2)),
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
    use super::Message;
    use std::io::Cursor;

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

        println!("{:?}", Message::deserialize(&mut Cursor::new(buffer), super::VERSION_MESSAGE));
        assert!(false);
    }

    #[test]
    fn test_u64() {
        let buffer = vec![0xDB, 0xFA, 0x6F, 0x98, 0xC9, 0xDE, 0xDF, 0xC5];
        let data = Data::deserialize(&BasicType::FixedU64, &mut Cursor::new(buffer));

        println!("{:?}", data);
        panic!();
    }
}
