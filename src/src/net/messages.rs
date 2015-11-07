use super::IPAddress;
use super::Services;
use utils::IntUtils;
use utils::ParserUtils;
use utils::CryptoUtils;

use time;

pub trait Serializable {
    fn serialize(&self) -> Vec<u8>;
}

#[derive(PartialEq, Copy, Clone, Debug)]
pub enum NetworkType {
    Main,
    TestNet,
    TestNet3,
    NameCoin,
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
}

impl Serializable for Command {
    fn serialize(&self) -> Vec<u8> {
        let data = match self {
            &Command::Addr        => "addr\0\0\0\0\0\0\0\0",
            &Command::GetAddr     =>    "getaddr\0\0\0\0\0",
            &Command::Version     =>    "version\0\0\0\0\0",
            &Command::Verack      =>   "verack\0\0\0\0\0\0",
            &Command::Ping        => "ping\0\0\0\0\0\0\0\0",
            &Command::Pong        => "pong\0\0\0\0\0\0\0\0",
            &Command::Reject      =>   "reject\0\0\0\0\0\0",
        };

        let mut result = vec![];
        result.extend(data.to_string().as_bytes().iter().cloned());

        result
    }
}

impl Command {
    pub fn deserialize(data: &mut Vec<u8>) -> Result<Command, String> {
        let data = ParserUtils::get_fixed_string(data, 12);

        match &data[..] {
            "version\0\0\0\0\0"    => Ok(Command::Version),
            "verack\0\0\0\0\0\0"   => Ok(Command::Verack),
            "ping\0\0\0\0\0\0\0\0" => Ok(Command::Ping),
            "pong\0\0\0\0\0\0\0\0" => Ok(Command::Pong),
            "getaddr\0\0\0\0\0"    => Ok(Command::GetAddr),
            "addr\0\0\0\0\0\0\0\0" => Ok(Command::Addr),
            "reject\0\0\0\0\0\0"   => Ok(Command::Reject),
            _                      => {
                println!("Unrecognized command {:?}", data);
                Err(format!("Unrecognized command `{:?}`\n", data))
            },
        }
    }
}

impl Serializable for NetworkType {
    fn serialize(&self) -> Vec<u8> {
        match self {
            &NetworkType::Main     => vec![0xF9, 0xBE, 0xB4, 0xD9],
            &NetworkType::TestNet  => vec![0xFA, 0xBF, 0xB5, 0xDA],
            &NetworkType::TestNet3 => vec![0x0B, 0x11, 0x09, 0x07],
            &NetworkType::NameCoin => vec![0xF9, 0xBE, 0xB4, 0xFE],
        }
    }
}

impl NetworkType {
    pub fn deserialize(data: &mut Vec<u8>) -> NetworkType {
        let data = ParserUtils::get_fixed_u32(data);
        print!("data = {:X}\n", data);

        match data {
            0xD9B4BEF9 => NetworkType::Main,
            0xDAB5BFFA => NetworkType::TestNet,
            0x0709110B => NetworkType::TestNet3,
            0xFEB4BEF9 => NetworkType::NameCoin,
            // TODO: handle error
            _          => unreachable!(),
        }
    }
}

#[derive(PartialEq, Debug)]
pub struct MessageHeader {
    magic: NetworkType,
    command: Command,
    length: u32,
    checksum: u32,
}

impl Serializable for MessageHeader {
    fn serialize(&self) -> Vec<u8> {
        let mut result = vec![];

        result.extend(self.magic.serialize().iter().cloned());
        result.extend(self.command.serialize().iter().cloned());
        result.extend(IntUtils::u32_to_vec_u8_padded(self.length).iter().cloned());
        result.extend(IntUtils::u32_to_vec_u8_padded(self.checksum).iter().cloned());

        result
    }
}

impl MessageHeader {
    pub fn deserialize(data: &mut Vec<u8>) -> Result<MessageHeader, String> {
        Ok(MessageHeader {
            magic: NetworkType::deserialize(data),
            command: try!(Command::deserialize(data)),
            length: ParserUtils::get_fixed_u32(data),
            checksum: ParserUtils::get_fixed_u32(data),
        })
    }

    pub fn len(&self) -> u32 { self.length }
    pub fn magic(&self) -> &NetworkType { &self.magic }
    pub fn command(&self) -> &Command { &self.command }
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

impl Serializable for VersionMessage {
    fn serialize(&self) -> Vec<u8> {
        let mut result = vec![];

        result.extend(IntUtils::i32_to_vec_u8_padded(self.version).into_iter());
        result.extend(self.services.serialize().into_iter());
        result.extend(IntUtils::to_vec_u8_padded(
                self.timestamp.to_timespec().sec).into_iter());
        result.extend(self.addr_recv.serialize(false).into_iter());
        if self.version >= 106 {
            result.extend(self.addr_from.serialize(false).into_iter());
            result.extend(IntUtils::u64_to_vec_u8_padded(self.nonce).into_iter());
            result.extend(ParserUtils::to_string(&self.user_agent).into_iter());
            result.extend(IntUtils::i32_to_vec_u8_padded(
                    self.start_height).into_iter());
        }
        if self.version >= 70001 {
            result.push(if self.relay { 0x01 } else { 0x00 });
        }

        result
    }
}

impl VersionMessage {
    pub fn deserialize(data: &mut Vec<u8>) -> VersionMessage {
        let version = ParserUtils::get_fixed_i32(data);
        VersionMessage {
            version:      version,
            services:     Services::deserialize(data),
            timestamp:    ParserUtils::get_time(data),
            addr_recv:    IPAddress::deserialize(data, false),
            addr_from:    IPAddress::deserialize(data, false),
            nonce:        ParserUtils::get_fixed_u64(data),
            user_agent:   ParserUtils::get_string(data),
            start_height: ParserUtils::get_fixed_i32(data),
            relay:        if version >= 70001 { ParserUtils::get_bool(data) } else { false },
        }
    }
}

pub struct PingMessage {
    nonce: u64,
}

impl Serializable for PingMessage {
    fn serialize(&self) -> Vec<u8> {
        let mut result = vec![];

        result.extend(IntUtils::u64_to_vec_u8_padded(self.nonce));

        result
    }
}

impl PingMessage {
    pub fn deserialize(data: &mut Vec<u8>) -> PingMessage {
        let nonce = ParserUtils::get_fixed_u64(data);
        PingMessage {
            nonce: nonce,
        }
    }
}

pub struct AddrMessage {
    pub addr_list: Vec<(time::Tm, IPAddress)>,
}

impl Serializable for AddrMessage {
    fn serialize(&self) -> Vec<u8> {
        let mut result = vec![];

        result.extend(IntUtils::to_variable_length_int(self.addr_list.len() as u64));

        for address in &self.addr_list {
            result.extend(ParserUtils::serialize_time(address.0));
            result.extend(address.1.serialize(true));
        }

        result
    }
}

impl AddrMessage {
    pub fn new(addr_list: Vec<(time::Tm, IPAddress)>) -> AddrMessage {
        AddrMessage {
            addr_list: addr_list,
        }
    }

    pub fn deserialize(data: &mut Vec<u8>) -> AddrMessage {
        let size = ParserUtils::get_variable_length_int(data);
        let mut addr_list = vec![];
        for _ in 0..size {
            let timestamp = ParserUtils::get_time(data);
            let ip_address = IPAddress::deserialize(data, true);
            addr_list.push((timestamp, ip_address));
        }

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
    data: u8,
}

impl Serializable for RejectMessage {
    fn serialize(&self) -> Vec<u8> {
        let mut result = vec![];
        result.extend(ParserUtils::to_string(&self.message).into_iter());
        result.push(self.ccode);
        result.extend(ParserUtils::to_string(&self.reason).into_iter());
        result.push(self.data);

        result
    }
}

impl RejectMessage {
    pub fn deserialize(data: &mut Vec<u8>) -> RejectMessage {
        RejectMessage {
            message: ParserUtils::get_string(data),
            ccode: data.pop().unwrap(),
            reason: ParserUtils::get_string(data),
            data: data.pop().unwrap(),
        }
    }
}

pub fn get_serialized_message(magic: NetworkType,
                              command: Command,
                              message: Option<Box<Serializable>>) -> Vec<u8> {
    let serialized = match message {
        Some(x) => x.serialize(),
        None => vec![],
    };

    let mut checksum = CryptoUtils::sha256(CryptoUtils::sha256(serialized.clone()));
    checksum.truncate(4);

    let header = MessageHeader {
        magic: magic,
        command: command,
        length: serialized.len() as u32,
        checksum: IntUtils::to_u32(&checksum),
    };

    let mut result = vec![];
    result.extend(header.serialize().iter().cloned());
    result.extend(serialized.iter().cloned());

    result
}

#[cfg(test)]
mod tests {
    use super::super::Services;
    use super::super::IPAddress;
    use super::*;

    use time;
    use std::net;

    #[test]
    fn test_message_serialize() {
        let message = VersionMessage {
            version: 60002,
            services: Services::new(true),
            timestamp: time::at_utc(time::Timespec::new(1355854353,0)),
            addr_recv: IPAddress::new(
                time::at_utc(time::Timespec::new(0,0)),
                Services::new(true),
                net::Ipv6Addr::new(0, 0, 0, 0, 0, 0xffff, 0, 0),
                0),
            addr_from: IPAddress::new(
                time::at_utc(time::Timespec::new(0,0)),
                Services::new(true),
                net::Ipv6Addr::new(0, 0, 0, 0, 0, 0xffff, 0, 0),
                0),
            nonce: 0x6517E68C5DB32E3B,
            user_agent: "/Satoshi:0.7.2/".to_string(),
            start_height: 212672,
            relay: false,
        };

        let serialized = get_serialized_message(NetworkType::Main,
                                                Command::Version,
                                                Some(Box::new(message)));

        assert_eq!(serialized,
            vec![// magic number
                 0xF9, 0xBE, 0xB4, 0xD9,
                 // command name
                 0x76, 0x65, 0x72, 0x73, 0x69, 0x6F, 0x6E, 0x00, 0x00, 0x00,
                 0x00, 0x00,
                 // payload length
                 0x64, 0x00, 0x00, 0x00,
                 // payload checksum
                 0x3B, 0x64, 0x8D, 0x5A,
                 // version
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
                 0xC0, 0x3E, 0x03, 0x00]);
    }

    #[test]
    fn test_version_message_serialize() {
        let message = VersionMessage {
            version: 60002,
            services: Services::new(true),
            timestamp: time::at_utc(time::Timespec::new(1355854353, 0)),
            addr_recv: IPAddress::new(
                time::at_utc(time::Timespec::new(0,0)),
                Services::new(true),
                net::Ipv6Addr::new(0, 0, 0, 0, 0, 0xffff, 0x0a00, 0x0001),
                8333),
            addr_from: IPAddress::new(
                time::at_utc(time::Timespec::new(0,0)),
                Services::new(true),
                net::Ipv6Addr::new(0, 0, 0, 0, 0, 0xffff, 0x0a00, 0x0002),
                8333),
            nonce: 0x6517E68C5DB32E3B,
            user_agent: "/Satoshi:0.7.2/".to_string(),
            start_height: 212672,
            relay: false,
        };


        let mut serialized = message.serialize();
        assert_eq!(
            serialized,
            vec![// version [60002]
                 0x62, 0xEA, 0x00, 0x00,
                 // services [NODE_NETWORK]
                 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                 // timestamp [Tue Dec 18 10:12:33 PST 2012]
                 0x11, 0xB2, 0xD0, 0x50, 0x00, 0x00, 0x00, 0x00,
                 // addr_recv [10.0.0.1]
                 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF,
                 0x0A, 0x00, 0x00, 0x01, 0x20, 0x8D,
                 // addr_from [10.0.0.2]
                 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF,
                 0x0A, 0x00, 0x00, 0x02, 0x20, 0x8D,
                 // nonce
                 0x3B, 0x2E, 0xB3, 0x5D, 0x8C, 0xE6, 0x17, 0x65,
                 // user_agent ["/Satoshi:0.7.2/"]
                 0x0F, 0x2F, 0x53, 0x61, 0x74, 0x6F, 0x73, 0x68, 0x69, 0x3A,
                 0x30, 0x2E, 0x37, 0x2E, 0x32, 0x2F,
                 // start_height [212672]
                 0xC0, 0x3E, 0x03, 0x00]);

        serialized.reverse();

        let deserialized = VersionMessage::deserialize(&mut serialized);
        assert!(serialized.len() == 0);
        assert_eq!(message, deserialized);
    }

    #[test]
    fn test_message_header_serialize() {
        let header = MessageHeader {
            magic: NetworkType::Main,
            command: Command::Version,
            length: 100,
            checksum: 0x5A8D643B,
        };

        let mut data = header.serialize();
        assert_eq!(
            vec![// main network magic number
                 0xF9, 0xBE, 0xB4, 0xD9,
                 // "version" command
                 0x76, 0x65, 0x72, 0x73, 0x69, 0x6F, 0x6E, 0x00, 0x00, 0x00, 0x00, 0x00,
                 // payload size
                 0x64, 0x00, 0x00, 0x00,
                 // checksum
                 0x3B, 0x64, 0x8D, 0x5A], data);

        data.reverse();

        assert_eq!(header, MessageHeader::deserialize(&mut data).unwrap());
        assert!(data.len() == 0);
    }

    #[test]
    fn test_network_serialize() {
        let network = NetworkType::Main;

        let mut data = network.serialize();
        assert_eq!(vec![0xF9, 0xBE, 0xB4, 0xD9], data);

        data.reverse();

        assert_eq!(network, NetworkType::deserialize(&mut data));
        assert!(data.len() == 0);
    }

    #[test]
    fn test_serialize_command() {
        let command = Command::Version;

        let mut data = command.serialize();
        assert_eq!(vec![0x76, 0x65, 0x72, 0x73, 0x69, 0x6F, 0x6E, 0x00, 0x00, 0x00,
                        0x00, 0x00],
                   data);

        data.reverse();

        assert_eq!(command, Command::deserialize(&mut data));
        assert!(data.len() == 0);
    }
}
