use super::IPAddress;
use super::Services;
use utils::IntUtils;
use utils::ParserUtils;
use utils::CryptoUtils;

use time;

pub trait Serializable {
    fn serialize(&self) -> Vec<u8>;
}

#[derive(PartialEq, Debug)]
pub enum NetworkType {
    Main,
    TestNet,
    TestNet3,
    NameCoin,
}

#[derive(PartialEq, Debug)]
pub enum Command {
    Version,
}

impl Serializable for Command {
    fn serialize(&self) -> Vec<u8> {
        let data = match self {
            &Command::Version     => "version\0\0\0\0\0",
        };

        let mut result = vec![];
        result.extend(data.to_string().as_bytes().iter().cloned());

        result
    }
}

impl Command {
    pub fn deserialize(data: &mut Vec<u8>) -> Command {
        let data = ParserUtils::get_fixed_string(data, 12);

        match &data[..] {
            "version\0\0\0\0\0" => Command::Version,
            _                   => unreachable!(),
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
    pub fn deserialize(data: &mut Vec<u8>) -> MessageHeader {
        MessageHeader {
            magic: NetworkType::deserialize(data),
            command: Command::deserialize(data),
            length: ParserUtils::get_fixed_u32(data),
            checksum: ParserUtils::get_fixed_u32(data),
        }
    }
}

#[derive(Debug, PartialEq)]
pub struct VersionMessage {
    version: i32,
    services: Services,
    timestamp: time::Tm,
    addr_recv: IPAddress,
    addr_from: IPAddress,
    nonce: u64,
    user_agent: String,
    start_height: i32,
    relay: bool,
}

impl Serializable for VersionMessage {
    fn serialize(&self) -> Vec<u8> {
        let mut result = vec![];

        result.extend(IntUtils::i32_to_vec_u8_padded(self.version).iter().cloned());
        result.extend(self.services.serialize().iter().cloned());
        result.extend(IntUtils::to_vec_u8_padded(
                self.timestamp.to_timespec().sec).iter().cloned());
        result.extend(self.addr_recv.serialize(false).iter().cloned());
        if self.version >= 106 {
            result.extend(self.addr_from.serialize(false).iter().cloned());
            result.extend(IntUtils::u64_to_vec_u8_padded(self.nonce).iter().cloned());
            result.extend(IntUtils::to_variable_length_int(
                    self.user_agent.as_bytes().len() as u64).iter().cloned());
            result.extend(self.user_agent.as_bytes().iter().cloned());
            result.extend(IntUtils::i32_to_vec_u8_padded(self.start_height).iter().cloned());
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

pub fn get_serialized_message(magic: NetworkType,
                              command: Command,
                              message: Box<Serializable>) -> Vec<u8> {
    let mut checksum = CryptoUtils::sha256(CryptoUtils::sha256(message.serialize()));
    checksum.truncate(4);

    let serialized = message.serialize();
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

        let serialized = get_serialized_message(NetworkType::Main, Command::Version, Box::new(message));

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

        assert_eq!(header, MessageHeader::deserialize(&mut data));
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
