use super::IPAddress;
use super::Services;
use utils::IntUtils;
use utils::ParserUtils;

use time;

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

impl VersionMessage {
    pub fn serialize(&self) -> Vec<u8> {
        let mut result = vec![];

        result.extend(IntUtils::i32_to_vec_u8_padded(self.version).iter().cloned());
        result.extend(self.services.serialize().iter().cloned());
        result.extend(IntUtils::to_vec_u8_padded(
                self.timestamp.to_timespec().sec).iter().cloned());
        result.extend(self.addr_recv.serialize(false).iter().cloned());
        result.extend(self.addr_from.serialize(false).iter().cloned());
        result.extend(IntUtils::u64_to_vec_u8_padded(self.nonce).iter().cloned());
        result.extend(IntUtils::to_variable_length_int(
                self.user_agent.as_bytes().len() as u64).iter().cloned());
        result.extend(self.user_agent.as_bytes().iter().cloned());
        result.extend(IntUtils::i32_to_vec_u8_padded(self.start_height).iter().cloned());
        result.push(if self.relay { 0x01 } else { 0x00 });

        result
    }

    pub fn deserialize(data: &mut Vec<u8>) -> VersionMessage {
        VersionMessage {
            version:      ParserUtils::get_fixed_i32(data),
            services:     Services::deserialize(data),
            timestamp:    ParserUtils::get_time(data),
            addr_recv:    IPAddress::deserialize(data, false),
            addr_from:    IPAddress::deserialize(data, false),
            nonce:        ParserUtils::get_fixed_u64(data),
            user_agent:   ParserUtils::get_string(data),
            start_height: ParserUtils::get_fixed_i32(data),
            relay:        ParserUtils::get_bool(data),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::Services;
    use super::super::IPAddress;
    use super::*;

    use time;
    use std::net;

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
                 0xC0, 0x3E, 0x03, 0x00,
                 // relay [false]
                 0x00]);

        serialized.reverse();

        let deserialized = VersionMessage::deserialize(&mut serialized);
        assert!(serialized.len() == 0);
        assert_eq!(message, deserialized);
    }
}
