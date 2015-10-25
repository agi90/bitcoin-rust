use std::net;
use time;
use utils::IntUtils;
use utils::ParserUtils;

pub mod messages;

#[derive(PartialEq, Debug)]
pub struct Services {
    node_network: bool
}

impl Services {
    pub fn new(node_network: bool) -> Services {
        Services {
            node_network: node_network,
        }
    }

    pub fn serialize(&self) -> Vec<u8> {
        let data = if self.node_network { 1 } else { 0 };
        IntUtils::to_vec_u8_padded(data)
    }

    pub fn deserialize(data: &mut Vec<u8>) -> Services {
        let node_network = ParserUtils::get_fixed_u64(data) == 1;
        Services::new(node_network)
    }
}

#[derive(PartialEq, Debug)]
pub struct IPAddress {
    timestamp: time::Tm,
    services: Services,
    address: net::Ipv6Addr,
    port: u16,
}

impl IPAddress {
    pub fn new(timestamp: time::Tm, services: Services,
               address: net::Ipv6Addr, port: u16) -> IPAddress {
        IPAddress {
            timestamp: timestamp,
            services: services,
            address: address,
            port: port,
        }
    }

    pub fn serialize(&self, include_timestamp: bool) -> Vec<u8> {
        let mut serialized = vec![];

        if include_timestamp {
            serialized.extend(IntUtils::to_vec_u8_padded(
                    self.timestamp.to_timespec().sec).iter().cloned());
        }

        serialized.extend(self.services.serialize());
        serialized.extend(self.address.segments().iter().flat_map(
                |x| IntUtils::u16_to_be_vec_u8_padded(*x)));
        serialized.extend(IntUtils::u16_to_be_vec_u8_padded(self.port));

        serialized
    }

    fn get_ip(data: &mut Vec<u8>) -> net::Ipv6Addr {
        let mut segments = [0u16;8];
        for i in 0..8 {
            segments[i] = ParserUtils::get_be_fixed_u16(data);
        }

        net::Ipv6Addr::new(segments[0], segments[1], segments[2], segments[3],
                           segments[4], segments[5], segments[6], segments[7])
    }

    pub fn deserialize(data: &mut Vec<u8>, with_timestamp: bool) -> IPAddress {
        let sec = if with_timestamp {
            // TODO: fix the case when u64 is too big for i64
            ParserUtils::get_fixed_u64(data) as i64
        } else {
            0
        };

        IPAddress {
            timestamp: time::at_utc(time::Timespec::new(sec, 0)),
            services:  Services::deserialize(data),
            address:   IPAddress::get_ip(data),
            port:      ParserUtils::get_be_fixed_u16(data),
        }
    }
}

#[cfg(test)]
mod tests {
    use time;
    use std::net;
    use super::Services;
    use super::IPAddress;

    #[test]
    fn test_ip_address_serialize_with_time() {
        let addr = IPAddress::new(
            time::at_utc(time::Timespec::new(12345678, 0)),
            Services::new(true),
            net::Ipv6Addr::new(0, 0, 0, 0, 0, 0xffff, 0x0a00, 0x0001),
            8333);

        let mut data = addr.serialize(true);

        assert_eq!(data,
               vec![0x4E, 0x61, 0xBC, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF,
                    0x0A, 0x00, 0x00, 0x01, 0x20, 0x8D]);

        data.reverse();
        let deserialized = IPAddress::deserialize(&mut data, true);

        assert!(data.len() == 0);
        assert_eq!(deserialized.services, addr.services);
        assert_eq!(deserialized.address,  addr.address);
        assert_eq!(deserialized.port,     addr.port);
    }

    #[test]
    fn test_ip_address_serialize() {
        let addr = IPAddress::new(
            time::now(),
            Services::new(true),
            net::Ipv6Addr::new(0, 0, 0, 0, 0, 0xffff, 0x0a00, 0x0001),
            8333);

        let mut data = addr.serialize(false);

        assert_eq!(data,
               vec![0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF,
                    0x0A, 0x00, 0x00, 0x01, 0x20, 0x8D]);

        data.reverse();
        let deserialized = IPAddress::deserialize(&mut data, false);

        assert!(data.len() == 0);
        assert_eq!(deserialized.services, addr.services);
        assert_eq!(deserialized.address,  addr.address);
        assert_eq!(deserialized.port,     addr.port);
    }
}
