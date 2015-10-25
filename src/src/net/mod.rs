use std::net;
use time;
use utils::IntUtils;
use utils::ParserUtils;

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

    pub fn deserialize(data: Vec<u8>) -> Services {
        let node_network = IntUtils::to_u64(&data) == 1;
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
            serialized.extend(IntUtils::to_vec_u8(
                    self.timestamp.to_timespec().sec).iter().cloned());
        }

        serialized.extend(self.services.serialize());
        serialized.extend(self.address.segments().iter().flat_map(
                |x| IntUtils::u16_to_vec_u8_padded(*x)));
        serialized.extend(IntUtils::u16_to_vec_u8_padded(self.port));

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

    pub fn deserialize(data_: Vec<u8>, with_timestamp: bool) -> IPAddress {
        let mut data = data_;
        data.reverse();

        let sec = if with_timestamp {
            ParserUtils::get_fixed_u32(&mut data) as i64
        } else {
            time::now().to_timespec().sec
        };

        let time =     time::at_utc(time::Timespec::new(sec, 0));
        let services = Services::deserialize(ParserUtils::get_bytes(&mut data, 8));
        let ip =       IPAddress::get_ip(&mut data);
        let port =     ParserUtils::get_be_fixed_u16(&mut data);

        IPAddress::new(time, services, ip, port)
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

        assert_eq!(addr.serialize(true),
               vec![0x4E, 0x61, 0xBC, 0x00,
                    0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF,
                    0x0A, 0x00, 0x00, 0x01, 0x20, 0x8D]);

        let deserialized = IPAddress::deserialize(addr.serialize(true), true);

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

        assert_eq!(addr.serialize(false),
               vec![0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF,
                    0x0A, 0x00, 0x00, 0x01, 0x20, 0x8D]);

        let deserialized = IPAddress::deserialize(addr.serialize(false), false);

        assert_eq!(deserialized.services, addr.services);
        assert_eq!(deserialized.address,  addr.address);
        assert_eq!(deserialized.port,     addr.port);
    }
}
