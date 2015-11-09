mod rpcengine;
pub mod messages;
pub mod p2pclient;

use std::net;
use utils::ParserUtils;

use self::messages::{Data, BasicType, ContainerData};

#[derive(PartialEq, Copy, Clone, Debug)]
pub struct Services {
    node_network: bool
}

impl Services {
    pub fn new(node_network: bool) -> Services {
        Services {
            node_network: node_network,
        }
    }

    pub fn from_data(data: &Data) -> Result<Services, String> {
        let u_value = try!(data.value_u());

        let node_network = u_value == 1;

        Ok(Services {
            node_network: node_network,
        })
    }

    pub fn to_data(&self) -> Data {
        let data = if self.node_network { 1 } else { 0 };
        Data::Unsigned(data)
    }
}

#[derive(PartialEq, Debug, Clone, Copy)]
pub struct IPAddress {
    services: Services,
    pub address: net::Ipv6Addr,
    port: u16,
}

impl IPAddress {
    pub fn new(services: Services, address: net::Ipv6Addr, port: u16) -> IPAddress {
        IPAddress {
            services: services,
            address: address,
            port: port,
        }
    }

    pub fn to_data(&self) -> ContainerData {
        let data = vec![
            self.services.to_data(),
            Data::Ip(self.address),
            Data::Unsigned(self.port as u64),
        ];

        ContainerData::Struct(data)
    }

    pub fn from_data(data: &Vec<Data>) -> Result<IPAddress, String> {
        if data.len() != 3 {
            return Err(format!("Invalid data {:?}", data));
        }

        Ok(IPAddress {
            services: try!(Services::from_data(data.get(0).unwrap())),
            address:  *try!(data.get(1).unwrap().value_ip()),
            port:     try!(data.get(2).unwrap().value_u()) as u16,
        })
    }
}
