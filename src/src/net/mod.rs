mod rpcengine;
mod store;
pub mod messages;
pub mod p2pclient;

use std::net;

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
}
