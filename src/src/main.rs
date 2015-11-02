mod utils;
pub mod script;
pub mod transaction;
pub mod net;

extern crate crypto;
extern crate regex;
extern crate rustc_serialize;
extern crate hyper;
extern crate time;
extern crate mio;
extern crate bytes;

pub fn main() {
        net::p2pclient::start("0.0.0.0:18333".parse().unwrap());
}
