mod utils;
pub mod script;
pub mod net;
#[cfg(test)]
mod test;

extern crate crypto;
extern crate regex;
extern crate rustc_serialize;
extern crate hyper;
extern crate time;
extern crate mio;
extern crate bytes;
extern crate rand;

use utils::Config;

pub fn main() {
    let config = Config::from_command_line().unwrap_or_else(
        |e| { println!("Error: {}", e); panic!() });

    net::p2pclient::start(format!("0.0.0.0:{}", config.port).parse().unwrap());
}
