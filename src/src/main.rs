extern crate rustc_serialize;
extern crate crypto;

use rustc_serialize::base64::FromBase64;

mod parser;

use parser::Parser;
use parser::ScriptElement;

fn main() {
    let parser = Parser::new();

    let data = parser.parse(
        "dqkUiavN76u6q7qruqu6q7qruqu6q7qIrA==".from_base64().unwrap());
    
    for script_element in data {
        match script_element {
            ScriptElement::OpCode(x) => print!("{}<{:X}> ", x.name, x.code),
            ScriptElement::Data(x) => print!("{:X} ", x),
        }
    }
    print!("\n");
}
