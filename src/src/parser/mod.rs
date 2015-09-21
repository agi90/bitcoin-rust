mod op_codes;

use std::collections::HashMap;

pub enum ScriptElement {
    OpCode(OpCode),
    Data(u8),
}

pub struct BitcoinStack {
    data: Vec<ScriptElement>,
    stack: Vec<Vec<u8>>,
    valid: bool,
}

pub struct OpCode {
    pub name: String,
    pub code: u8,
    parser: Box<Fn(BitcoinStack) -> BitcoinStack>,
}

impl OpCode {
    fn new(name: &str, code: u8, parser: Box<Fn(BitcoinStack) -> BitcoinStack>) ->
    OpCode {
        OpCode {
            name: name.to_string(),
            code: code,
            parser: parser,
        }
    }
}

pub struct Parser {
    op_codes : HashMap<u8, OpCode>,
}

impl Parser {
    pub fn new() -> Parser {
        let mut op_codes = HashMap::new();
        
        op_codes.insert(0x76,
                        OpCode::new("OP_DUP", 0x76, Box::new(op_codes::OP_DUP)));

        op_codes.insert(0xa9,
                        OpCode::new("OP_HASH160", 0xa9, Box::new(op_codes::OP_HASH160)));

        // op_codes.insert(0x88, OpCode::new("OP_EQUALVERIFY", 0x88,
        //                                  &'a op_codes::OP_EQUALVERIFY));
        // op_codes.insert(0xac, OpCode::new("OP_CHECKSIG", 0xac, &'a op_codes::OP_CHECKSIG));
        Parser {
            op_codes: op_codes,
        }
    }

    pub fn parse(&self, script: Vec<u8>) -> Vec<ScriptElement> {
        let mut parsed : Vec<ScriptElement> = Vec::new();
        for opcode in script {
            let copy = self.op_codes.get(&opcode);
            match copy {
                Some(ref x) => parsed.push(ScriptElement::OpCode(x)),
                None => parsed.push(ScriptElement::Data(opcode)),
            };
        }

        return parsed;
    }
}
