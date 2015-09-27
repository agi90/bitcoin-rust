mod op_codes;

use std::collections::HashMap;

pub enum ScriptElement<'a> {
    OpCode(&'a OpCode),
    Data(u8),
}

pub struct BitcoinStack<'a> {
    data: Vec<ScriptElement<'a>>,
    stack: Vec<Vec<u8>>,
    valid: bool,
}

impl<'a> BitcoinStack<'a> {
    pub fn new(data: Vec<ScriptElement<'a>>, stack: Vec<Vec<u8>>)
    -> BitcoinStack 
    {
        BitcoinStack {
            data: data,
            stack: stack,
            valid: true
        }
    }
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

const OP_CODES : [(&'static str, u8, fn(BitcoinStack) -> BitcoinStack); 28] = [
    ("OP_FALSE",        0x00, op_codes::op_false),
    // opcodes 0x01 - 0x4b op_pushdata
    ("OP_PUSHDATA1",    0x4c, op_codes::op_pushdata1),
    ("OP_PUSHDATA2",    0x4d, op_codes::op_pushdata2),
    ("OP_PUSHDATA4",    0x4e, op_codes::op_pushdata4),
    ("OP_1NEGATE",      0x4f, op_codes::op_1negate),
    // TODO: opcodes 0x50
    ("OP_1",            0x51, op_codes::op_1),
    ("OP_2",            0x52, op_codes::op_2),
    ("OP_3",            0x53, op_codes::op_3),
    ("OP_4",            0x54, op_codes::op_4),
    ("OP_5",            0x55, op_codes::op_5),
    ("OP_6",            0x56, op_codes::op_6),
    ("OP_7",            0x57, op_codes::op_7),
    ("OP_8",            0x58, op_codes::op_8),
    ("OP_9",            0x59, op_codes::op_9),
    ("OP_10",           0x5a, op_codes::op_10),
    ("OP_11",           0x5b, op_codes::op_11),
    ("OP_12",           0x5c, op_codes::op_12),
    ("OP_13",           0x5d, op_codes::op_13),
    ("OP_14",           0x5e, op_codes::op_14),
    ("OP_15",           0x5f, op_codes::op_15),
    ("OP_16",           0x60, op_codes::op_16),
    ("OP_NOP",          0x61, op_codes::op_nop),
    // TODO: opcodes 0x62 - 0x68
    ("OP_VERIFY",       0x69, op_codes::op_verify),
    ("OP_RETURN",       0x6a, op_codes::op_return),
    // TODO: opcodes 0x6b - 0x75
    ("OP_DUP",          0x76, op_codes::op_dup),
    // TODO: opcodes 0x77 - 0x87
    ("OP_EQUALVERIFY",  0x88, op_codes::op_equalverify),
    // TODO: opcodes 0x89 - 0xa8
    ("OP_HASH160",      0xa9, op_codes::op_hash160),
    ("OP_HASH256",      0xaa, op_codes::op_hash256),
    // TODO: opcodes 0xab - 0xff
];

impl Parser {
    pub fn new() -> Parser {
        let mut op_codes = HashMap::new();

        for op_code in OP_CODES.iter()
            .map(|op| (op.1, OpCode::new(op.0, op.1, Box::new(op.2)))) {
                op_codes.insert(op_code.0, op_code.1);
            };

        Parser {
            op_codes: op_codes,
        }
    }

    pub fn parse(&self, script: Vec<u8>) -> Vec<ScriptElement> {
        let mut parsed : Vec<ScriptElement> = Vec::new();

        let mut data : u8 = 0;
        for opcode in script {
            if data > 0 {
                // If this opcode follows a 0x01-0x4b opcode, then it's just data
                parsed.push(ScriptElement::Data(opcode));
                data -= 1;
                continue;
            }

            match self.op_codes.get(&opcode) {
                Some(x) => parsed.push(ScriptElement::OpCode(x)),
                None => {
                    // This opcode will push `opcode` bytes to the stack
                    assert!(opcode < 0x4c);
                    parsed.push(ScriptElement::Data(opcode));
                    data = opcode;
                }
            };
        }

        return parsed;
    }

    pub fn execute(&self, input_stack: Vec<Vec<u8>>,
                   parsed_script: Vec<ScriptElement>) -> bool {
        let mut script = parsed_script;
        script.reverse();

        let mut stack = BitcoinStack::new(script, input_stack);
        
        while !stack.data.is_empty() {
            match stack.data.last().unwrap() {
                &ScriptElement::Data(x) => {
                    assert!(x < 0x4c);

                    stack.data.pop();
                    stack = op_codes::op_pushdata(stack, x);
                },
                &ScriptElement::OpCode(x) => {
                    let ref parser = (*x).parser;
                    stack = parser(stack);
                    stack.data.pop();
                },
            };
        }

        return stack.valid;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use rustc_serialize::base64::FromBase64;

    fn test_parse_execute(script: &str, sig: &str, pub_key: &str) {
        let parser = Parser::new();

        let data = parser.parse(script.from_base64().unwrap());
        
        assert!(parser.execute(vec![sig.from_base64().unwrap(),
                                    pub_key.from_base64().unwrap()], data));
    }

    #[test]
    fn test_execute_success() {
        test_parse_execute("qRQQGIU2cPnzsFgsW57ozpN2SsMrk4g=",
                           "",
                           "A4KCJjISxgnZ6ipuPhct4jjYw5yr1awcoQZG4j/V9RUI");
    }
}
