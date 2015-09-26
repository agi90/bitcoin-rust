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

impl Parser {
    pub fn new() -> Parser {
        let mut op_codes = HashMap::new();
        
        op_codes.insert(0x76, OpCode::new("OP_DUP", 0x76,
                                          Box::new(op_codes::op_dup)));

        op_codes.insert(0xa9, OpCode::new("OP_HASH160", 0xa9,
                                          Box::new(op_codes::op_hash160)));

        op_codes.insert(0xaa, OpCode::new("OP_HASH256", 0xaa,
                                          Box::new(op_codes::op_hash256)));

        op_codes.insert(0x88, OpCode::new("OP_EQUALVERIFY", 0x88,
                                          Box::new(op_codes::op_equalverify)));

        Parser {
            op_codes: op_codes,
        }
    }

    pub fn parse(&self, script: Vec<u8>) -> Vec<ScriptElement> {
        let mut parsed : Vec<ScriptElement> = Vec::new();

        let mut data : u8 = 0;
        for opcode in script {
            if data > 0 {
                // If this opcode follows a 0x00-0x46 opcode, then it's just data
                parsed.push(ScriptElement::Data(opcode));
                data -= 1;
                continue;
            }

            match self.op_codes.get(&opcode) {
                Some(x) => parsed.push(ScriptElement::OpCode(x)),
                None => {
                    // This opcode will push `opcode` bytes to the stack
                    assert!(opcode < 0x47);
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
                    stack = self.push_to_stack(stack, x);
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

    fn push_to_stack<'a>(&'a self, stack: BitcoinStack<'a>, bytes: u8)
    -> BitcoinStack {
        let mut data : Vec<u8> = vec![];
        let mut new_stack = stack;

        for _ in 0..bytes {
            match new_stack.data.last().unwrap() {
                &ScriptElement::Data(x) => data.push(x),
                &ScriptElement::OpCode(_) => assert!(false),
            }

            new_stack.data.pop();
        }

        new_stack.stack.push(data);

        return new_stack;
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
