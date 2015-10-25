mod op_codes;
mod human_parser;

use utils::IntUtils;

use std::cmp;
use std::fmt;
use std::collections::HashMap;
use std::rc::Rc;

pub struct Context<'a> {
    data: Rc<ScriptElement<'a>>,
    stack: Vec<Vec<u8>>,
    valid: bool,
    altstack: Vec<Vec<u8>>,
    codeseparator: usize,
    // fn(codeseparator: usize, pub_key_str: Vec<u8>, sig_str: Vec<u8) -> bool
    checksig: fn(usize, &Vec<u8>, &Vec<u8>) -> bool,
    // Whether or not the last OP_IF, OP_ELSE or OP_NOTIF has been executed
    conditional_executed: Vec<bool>,
}

pub struct ScriptElement<'a> {
    op_code: &'a OpCode,
    data: Vec<u8>,
    next: Option<Rc<ScriptElement<'a>>>,
    next_else: Option<Rc<ScriptElement<'a>>>,
    id: usize,
}

pub struct OpCode {
    pub name: &'static str,
    pub code: u8,
    advancing: bool,
    parser: fn(Context) -> Context,
}

impl<'a> Context<'a> {
    pub fn new(data: Rc<ScriptElement<'a>>, stack: Vec<Vec<u8>>,
               checksig: fn(usize, &Vec<u8>, &Vec<u8>) -> bool) -> Context {
        Context {
            data: data,
            stack: stack,
            valid: true,
            altstack: vec![],
            codeseparator: 0,
            checksig: checksig,
            conditional_executed: vec![],
        }
    }
}

impl<'a> ScriptElement<'a> {
    pub fn new(op_code: &'a OpCode, data: Vec<u8>, id: usize) -> ScriptElement {
        ScriptElement {
            op_code: op_code,
            data: data,
            next: None,
            next_else: None,
            id: id,
        }
    }
}

impl<'a> cmp::PartialEq for ScriptElement<'a> {
    fn eq(&self, other: &ScriptElement) -> bool {
        self.op_code == other.op_code && self.data == other.data &&
            self.id == other.id
    }
}

impl<'a> fmt::Debug for ScriptElement<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "ScriptElement(id={}, op_code={:?}, data={:?})",
        self.id, self.op_code.name, self.data)
    }
}

impl OpCode {
    fn new(name: &'static str, code: u8, advancing: bool,
           parser: fn(Context) -> Context) -> OpCode {
        OpCode {
            name: name,
            code: code,
            advancing: advancing,
            parser: parser,
        }
    }
}

pub struct Parser {
    op_codes : HashMap<u8, OpCode>,
    human_readable_parser: human_parser::Parser,
}

impl Parser {
    pub fn new() -> Parser {
        let mut op_codes = HashMap::new();

        for op_code in op_codes::OP_CODES.iter()
            .map(|op| (op.1, OpCode::new(op.0, op.1, op.2, op.3))) {
                op_codes.insert(op_code.0, op_code.1);
            };

        for op in 0x01..0x4c {
            op_codes.insert(op, OpCode::new(op_codes::OP_PUSHDATA.0,
                                            op,
                                            op_codes::OP_PUSHDATA.2,
                                            op_codes::OP_PUSHDATA.3));
        }

        for op in 0xbau16..0x100u16 {
            op_codes.insert(op as u8, OpCode::new(op_codes::OP_INVALID.0,
                                            op as u8,
                                            op_codes::OP_INVALID.2,
                                            op_codes::OP_INVALID.3));
        }

        Parser {
            op_codes: op_codes,
            human_readable_parser: human_parser::Parser::new(&op_codes::OP_CODES),
        }
    }

    pub fn preprocess_human_readable(&self, script: &str) -> Result<Vec<u8>, String> {
        self.human_readable_parser.parse(script)
    }

    pub fn parse_human_readable(&self, script: &str) -> Result<Rc<ScriptElement>, String> {
        let human_parsed = self.preprocess_human_readable(script);

        match human_parsed {
            Err(x) => Err(x),
            Ok(x) => self.parse(x),
        }
    }

    fn get_data(&self, script: &mut Vec<u8>, bytes: i32) -> Result<Vec<u8>, String> {
        let mut data = Vec::new();

        for _ in 0..bytes {
            let el = script.pop();
            match el {
                Some(x) => data.push(x),
                None => return Err(format!("Unexpected end of data")),
            };
        }

        Ok(data)
    }

    fn get_data_bytes(&self, script: &mut Vec<u8>, bytes: u8) -> Result<Vec<u8>, String> {
        assert!(bytes <= 4);
        assert!(script.len() >= bytes as usize);

        let mut vec_u8_number: Vec<u8> = vec![];
        for _ in 0..bytes {
            vec_u8_number.push(script.pop().unwrap());
        }

        // TODO: Reasearch this better. It's unclear to me
        // whether PUSHDATA{1,2,4} have a u32 or a i32 as argument.
        // It feels wrong to have a u32 given that everything else
        // is a i32, but there are tests in the official client that
        // use 0xFF as argument for PUSHDATA1 which clearly is not a i32.
        let number = IntUtils::to_u32(&vec_u8_number);

        self.get_data(script, number as i32)
    }

    fn to_script_elements(&self, script_: Vec<u8>)
    -> Result<Vec<Box<ScriptElement>>, String> {
        let mut script = script_;
        let mut script_elements: Vec<Box<ScriptElement>> = vec![];
        let len = script.len();

        if script.len() == 0 {
            // When the script is empty we just return a singleton
            // with OP_NOP which is equivalent but makes things easier
            // for us
            let op_nop = self.op_codes.get(&op_codes::OP_NOP).unwrap();
            return Ok(vec![Box::new(ScriptElement::new(op_nop, vec![], 0))]);
        }

        script.reverse();
        while script.len() > 0 {
            let op_code = script.pop().unwrap();
            let op = match self.op_codes.get(&op_code) {
                Some(x) => x,
                None => return Err(format!("Op `0x{:2x}` not recognized.", op_code)),
            };

            let id = len - script.len() - 1;

            let data = match op.code {
                0x01 ... 0x4b => self.get_data(&mut script, op.code as i32),
                // PUSHDATA{1,2,4}
                0x4c ... 0x4e => {
                    let bytes = match op_code {
                        0x4c => 1,
                        0x4d => 2,
                        0x4e => 4,
                        _ => unreachable!(),
                    };

                    self.get_data_bytes(&mut script, bytes)
                },
                _ => Ok(vec![]),
            };

            let element = ScriptElement::new(op, data.unwrap(), id);
            script_elements.push(Box::new(element));
        }

        Ok(script_elements)
    }

    fn compile_ifs<'a>(&'a self, script_: Vec<Box<ScriptElement<'a>>>)
    -> Result<Vec<(Box<ScriptElement>, u32)>, String> {
        let mut script = script_;
        script.reverse();

        let mut script_elements: Vec<(Box<ScriptElement>, u32)> = vec![];
        let mut level = 0;

        while script.len() > 0 {
            let element = script.pop().unwrap();
            let code = element.op_code.code;

            match code {
                op_codes::OP_ENDIF |
                op_codes::OP_ELSE  => { level -= 1 },
                _ => {},
            };

            script_elements.push((element, level));

            match code {
                op_codes::OP_IF | op_codes::OP_ELSE | op_codes::OP_NOTIF => { level += 1 },
                _ => {},
            };
        }

        if level != 0 {
            return Err(format!("Unbalanced IF or IF_NOT. level={}", level));
        }

        Ok(script_elements)
    }


    fn build_script<'a>(&'a self, script_elements_: Vec<(Box<ScriptElement<'a>>, u32)>,
                        level: u32) -> Option<(Rc<ScriptElement>, u32)>
    {
        let mut script_elements = script_elements_;

        while script_elements.len() > 1 {
            let code = script_elements.last().unwrap().0.op_code.code;
            let parent = Rc::new(*script_elements.pop().unwrap().0);
            script_elements.last_mut().unwrap().0.next = Some(parent.clone());

            if code == op_codes::OP_ENDIF || code == op_codes::OP_ELSE {
                let branch = self.get_next_branch(&mut script_elements, level);
                let mut branching_el = script_elements.last_mut().unwrap();

                branching_el.0.next = if branch.len() > 0 {
                    Some(self.build_script(branch, level + 1).unwrap().0)
                } else {
                    Some(parent.clone())
                };

                branching_el.0.next_else = Some(parent);
            }
        }

        script_elements.pop().map(|x| (Rc::new(*x.0), x.1))
    }

    pub fn parse(&self, script: Vec<u8>) -> Result<Rc<ScriptElement>, String> {
        print!("parse={:?}\n", script);
        let elements = self.to_script_elements(script);
        let compiled = self.compile_ifs(elements.unwrap());
        let head     = self.build_script(compiled.unwrap(), 0);

        match head {
            Some(x) => {
                Ok(x.0)
            },
            None => Err(format!("Empty script")),
        }
    }

    fn get_next_branch<'a>(&'a self,
                           script_elements: &mut Vec<(Box<ScriptElement<'a>>, u32)>,
                           level: u32) -> Vec<(Box<ScriptElement<'a>>, u32)> {
        let mut branch = vec![];
        while script_elements.last().unwrap().1 != level {
            let el = script_elements.pop().unwrap();
            branch.insert(0, el);
        }
        branch
    }

    fn no_checksig_allowed(_: usize, _: &Vec<u8>, _: &Vec<u8>) -> bool { false }

    pub fn execute(&self, sig_script_: Vec<u8>, script_pub_key_: Vec<u8>,
                   checksig: fn(usize, &Vec<u8>, &Vec<u8>) -> bool)
    -> Result<bool, String> {
        let sig_script = try!(self.parse(sig_script_));
        let script_pub_key = try!(self.parse(script_pub_key_));

        // OP_CHECKSIG is not allowed when executing sigScript
        // TODO: ideally we should just invalidate the context
        let sig_script_context = try!(self.execute_base(vec![],
                                                        sig_script,
                                                        Parser::no_checksig_allowed));

        if !sig_script_context.valid {
            return Ok(false);
        }

        let script_pub_key_context = try!(self.execute_base(sig_script_context.stack,
                                                            script_pub_key, checksig));

        Ok(script_pub_key_context.valid &&
           op_codes::is_true(&script_pub_key_context.stack.last()))
    }

    fn execute_base<'a>(&'a self, input_stack: Vec<Vec<u8>>,
                   parsed_script: Rc<ScriptElement<'a>>,
                   checksig: fn(usize, &Vec<u8>, &Vec<u8>) -> bool)
    -> Result<Context, String> {
        let mut context = Context::new(parsed_script, input_stack, checksig);
        let mut done = false;

        while !done && context.valid {
            let ref advancing = context.data.op_code.advancing;
            let ref parser = context.data.op_code.parser;

            let mut new_context = parser(context);

            if !advancing {
                match new_context.data.next.clone() {
                    Some(ref x) => new_context.data = x.clone(),
                    None => done = true,
                }
            }

            context = new_context;
        }

        Ok(context)
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use std::rc::Rc;

    mod official_test;

    fn mock_checksig(_: usize, _: &Vec<u8>, _: &Vec<u8>) -> bool { true }

    fn equal_checksig(_: usize, x: &Vec<u8>, y: &Vec<u8>) -> bool { x.eq(y) }

    fn print_script(head: Rc<ScriptElement>) {
        print!("{:?} -(next)-> {:?} -(else)-> {:?}\n",
            head, head.next.clone(), head.next_else.clone());

        if head.next.is_some() {
            print_script(head.next.clone().unwrap());
        }
    }

    fn check_script(script: &str, parser: &Parser) -> Result<bool, String> {
        let raw_script = try!(parser.preprocess_human_readable(script));
        let data = try!(parser.parse(raw_script.clone()));

        if raw_script.len() == 0 {
            return Ok(true);
        }

        print_script(data.clone());

        let mut el = Some(data.clone());
        while el != None {
            let e = el.unwrap();

            // Test that the id and the actual position in the script coincide
            // TODO: test both branches of the if.
            if raw_script[e.id] != e.op_code.code {
                return Err(
                    format!("Mismatched op at {}, {} != {}\n", e.id, raw_script[e.id], e.op_code.code));
            }

            el = e.next.clone();
        }

        Ok(true)
    }

    fn test_base(script_sig: &str,
                 script_pub_key: &str,
                 expected: bool,
                 checksig: fn(usize, &Vec<u8>, &Vec<u8>) -> bool) -> Result<bool, String> {
        print!("\n\n sig=`{}` pub_key=`{}` [expected={}]\n",
               script_sig, script_pub_key, expected);

        let parser = Parser::new();

        if script_sig.len() > 0 {
            try!(check_script(script_sig, &parser));
        }

        if script_pub_key.len() > 0 {
            try!(check_script(script_pub_key, &parser));
        }

        let raw_script_sig = parser.preprocess_human_readable(script_sig).unwrap();
        let raw_script_pub_key = parser.preprocess_human_readable(script_pub_key).unwrap();

        let result = parser.execute(raw_script_sig, raw_script_pub_key, checksig).unwrap();
        Ok(result == expected)
    }

    fn test_with_checksig(script_sig: &str,
                          script_pub_key: &str,
                          expected: bool,
                          checksig: fn(usize, &Vec<u8>, &Vec<u8>) -> bool) {
        assert!(test_base(script_sig, script_pub_key, expected, checksig).unwrap());
    }

    fn test_execute(script_sig: &str, script_pub_key: &str, expected: bool) {
        test_with_checksig(script_sig, script_pub_key, expected, mock_checksig);
    }

    fn test_parse_execute(script: &str, expected: bool) {
        test_with_checksig("", script, expected, mock_checksig);
    }

    #[test]
    fn test_official_client_compat() {
        let result = official_test::Tester::test(|sig, pub_key, _| {
            let result = test_base(sig, pub_key, true, mock_checksig);
            result.is_ok() && result.unwrap()
        });

        assert_eq!(result, 576);
    }

    #[test]
    fn test_checksig() {
        test_with_checksig("", "1 1 CHECKSIG", true, equal_checksig);
        test_with_checksig("", "1 2 CHECKSIG", false, equal_checksig);
        test_with_checksig("", "'this_is_my_sig' 'this_is_my_sig' CHECKSIG", true, equal_checksig);
        test_with_checksig("", "0 'a' 'b' 2 'c' 'd' 'a' 'b' 4 CHECKMULTISIGVERIFY DEPTH 0 EQUAL",
                           true, equal_checksig);
        test_with_checksig("", "0 'a' 'b' 2 'c' 'd' 'b' 'a' 4 CHECKMULTISIGVERIFY DEPTH 0 EQUAL",
                           false, equal_checksig);
        test_with_checksig("", "0 'a' 1 'b' 1 CHECKMULTISIGVERIFY DEPTH 0 EQUAL",
                           false, equal_checksig);
        test_with_checksig("", "0 'a' 1 'b' 'c' 2 CHECKMULTISIGVERIFY DEPTH 0 EQUAL",
                           false, equal_checksig);
        test_with_checksig("", "0 'a' 1 'b' 'c' 'd' 3 CHECKMULTISIGVERIFY DEPTH 0 EQUAL",
                           false, equal_checksig);
        test_with_checksig("", "0 'a' 1 'b' 'c' 'd' 'a' 4 CHECKMULTISIGVERIFY DEPTH 0 EQUAL",
                           true, equal_checksig);
    }

    #[test]
    fn test_execute_success() {
        test_execute("1 2", "2 EQUALVERIFY 1 EQUAL", true);

        test_parse_execute("1 1 IF IF 1 ELSE 0 ENDIF ENDIF", true);
        test_parse_execute("1 0 IF IF 1 ELSE 0 ENDIF ENDIF", true);
        test_parse_execute("1 0 IF IF 1 ELSE 0 ENDIF ENDIF", true);
        test_parse_execute("0 1 IF IF 1 ELSE 0 ENDIF ENDIF", false);

        test_parse_execute("0 0 EQUAL", true);
        test_parse_execute("1 0 EQUAL", false);
        test_parse_execute("1 1 EQUAL", true);
        test_parse_execute("1 2 EQUAL", false);
        test_parse_execute("1 0x02 0x0100 EQUAL", false);
        test_parse_execute("1 0x02 0x0100 NUMEQUAL", true);
        test_parse_execute("0 0x01 0x80 EQUAL", false);
        test_parse_execute("0 0x01 0x80 NUMEQUAL", true);

        test_parse_execute("0 1 1 EQUALVERIFY", false);
        test_parse_execute("1 1 1 EQUALVERIFY", true);
        test_parse_execute("1 1 2 EQUALVERIFY", false);

        test_parse_execute("0 IF 1 ELSE 0 ENDIF", false);
        test_parse_execute("1 IF 1 ELSE 0 ENDIF", true);

        test_parse_execute("1 1 VERIFY", true);
        test_parse_execute("1 VERIFY 1", true);
        test_parse_execute("1 VERIFY 0", false);
        test_parse_execute("0 VERIFY", false);

        test_parse_execute("0 1 IFDUP EQUALVERIFY 1", true);
        test_parse_execute("1 0 IFDUP EQUALVERIFY 1", false);

        test_parse_execute("DEPTH 0 EQUAL", true);
        test_parse_execute("1 DEPTH 1 EQUAL", true);
        test_parse_execute("1 1 DEPTH 2 EQUAL", true);
        test_parse_execute("1 1 1 DEPTH 3 EQUAL", true);
        test_parse_execute("1 1 1 1 DEPTH 4 EQUAL", true);
        test_parse_execute("1 1 1 1 1 DEPTH 5 EQUAL", true);
        test_parse_execute("1 1 1 1 1 1 DEPTH 6 EQUAL", true);
        test_parse_execute("1 1 1 1 1 1 1 DEPTH 7 EQUAL", true);
        test_parse_execute("1 1 1 1 1 1 1 1 DEPTH 8 EQUAL", true);
        test_parse_execute("1 1 1 1 1 1 1 1 1 DEPTH 9 EQUAL", true);
        test_parse_execute("1 1 1 1 1 1 1 1 1 1 DEPTH 10 EQUAL", true);
        test_parse_execute("1 1 1 1 1 1 1 1 1 1 1 DEPTH 11 EQUAL", true);
        test_parse_execute("1 1 1 1 1 1 1 1 1 1 1 1 DEPTH 12 EQUAL", true);
        test_parse_execute("1 1 1 1 1 1 1 1 1 1 1 1 1 DEPTH 13 EQUAL", true);
        test_parse_execute("1 1 1 1 1 1 1 1 1 1 1 1 1 1 DEPTH 14 EQUAL", true);
        test_parse_execute("1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 DEPTH 15 EQUAL", true);
        test_parse_execute("1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 DEPTH 16 EQUAL", true);

        test_parse_execute("DROP DEPTH 0 EQUAL", true);
        test_parse_execute("1 DROP DEPTH 0 EQUAL", true);
        test_parse_execute("1 1 DROP DEPTH 1 EQUAL", true);

        test_parse_execute("1 NIP 1 EQUAL", true);
        test_parse_execute("2 1 NIP 1 EQUAL", true);
        test_parse_execute("3 2 1 NIP 1 EQUALVERIFY 3 EQUAL", true);

        test_parse_execute("1 2 3 OVER 2 EQUALVERIFY 3 EQUALVERIFY 2 EQUALVERIFY 1 EQUAL", true);
        test_parse_execute("1 2 OVER 1 EQUALVERIFY 2 EQUALVERIFY 1 EQUAL", true);
        test_parse_execute("2 1 OVER EQUALVERIFY", false);

        test_parse_execute("1 0 PICK EQUAL", true);
        test_parse_execute("3 2 1 PICK 3 EQUALVERIFY 2 EQUALVERIFY 3 EQUAL", true);
        test_parse_execute("4 3 2 2 PICK 4 EQUALVERIFY 2 EQUALVERIFY 3 EQUALVERIFY 4 EQUAL", true);

        test_parse_execute("1 0 ROLL 1 EQUAL", true);
        test_parse_execute("3 2 1 ROLL 3 EQUALVERIFY 2 EQUAL", true);
        test_parse_execute("4 3 2 2 ROLL 4 EQUALVERIFY 2 EQUALVERIFY 3 EQUAL", true);

        test_parse_execute("1 2 3 ROT 1 EQUALVERIFY 3 EQUALVERIFY 2 EQUAL", true);
        test_parse_execute("1 2 3 ROT ROT ROT 3 EQUALVERIFY 2 EQUALVERIFY 1 EQUAL", true);

        test_parse_execute("1 0 SWAP 1 EQUALVERIFY 0 EQUAL", true);
        test_parse_execute("1 0 SWAP SWAP 0 EQUALVERIFY 1 EQUAL", true);
        test_parse_execute("1 2 SWAP 1 EQUALVERIFY 2 EQUAL", true);

        test_parse_execute("1 1 2DROP DEPTH 0 EQUAL", true);
        test_parse_execute("1 1 1 2DROP DEPTH 1 EQUAL", true);
        test_parse_execute("1 1 1 1 2DROP DEPTH 2 EQUAL", true);

        test_parse_execute("1 2 2DUP 2 EQUALVERIFY 1 EQUALVERIFY 2 EQUALVERIFY 1 EQUAL", true);
        test_parse_execute("2 3 2DUP 3 EQUALVERIFY 2 EQUALVERIFY 3 EQUALVERIFY 2 EQUAL", true);
        test_parse_execute("1 2 3 3DUP 3 EQUALVERIFY 2 EQUALVERIFY 1 EQUALVERIFY 3 EQUALVERIFY 2 EQUALVERIFY 1 EQUAL", true);
        test_parse_execute("2 3 4 3DUP 4 EQUALVERIFY 3 EQUALVERIFY 2 EQUALVERIFY 4 EQUALVERIFY 3 EQUALVERIFY 2 EQUAL", true);
        test_parse_execute("1 1 1 3DUP 3DUP 3DUP DEPTH 12 EQUAL", true);

        test_parse_execute("1 2 TUCK 2 EQUALVERIFY 1 EQUALVERIFY 2 EQUAL", true);

        test_parse_execute("1 2 3 4 2OVER 2 EQUALVERIFY 1 EQUALVERIFY 4 EQUALVERIFY 3 EQUALVERIFY 2 EQUALVERIFY 1 EQUAL", true);

        test_parse_execute("1 2 3 4 5 6 2ROT 2 EQUALVERIFY 1 EQUALVERIFY 6 EQUALVERIFY 5 EQUALVERIFY 4 EQUALVERIFY 3 EQUAL", true);

        test_parse_execute("1 2 3 4 2SWAP 2 EQUALVERIFY 1 EQUALVERIFY 4 EQUALVERIFY 3 EQUAL", true);

        test_parse_execute("4 TOALTSTACK 11 FROMALTSTACK 4 EQUALVERIFY 11 EQUAL", true);
        test_parse_execute("1 TOALTSTACK FROMALTSTACK", true);
        test_parse_execute("0 TOALTSTACK 1", true);

        test_parse_execute("0 SIZE", false);
        test_parse_execute("1 SIZE", true);
        test_parse_execute("0 SIZE 0 EQUAL", true);
        test_parse_execute("0 SIZE EQUAL", true);
        test_parse_execute("1 SIZE 1 EQUAL", true);
        test_parse_execute("1 SIZE EQUAL", true);
        test_parse_execute("2 SIZE 1 EQUAL", true);
        test_parse_execute("12 SIZE 1 EQUALVERIFY 12 EQUAL", true);
        test_parse_execute("0x05 0xaabbccddee SIZE 5 EQUAL", true);
        test_parse_execute("0x06 0x6c6f6c777574 SIZE 6 EQUAL", true);
        test_parse_execute("0x01 0x6c SIZE 1 EQUAL", true);

        test_parse_execute("'' SIZE 0 EQUAL", true);
        test_parse_execute("'a' SIZE 1 EQUAL", true);
        test_parse_execute("'abcdefghil' SIZE 10 EQUALVERIFY 0x0a 0x6162636465666768696c EQUAL", true);
        test_parse_execute("'漢字' SIZE 6 EQUAL", true);

        test_parse_execute("0 1ADD 1 EQUAL", true);
        test_parse_execute("1 1ADD 2 EQUAL", true);

        test_parse_execute("1 1SUB 0 EQUAL", true);
        test_parse_execute("2 1SUB 1 EQUAL", true);

        test_parse_execute("444 1SUB 443 EQUAL", true);

        test_parse_execute("PUSHDATA1 0x01 0x02 0x01 0x02 EQUAL", true);
        test_parse_execute("PUSHDATA2 0x0100 0x02 0x01 0x02 EQUAL", true);
        test_parse_execute("PUSHDATA4 0x01000000 0x02 0x01 0x02 EQUAL", true);

        // For some reason the official bitcoin clinet uses 0x4b - 0x4d for PUSHDATA1-4
        // so we chack that works too here
        test_parse_execute("0x4c 0x01 0x02 0x01 0x02 EQUAL", true);
        test_parse_execute("0x4d 0x0100 0x02 0x01 0x02 EQUAL", true);
        test_parse_execute("0x4e 0x01000000 0x02 0x01 0x02 EQUAL", true);

        // copied from https://github.com/bitcoin/bitcoin/blob/master/src/test/data/script_valid.json
        test_parse_execute("0 0 EQUAL", true);
        test_parse_execute("1 1 ADD 2 EQUAL", true);
        test_parse_execute("1 1ADD 2 EQUAL", true);
        test_parse_execute("111 1SUB 110 EQUAL", true);
        test_parse_execute("111 1 ADD 12 SUB 100 EQUAL", true);
        test_parse_execute("0 ABS 0 EQUAL", true);
        test_parse_execute("16 ABS 16 EQUAL", true);
        test_parse_execute("-16 ABS -16 NEGATE EQUAL", true);
        test_parse_execute("0 NOT NOP", true);
        test_parse_execute("1 NOT 0 EQUAL", true);
        test_parse_execute("11 NOT 0 EQUAL", true);
        test_parse_execute("0 0NOTEQUAL 0 EQUAL", true);
        test_parse_execute("1 0NOTEQUAL 1 EQUAL", true);
        test_parse_execute("111 0NOTEQUAL 1 EQUAL", true);
        test_parse_execute("-111 0NOTEQUAL 1 EQUAL", true);
        test_parse_execute("1 1 BOOLAND NOP", true);
        test_parse_execute("1 0 BOOLAND NOT", true);
        test_parse_execute("0 1 BOOLAND NOT", true);
        test_parse_execute("0 0 BOOLAND NOT", true);
        test_parse_execute("16 17 BOOLAND NOP", true);
        test_parse_execute("1 1 BOOLOR NOP", true);
        test_parse_execute("1 0 BOOLOR NOP", true);
        test_parse_execute("0 1 BOOLOR NOP", true);
        test_parse_execute("0 0 BOOLOR NOT", true);
        test_parse_execute("16 17 BOOLOR NOP", true);
        test_parse_execute("11 10 1 ADD NUMEQUAL", true);
        test_parse_execute("11 10 1 ADD NUMEQUALVERIFY 1", true);
        test_parse_execute("11 10 1 ADD NUMNOTEQUAL NOT", true);
        test_parse_execute("111 10 1 ADD NUMNOTEQUAL", true);
        test_parse_execute("11 10 LESSTHAN NOT", true);
        test_parse_execute("4 4 LESSTHAN NOT", true);
        test_parse_execute("10 11 LESSTHAN", true);
        test_parse_execute("-11 11 LESSTHAN", true);
        test_parse_execute("-11 -10 LESSTHAN", true);
        test_parse_execute("11 10 GREATERTHAN", true);
        test_parse_execute("4 4 GREATERTHAN NOT", true);
        test_parse_execute("10 11 GREATERTHAN NOT", true);
        test_parse_execute("-11 11 GREATERTHAN NOT", true);
        test_parse_execute("-11 -10 GREATERTHAN NOT", true);
        test_parse_execute("11 10 LESSTHANOREQUAL NOT", true);
        test_parse_execute("4 4 LESSTHANOREQUAL", true);
        test_parse_execute("10 11 LESSTHANOREQUAL", true);
        test_parse_execute("-11 11 LESSTHANOREQUAL", true);
        test_parse_execute("-11 -10 LESSTHANOREQUAL", true);
        test_parse_execute("11 10 GREATERTHANOREQUAL", true);
        test_parse_execute("4 4 GREATERTHANOREQUAL", true);
        test_parse_execute("10 11 GREATERTHANOREQUAL NOT", true);
        test_parse_execute("-11 11 GREATERTHANOREQUAL NOT", true);
        test_parse_execute("-11 -10 GREATERTHANOREQUAL NOT", true);
        test_parse_execute("1 0 MIN 0 NUMEQUAL", true);
        test_parse_execute("0 1 MIN 0 NUMEQUAL", true);
        test_parse_execute("-1 0 MIN -1 NUMEQUAL", true);
        test_parse_execute("0 -2147483647 MIN -2147483647 NUMEQUAL", true);
        test_parse_execute("2147483647 0 MAX 2147483647 NUMEQUAL", true);
        test_parse_execute("0 100 MAX 100 NUMEQUAL", true);
        test_parse_execute("-100 0 MAX 0 NUMEQUAL", true);
        test_parse_execute("0 -2147483647 MAX 0 NUMEQUAL", true);
        test_parse_execute("0 0 1 WITHIN", true);
        test_parse_execute("1 0 1 WITHIN NOT", true);
        test_parse_execute("0 -2147483647 2147483647 WITHIN", true);
        test_parse_execute("-1 -100 100 WITHIN", true);
        test_parse_execute("11 -100 100 WITHIN", true);
        test_parse_execute("-2147483647 -100 100 WITHIN NOT", true);
        test_parse_execute("2147483647 -100 100 WITHIN NOT", true);
        test_parse_execute("'' RIPEMD160 0x14 0x9c1185a5c5e9fc54612808977ee8f548b2258d31 EQUAL", true);
        test_parse_execute("'a' RIPEMD160 0x14 0x0bdc9d2d256b3ee9daae347be6f4dc835a467ffe EQUAL", true);
        test_parse_execute("'abcdefghijklmnopqrstuvwxyz' RIPEMD160 0x14 0xf71c27109c692c1b56bbdceb5b9d2865b3708dbc EQUAL", true);
        test_parse_execute("'' SHA1 0x14 0xda39a3ee5e6b4b0d3255bfef95601890afd80709 EQUAL", true);
        test_parse_execute("'a' SHA1 0x14 0x86f7e437faa5a7fce15d1ddcb9eaeaea377667b8 EQUAL", true);
        test_parse_execute("'abcdefghijklmnopqrstuvwxyz' SHA1 0x14 0x32d10c7b8cf96570ca04ce37f2a19d84240d3a89 EQUAL", true);
        test_parse_execute("'' SHA256 0x20 0xe3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 EQUAL", true);
        test_parse_execute("'a' SHA256 0x20 0xca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb EQUAL", true);
        test_parse_execute("'abcdefghijklmnopqrstuvwxyz' SHA256 0x20 0x71c480df93d6ae2f1efad1447c66c9525e316218cf51fc8d9ed832f2daf18b73 EQUAL", true);
        test_parse_execute("'' DUP HASH160 SWAP SHA256 RIPEMD160 EQUAL", true);
        test_parse_execute("'' DUP HASH256 SWAP SHA256 SHA256 EQUAL", true);
        test_parse_execute("'' NOP HASH160 0x14 0xb472a266d0bd89c13706a4132ccfb16f7c3b9fcb EQUAL", true);
        test_parse_execute("'a' HASH160 NOP 0x14 0x994355199e516ff76c4fa4aab39337b9d84cf12b EQUAL", true);
        test_parse_execute("'' HASH256 0x20 0x5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456 EQUAL", true);
        test_parse_execute("'a' HASH256 0x20 0xbf5d3affb73efd2ec6c36ad3112dd933efed63c4e1cbffcfa88e2759c144f2d8 EQUAL", true);
        test_parse_execute("0x4c 0x4b 0x111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111 0x4b 0x111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111 EQUAL", true);
        test_parse_execute("0x4d 0xFF00 0x111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111 0x4c 0xFF 0x111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111 EQUAL", true);
        test_parse_execute("0 0 0 CHECKMULTISIG VERIFY DEPTH 0 EQUAL", true);
        test_parse_execute("0 0 0 CHECKMULTISIGVERIFY DEPTH 0 EQUAL", true);
        test_parse_execute("0 0 0 1 CHECKMULTISIG VERIFY DEPTH 0 EQUAL", true);
        test_parse_execute("0 0 0 1 CHECKMULTISIGVERIFY DEPTH 0 EQUAL", true);

        test_parse_execute("0 0 'a' 'b' 2 CHECKMULTISIG VERIFY DEPTH 0 EQUAL", true);
        test_parse_execute("0 0 'a' 'b' 'c' 3 CHECKMULTISIG VERIFY DEPTH 0 EQUAL", true);
        test_parse_execute("0 0 'a' 'b' 'c' 'd' 4 CHECKMULTISIG VERIFY DEPTH 0 EQUAL", true);
        test_parse_execute("0 0 'a' 'b' 'c' 'd' 'e' 5 CHECKMULTISIG VERIFY DEPTH 0 EQUAL", true);
        test_parse_execute("0 0 'a' 'b' 'c' 'd' 'e' 'f' 6 CHECKMULTISIG VERIFY DEPTH 0 EQUAL", true);
        test_parse_execute("0 0 'a' 'b' 'c' 'd' 'e' 'f' 'g' 7 CHECKMULTISIG VERIFY DEPTH 0 EQUAL", true);
        test_parse_execute("0 0 'a' 'b' 'c' 'd' 'e' 'f' 'g' 'h' 8 CHECKMULTISIG VERIFY DEPTH 0 EQUAL", true);
        test_parse_execute("0 0 'a' 'b' 'c' 'd' 'e' 'f' 'g' 'h' 'i' 9 CHECKMULTISIG VERIFY DEPTH 0 EQUAL", true);
        test_parse_execute("0 0 'a' 'b' 'c' 'd' 'e' 'f' 'g' 'h' 'i' 'j' 10 CHECKMULTISIG VERIFY DEPTH 0 EQUAL", true);
        test_parse_execute("0 0 'a' 'b' 'c' 'd' 'e' 'f' 'g' 'h' 'i' 'j' 'k' 11 CHECKMULTISIG VERIFY DEPTH 0 EQUAL", true);
        test_parse_execute("0 0 'a' 'b' 'c' 'd' 'e' 'f' 'g' 'h' 'i' 'j' 'k' 'l' 12 CHECKMULTISIG VERIFY DEPTH 0 EQUAL", true);
        test_parse_execute("0 0 'a' 'b' 'c' 'd' 'e' 'f' 'g' 'h' 'i' 'j' 'k' 'l' 'm' 13 CHECKMULTISIG VERIFY DEPTH 0 EQUAL", true);
        test_parse_execute("0 0 'a' 'b' 'c' 'd' 'e' 'f' 'g' 'h' 'i' 'j' 'k' 'l' 'm' 'n' 14 CHECKMULTISIG VERIFY DEPTH 0 EQUAL", true);
        test_parse_execute("0 0 'a' 'b' 'c' 'd' 'e' 'f' 'g' 'h' 'i' 'j' 'k' 'l' 'm' 'n' 'o' 15 CHECKMULTISIG VERIFY DEPTH 0 EQUAL", true);
        test_parse_execute("0 0 'a' 'b' 'c' 'd' 'e' 'f' 'g' 'h' 'i' 'j' 'k' 'l' 'm' 'n' 'o' 'p' 16 CHECKMULTISIG VERIFY DEPTH 0 EQUAL", true);
        test_parse_execute("0 0 'a' 'b' 'c' 'd' 'e' 'f' 'g' 'h' 'i' 'j' 'k' 'l' 'm' 'n' 'o' 'p' 'q' 17 CHECKMULTISIG VERIFY DEPTH 0 EQUAL", true);
        test_parse_execute("0 0 'a' 'b' 'c' 'd' 'e' 'f' 'g' 'h' 'i' 'j' 'k' 'l' 'm' 'n' 'o' 'p' 'q' 'r' 18 CHECKMULTISIG VERIFY DEPTH 0 EQUAL", true);
        test_parse_execute("0 0 'a' 'b' 'c' 'd' 'e' 'f' 'g' 'h' 'i' 'j' 'k' 'l' 'm' 'n' 'o' 'p' 'q' 'r' 's' 19 CHECKMULTISIG VERIFY DEPTH 0 EQUAL", true);
        test_parse_execute("0 0 'a' 'b' 'c' 'd' 'e' 'f' 'g' 'h' 'i' 'j' 'k' 'l' 'm' 'n' 'o' 'p' 'q' 'r' 's' 't' 20 CHECKMULTISIG VERIFY DEPTH 0 EQUAL", true);
        test_parse_execute("0 0 'a' 1 CHECKMULTISIGVERIFY DEPTH 0 EQUAL", true);
        test_parse_execute("0 0 'a' 'b' 2 CHECKMULTISIGVERIFY DEPTH 0 EQUAL", true);
        test_parse_execute("0 0 'a' 'b' 'c' 3 CHECKMULTISIGVERIFY DEPTH 0 EQUAL", true);
        test_parse_execute("0 0 'a' 'b' 'c' 'd' 4 CHECKMULTISIGVERIFY DEPTH 0 EQUAL", true);
        test_parse_execute("0 0 'a' 'b' 'c' 'd' 'e' 5 CHECKMULTISIGVERIFY DEPTH 0 EQUAL", true);
        test_parse_execute("0 0 'a' 'b' 'c' 'd' 'e' 'f' 6 CHECKMULTISIGVERIFY DEPTH 0 EQUAL", true);
        test_parse_execute("0 0 'a' 'b' 'c' 'd' 'e' 'f' 'g' 7 CHECKMULTISIGVERIFY DEPTH 0 EQUAL", true);
        test_parse_execute("0 0 'a' 'b' 'c' 'd' 'e' 'f' 'g' 'h' 8 CHECKMULTISIGVERIFY DEPTH 0 EQUAL", true);
        test_parse_execute("0 0 'a' 'b' 'c' 'd' 'e' 'f' 'g' 'h' 'i' 9 CHECKMULTISIGVERIFY DEPTH 0 EQUAL", true);
        test_parse_execute("0 0 'a' 'b' 'c' 'd' 'e' 'f' 'g' 'h' 'i' 'j' 10 CHECKMULTISIGVERIFY DEPTH 0 EQUAL", true);
        test_parse_execute("0 0 'a' 'b' 'c' 'd' 'e' 'f' 'g' 'h' 'i' 'j' 'k' 11 CHECKMULTISIGVERIFY DEPTH 0 EQUAL", true);
        test_parse_execute("0 0 'a' 'b' 'c' 'd' 'e' 'f' 'g' 'h' 'i' 'j' 'k' 'l' 12 CHECKMULTISIGVERIFY DEPTH 0 EQUAL", true);
        test_parse_execute("0 0 'a' 'b' 'c' 'd' 'e' 'f' 'g' 'h' 'i' 'j' 'k' 'l' 'm' 13 CHECKMULTISIGVERIFY DEPTH 0 EQUAL", true);
        test_parse_execute("0 0 'a' 'b' 'c' 'd' 'e' 'f' 'g' 'h' 'i' 'j' 'k' 'l' 'm' 'n' 14 CHECKMULTISIGVERIFY DEPTH 0 EQUAL", true);
        test_parse_execute("0 0 'a' 'b' 'c' 'd' 'e' 'f' 'g' 'h' 'i' 'j' 'k' 'l' 'm' 'n' 'o' 15 CHECKMULTISIGVERIFY DEPTH 0 EQUAL", true);
        test_parse_execute("0 0 'a' 'b' 'c' 'd' 'e' 'f' 'g' 'h' 'i' 'j' 'k' 'l' 'm' 'n' 'o' 'p' 16 CHECKMULTISIGVERIFY DEPTH 0 EQUAL", true);
        test_parse_execute("0 0 'a' 'b' 'c' 'd' 'e' 'f' 'g' 'h' 'i' 'j' 'k' 'l' 'm' 'n' 'o' 'p' 'q' 17 CHECKMULTISIGVERIFY DEPTH 0 EQUAL", true);
        test_parse_execute("0 0 'a' 'b' 'c' 'd' 'e' 'f' 'g' 'h' 'i' 'j' 'k' 'l' 'm' 'n' 'o' 'p' 'q' 'r' 18 CHECKMULTISIGVERIFY DEPTH 0 EQUAL", true);
        test_parse_execute("0 0 'a' 'b' 'c' 'd' 'e' 'f' 'g' 'h' 'i' 'j' 'k' 'l' 'm' 'n' 'o' 'p' 'q' 'r' 's' 19 CHECKMULTISIGVERIFY DEPTH 0 EQUAL", true);
        test_parse_execute("0 0 'a' 'b' 'c' 'd' 'e' 'f' 'g' 'h' 'i' 'j' 'k' 'l' 'm' 'n' 'o' 'p' 'q' 'r' 's' 't' 20 CHECKMULTISIGVERIFY DEPTH 0 EQUAL", true);
    }
}
