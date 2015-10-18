mod op_codes;

use utils::IntUtils;

use std::cmp;
use std::fmt;
use std::collections::HashMap;
use std::rc::Rc;

use rustc_serialize::hex::FromHex;
use regex::Regex;

pub struct Context<'a> {
    data: Rc<ScriptElement<'a>>,
    stack: Vec<Vec<u8>>,
    valid: bool,
    altstack: Vec<Vec<u8>>,
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
    pub fn new(data: Rc<ScriptElement<'a>>, stack: Vec<Vec<u8>>) -> Context {
        Context {
            data: data,
            stack: stack,
            valid: true,
            altstack: vec![],
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
    human_readable_parser: HumanReadableParser,
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

        Parser {
            op_codes: op_codes,
            human_readable_parser: HumanReadableParser::new(&op_codes::OP_CODES),
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

    fn to_script_elements(&self, script_: Vec<u8>) -> Result<Vec<Box<ScriptElement>>, String> {
        let mut script = script_;
        let mut script_elements: Vec<Box<ScriptElement>> = vec![];
        let len = script.len();

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
                op_codes::OP_ELSE |
                op_codes::OP_NOTIF => { level -= 1 },
                _ => {},
            };

            script_elements.push((element, level));

            match code {
                op_codes::OP_IF | op_codes::OP_ELSE => { level += 1 },
                _ => {},
            };
        }

        if level != 0 {
            return Err(format!("Unbalanced IF or IF_NOT. level={}", level));
        }

        Ok(script_elements)
    }

    fn build_script<'a>(&'a self, script_elements_: Vec<(Box<ScriptElement<'a>>, u32)>,
                        parent: Option<Rc<ScriptElement<'a>>>,
                        level: u32) -> Option<(Rc<ScriptElement>, u32)>
    {
        let mut script_elements = script_elements_;

        while script_elements.len() > 1 {
            let endif = Some(Rc::new(*script_elements.pop().unwrap().0));
            script_elements.last_mut().unwrap().0.next = endif.clone();

            if script_elements.last().unwrap().1 != level {
                let branch = self.get_next_branch(&mut script_elements, level);
                let mut branching_el = script_elements.pop().unwrap();

                if branching_el.0.op_code.code == op_codes::OP_ELSE {
                    let if_branch = self.get_next_branch(&mut script_elements, level);
                    branching_el = script_elements.pop().unwrap();

                    branching_el.0.next =
                        Some(self.build_script(if_branch, endif.clone(), level + 1)
                                 .unwrap().0);

                    branching_el.0.next_else =
                        Some(self.build_script(branch, endif.clone(), level + 1)
                                 .unwrap().0);
                } else {
                    branching_el.0.next =
                        Some(self.build_script(branch, None, level + 1).unwrap().0);

                    branching_el.0.next_else = endif;
                }

                let branching_el_rc = Some((Rc::new(*branching_el.0), branching_el.1));
                if script_elements.len() == 0 {
                    return branching_el_rc.clone();
                }

                script_elements.last_mut().unwrap().0.next =
                    Some(branching_el_rc.unwrap().0);
            }
        }

        let mut last = script_elements.pop().unwrap();
        if parent.is_some() {
            last.0.next = parent;
        }

        Some((Rc::new(*last.0), last.1))
    }

    pub fn parse(&self, script: Vec<u8>) -> Result<Rc<ScriptElement>, String> {
        let elements = self.to_script_elements(script);
        let compiled = self.compile_ifs(elements.unwrap());
        let head     = self.build_script(compiled.unwrap(), None, 0);

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

    pub fn execute(&self, input_stack: Vec<Vec<u8>>,
                   parsed_script: Rc<ScriptElement>) -> bool {
        let mut context = Context::new(parsed_script, input_stack);
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

        return context.valid && op_codes::is_true(&context.stack.last());
    }
}

pub struct HumanReadableParser {
    op_codes_map: HashMap<String, u8>,
}

impl HumanReadableParser {
    pub fn new(op_codes: &[(&str, u8, bool, fn(Context) -> Context)])
    -> HumanReadableParser {
        let mut op_codes_map = HashMap::new();

        for op_code in op_codes.iter()
            .map(|op| (op.0.to_string(), op.1)) {
                op_codes_map.insert(op_code.0, op_code.1);
            };

        HumanReadableParser {
            op_codes_map: op_codes_map
        }
    }

    fn parse_non_op_code(&self, token: &str) -> Result<Vec<u8>, String> {
        let hex = Regex::new(r"^0x(?P<h>[0-9a-fA-F]+)$").unwrap();
        if hex.is_match(token) {
            return Ok(hex.replace_all(token, "$h").from_hex().unwrap());
        }

        let string = Regex::new(r"^'(?P<s>[^']*)'$").unwrap();
        if string.is_match(token) {
            let result = string.replace_all(token, "$s");
            return self.parse_string_literal(&result);
        }

        let number = Regex::new(r"^[+-]?[0-9]+$").unwrap();
        if number.is_match(token) {
            return self.parse_number(token);
        }

        Err(format!("Token not recognized `{}`\n", token))
    }

    fn parse_number(&self, token: &str) -> Result<Vec<u8>, String> {
        let result = token.parse::<i32>().unwrap();
        let mut result_array = IntUtils::to_vec_u8(result);
        let len = result_array.len();
        result_array.insert(0, len as u8);
        return Ok(result_array);
    }

    fn parse_string_literal(&self, token: &str) -> Result<Vec<u8>, String> {
        if token.len() > 75 {
            return Err(format!(
                    "The literal `{}` is too long, the maximum length allowed is 75.",
                    token));
        }

        let mut result_array = Vec::new();

        result_array.push(token.len() as u8);
        result_array.extend(token.as_bytes().iter().cloned());
        return Ok(result_array);
    }

    fn get_op_codes(&self, token: &str) -> Result<Vec<u8>, String> {
        match self.op_codes_map.get(&token.to_string()) {
            Some(x) => Ok(vec![*x]),
            None => self.parse_non_op_code(token),
        }
    }

    pub fn parse(&self, script: &str) -> Result<Vec<u8>, String> {
        let mut result: Vec<u8> = vec![];

        for s in script.split(" ") {
            let op_codes = self.get_op_codes(s);
            match op_codes {
                Err(x) => return Err(x),
                Ok(x) => {
                    for op_code in x {
                        result.push(op_code);
                    };
                },
            };
        }

        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::rc::Rc;

    fn print_script(head: Rc<ScriptElement>) {
        print!("{:?} -(next)-> {:?} -(else)-> {:?}\n",
            head, head.next.clone(), head.next_else.clone());

        if head.next.is_some() {
            print_script(head.next.clone().unwrap());
        }
        if head.next_else.is_some() {
            print_script(head.next_else.clone().unwrap());
        }
    }

    fn test_parse_execute(script: &str, expected: bool) {
        print!("\n\n {}\n", script);
        let parser = Parser::new();

        let raw_script = parser.preprocess_human_readable(script).unwrap();
        let data = parser.parse(raw_script.clone());

        match &data {
            &Ok(_) => {},
            &Err(ref x) => print!("Error: {}\n", x),
        }

        assert!(data.is_ok());
        print_script(data.clone().unwrap());

        let mut el = Some(data.clone().unwrap());
        while el != None {
            let e = el.unwrap();

            // Test that the id and the actual position in the script coincide
            // TODO: test both branches of the if.
            assert_eq!(raw_script[e.id], e.op_code.code);

            el = e.next.clone();
        }

        assert_eq!(parser.execute(vec![], data.unwrap()), expected);
    }

    #[test]
    fn test_execute_success() {
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
    }
}
