mod op_codes;

use rustc_serialize::hex::FromHex;
use regex::Regex;

use std::cmp;
use std::fmt;
use std::collections::HashMap;
use std::rc::Rc;

pub struct Context<'a> {
    data: Rc<ScriptElement<'a>>,
    stack: Vec<Vec<u8>>,
    valid: bool,
}

pub struct ScriptElement<'a> {
    op_code: &'a OpCode,
    data: Vec<u8>,
    next: Option<Rc<ScriptElement<'a>>>,
    next_else: Option<Rc<ScriptElement<'a>>>,
    id: u32,
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
            valid: true
        }
    }
}

impl<'a> ScriptElement<'a> {
    pub fn new(op_code: &'a OpCode, data: Vec<u8>, id: u32) -> ScriptElement {
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
    op_pushdata : OpCode,
}

const OP_PUSHDATA : (&'static str, u8, bool, fn(Context) -> Context) =
    ("PUSHDATA",     0x01, false, op_codes::op_pushdata);

const OP_CODES : [(&'static str, u8, bool, fn(Context) -> Context); 30] = [
    ("0",            0x00, false, op_codes::op_false),
    // opcodes 0x02 - 0x4b op_pushdata
    ("1NEGATE",      0x4f, false, op_codes::op_1negate),
    // TODO: opcodes 0x50
    ("1",            0x51, false, op_codes::op_1),
    ("2",            0x52, false, op_codes::op_2),
    ("3",            0x53, false, op_codes::op_3),
    ("4",            0x54, false, op_codes::op_4),
    ("5",            0x55, false, op_codes::op_5),
    ("6",            0x56, false, op_codes::op_6),
    ("7",            0x57, false, op_codes::op_7),
    ("8",            0x58, false, op_codes::op_8),
    ("9",            0x59, false, op_codes::op_9),
    ("10",           0x5a, false, op_codes::op_10),
    ("11",           0x5b, false, op_codes::op_11),
    ("12",           0x5c, false, op_codes::op_12),
    ("13",           0x5d, false, op_codes::op_13),
    ("14",           0x5e, false, op_codes::op_14),
    ("15",           0x5f, false, op_codes::op_15),
    ("16",           0x60, false, op_codes::op_16),
    ("NOP",          0x61, false, op_codes::op_nop),
    ("IF",           0x63, true,  op_codes::op_if),
    ("NOTIF",        0x64, true,  op_codes::op_notif),
    ("ELSE",         0x67, false, op_codes::op_else),
    ("ENDIF",        0x68, false, op_codes::op_endif),
    ("NOP",          0x61, false, op_codes::op_nop),
    // TODO: opcodes 0x62 - 0x68
    ("VERIFY",       0x69, false, op_codes::op_verify),
    ("RETURN",       0x6a, false, op_codes::op_return),
    // TODO: opcodes 0x6b - 0x75
    ("DUP",          0x76, false, op_codes::op_dup),
    // TODO: opcodes 0x77 - 0x87
    ("EQUALVERIFY",  0x88, false, op_codes::op_equalverify),
    // TODO: opcodes 0x89 - 0xa8
    ("HASH160",      0xa9, false, op_codes::op_hash160),
    ("HASH256",      0xaa, false, op_codes::op_hash256),
    // TODO: opcodes 0xab - 0xff
];

const OP_IF: u8 = 0x63;
const OP_NOTIF: u8 = 0x64;
const OP_ELSE: u8 = 0x67;
const OP_ENDIF: u8 = 0x68;

impl Parser {
    pub fn new() -> Parser {
        let mut op_codes = HashMap::new();

        for op_code in OP_CODES.iter()
            .map(|op| (op.1, OpCode::new(op.0, op.1, op.2, op.3))) {
                op_codes.insert(op_code.0, op_code.1);
            };

        Parser {
            op_codes: op_codes,
            op_pushdata: OpCode::new(OP_PUSHDATA.0, OP_PUSHDATA.1, OP_PUSHDATA.2,
                                     OP_PUSHDATA.3),
        }
    }

    pub fn parse_human_readable(&self, script: &str) -> Result<Rc<ScriptElement>, &str> {
        let mut op_codes_map = HashMap::new();

        for op_code in OP_CODES.iter()
            .map(|op| (op.0, self.op_codes.get(&op.1))) {
                op_codes_map.insert(op_code.0, op_code.1);
            };

        let mut result = vec![];

        for s in script.split(" ") {
            match op_codes_map.get(&s) {
                Some(x) => {
                    result.push(x.unwrap().code);
                },
                None => {
                    let re = Regex::new(r"0x(?P<h>[0-9a-fA-F]+)").unwrap();
                    let hex = re.replace_all(s, "$h").from_hex();
                    match hex {
                        Ok(x) => {
                            for h in x {
                                result.push(h);
                            }
                        },
                        Err(_) => {
                            print!("Token not recognized `{}`\n", s);
                            return Err("Unable to parse hex.");
                        },
                    };

                },
            };
        }
        
        for h in &result {
            print!("{:x} ", h);
        }
        print!("\n");

        self.parse(result)
    }
    
    pub fn parse(&self, script_: Vec<u8>) -> Result<Rc<ScriptElement>, &str> {
        let mut script = script_;
        script.reverse();

        let mut script_elements: Vec<(Box<ScriptElement>, u32)> = vec![];
        let mut level = 0;
        let mut id = 0;

        while script.len() > 0 {
            let op_code = script.pop().unwrap();
            let element: ScriptElement;

            match self.op_codes.get(&op_code) {
                Some(x) => {
                    print!("op_code = {:?}\n", x);
                    element = ScriptElement::new(x, vec![], id);
                    id += 1;
                },
                None => {
                    // This opcode will push `op_code` bytes to the stack
                    assert!(op_code < 0x4c);
                    let mut data = Vec::new();

                    print!("op_code = {}\n", op_code);
                    for _ in 0..op_code {
                        let el = script.pop();
                        print!("popping {:?}\n", el);
                        match el {
                            Some(x) => data.push(x),
                            None => return Err("Unexpected end of data"),
                        };
                    }
                
                    element = ScriptElement::new(&self.op_pushdata, data, id);
                    id += 1;
                },
            };

            if op_code == OP_ENDIF || op_code == OP_ELSE || op_code == OP_NOTIF {
                level -= 1;
            }

            script_elements.push((Box::new(element), level));

            if op_code == OP_IF || op_code == OP_ELSE {
                level += 1;
            }
        }

        if level != 0 {
            return Err("Unbalanced OP_IF{,NOT}");
        }

        let head = self.build_script(script_elements, None, 0);
        match head {
            Some(x) => {
                Ok(x.0)
            },
            None => Err("Empty script"),
        }
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

                if branching_el.0.op_code.code == OP_ELSE { 
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

    fn get_next_branch<'a>(&'a self, script_elements: &mut Vec<(Box<ScriptElement<'a>>, u32)>,
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

        while !done {
            let ref advancing = context.data.op_code.advancing;
            let ref parser = context.data.op_code.parser;
            print!("op = {:?}\n", context.data.op_code);

            let mut new_context = parser(context);

            if !advancing {
                match new_context.data.next.clone() {
                    Some(ref x) => new_context.data = x.clone(),
                    None => done = true,
                }
            }

            context = new_context;
            print!("stack.stack = {:?}\n", context.stack);
        }

        return context.valid && op_codes::is_true(&context.stack.last());
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
        print!("\n\n");
        let parser = Parser::new();

        let data = parser.parse_human_readable(script);
    
        match data {
            Ok(_) => {},
            Err(x) => print!("Error: {}\n", x),
        }

        assert!(data.is_ok());
        print_script(data.clone().unwrap());

        assert!(parser.execute(vec![], data.unwrap()) == expected);
    }

    #[test]
    fn test_execute_success() {
        test_parse_execute("1 1 IF IF 1 ELSE 0 ENDIF ENDIF", true);
        test_parse_execute("1 0 IF IF 1 ELSE 0 ENDIF ENDIF", true);
        test_parse_execute("1 0 IF IF 1 ELSE 0 ENDIF ENDIF", true);
        test_parse_execute("0 1 IF IF 1 ELSE 0 ENDIF ENDIF", false);
        test_parse_execute("0 1 1 EQUALVERIFY", false);
        test_parse_execute("1 1 1 EQUALVERIFY", true);
        test_parse_execute("1 1 2 EQUALVERIFY", false);
        test_parse_execute("0 IF 1 ELSE 0 ENDIF", false);
        test_parse_execute("1 IF 1 ELSE 0 ENDIF", true);
        test_parse_execute("1 1 VERIFY", true);
        test_parse_execute("1 VERIFY", true);
        test_parse_execute("1 VERIFY 0", false);
        test_parse_execute("0 VERIFY", false);
    }
}
