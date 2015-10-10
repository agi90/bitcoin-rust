mod op_codes;

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
    human_readable_parser: HumanReadableParser,
}


impl Parser {
    pub fn new() -> Parser {
        let mut op_codes = HashMap::new();

        for op_code in op_codes::OP_CODES.iter()
            .map(|op| (op.1, OpCode::new(op.0, op.1, op.2, op.3))) {
                op_codes.insert(op_code.0, op_code.1);
            };

        Parser {
            op_codes: op_codes,
            op_pushdata: OpCode::new(op_codes::OP_PUSHDATA.0,
                                     op_codes::OP_PUSHDATA.1,
                                     op_codes::OP_PUSHDATA.2,
                                     op_codes::OP_PUSHDATA.3),
            human_readable_parser: HumanReadableParser::new(&op_codes::OP_CODES),
        }
    }

    pub fn parse_human_readable(&self, script: &str) -> Result<Rc<ScriptElement>, String> {
        let human_parsed = self.human_readable_parser.parse(script);

        match human_parsed {
            Err(x) => Err(x),
            Ok(x) => self.parse(x),
        }
    }

    pub fn parse(&self, script_: Vec<u8>) -> Result<Rc<ScriptElement>, String> {
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
                    element = ScriptElement::new(x, vec![], id);
                    id += 1;
                },
                None => {
                    // This opcode will push `op_code` bytes to the stack
                    assert!(op_code < 0x4c);
                    let mut data = Vec::new();

                    for _ in 0..op_code {
                        let el = script.pop();
                        match el {
                            Some(x) => data.push(x),
                            None => return Err(format!("Unexpected end of data")),
                        };
                    }

                    element = ScriptElement::new(&self.op_pushdata, data, id);
                    id += 1;
                },
            };

            if op_code == op_codes::OP_ENDIF || op_code == op_codes::OP_ELSE ||
               op_code == op_codes::OP_NOTIF {
                level -= 1;
            }

            script_elements.push((Box::new(element), level));

            if op_code == op_codes::OP_IF || op_code == op_codes::OP_ELSE {
                level += 1;
            }
        }

        if level != 0 {
            return Err(format!("Unbalanced OP_IF or IF_NOT. level={}", level));
        }

        let head = self.build_script(script_elements, None, 0);
        match head {
            Some(x) => {
                Ok(x.0)
            },
            None => Err(format!("Empty script")),
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

        while !done {
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

    fn parse_hex(&self, token: &str) -> Result<Vec<u8>, String> {
        let re = Regex::new(r"0x(?P<h>[0-9a-fA-F]+)").unwrap();
        let hex = re.replace_all(token, "$h").from_hex();

        match hex {
            Ok(x) => Ok(x),
            Err(_) => {
                Err(format!("Token not recognized `{}`\n", token))
            },
        }
    }

    fn get_op_codes(&self, token: &str) -> Result<Vec<u8>, String> {
        match self.op_codes_map.get(&token.to_string()) {
            Some(x) => Ok(vec![*x]),
            None => self.parse_hex(token),
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
        print!("\n\n");
        let parser = Parser::new();

        let data = parser.parse_human_readable(script);

        match &data {
            &Ok(_) => {},
            &Err(ref x) => print!("Error: {}\n", x),
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

        test_parse_execute("0 0 EQUAL", true);
        test_parse_execute("1 0 EQUAL", false);
        test_parse_execute("1 1 EQUAL", true);
        test_parse_execute("1 2 EQUAL", false);

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
    }
}
