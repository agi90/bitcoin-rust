use regex::Regex;
use rustc_serialize::hex::FromHex;

use std::collections::HashMap;

use super::Context;
use utils::IntUtils;

pub struct Parser {
    op_codes_map: HashMap<String, u8>,
}

impl Parser {
    pub fn new(op_codes: &[(&str, u8, bool, fn(Context) -> Context)])
    -> Parser {
        let mut op_codes_map = HashMap::new();

        for op_code in op_codes.iter()
            .map(|op| (op.0.to_string(), op.1)) {
                op_codes_map.insert(op_code.0, op_code.1);
            };

        Parser {
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
        let result = token.parse::<i64>().unwrap();
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
            if s.len() == 0 { continue; }
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
