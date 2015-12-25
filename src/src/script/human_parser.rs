use regex::Regex;
use rustc_serialize::hex::FromHex;

use std::cmp;

use super::op_codes::OpCode;
use utils::IntUtils;

pub struct Parser;

impl Parser {
    fn parse_non_op_code(token: &str) -> Result<Vec<u8>, String> {
        let hex = Regex::new(r"^0x(?P<h>[0-9a-fA-F]+)$").unwrap();
        if hex.is_match(token) {
            return Ok(hex.replace_all(token, "$h").from_hex().unwrap());
        }

        let string = Regex::new(r"^'(?P<s>[^']*)'$").unwrap();
        if string.is_match(token) {
            let result = string.replace_all(token, "$s");
            return Self::parse_string_literal(&result);
        }

        let number = Regex::new(r"^[+-]?[0-9]+$").unwrap();
        if number.is_match(token) {
            return Self::parse_number(token);
        }

        Err(format!("Token not recognized `{}`\n", token))
    }

    fn parse_number(token: &str) -> Result<Vec<u8>, String> {
        let result = token.parse::<i64>().unwrap();
        let mut result_array = IntUtils::to_vec_u8(result);
        let len = result_array.len();
        result_array.insert(0, len as u8);
        return Ok(result_array);
    }

    fn parse_string_literal(token: &str) -> Result<Vec<u8>, String> {
        let mut start = 0;
        let mut result_array = Vec::new();

        loop {
            let end = cmp::min(start + 75, token.len());

            let slice = &token[start..end];
            result_array.push(slice.len() as u8);
            result_array.extend(slice.as_bytes().iter().cloned());

            if end >= token.len() {
                break;
            }

            start = end;
        }

        return Ok(result_array);
    }

    fn get_op_codes(token: &str) -> Result<Vec<u8>, String> {
        match OpCode::from_str(&token.to_string()) {
            Some(x) => Ok(vec![x.to_byte()]),
            None => Self::parse_non_op_code(token),
        }
    }

    pub fn parse(script: &str) -> Result<Vec<u8>, String> {
        let mut result: Vec<u8> = vec![];

        for s in script.split(" ") {
            if s.len() == 0 { continue; }
            let op_codes = Self::get_op_codes(s);
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
