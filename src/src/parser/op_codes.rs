extern crate rustc_serialize;

use super::BitcoinStack;
use super::ScriptElement;

use crypto::sha2;
use crypto::ripemd160;
use crypto::digest::Digest;

use std::fmt;
use std::cmp;

fn ripemd160(input : Vec<u8>) -> Vec<u8> {
    let mut ripemd160 = ripemd160::Ripemd160::new();
    ripemd160.input(&input[..]);

    let mut result = [0u8;20];
    ripemd160.result(&mut result[0..20]);

    let mut result_array = Vec::new();
    result_array.extend(result.iter().cloned());

    return result_array;
}

fn sha256(input : Vec<u8>) -> Vec<u8> {
    let mut sha256 = sha2::Sha256::new();
    sha256.input(&input[..]);

    let mut result = [0u8;32];
    sha256.result(&mut result[0..32]);

    let mut result_array = Vec::new();
    result_array.extend(result.iter().cloned());

    return result_array;
}

pub fn op_dup(stack: BitcoinStack) -> BitcoinStack {
    assert!(stack.stack.len() > 0);

    let mut new_stack = stack;
    let last = new_stack.stack.last().unwrap().clone();
    new_stack.stack.push(last);

    return new_stack;
}

pub fn op_hash256(stack: BitcoinStack) -> BitcoinStack {
    let mut new_stack = stack;
    let last = new_stack.stack.pop().unwrap();

    new_stack.stack.push(sha256(sha256(last)));
    return new_stack;
}

pub fn op_hash160(stack: BitcoinStack) -> BitcoinStack {
    let mut new_stack = stack;
    let last = new_stack.stack.pop().unwrap();

    new_stack.stack.push(ripemd160(sha256(last)));
    return new_stack;
}

pub fn op_equalverify(stack: BitcoinStack) -> BitcoinStack {
    assert!(stack.stack.len() >= 2);

    let mut new_stack = stack;
    let x = new_stack.stack.pop().unwrap();
    let y = new_stack.stack.pop().unwrap();

    new_stack.valid = x.eq(&y);
    return new_stack;
}

impl<'a> cmp::PartialEq for ScriptElement<'a> {
    fn eq(&self, other: &ScriptElement<'a>) -> bool {
        match self {
            &ScriptElement::OpCode(x) => match other {
                &ScriptElement::OpCode(y) => x.name == y.name && x.code == y.code,
                _ => false,
            },
            &ScriptElement::Data(x) => match other {
                &ScriptElement::Data(y) => x == y,
                _ => false,
            }
        }
    }

    fn ne(&self, other: &ScriptElement<'a>) -> bool {
        !self.eq(other)
    }
}

impl<'a> cmp::PartialEq for BitcoinStack<'a> {
    fn eq(&self, other: &BitcoinStack<'a>) -> bool {
        self.data == other.data && self.stack == other.stack &&
            self.valid == other.valid
    }

    fn ne(&self, other: &BitcoinStack<'a>) -> bool {
        !self.eq(other)
    }
}

impl<'a> fmt::Debug for ScriptElement<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            &ScriptElement::OpCode(x) => 
                write!(f, "ScriptElement(type=OpCode, data={:?})", x.name),
            &ScriptElement::Data(x) =>
                write!(f, "ScriptElement(type=Data, data={:?})", x),
        }

    }
}

impl<'a> fmt::Debug for BitcoinStack<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {

        write!(f, "BitcoinStack(data={:?}, stack={:?}, valid={})",
            self.data, self.stack, self.valid)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::ripemd160;
    use super::sha256;
    use super::super::BitcoinStack;

    use rustc_serialize::base64::FromBase64;

    fn test_hash(hash: &Fn(Vec<u8>) -> Vec<u8>, input: &str, expected: &str) {
        let output = hash(input.from_base64().unwrap());
        assert_eq!(output, expected.from_base64().unwrap());
    }

    #[test]
    fn test_ripemd160() {
        test_hash(&ripemd160, "MQ==", "xHkHq9KoBJLKk4iwXA44JRj/OWA=");
        test_hash(&ripemd160, "dGVzdA==", "XlL+5H5rBwVl90NyRozcaZ3okQc=");
        test_hash(&ripemd160, "dGVzdF8y", "rwwVga+QLGzlz74RtoOwUT/L6Bw=");
    }

    #[test]
    fn test_sha256() {
        test_hash(&sha256, "MQ==", "a4ayc/80/OGda4BO/1o/V0etpOqiLx1JwB5S3beHW0s=");
        test_hash(&sha256, "dGVzdA==", "n4bQgYhMfWWaL+qgxVrQFaO/TxsrC4Is0V1sFbDwCgg=");
        test_hash(&sha256, "dGVzdF8y", "oQnb2DKAEyn4QJvuKEUCStTOqfAz+lwr0XfG/T54ZYc=");
    }

    #[test]
    fn test_op_dup() {
        let stack = BitcoinStack::new(vec![], vec![vec![0x01]]);
        let output = op_dup(stack);

        assert_eq!(BitcoinStack::new(vec![], vec![vec![0x01], vec![0x01]]), output);
    }

    #[test]
    #[should_panic]
    fn test_op_dup_panic() {
        let stack = BitcoinStack::new(vec![], vec![]);
        op_dup(stack);
    }

    #[test]
    fn test_op_equalverify_true() {
        let stack = BitcoinStack::new(vec![], vec![vec![0x01], vec![0x1]]);
        let output = op_equalverify(stack);

        assert!(output.valid);
        assert_eq!(BitcoinStack::new(vec![], vec![]), output);
    }

    #[test]
    fn test_op_equalverify_false() {
        let stack = BitcoinStack::new(vec![], vec![vec![0x01], vec![0x2]]);
        let output = op_equalverify(stack);

        assert!(!output.valid);
        assert_eq!(output.data, vec![]);
    }

    #[test]
    #[should_panic]
    fn test_op_equalverify_panic() {
        let stack = BitcoinStack::new(vec![], vec![]);
        op_equalverify(stack);
    }

    fn test_op_hash(op_hash: &Fn(BitcoinStack) -> BitcoinStack,
                    input: &str, expected: &str) {
        let stack = BitcoinStack::new(vec![], vec![input.from_base64().unwrap()]);
        let output = op_hash(stack);

        assert_eq!(BitcoinStack::new(vec![], vec![expected.from_base64().unwrap()]),
                   output);
    }

    #[test]
    fn test_op_hash256() {
        test_op_hash(&op_hash256, "YQ==", "v106/7c+/S7Gw2rTES3ZM+/tY8Thy//PqI4nWcFE8tg=");
        test_op_hash(&op_hash256, "", "Xfbg4nYTWdMKgnUFjimfzAOBU0VF9Vz0PkGYP11MlFY=");
        test_op_hash(&op_hash256, "YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXo", "yhObwQwvZg2kJmb3LomiJZNvxg8ZPBYRJKZyBQxDRnE=");
    }

    #[test]
    fn test_op_hash160() {
        test_op_hash(&op_hash160, "", "tHKiZtC9icE3BqQTLM+xb3w7n8s=");
        test_op_hash(&op_hash160, "YQ==", "mUNVGZ5Rb/dsT6Sqs5M3udhM8Ss=");
        test_op_hash(&op_hash160, "YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXo", "woahrwlH9Y0a14c4WxwsSpdvnnE=");
    }
}
