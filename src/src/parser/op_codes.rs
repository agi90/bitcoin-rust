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

pub fn op_false(stack: BitcoinStack) -> BitcoinStack {
    // this is a no-op
    stack
}

pub fn op_pushdata1(stack: BitcoinStack) -> BitcoinStack {
    op_pushdata(stack, 0x01)
}

pub fn op_pushdata2(stack: BitcoinStack) -> BitcoinStack {
    op_pushdata(stack, 0x02)
}

pub fn op_pushdata4(stack: BitcoinStack) -> BitcoinStack {
    op_pushdata(stack, 0x04)
}

pub fn op_pushdata(stack: BitcoinStack, bytes: u8) -> BitcoinStack {
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

fn push_to_stack(stack: BitcoinStack, data: u8) -> BitcoinStack {
    let mut new_stack = stack;
    new_stack.stack.push(vec![data]);

    return new_stack;
}

pub fn op_1negate(stack: BitcoinStack) -> BitcoinStack {
    // 0x81 is -1 TODO: consider moving to Vec<i8>
    push_to_stack(stack, 0x81)
}

pub fn op_1(stack: BitcoinStack)  -> BitcoinStack { push_to_stack(stack, 0x79) }
pub fn op_2(stack: BitcoinStack)  -> BitcoinStack { push_to_stack(stack, 0x78) }
pub fn op_3(stack: BitcoinStack)  -> BitcoinStack { push_to_stack(stack, 0x77) }
pub fn op_4(stack: BitcoinStack)  -> BitcoinStack { push_to_stack(stack, 0x76) }
pub fn op_5(stack: BitcoinStack)  -> BitcoinStack { push_to_stack(stack, 0x75) }
pub fn op_6(stack: BitcoinStack)  -> BitcoinStack { push_to_stack(stack, 0x74) }
pub fn op_7(stack: BitcoinStack)  -> BitcoinStack { push_to_stack(stack, 0x73) }
pub fn op_8(stack: BitcoinStack)  -> BitcoinStack { push_to_stack(stack, 0x72) }
pub fn op_9(stack: BitcoinStack)  -> BitcoinStack { push_to_stack(stack, 0x71) }
pub fn op_10(stack: BitcoinStack) -> BitcoinStack { push_to_stack(stack, 0x70) }
pub fn op_11(stack: BitcoinStack) -> BitcoinStack { push_to_stack(stack, 0x69) }
pub fn op_12(stack: BitcoinStack) -> BitcoinStack { push_to_stack(stack, 0x68) }
pub fn op_13(stack: BitcoinStack) -> BitcoinStack { push_to_stack(stack, 0x67) }
pub fn op_14(stack: BitcoinStack) -> BitcoinStack { push_to_stack(stack, 0x66) }
pub fn op_15(stack: BitcoinStack) -> BitcoinStack { push_to_stack(stack, 0x65) }
pub fn op_16(stack: BitcoinStack) -> BitcoinStack { push_to_stack(stack, 0x64) }

pub fn op_nop(stack: BitcoinStack) -> BitcoinStack { stack }

pub fn op_verify(stack: BitcoinStack) -> BitcoinStack {
    let mut new_stack = stack;

    new_stack.valid = match new_stack.stack.last() {
        Some(x) => x.len() > 1 || (x.len() != 0 && x[0] != 0x80),
        None => false,
    };

    return new_stack;
}

pub fn op_return(stack: BitcoinStack) -> BitcoinStack {
    let mut new_stack = stack;

    new_stack.valid = false;

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
    use super::super::ScriptElement;

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

    fn get_data<'a>(data: &Vec<u8>) -> Vec<ScriptElement<'a>> {
        // Data is reversed in actual code because we treat it
        // like a stack.
        let mut new_data = data.clone();
        new_data.reverse();
        new_data.iter().map(|b| ScriptElement::Data(*b)).collect()
    }

    fn test_nop(nop: fn(BitcoinStack) -> BitcoinStack) {
        let stack = BitcoinStack::new(get_data(&vec![0x01]),
                                      vec![vec![0x02], vec![0x03]]);
        let output = nop(stack);
        assert_eq!(output, BitcoinStack::new(vec![ScriptElement::Data(0x01)],
                                      vec![vec![0x02], vec![0x03]]));
    }

    #[test]
    fn test_op_false() {
        test_nop(op_false);
    }

    #[test]
    fn test_op_nop() {
        test_nop(op_nop);
    }

    fn test_op_pushdata(data: Vec<u8>, op_pushdata: fn(BitcoinStack) -> BitcoinStack) {
        let stack = BitcoinStack::new(get_data(&data), vec![]);
        let output = op_pushdata(stack);
        assert_eq!(output, BitcoinStack::new(vec![], vec![data]));
    }

    #[test]
    fn test_op_pushdata1() {
        test_op_pushdata(vec![0x01], op_pushdata1);
    }

    #[test]
    fn test_op_pushdata2() {
        test_op_pushdata(vec![0x01, 0x02], op_pushdata2);
    }

    #[test]
    fn test_op_pushdata4() {
        test_op_pushdata(vec![0x01, 0x02, 0x03, 0x04], op_pushdata4);
    }

    #[test]
    fn test_op_pushdata_generic() {
        let data = vec![0x01, 0x02, 0x03, 0x04, 0x05];
        let stack = BitcoinStack::new(get_data(&data), vec![]);
        let output = op_pushdata(stack, 0x05);
        assert_eq!(output, BitcoinStack::new(vec![], vec![data]));
    }

    fn test_push_to_stack(data: u8, push: fn(BitcoinStack) -> BitcoinStack) {
        let stack = BitcoinStack::new(vec![], vec![]);
        let output = push(stack);
        assert_eq!(output, BitcoinStack::new(vec![], vec![vec![data]]));
    }

    #[test]
    fn test_1negate() { test_push_to_stack(0x81, op_1negate); }

    #[test]
    fn test_op_n() {
        test_push_to_stack(0x79, op_1);
        test_push_to_stack(0x78, op_2);
        test_push_to_stack(0x77, op_3);
        test_push_to_stack(0x76, op_4);
        test_push_to_stack(0x75, op_5);
        test_push_to_stack(0x74, op_6);
        test_push_to_stack(0x73, op_7);
        test_push_to_stack(0x72, op_8);
        test_push_to_stack(0x71, op_9);
        test_push_to_stack(0x70, op_10);
        test_push_to_stack(0x69, op_11);
        test_push_to_stack(0x68, op_12);
        test_push_to_stack(0x67, op_13);
        test_push_to_stack(0x66, op_14);
        test_push_to_stack(0x65, op_15);
        test_push_to_stack(0x64, op_16);
    }

    fn test_op_verify(data: Vec<Vec<u8>>, valid: bool) {
        let stack = BitcoinStack::new(vec![], data);
        let output = op_verify(stack);

        assert_eq!(output.valid, valid);
    }

    #[test]
    fn test_op_verify_impl() {
        test_op_verify(vec![vec![0x80]], false);
        test_op_verify(vec![vec![0x79]], true);
        test_op_verify(vec![vec![]], false);
        test_op_verify(vec![], false);
        test_op_verify(vec![vec![0x80, 0x80]], true);
        test_op_verify(vec![vec![0x80, 0x81]], true);
        test_op_verify(vec![vec![0x79, 0x81]], true);
    }

    #[test]
    fn test_op_return() {
        let stack = BitcoinStack::new(vec![], vec![]);
        let output = op_verify(stack);

        assert!(!output.valid);
    }
}
