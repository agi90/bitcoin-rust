extern crate rustc_serialize;

use super::Context;
use super::OpCode;

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

    result_array
}

fn sha256(input : Vec<u8>) -> Vec<u8> {
    let mut sha256 = sha2::Sha256::new();
    sha256.input(&input[..]);

    let mut result = [0u8;32];
    sha256.result(&mut result[0..32]);

    let mut result_array = Vec::new();
    result_array.extend(result.iter().cloned());

    result_array
}

pub fn op_dup(context: Context) -> Context {
    assert!(context.stack.len() > 0);

    let mut new_context = context;
    let last = new_context.stack.last().unwrap().clone();
    new_context.stack.push(last);

    new_context
}

pub fn op_hash256(context: Context) -> Context {
    let mut new_context = context;
    let last = new_context.stack.pop().unwrap();

    new_context.stack.push(sha256(sha256(last)));

    new_context
}

pub fn op_hash160(context: Context) -> Context {
    let mut new_context = context;
    let last = new_context.stack.pop().unwrap();

    new_context.stack.push(ripemd160(sha256(last)));

    new_context
}

pub fn op_equalverify(context: Context) -> Context {
    assert!(context.stack.len() >= 2);

    let mut new_context = context;
    let x = new_context.stack.pop().unwrap();
    let y = new_context.stack.pop().unwrap();

    new_context.valid = x.eq(&y);

    new_context
}

pub fn op_false(context: Context) -> Context {
    let mut new_context = context;
    new_context.stack.push(vec![]);

    new_context
}

pub fn op_pushdata(context: Context) -> Context {
    let mut new_context = context;
    new_context.stack.push(new_context.data.data.clone());

    new_context
}

fn push_to_stack(context: Context, data: u8) -> Context {
    let mut new_context = context;
    new_context.stack.push(vec![data]);

    new_context
}

pub fn op_1negate(context: Context) -> Context {
    // 0x81 is -1 TODO: consider moving to Vec<i8>
    push_to_stack(context, 0x81)
}

pub fn  op_1(context: Context) -> Context { push_to_stack(context, 0x79) }
pub fn  op_2(context: Context) -> Context { push_to_stack(context, 0x78) }
pub fn  op_3(context: Context) -> Context { push_to_stack(context, 0x77) }
pub fn  op_4(context: Context) -> Context { push_to_stack(context, 0x76) }
pub fn  op_5(context: Context) -> Context { push_to_stack(context, 0x75) }
pub fn  op_6(context: Context) -> Context { push_to_stack(context, 0x74) }
pub fn  op_7(context: Context) -> Context { push_to_stack(context, 0x73) }
pub fn  op_8(context: Context) -> Context { push_to_stack(context, 0x72) }
pub fn  op_9(context: Context) -> Context { push_to_stack(context, 0x71) }
pub fn op_10(context: Context) -> Context { push_to_stack(context, 0x70) }
pub fn op_11(context: Context) -> Context { push_to_stack(context, 0x69) }
pub fn op_12(context: Context) -> Context { push_to_stack(context, 0x68) }
pub fn op_13(context: Context) -> Context { push_to_stack(context, 0x67) }
pub fn op_14(context: Context) -> Context { push_to_stack(context, 0x66) }
pub fn op_15(context: Context) -> Context { push_to_stack(context, 0x65) }
pub fn op_16(context: Context) -> Context { push_to_stack(context, 0x64) }

pub fn op_nop(context: Context) -> Context { context }

pub fn op_if(context: Context) -> Context {
    let mut new_context = context;
    let last = new_context.stack.pop().unwrap();

    if is_true(&Some(&last)) {
        new_context.data = new_context.data.next.clone().unwrap();
    } else {
        new_context.data = new_context.data.next_else.clone().unwrap();
    }
    
    new_context
}

pub fn op_notif(context: Context) -> Context {
    let mut new_context = context;
    let last = new_context.stack.pop().unwrap();

    if !is_true(&Some(&last)) {
        new_context.data = new_context.data.next.clone().unwrap();
    } else {
        new_context.data = new_context.data.next_else.clone().unwrap();
    }
    
    new_context
}

pub fn op_else(_: Context) -> Context {
    // this op should never be invoked
    unimplemented!()
}

pub fn op_endif(context: Context) -> Context { context }

pub fn is_true(element: &Option<&Vec<u8>>) -> bool {
    match element {
        &Some(x) => x.len() > 1 || (x.len() != 0 && x[0] != 0x80),
        &None => false,
    }
}

pub fn op_verify(context: Context) -> Context {
    let mut new_context = context;

    new_context.valid = is_true(&new_context.stack.last());
    return new_context;
}

pub fn op_return(context: Context) -> Context {
    let mut new_context = context;

    new_context.valid = false;

    return new_context;
}

impl cmp::PartialEq for OpCode {
    fn eq(&self, other: &OpCode) -> bool {
        self.name == other.name && self.code == other.code
    }
}

impl fmt::Debug for OpCode {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "OpCode({}, 0x{:x})", self.name, self.code)
    }
}

impl<'a> fmt::Debug for Context<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Context(data={:?}, stack={:?}, valid={:?})",
               self.data, self.stack, self.valid)
    }
}

impl<'a> cmp::PartialEq for Context<'a> {
    fn eq(&self, other: &Context<'a>) -> bool {
        self.data == other.data && self.stack == other.stack &&
            self.valid == other.valid
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::ripemd160;
    use super::sha256;
    use super::super::Context;
    use super::super::ScriptElement;
    use super::super::OpCode;

    use std::rc::Rc;
    use rustc_serialize::base64::FromBase64;

    static TEST_OP_CODE: OpCode = OpCode {
        name: "TEST",
        code: 0x00,
        advancing: false,
        parser: op_nop
    };  

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

    fn get_context<'a>(stack: Vec<Vec<u8>>) -> Context<'a> {
        let op_code = &TEST_OP_CODE;
        let script_element = ScriptElement::new(op_code, vec![], 0);

        Context::new(Rc::new(script_element), stack)
    }

    #[test]
    fn test_op_dup() {
        let context = get_context(vec![vec![0x01]]);
        let output = op_dup(context);

        assert_eq!(get_context(vec![vec![0x01], vec![0x01]]), output);
    }

    #[test]
    #[should_panic]
    fn test_op_dup_panic() {
        let context = get_context(vec![]);
        op_dup(context);
    }

    #[test]
    fn test_op_equalverify_true() {
        let context = get_context(vec![vec![0x01], vec![0x1]]);
        let output = op_equalverify(context);

        assert_eq!(get_context(vec![]), output);
    }

    #[test]
    fn test_op_equalverify_false() {
        let context = get_context(vec![vec![0x01], vec![0x2]]);
        let output = op_equalverify(context);

        let mut expected = get_context(vec![]);
        expected.valid = false;

        assert_eq!(expected, output);
    }

    #[test]
    #[should_panic]
    fn test_op_equalverify_panic() {
        let context = get_context(vec![]);
        op_equalverify(context);
    }

    fn test_op_hash(op_hash: &Fn(Context) -> Context,
                    input: &str, expected: &str) {
        let context = get_context(vec![input.from_base64().unwrap()]);
        let output = op_hash(context);

        assert_eq!(get_context(vec![expected.from_base64().unwrap()]),
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

    fn test_nop(nop: fn(Context) -> Context) {
        let context = get_context(vec![vec![0x02], vec![0x03]]);
        let output = nop(context);
        assert_eq!(output, get_context(vec![vec![0x02], vec![0x03]]));
    }

    #[test]
    fn test_op_false() {
        let context = get_context(vec![vec![0x02], vec![0x03]]);
        let output = op_false(context);

        assert_eq!(output, get_context(vec![vec![0x02], vec![0x03], vec![]]));
    }

    #[test]
    fn test_op_nop() {
        test_nop(op_nop);
    }

    #[test]
    fn test_op_pushdata_generic() {
        let data = vec![0x01, 0x02, 0x03, 0x04, 0x05];

        let op_code = &TEST_OP_CODE;
        let script_element = Rc::new(ScriptElement::new(op_code, data.clone(), 0));
        let context = Context::new(script_element.clone(), vec![]);
        let expected = Context::new(script_element.clone(), vec![data]);

        let output = op_pushdata(context);
        assert_eq!(output, expected);
    }

    fn test_push_to_stack(data: u8, push: fn(Context) -> Context) {
        let context = get_context(vec![]);
        let output = push(context);
        assert_eq!(output, get_context(vec![vec![data]]));
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
        let context = get_context(data);
        let output = op_verify(context);

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
        let context = get_context(vec![]);
        let output = op_verify(context);

        assert!(!output.valid);
    }
}
