extern crate rustc_serialize;

use super::Context;
use super::OpCode;

use crypto::sha2;
use crypto::ripemd160;
use crypto::digest::Digest;

use std::fmt;
use std::cmp;

const ZERO : u8 = 0x80;

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
    pick(context, 0)
}

pub fn op_ifdup(context: Context) -> Context {
    assert!(context.stack.len() > 0);

    if is_true(&context.stack.last()) {
        return op_dup(context);
    }

    context
}

pub fn to_vec_u8(x: i32) -> Vec<u8> {
    let u = x.abs();
    let sign: u8 = if u == x { 0x00 } else { 0x80 };

    let byte0 = (u  & 0x000000ff)              as u8;
    let byte1 = ((u & 0x0000ff00) / 0x100)     as u8;
    let byte2 = ((u & 0x00ff0000) / 0x10000)   as u8;
    let byte3 = ((u & 0x7f000000) / 0x1000000) as u8;

    if u == 0 {
        vec![]
    } else if u <= 0x7f {
        vec![u as u8 | sign]
    } else if u <= 0x7fff {
        vec![byte0, byte1 | sign]
    } else if u <= 0x7fffff {
        vec![byte0, byte1, byte2 | sign]
    } else {
        vec![byte0, byte1, byte2, byte3 | sign]
    }
}

pub fn to_i32(x: &Vec<u8>) -> i32 {
    assert!(x.len() <= 4);

    let last = match x.last() {
        Some(x) => *x,
        None => 0
    };

    let mut sign = (last & 0x80) as i64;

    let mut result: i64 = 0;
    if x.len() >= 1 {
        result += *x.first().unwrap() as i64;
    }

    if x.len() >= 2 {
        result += *x.get(1).unwrap() as i64 * 0x100;
        sign *= 0x100;
    }

    if x.len() >= 3 {
        result += *x.get(2).unwrap() as i64 * 0x10000;
        sign *= 0x100;
    }

    if x.len() == 4 {
        result += *x.get(3).unwrap() as i64 * 0x1000000;
        sign *= 0x100;
    }

    if sign != 0 {
        result = (result - sign) * -1;
    }

    result as i32
}

pub fn op_depth(context: Context) -> Context {
    assert!(context.stack.len() <= 0x7f);

    let mut new_context = context;
    let size = to_vec_u8(new_context.stack.len() as i32);
    new_context.stack.push(size);

    new_context
}

pub fn op_drop(context: Context) -> Context {
    let mut new_context = context;
    new_context.stack.pop();

    new_context
}

pub fn op_nip(context: Context) -> Context {
    assert!(context.stack.len() >= 1);

    let mut new_context = context;
    let el = new_context.stack.pop().unwrap();
    new_context.stack.pop();
    new_context.stack.push(el);

    new_context
}

fn pick(context: Context, depth: usize) -> Context {
    assert!(context.stack.len() >= depth + 1);

    let mut new_context = context;
    let el = new_context.stack.get(new_context.stack.len() - depth - 1).unwrap().clone();
    new_context.stack.push(el);

    new_context
}

pub fn op_toaltstack(context: Context) -> Context {
    assert!(context.stack.len() > 0);

    let mut new_context = context;
    let el = new_context.stack.pop().unwrap();
    new_context.altstack.push(el);

    new_context
}

pub fn op_fromaltstack(context: Context) -> Context {
    assert!(context.altstack.len() > 0);

    let mut new_context = context;
    let el = new_context.altstack.pop().unwrap();
    new_context.stack.push(el);

    new_context
}

pub fn op_over(context: Context) -> Context {
    pick(context, 1)
}

pub fn op_pick(context: Context) -> Context {
    assert!(context.stack.len() > 0);

    let mut new_context = context;
    let el = new_context.stack.pop().unwrap();
    let size = to_i32(&el);

    pick(new_context, size as usize)
}

fn roll(context: Context, size: u8) -> Context {
    assert!(size == 0x00 || context.stack.len() > size as usize - 1);

    let mut new_context = context;

    let pos = new_context.stack.len() - 1 - size as usize;
    let el = new_context.stack.remove(pos);
    new_context.stack.push(el);

    new_context
}

pub fn op_roll(context: Context) -> Context {
    assert!(context.stack.len() > 0);

    let mut new_context = context;
    let size = to_i32(&new_context.stack.pop().unwrap());
    assert!(size <= 0xff);
    assert!(size >= 0x00);


    roll(new_context, size as u8)
}

pub fn op_rot(context: Context)  -> Context { roll(context, 2) }
pub fn op_swap(context: Context) -> Context { roll(context, 1) }

pub fn op_tuck(context: Context) -> Context {
    pick(roll(context, 1), 1)
}

pub fn op_2drop(context: Context) -> Context {
    op_drop(op_drop(context))
}

pub fn op_2dup(context: Context) -> Context {
    pick(pick(context, 1), 1)
}

pub fn op_3dup(context: Context) -> Context {
    pick(pick(pick(context, 2), 2), 2)
}

pub fn op_2over(context: Context) -> Context {
    pick(pick(context, 3), 3)
}

pub fn op_2rot(context: Context) -> Context {
    roll(roll(context, 5), 5)
}

pub fn op_2swap(context: Context) -> Context {
    roll(roll(context, 3), 3)
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
    op_verify(op_equal(context))
}

pub fn op_equal(context: Context) -> Context {
    assert!(context.stack.len() >= 2);

    let mut new_context = context;
    let x = new_context.stack.pop().unwrap();
    let y = new_context.stack.pop().unwrap();

    let result = if x.eq(&y) { vec![0x01] } else { vec![] };
    new_context.stack.push(result);

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

pub fn  op_1(context: Context) -> Context { push_to_stack(context, 0x01) }
pub fn  op_2(context: Context) -> Context { push_to_stack(context, 0x02) }
pub fn  op_3(context: Context) -> Context { push_to_stack(context, 0x03) }
pub fn  op_4(context: Context) -> Context { push_to_stack(context, 0x04) }
pub fn  op_5(context: Context) -> Context { push_to_stack(context, 0x05) }
pub fn  op_6(context: Context) -> Context { push_to_stack(context, 0x06) }
pub fn  op_7(context: Context) -> Context { push_to_stack(context, 0x07) }
pub fn  op_8(context: Context) -> Context { push_to_stack(context, 0x08) }
pub fn  op_9(context: Context) -> Context { push_to_stack(context, 0x09) }
pub fn op_10(context: Context) -> Context { push_to_stack(context, 0x0a) }
pub fn op_11(context: Context) -> Context { push_to_stack(context, 0x0b) }
pub fn op_12(context: Context) -> Context { push_to_stack(context, 0x0c) }
pub fn op_13(context: Context) -> Context { push_to_stack(context, 0x0d) }
pub fn op_14(context: Context) -> Context { push_to_stack(context, 0x0e) }
pub fn op_15(context: Context) -> Context { push_to_stack(context, 0x0f) }
pub fn op_16(context: Context) -> Context { push_to_stack(context, 0x10) }

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
        &Some(x) => to_i32(x) != 0,
        &None => false,
    }
}

pub fn op_verify(context: Context) -> Context {
    let mut new_context = context;

    new_context.valid = is_true(&new_context.stack.last());
    new_context.stack.pop();

    return new_context;
}

pub fn op_return(context: Context) -> Context {
    let mut new_context = context;

    new_context.valid = false;

    return new_context;
}

pub fn op_size(context: Context) -> Context {
    assert!(context.stack.len() > 0);

    let mut new_context = context;
    let size = to_vec_u8(new_context.stack.last().unwrap().len() as i32);

    new_context.stack.push(size);

    new_context
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

pub const OP_PUSHDATA : (&'static str, u8, bool, fn(Context) -> Context) =
    ("PUSHDATA",     0x01, false, op_pushdata);

pub const OP_CODES : [(&'static str, u8, bool, fn(Context) -> Context); 50] = [
    ("0",            0x00, false, op_false),
    // opcodes 0x02 - 0x4b op_pushdata
    ("1NEGATE",      0x4f, false, op_1negate),
    // TODO: opcodes 0x50
    ("1",            0x51, false, op_1),
    ("2",            0x52, false, op_2),
    ("3",            0x53, false, op_3),
    ("4",            0x54, false, op_4),
    ("5",            0x55, false, op_5),
    ("6",            0x56, false, op_6),
    ("7",            0x57, false, op_7),
    ("8",            0x58, false, op_8),
    ("9",            0x59, false, op_9),
    ("10",           0x5a, false, op_10),
    ("11",           0x5b, false, op_11),
    ("12",           0x5c, false, op_12),
    ("13",           0x5d, false, op_13),
    ("14",           0x5e, false, op_14),
    ("15",           0x5f, false, op_15),
    ("16",           0x60, false, op_16),
    ("NOP",          0x61, false, op_nop),
    ("IF",           0x63, true,  op_if),
    ("NOTIF",        0x64, true,  op_notif),
    ("ELSE",         0x67, false, op_else),
    ("ENDIF",        0x68, false, op_endif),
    ("NOP",          0x61, false, op_nop),
    // TODO: opcodes 0x62 - 0x68
    ("VERIFY",       0x69, false, op_verify),
    ("RETURN",       0x6a, false, op_return),
    ("TOALTSTACK",   0x6b, false, op_toaltstack),
    ("FROMALTSTACK", 0x6c, false, op_fromaltstack),
    ("2DROP",        0x6d, false, op_2drop),
    ("2DUP",         0x6e, false, op_2dup),
    ("3DUP",         0x6f, false, op_3dup),
    ("2OVER",        0x70, false, op_2over),
    ("2ROT",         0x71, false, op_2rot),
    ("2SWAP",        0x72, false, op_2swap),
    ("IFDUP",        0x73, false, op_ifdup),
    ("DEPTH",        0x74, false, op_depth),
    ("DROP",         0x75, false, op_drop),
    ("DUP",          0x76, false, op_dup),
    ("NIP",          0x77, false, op_nip),
    ("OVER",         0x78, false, op_over),
    ("PICK",         0x79, false, op_pick),
    ("ROLL",         0x7a, false, op_roll),
    ("ROT",          0x7b, false, op_rot),
    ("SWAP",         0x7c, false, op_swap),
    ("TUCK",         0x7d, false, op_tuck),
    // TODO: opcodes 0x7e - 0x81 (disabled opcodes)
    ("SIZE",         0x82, false, op_size),
    // TODO: opcodes 0x83 - 0x87
    ("EQUAL",        0x87, false, op_equal),
    ("EQUALVERIFY",  0x88, false, op_equalverify),
    // TODO: opcodes 0x89 - 0xa8
    ("HASH160",      0xa9, false, op_hash160),
    ("HASH256",      0xaa, false, op_hash256),
    // TODO: opcodes 0xab - 0xff
];

pub const OP_IF: u8 = 0x63;
pub const OP_NOTIF: u8 = 0x64;
pub const OP_ELSE: u8 = 0x67;
pub const OP_ENDIF: u8 = 0x68;

#[cfg(test)]
mod tests {
    use super::*;
    use super::ripemd160;
    use super::sha256;
    use super::ZERO;

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
    fn test_op_equalverify_zero_false() {
        let context = get_context(vec![vec![], vec![ZERO]]);
        let output = op_equalverify(context);
        let mut expected = get_context(vec![]);
        expected.valid = false;

        assert_eq!(expected, output);
    }

    #[test]
    fn test_op_equalverify_true() {
        let context = get_context(vec![vec![0x01], vec![0x01]]);
        let output = op_equalverify(context);

        assert_eq!(get_context(vec![]), output);
    }

    #[test]
    fn test_op_equalverify_false() {
        let context = get_context(vec![vec![0x01], vec![0x02]]);
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

    #[test]
    fn test_op_equal_true() {
        let context = get_context(vec![vec![0x01], vec![0x01]]);
        let output = op_equal(context);

        assert_eq!(get_context(vec![vec![0x01]]), output);
    }

    #[test]
    fn test_op_equal_false() {
        let context = get_context(vec![vec![0x01], vec![0x02]]);
        let output = op_equal(context);

        assert_eq!(get_context(vec![vec![]]), output);
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
        test_push_to_stack(0x01, op_1);
        test_push_to_stack(0x02, op_2);
        test_push_to_stack(0x03, op_3);
        test_push_to_stack(0x04, op_4);
        test_push_to_stack(0x05, op_5);
        test_push_to_stack(0x06, op_6);
        test_push_to_stack(0x07, op_7);
        test_push_to_stack(0x08, op_8);
        test_push_to_stack(0x09, op_9);
        test_push_to_stack(0x0a, op_10);
        test_push_to_stack(0x0b, op_11);
        test_push_to_stack(0x0c, op_12);
        test_push_to_stack(0x0d, op_13);
        test_push_to_stack(0x0e, op_14);
        test_push_to_stack(0x0f, op_15);
        test_push_to_stack(0x10, op_16);
    }

    fn test_op_verify(data: Vec<Vec<u8>>, valid: bool) {
        let context = get_context(data);
        let output = op_verify(context);

        assert_eq!(output.valid, valid);
    }

    #[test]
    fn test_op_verify_impl() {
        test_op_verify(vec![vec![ZERO]], false);
        test_op_verify(vec![vec![0x01]], true);
        test_op_verify(vec![vec![]], false);
        test_op_verify(vec![], false);
        test_op_verify(vec![vec![ZERO, ZERO]], true);
        test_op_verify(vec![vec![ZERO, 0x81]], true);
        test_op_verify(vec![vec![0x01, 0x81]], true);
    }

    #[test]
    fn test_op_return() {
        let context = get_context(vec![]);
        let output = op_verify(context);

        assert!(!output.valid);
    }

    #[test]
    fn test_op_ifdup_false() {
        let context = get_context(vec![vec![]]);
        let output = op_ifdup(context);

        assert_eq!(output, get_context(vec![vec![]]));
    }

    #[test]
    fn test_op_ifdup_true() {
        let context = get_context(vec![vec![0x81]]);
        let output = op_ifdup(context);

        assert_eq!(output, get_context(vec![vec![0x81], vec![0x81]]));
    }

    #[test]
    #[should_panic]
    fn test_op_ifdup_panic() {
        op_ifdup(get_context(vec![]));
    }

    fn test_stack_base(op: fn(Context) -> Context, stack: Vec<Vec<u8>>,
                       expected: Vec<Vec<u8>>) {
        let output = op(get_context(stack));
        assert_eq!(output, get_context(expected));
    }

    #[test]
    fn test_op_depth() {
        test_stack_base(op_depth, vec![], vec![vec![]]);
        test_stack_base(op_depth, vec![vec![0x01]], vec![vec![0x01], vec![0x01]]);
        test_stack_base(op_depth, vec![vec![0x01], vec![0x02]],
                        vec![vec![0x01], vec![0x02], vec![0x02]]);
        test_stack_base(op_depth, vec![vec![0x01], vec![0x02], vec![0x03]],
                        vec![vec![0x01], vec![0x02], vec![0x03], vec![0x03]]);
    }

    #[test]
    fn test_op_drop() {
        test_stack_base(op_drop, vec![], vec![]);
        test_stack_base(op_drop, vec![vec![0x01]], vec![]);
        test_stack_base(op_drop, vec![vec![0x01], vec![0x01]], vec![vec![0x01]]);
    }

    #[test]
    fn test_op_nip() {
        test_stack_base(op_nip, vec![vec![0x01]], vec![vec![0x01]]);
        test_stack_base(op_nip, vec![vec![0x02], vec![0x01]], vec![vec![0x01]]);
        test_stack_base(op_nip, vec![vec![0x03], vec![0x02], vec![0x01]], vec![vec![0x03], vec![0x01]]);
    }

    #[test]
    fn test_op_over() {
        test_stack_base(op_over, vec![vec![0x02], vec![0x01]], vec![vec![0x02], vec![0x01], vec![0x02]]);
    }

    #[test]
    fn test_op_pick() {
        test_stack_base(op_pick, vec![vec![0x03], vec![0x02], vec![0x01]], vec![vec![0x03], vec![0x02], vec![0x03]]);
        test_stack_base(op_pick, vec![vec![0x04], vec![0x03], vec![0x02], vec![0x02]],
                                 vec![vec![0x04], vec![0x03], vec![0x02], vec![0x04]]);
    }

    #[test]
    fn test_op_roll() {
        test_stack_base(op_roll, vec![vec![0x03], vec![0x02], vec![0x01]], vec![vec![0x02], vec![0x03]]);
        test_stack_base(op_roll, vec![vec![0x04], vec![0x03], vec![0x02], vec![0x02]],
                                 vec![vec![0x03], vec![0x02], vec![0x04]]);
        test_stack_base(op_roll, vec![vec![0x04], vec![0x03], vec![0x02], vec![0x01]],
                                 vec![vec![0x04], vec![0x02], vec![0x03]]);
        test_stack_base(op_roll, vec![vec![0x04], vec![0x03], vec![0x02], vec![]],
                                 vec![vec![0x04], vec![0x03], vec![0x02]]);
    }

    #[test]
    fn test_op_rot() {
        test_stack_base(op_rot, vec![vec![0x01], vec![0x02], vec![0x03]],
                                vec![vec![0x02], vec![0x03], vec![0x01]]);
    }

    #[test]
    fn test_op_swap() {
        test_stack_base(op_swap, vec![vec![0x01], vec![0x02], vec![0x03]],
                                 vec![vec![0x01], vec![0x03], vec![0x02]]);
    }

    #[test]
    fn test_op_tuck() {
        test_stack_base(op_tuck, vec![vec![0x01], vec![0x02]],
                                 vec![vec![0x02], vec![0x01], vec![0x02]]);
    }

    #[test]
    fn test_op_2drop() {
        test_stack_base(op_2drop, vec![vec![0x01], vec![0x02], vec![0x03]],
                                  vec![vec![0x01]]);
        test_stack_base(op_2drop, vec![vec![0x01], vec![0x02]],
                                  vec![]);
    }

    #[test]
    fn test_op_2dup() {
        test_stack_base(op_2dup, vec![vec![0x01], vec![0x02], vec![0x03]],
                                 vec![vec![0x01], vec![0x02], vec![0x03], vec![0x02], vec![0x03]]);
        test_stack_base(op_2dup, vec![vec![0x02], vec![0x03]],
                                 vec![vec![0x02], vec![0x03], vec![0x02], vec![0x03]]);
    }

    #[test]
    fn test_op_3dup() {
        test_stack_base(op_3dup, vec![vec![0x01], vec![0x02], vec![0x03]],
                                 vec![vec![0x01], vec![0x02], vec![0x03], vec![0x01], vec![0x02], vec![0x03]]);
    }

    #[test]
    fn test_op_2over() {
        test_stack_base(op_2over, vec![vec![0x01], vec![0x02], vec![0x03], vec![0x04]],
                                  vec![vec![0x01], vec![0x02], vec![0x03], vec![0x04], vec![0x01], vec![0x02]]);
    }

    #[test]
    fn test_op_2rot() {
        test_stack_base(op_2rot, vec![vec![0x01], vec![0x02], vec![0x03], vec![0x04], vec![0x05], vec![0x06]],
                                 vec![vec![0x03], vec![0x04], vec![0x05], vec![0x06], vec![0x01], vec![0x02]]);
    }

    #[test]
    fn test_op_2swap() {
        test_stack_base(op_2swap, vec![vec![0x01], vec![0x02], vec![0x03], vec![0x04]],
                                  vec![vec![0x03], vec![0x04], vec![0x01], vec![0x02]]);
    }

    #[test]
    fn test_op_fromaltstack() {
        let mut context = get_context(vec![]);
        context.altstack = vec![vec![0x01]];

        assert_eq!(get_context(vec![vec![0x01]]), op_fromaltstack(context));
    }

    #[test]
    fn test_op_toaltstack() {
        let mut expected = get_context(vec![]);
        expected.altstack = vec![vec![0x01]];

        let context = get_context(vec![vec![0x01]]);

        assert_eq!(expected, op_toaltstack(context));
    }

    #[test]
    fn test_op_size() {
        test_stack_base(op_size, vec![vec![]],
                                 vec![vec![], vec![]]);
        test_stack_base(op_size, vec![vec![0x01, 0x02, 0x03, 0x04, 0x05]],
                                 vec![vec![0x01, 0x02, 0x03, 0x04, 0x05], vec![0x05]]);
        test_stack_base(op_size, vec![vec![0x01]],
                                 vec![vec![0x01], vec![0x01]]);
        test_stack_base(op_size, vec![vec![0x01, 0x02]],
                                 vec![vec![0x01, 0x02], vec![0x02]]);
    }

    #[test]
    fn test_to_i32() {
        assert_eq!(to_i32(&vec![0x01]), 1);
        assert_eq!(to_i32(&vec![0x81]), -1);

        assert_eq!(to_i32(&vec![0x7f]), 127);
        assert_eq!(to_i32(&vec![0xff]), -127);

        assert_eq!(to_i32(&vec![0x80, 0x00]), 128);
        assert_eq!(to_i32(&vec![0x80, 0x80]), -128);

        assert_eq!(to_i32(&vec![0xff, 0x7f]), 32767);
        assert_eq!(to_i32(&vec![0xff, 0xff]), -32767);

        assert_eq!(to_i32(&vec![0x00, 0x80, 0x00]), 32768);
        assert_eq!(to_i32(&vec![0x00, 0x80, 0x80]), -32768);

        assert_eq!(to_i32(&vec![0xff, 0xff, 0x7f]), 8388607);
        assert_eq!(to_i32(&vec![0xff, 0xff, 0xff]), -8388607);

        assert_eq!(to_i32(&vec![0x00, 0x00, 0x80, 0x00]), 8388608);
        assert_eq!(to_i32(&vec![0x00, 0x00, 0x80, 0x80]), -8388608);

        assert_eq!(to_i32(&vec![0xff, 0xff, 0xff, 0x7f]), 2147483647);
        assert_eq!(to_i32(&vec![0xff, 0xff, 0xff, 0xff]), -2147483647);
    }

    #[test]
    fn test_to_vec_u8() {
        assert_eq!(vec![0x01], to_vec_u8(1));
        assert_eq!(vec![0x81], to_vec_u8(-1));

        assert_eq!(vec![0x7f], to_vec_u8(127));
        assert_eq!(vec![0xff], to_vec_u8(-127));

        assert_eq!(vec![0x80, 0x00], to_vec_u8(128));
        assert_eq!(vec![0x80, 0x80], to_vec_u8(-128));

        assert_eq!(vec![0xff, 0x7f], to_vec_u8(32767));
        assert_eq!(vec![0xff, 0xff], to_vec_u8(-32767));

        assert_eq!(vec![0x00, 0x80, 0x00], to_vec_u8(32768));
        assert_eq!(vec![0x00, 0x80, 0x80], to_vec_u8(-32768));

        assert_eq!(vec![0xff, 0xff, 0x7f], to_vec_u8(8388607));
        assert_eq!(vec![0xff, 0xff, 0xff], to_vec_u8(-8388607));

        assert_eq!(vec![0x00, 0x00, 0x80, 0x00], to_vec_u8(8388608));
        assert_eq!(vec![0x00, 0x00, 0x80, 0x80], to_vec_u8(-8388608));

        assert_eq!(vec![0xff, 0xff, 0xff, 0x7f], to_vec_u8(2147483647));
        assert_eq!(vec![0xff, 0xff, 0xff, 0xff], to_vec_u8(-2147483647));
    }
}
