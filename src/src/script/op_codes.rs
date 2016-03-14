use super::Context;

use utils::IntUtils;
use utils::CryptoUtils;

use serialize::Deserialize;
use super::BitcoinScript;

use std::fmt;
use std::cmp;

use std::io::Cursor;

fn op_dup(context: Context) -> Context {
    pick(context, 0)
}

fn op_ifdup(context: Context) -> Context {
    assert!(context.stack.len() > 0);

    if is_true(&context.stack.last()) {
        return op_dup(context);
    }

    context
}

fn stack_op<F>(context: Context, op: F) -> Context
where F: Fn(&mut Vec<Vec<u8>>) {
    let mut new_context = context;
    op(&mut new_context.stack);

    new_context
}

fn op_depth(context: Context) -> Context {
    assert!(context.stack.len() <= 0x7f);

    stack_op(context, |st| {
        let size = IntUtils::to_vec_u8(st.len() as i64);
        st.push(size);
    })
}

fn op_drop(context: Context) -> Context {
    stack_op(context, |st| { st.pop(); })
}

fn op_nip(context: Context) -> Context {
    assert!(context.stack.len() >= 1);

    stack_op(context, |st| {
        let el = st.pop().unwrap();
        st.pop();
        st.push(el);
    })
}

fn pick(context: Context, depth: usize) -> Context {
    assert!(context.stack.len() >= depth + 1);

    stack_op(context, |st| {
        let el = st.get(st.len() - depth - 1).unwrap().clone();
        st.push(el);
    })
}

fn op_toaltstack(context: Context) -> Context {
    assert!(context.stack.len() > 0);

    let mut new_context = context;
    let el = new_context.stack.pop().unwrap();
    new_context.altstack.push(el);

    new_context
}

fn op_fromaltstack(context: Context) -> Context {
    assert!(context.altstack.len() > 0);

    let mut new_context = context;
    let el = new_context.altstack.pop().unwrap();
    new_context.stack.push(el);

    new_context
}

fn op_over(context: Context) -> Context {
    pick(context, 1)
}

fn op_pick(context: Context) -> Context {
    assert!(context.stack.len() > 0);

    let mut new_context = context;
    let el = new_context.stack.pop().unwrap();
    let size = IntUtils::to_i32(&el);

    pick(new_context, size as usize)
}

fn roll(context: Context, size: u8) -> Context {
    assert!(size == 0x00 || context.stack.len() > size as usize - 1);

    stack_op(context, |st| {
        let pos = st.len() - 1 - size as usize;
        let el = st.remove(pos);
        st.push(el);
    })
}

fn op_roll(context: Context) -> Context {
    assert!(context.stack.len() > 0);

    let mut new_context = context;
    let size = IntUtils::to_i32(&new_context.stack.pop().unwrap());
    assert!(size <= 0xff);
    assert!(size >= 0x00);

    roll(new_context, size as u8)
}

fn op_rot(context: Context)  -> Context { roll(context, 2) }
fn op_swap(context: Context) -> Context { roll(context, 1) }

fn op_tuck(context: Context) -> Context {
    pick(roll(context, 1), 1)
}

fn op_2drop(context: Context) -> Context {
    op_drop(op_drop(context))
}

fn op_2dup(context: Context) -> Context {
    pick(pick(context, 1), 1)
}

fn op_3dup(context: Context) -> Context {
    pick(pick(pick(context, 2), 2), 2)
}

fn op_2over(context: Context) -> Context {
    pick(pick(context, 3), 3)
}

fn op_2rot(context: Context) -> Context {
    roll(roll(context, 5), 5)
}

fn op_2swap(context: Context) -> Context {
    roll(roll(context, 3), 3)
}

fn unary_op<F>(context: Context, op: F) -> Context
where F: Fn(i32) -> i64 {
    assert!(context.stack.len() > 0);

    stack_op(context, |st| {
        let input = IntUtils::to_i32(&st.pop().unwrap());
        st.push(IntUtils::to_vec_u8(op(input) as i64));
    })
}

fn op_1add(context: Context)   -> Context { unary_op(context, |a| a as i64 + 1 ) }
fn op_1sub(context: Context)   -> Context { unary_op(context, |a| a as i64 - 1) }
fn op_negate(context: Context) -> Context { unary_op(context, |a| a as i64 * -1) }
fn op_abs(context: Context)    -> Context { unary_op(context, |a| a.abs() as i64) }
fn op_not(context: Context) -> Context {
    unary_op(context, |a| if a == 0 { 1 } else { 0 })
}

fn op_0notequal(context: Context) -> Context {
    unary_op(context, |a| if a == 0 { 0 } else { 1 })
}

fn binary_op<F>(context: Context, op: F) -> Context
where F: Fn(i32, i32) -> i64 {
    assert!(context.stack.len() >= 2);

    stack_op(context, |st| {
        let input1 = IntUtils::to_i32(&st.pop().unwrap());
        let input2 = IntUtils::to_i32(&st.pop().unwrap());
        st.push(IntUtils::to_vec_u8(op(input2, input1)));
    })
}

fn bool_binary_op<F>(context: Context, op: F) -> Context
where F: Fn(i32, i32) -> bool {
    binary_op(context, |a, b| if op(a, b) { 1 } else { 0 })
}

fn op_add(context: Context) -> Context { binary_op(context, |a, b| a as i64 + b as i64) }
fn op_sub(context: Context) -> Context { binary_op(context, |a, b| a as i64 - b as i64) }

fn op_booland(context: Context) -> Context {
    bool_binary_op(context, |a, b| a != 0 && b != 0)
}

fn op_boolor(context: Context) -> Context {
    bool_binary_op(context, |a, b| a != 0 || b != 0)
}

fn op_numequal(context: Context) -> Context {
    bool_binary_op(context, |a, b| a == b)
}

fn op_numequalverify(context: Context) -> Context {
    op_verify(op_numequal(context))
}

fn op_numnotequal(context: Context) -> Context {
    bool_binary_op(context, |a, b| a != b)
}

fn op_lessthan(context: Context) -> Context {
    bool_binary_op(context, |a, b| a < b)
}

fn op_greaterthan(context: Context) -> Context {
    bool_binary_op(context, |a, b| a > b)
}

fn op_lessthanorequal(context: Context) -> Context {
    bool_binary_op(context, |a, b| a <= b)
}

fn op_greaterthanorequal(context: Context) -> Context {
    bool_binary_op(context, |a, b| a >= b)
}

fn op_min(context: Context) -> Context {
    binary_op(context, |a, b| cmp::min(a,b) as i64)
}

fn op_max(context: Context) -> Context {
    binary_op(context, |a, b| cmp::max(a,b) as i64)
}

fn ternary_op<F>(context: Context, op: F) -> Context
where F: Fn(i32, i32, i32) -> i32 {
    assert!(context.stack.len() >= 3);

    stack_op(context, |st| {
        let input1 = IntUtils::to_i32(&st.pop().unwrap());
        let input2 = IntUtils::to_i32(&st.pop().unwrap());
        let input3 = IntUtils::to_i32(&st.pop().unwrap());
        st.push(IntUtils::to_vec_u8(op(input3, input2, input1) as i64));
    })
}

fn bool_ternary_op<F>(context: Context, op: F) -> Context
where F: Fn(i32, i32, i32) -> bool {
    ternary_op(context, |a, b, c| if op(a, b, c) { 1 } else { 0 })
}

fn op_within(context: Context) -> Context {
    bool_ternary_op(context, |x, min, max| x >= min && x < max)
}

fn op_sha256(context: Context) -> Context {
    stack_op(context, |st| {
        let last = st.pop().unwrap();
        st.push(CryptoUtils::sha256(&last).to_vec());
    })
}

fn op_sha1(context: Context) -> Context {
    stack_op(context, |st| {
        let last = st.pop().unwrap();
        st.push(CryptoUtils::sha1(&last).to_vec());
    })
}

fn op_hash256(context: Context) -> Context {
    stack_op(context, |st| {
        let last = st.pop().unwrap();
        st.push(CryptoUtils::sha256(&CryptoUtils::sha256(&last)).to_vec());
    })
}

fn op_ripemd160(context: Context) -> Context {
    stack_op(context, |st| {
        let last = st.pop().unwrap();
        st.push(CryptoUtils::ripemd160(&last).to_vec());
    })
}

fn op_codeseparator(context: Context) -> Context {
    let mut new_context = context;

    new_context.codeseparator = new_context.script.index();

    new_context
}

fn get_boolean(data: bool) -> Vec<u8> {
    if data {
        vec![0x01]
    } else {
        vec![]
    }
}

fn op_checksig(context: Context) -> Context {
    assert!(context.stack.len() >= 2);

    let codeseparator = context.codeseparator;
    let checksig = context.checksig;
    let mut new_context = context;

    let pub_key_str = new_context.stack.pop().unwrap();
    let sig_str = new_context.stack.pop().unwrap();

    let result = get_boolean(checksig(codeseparator, &pub_key_str, &sig_str));

    new_context.stack.push(result);

    new_context
}

fn op_checksigverify(context: Context) -> Context {
    op_verify(op_checksig(context))
}

fn op_checkmultisig(context: Context) -> Context {
    assert!(context.stack.len() > 1);

    let codeseparator = context.codeseparator;
    let checksig = context.checksig;
    let mut new_context = context;

    let pub_keys_number = IntUtils::to_i32(&new_context.stack.pop().unwrap());
    assert!(pub_keys_number >= 0);
    assert!(pub_keys_number <= 20);
    assert!(new_context.stack.len() > pub_keys_number as usize);

    let mut pub_keys = vec![];
    for _ in 0..pub_keys_number {
        pub_keys.push(new_context.stack.pop().unwrap());
    }
    pub_keys.reverse();

    let sig_strs_number = IntUtils::to_i32(&new_context.stack.pop().unwrap());
    assert!(sig_strs_number >= 0);
    assert!(sig_strs_number <= pub_keys_number);
    assert!(new_context.stack.len() > sig_strs_number as usize);

    let mut sig_strs = vec![];
    for _ in 0..sig_strs_number {
        sig_strs.push(new_context.stack.pop().unwrap());
    }
    sig_strs.reverse();

    let mut verified = 0;
    while pub_keys.len() > 0 && sig_strs.len() > 0 {
        let sig_str = sig_strs.pop().unwrap();
        while pub_keys.len() > 0 {
            let pub_key = pub_keys.pop().unwrap();
            if checksig(codeseparator, &pub_key, &sig_str) {
                verified += 1;
                break;
            }
        }
    }

    let result = verified == sig_strs_number;
    // Apparently the official client has a bug that
    // pops an extra element from the stack that we have
    // to emulate here.
    new_context.stack.pop();
    new_context.stack.push(get_boolean(result));

    new_context
}

fn op_checkmultisigverify(context: Context) -> Context {
    op_verify(op_checkmultisig(context))
}

fn op_hash160(context: Context) -> Context {
    stack_op(context, |st| {
        let last = st.pop().unwrap();
        st.push(CryptoUtils::ripemd160(&CryptoUtils::sha256(&last))
                .to_vec());
    })
}

fn op_equalverify(context: Context) -> Context {
    op_verify(op_equal(context))
}

fn op_equal(context: Context) -> Context {
    assert!(context.stack.len() >= 2);

    stack_op(context, |st| {
        let x = st.pop().unwrap();
        let y = st.pop().unwrap();

        st.push(get_boolean(x.eq(&y)));
    })
}

fn op_false(context: Context) -> Context {
    stack_op(context, |st| st.push(vec![]))
}

fn op_pushdata(context: Context) -> Context {
    let mut new_context = context;
    let byte = new_context.script.current().unwrap().to_byte();

    new_context.script.next();
    let data = new_context.script.read(byte as usize);
    new_context.stack.push(data);

    new_context
}

fn op_pushdata1(context: Context) -> Context {
    op_pushdata_base::<u8>(context, 1)
}

fn op_pushdata2(context: Context) -> Context {
    op_pushdata_base::<u16>(context, 2)
}

fn op_pushdata4(context: Context) -> Context {
    op_pushdata_base::<u32>(context, 4)
}

// TODO: see if there's a better way to do this
trait ToUsize {
    fn to_usize(self) -> usize;
}

impl ToUsize for u8 {
    fn to_usize(self) -> usize { self as usize }
}

impl ToUsize for u16 {
    fn to_usize(self) -> usize { self as usize }
}

impl ToUsize for u32 {
    fn to_usize(self) -> usize { self as usize }
}

fn op_pushdata_base<T: Deserialize + ToUsize>(context: Context, size: usize) -> Context {
    let mut new_context = context;

    new_context.script.next();

    let data = new_context.script.read(size);

    if data.len() < size {
        // not enough data
        new_context.valid = false;
        return new_context;
    }

    let bytes = T::deserialize(&mut Cursor::new(data));

    match bytes {
        Ok(b) => {
            let mut data = vec![];
            let b_usize = b.to_usize();
            if b_usize > 0 {
                new_context.script.next();
                data = new_context.script.read(b_usize);
            }

            new_context.stack.push(data);
        }
        Err(_) => {
            new_context.valid = false;
        }
    }

    new_context
}

fn push_to_stack(context: Context, data: u8) -> Context {
    stack_op(context, |st| st.push(vec![data]))
}

fn op_1negate(context: Context) -> Context {
    // 0x81 is -1 TODO: consider moving to Vec<i8>
    push_to_stack(context, 0x81)
}

fn  op_1(context: Context) -> Context { push_to_stack(context, 0x01) }
fn  op_2(context: Context) -> Context { push_to_stack(context, 0x02) }
fn  op_3(context: Context) -> Context { push_to_stack(context, 0x03) }
fn  op_4(context: Context) -> Context { push_to_stack(context, 0x04) }
fn  op_5(context: Context) -> Context { push_to_stack(context, 0x05) }
fn  op_6(context: Context) -> Context { push_to_stack(context, 0x06) }
fn  op_7(context: Context) -> Context { push_to_stack(context, 0x07) }
fn  op_8(context: Context) -> Context { push_to_stack(context, 0x08) }
fn  op_9(context: Context) -> Context { push_to_stack(context, 0x09) }
fn op_10(context: Context) -> Context { push_to_stack(context, 0x0a) }
fn op_11(context: Context) -> Context { push_to_stack(context, 0x0b) }
fn op_12(context: Context) -> Context { push_to_stack(context, 0x0c) }
fn op_13(context: Context) -> Context { push_to_stack(context, 0x0d) }
fn op_14(context: Context) -> Context { push_to_stack(context, 0x0e) }
fn op_15(context: Context) -> Context { push_to_stack(context, 0x0f) }
fn op_16(context: Context) -> Context { push_to_stack(context, 0x10) }

fn op_nop(context: Context) -> Context { context }

fn op_if(context: Context) -> Context {
    let mut new_context = context;
    let last = new_context.stack.pop().unwrap();

    new_context.script.next();

    if is_true(&Some(&last)) {
        new_context.conditional_executed.push(true);
        new_context
    } else {
        new_context.conditional_executed.push(false);
        goto_next_branch(new_context)
    }
}

fn goto_next_branch(context: Context) -> Context {
    let mut new_context = context;
    let mut level = 1;

    while level > 0 && new_context.script.valid() {
        let next = get_next_op(&new_context.script);

        new_context.script.pointer = next;

        match new_context.script.current() {
            Some(op) => match op {
                OpCode::If | OpCode::NotIf => level += 1,
                OpCode::Else => {
                    if level == 1 {
                        break;
                    }
                },
                OpCode::EndIf => {
                    level -= 1;
                    if level == 0 {
                        break;
                    }
                }
                _ => {}
            },
            None => {
                new_context.valid = false;
                return new_context;
            }
        };

        new_context.script.next();
    }

    new_context
}

// TODO: this should use more the existing logic that implements pushdata
fn get_next_op(script: &BitcoinScript) -> usize {
    let mut i = script.pointer;
    let sc = &script.script;

    while i < sc.len() {
        match sc[i] {
            0x01 ... 0x4b => {
                i += sc[i] as usize;
            },
            0x4c => {
                if sc.len() <= i + 1 {
                    return sc.len();
                }
                i += sc[i + 1] as usize;
            },
            0x4d => {
                if sc.len() <= i + 2 {
                    return sc.len();
                }
                let bytes_array = &sc[i+1..i+3];
                let bytes = u16::deserialize(&mut Cursor::new(bytes_array));
                // TODO: handle errors
                i += bytes.unwrap() as usize;
            },
            0x4e => {
                if sc.len() <= i + 4 {
                    return sc.len();
                }
                let bytes_array = &sc[i+1..i+5];
                let bytes = u32::deserialize(&mut Cursor::new(bytes_array));
                // TODO: handle errors
                i += bytes.unwrap() as usize;
            },
            _ => {
                return i;
            },
        }

        i += 1;
    }

    sc.len()
}

fn op_else(context: Context) -> Context {
    let mut new_context = context;
    let conditional_executed = new_context.conditional_executed.pop().unwrap();
    new_context.script.next();
    new_context.conditional_executed.push(!conditional_executed);

    if !conditional_executed {
        new_context
    } else {
        goto_next_branch(new_context)
    }
}

fn op_notif(context: Context) -> Context {
    let mut new_context = context;
    let last = new_context.stack.pop().unwrap();

    new_context.script.next();

    if !is_true(&Some(&last)) {
        new_context.conditional_executed.push(true);
        new_context
    } else {
        new_context.conditional_executed.push(false);
        goto_next_branch(new_context)
    }
}

fn op_endif(context: Context) -> Context {
    let mut new_context = context;

    new_context.conditional_executed.pop();

    new_context
}

fn to_bool(element: &Vec<u8>) -> bool {
    if element.len() == 0 {
        return false;
    }

    for i in 0..element.len()-1 {
        if *element.get(i).unwrap() != 0x00 {
            return true;
        }
    }

    return *element.last().unwrap() != 0x80;
}

pub fn is_true(element: &Option<&Vec<u8>>) -> bool {
    match element {
        &Some(x) => to_bool(x),
        &None => false,
    }
}

fn op_verify(context: Context) -> Context {
    let mut new_context = context;

    new_context.valid = is_true(&new_context.stack.last());
    new_context.stack.pop();

    return new_context;
}

fn op_mark_invalid(context: Context) -> Context {
    let mut new_context = context;

    new_context.valid = false;

    return new_context;
}

fn op_size(context: Context) -> Context {
    assert!(context.stack.len() > 0);

    stack_op(context, |st| {
        let size = IntUtils::to_vec_u8(st.last().unwrap().len() as i64);
        st.push(size);
    })
}

impl fmt::Debug for Context {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Context(data={:?}, stack={:?}, valid={:?}, branch_executed={:?})",
               self.script, self.stack, self.valid, self.conditional_executed)
    }
}

impl cmp::PartialEq for Context {
    fn eq(&self, other: &Context) -> bool {
        self.script == other.script && self.stack == other.stack &&
            self.valid == other.valid
    }
}

macro_rules! op_codes {
    ($($element: ident: ($tostring: expr, $hex: expr, $func: path)),+;
     $($advancing: ident),*) => {
        #[derive(Debug, Copy, Clone, PartialEq)]
        pub enum OpCode {
            $($element),+
        }

        impl OpCode {
            pub fn to_byte(&self) -> u8 {
                match self {
                    $(&OpCode::$element => $hex),*
                }
            }

            pub fn from_byte(hex: u8) -> Option<OpCode> {
                match hex {
                    $($hex => Some(OpCode::$element)),*,
                    _ => None,
                }
            }

            pub fn execute(&self, context: Context) -> Context {
                match self {
                    $(&OpCode::$element => $func(context)),*
                }
            }

            pub fn is_advancing(&self) -> bool {
                match self {
                    $(&OpCode::$advancing => true),*,
                    _ => false,
                }
            }

            pub fn from_str(data: &str) -> Option<OpCode> {
                match data {
                    $($tostring => Some(OpCode::$element)),*,
                    _ => None,
                }
            }
        }
    }
}

op_codes!(
    _0:                  ("0",                  0x00, op_false),
    // TODO: maybe figure it out if I can use a macro to generate Push[1..75]Bytes
    Push1Byte:           ("PUSH1",              0x01, op_pushdata),
    Push2Bytes:          ("PUSH2",              0x02, op_pushdata),
    Push3Bytes:          ("PUSH3",              0x03, op_pushdata),
    Push4Bytes:          ("PUSH4",              0x04, op_pushdata),
    Push5Bytes:          ("PUSH5",              0x05, op_pushdata),
    Push6Bytes:          ("PUSH6",              0x06, op_pushdata),
    Push7Bytes:          ("PUSH7",              0x07, op_pushdata),
    Push8Bytes:          ("PUSH8",              0x08, op_pushdata),
    Push9Bytes:          ("PUSH9",              0x09, op_pushdata),
    Push10Bytes:         ("PUSH10",             0x0a, op_pushdata),
    Push11Bytes:         ("PUSH11",             0x0b, op_pushdata),
    Push12Bytes:         ("PUSH12",             0x0c, op_pushdata),
    Push13Bytes:         ("PUSH13",             0x0d, op_pushdata),
    Push14Bytes:         ("PUSH14",             0x0e, op_pushdata),
    Push15Bytes:         ("PUSH15",             0x0f, op_pushdata),
    Push16Bytes:         ("PUSH16",             0x10, op_pushdata),
    Push17Bytes:         ("PUSH17",             0x11, op_pushdata),
    Push18Bytes:         ("PUSH18",             0x12, op_pushdata),
    Push19Bytes:         ("PUSH19",             0x13, op_pushdata),
    Push20Bytes:         ("PUSH20",             0x14, op_pushdata),
    Push21Bytes:         ("PUSH21",             0x15, op_pushdata),
    Push22Bytes:         ("PUSH22",             0x16, op_pushdata),
    Push23Bytes:         ("PUSH23",             0x17, op_pushdata),
    Push24Bytes:         ("PUSH24",             0x18, op_pushdata),
    Push25Bytes:         ("PUSH25",             0x19, op_pushdata),
    Push26Bytes:         ("PUSH26",             0x1a, op_pushdata),
    Push27Bytes:         ("PUSH27",             0x1b, op_pushdata),
    Push28Bytes:         ("PUSH28",             0x1c, op_pushdata),
    Push29Bytes:         ("PUSH29",             0x1d, op_pushdata),
    Push30Bytes:         ("PUSH30",             0x1e, op_pushdata),
    Push31Bytes:         ("PUSH31",             0x1f, op_pushdata),
    Push32Bytes:         ("PUSH32",             0x20, op_pushdata),
    Push33Bytes:         ("PUSH33",             0x21, op_pushdata),
    Push34Bytes:         ("PUSH34",             0x22, op_pushdata),
    Push35Bytes:         ("PUSH35",             0x23, op_pushdata),
    Push36Bytes:         ("PUSH36",             0x24, op_pushdata),
    Push37Bytes:         ("PUSH37",             0x25, op_pushdata),
    Push38Bytes:         ("PUSH38",             0x26, op_pushdata),
    Push39Bytes:         ("PUSH39",             0x27, op_pushdata),
    Push40Bytes:         ("PUSH40",             0x28, op_pushdata),
    Push41Bytes:         ("PUSH41",             0x29, op_pushdata),
    Push42Bytes:         ("PUSH42",             0x2a, op_pushdata),
    Push43Bytes:         ("PUSH43",             0x2b, op_pushdata),
    Push44Bytes:         ("PUSH44",             0x2c, op_pushdata),
    Push45Bytes:         ("PUSH45",             0x2d, op_pushdata),
    Push46Bytes:         ("PUSH46",             0x2e, op_pushdata),
    Push47Bytes:         ("PUSH47",             0x2f, op_pushdata),
    Push48Bytes:         ("PUSH48",             0x30, op_pushdata),
    Push49Bytes:         ("PUSH49",             0x31, op_pushdata),
    Push50Bytes:         ("PUSH50",             0x32, op_pushdata),
    Push51Bytes:         ("PUSH51",             0x33, op_pushdata),
    Push52Bytes:         ("PUSH52",             0x34, op_pushdata),
    Push53Bytes:         ("PUSH53",             0x35, op_pushdata),
    Push54Bytes:         ("PUSH54",             0x36, op_pushdata),
    Push55Bytes:         ("PUSH55",             0x37, op_pushdata),
    Push56Bytes:         ("PUSH56",             0x38, op_pushdata),
    Push57Bytes:         ("PUSH57",             0x39, op_pushdata),
    Push58Bytes:         ("PUSH58",             0x3a, op_pushdata),
    Push59Bytes:         ("PUSH59",             0x3b, op_pushdata),
    Push60Bytes:         ("PUSH60",             0x3c, op_pushdata),
    Push61Bytes:         ("PUSH61",             0x3d, op_pushdata),
    Push62Bytes:         ("PUSH62",             0x3e, op_pushdata),
    Push63Bytes:         ("PUSH63",             0x3f, op_pushdata),
    Push64Bytes:         ("PUSH64",             0x40, op_pushdata),
    Push65Bytes:         ("PUSH65",             0x41, op_pushdata),
    Push66Bytes:         ("PUSH66",             0x42, op_pushdata),
    Push67Bytes:         ("PUSH67",             0x43, op_pushdata),
    Push68Bytes:         ("PUSH68",             0x44, op_pushdata),
    Push69Bytes:         ("PUSH69",             0x45, op_pushdata),
    Push70Bytes:         ("PUSH70",             0x46, op_pushdata),
    Push71Bytes:         ("PUSH71",             0x47, op_pushdata),
    Push72Bytes:         ("PUSH72",             0x48, op_pushdata),
    Push73Bytes:         ("PUSH73",             0x49, op_pushdata),
    Push74Bytes:         ("PUSH74",             0x4a, op_pushdata),
    Push75Bytes:         ("PUSH75",             0x4b, op_pushdata),
    PushData1:           ("PUSHDATA1",          0x4c, op_pushdata1),
    PushData2:           ("PUSHDATA2",          0x4d, op_pushdata2),
    PushData4:           ("PUSHDATA4",          0x4e, op_pushdata4),
    _1Negate:            ("1NEGATE",            0x4f, op_1negate),
    Reserved:            ("RESERVED",           0x50, op_mark_invalid),
    _1:                  ("1",                  0x51, op_1),
    _2:                  ("2",                  0x52, op_2),
    _3:                  ("3",                  0x53, op_3),
    _4:                  ("4",                  0x54, op_4),
    _5:                  ("5",                  0x55, op_5),
    _6:                  ("6",                  0x56, op_6),
    _7:                  ("7",                  0x57, op_7),
    _8:                  ("8",                  0x58, op_8),
    _9:                  ("9",                  0x59, op_9),
    _10:                 ("10",                 0x5a, op_10),
    _11:                 ("11",                 0x5b, op_11),
    _12:                 ("12",                 0x5c, op_12),
    _13:                 ("13",                 0x5d, op_13),
    _14:                 ("14",                 0x5e, op_14),
    _15:                 ("15",                 0x5f, op_15),
    _16:                 ("16",                 0x60, op_16),
    Nop:                 ("NOP",                0x61, op_nop),
    Ver:                 ("VER",                0x62, op_mark_invalid),
    If:                  ("IF",                 0x63, op_if),
    NotIf:               ("NOTIF",              0x64, op_notif),
    // TODO: opcodes 0x65 - 0x66 (reserved opcodes)
    Else:                ("ELSE",               0x67, op_else),
    EndIf:               ("ENDIF",              0x68, op_endif),
    Verify:              ("VERIFY",             0x69, op_verify),
    Return:              ("RETURN",             0x6a, op_mark_invalid),
    ToAltStack:          ("TOALTSTACK",         0x6b, op_toaltstack),
    FromAltStack:        ("FROMALTSTACK",       0x6c, op_fromaltstack),
    _2Drop:              ("2DROP",              0x6d, op_2drop),
    _2Dup:               ("2DUP",               0x6e, op_2dup),
    _3Dup:               ("3DUP",               0x6f, op_3dup),
    _2Over:              ("2OVER",              0x70, op_2over),
    _2Rot:               ("2ROT",               0x71, op_2rot),
    _2Swap:              ("2SWAP",              0x72, op_2swap),
    IfDup:               ("IFDUP",              0x73, op_ifdup),
    Depth:               ("DEPTH",              0x74, op_depth),
    _Drop:               ("DROP",               0x75, op_drop),
    Dup:                 ("DUP",                0x76, op_dup),
    Nip:                 ("NIP",                0x77, op_nip),
    Over:                ("OVER",               0x78, op_over),
    Pick:                ("PICK",               0x79, op_pick),
    Roll:                ("ROLL",               0x7a, op_roll),
    Rot:                 ("ROT",                0x7b, op_rot),
    Swap:                ("SWAP",               0x7c, op_swap),
    Tuck:                ("TUCK",               0x7d, op_tuck),
    // opcodes 0x7e - 0x81 (disabled opcodes)
    Size:                ("SIZE",               0x82, op_size),
    // opcodes 0x83 - 0x86 (disabled opcodes)
    Equal:               ("EQUAL",              0x87, op_equal),
    EqualVerify:         ("EQUALVERIFY",        0x88, op_equalverify),
    Reserved1:           ("RESERVED1",          0x89, op_mark_invalid),
    Reserved2:           ("RESERVED2",          0x8a, op_mark_invalid),
    _1Add:               ("1ADD",               0x8b, op_1add),
    _1Sub:               ("1SUB",               0x8c, op_1sub),
    // opcodes 0x8d - 0x8e (disabled opcodes)
    Negate:              ("NEGATE",             0x8f, op_negate),
    Abs:                 ("ABS",                0x90, op_abs),
    Not:                 ("NOT",                0x91, op_not),
    _0NotEqual:          ("0NOTEQUAL",          0x92, op_0notequal),
    Add:                 ("ADD",                0x93, op_add),
    Sub:                 ("SUB",                0x94, op_sub),
    // opcodes 0x95 - 0x99 (disabled opcodes)
    BoolAnd:             ("BOOLAND",            0x9a, op_booland),
    BoolOr:              ("BOOLOR",             0x9b, op_boolor),
    NumEqual:            ("NUMEQUAL",           0x9c, op_numequal),
    NumEqualVerify:      ("NUMEQUALVERIFY",     0x9d, op_numequalverify),
    NumNotEqual:         ("NUMNOTEQUAL",        0x9e, op_numnotequal),
    LessThan:            ("LESSTHAN",           0x9f, op_lessthan),
    GreaterThan:         ("GREATERTHAN",        0xa0, op_greaterthan),
    LessThanOrEqual:     ("LESSTHANOREQUAL",    0xa1, op_lessthanorequal),
    GreaterThanOrEqual:  ("GREATERTHANOREQUAL", 0xa2, op_greaterthanorequal),
    Min:                 ("MIN",                0xa3, op_min),
    Max:                 ("MAX",                0xa4, op_max),
    Within:              ("WITHIN",             0xa5, op_within),
    Ripemd160:           ("RIPEMD160",          0xa6, op_ripemd160),
    Sha1:                ("SHA1",               0xa7, op_sha1),
    Sha256:              ("SHA256",             0xa8, op_sha256),
    Hash160:             ("HASH160",            0xa9, op_hash160),
    Hash256:             ("HASH256",            0xaa, op_hash256),
    CodeSeparator:       ("CODESEPARATOR",      0xab, op_codeseparator),
    CheckSig:            ("CHECKSIG",           0xac, op_checksig),
    CheckSigVerify:      ("CHECKSIGVERIFY",     0xad, op_checksigverify),
    CheckMultiSig:       ("CHECKMULTISIG",      0xae, op_checkmultisig),
    CheckMultiSigVerify: ("CHECKMULTISIGVERIFY",0xaf, op_checkmultisigverify),
    Nop1:                ("NOP1",               0xb0, op_nop),
    // TODO: CheckLockTimeVerify
    CheckLockTimeVerify: ("CHECKLOCKTIMEVERIFY",0xb1, op_nop),
    Nop3:                ("NOP3",               0xb2, op_nop),
    Nop4:                ("NOP4",               0xb3, op_nop),
    Nop5:                ("NOP5",               0xb4, op_nop),
    Nop6:                ("NOP6",               0xb5, op_nop),
    Nop7:                ("NOP7",               0xb6, op_nop),
    Nop8:                ("NOP8",               0xb7, op_nop),
    Nop9:                ("NOP9",               0xb8, op_nop),
    Nop10:               ("NOP10",              0xb9, op_nop),
    Invalid11:           ("INVALID11",          0xba, op_mark_invalid),
    Invalid12:           ("INVALID12",          0xbb, op_mark_invalid),
    Invalid13:           ("INVALID13",          0xbc, op_mark_invalid),
    Invalid14:           ("INVALID14",          0xbd, op_mark_invalid),
    Invalid15:           ("INVALID15",          0xbe, op_mark_invalid),
    Invalid16:           ("INVALID16",          0xbf, op_mark_invalid),
    Invalid17:           ("INVALID17",          0xc0, op_mark_invalid),
    Invalid18:           ("INVALID18",          0xc1, op_mark_invalid),
    Invalid19:           ("INVALID19",          0xc2, op_mark_invalid),
    Invalid20:           ("INVALID20",          0xc3, op_mark_invalid),
    Invalid21:           ("INVALID21",          0xc4, op_mark_invalid),
    Invalid22:           ("INVALID22",          0xc5, op_mark_invalid),
    Invalid23:           ("INVALID23",          0xc6, op_mark_invalid),
    Invalid24:           ("INVALID24",          0xc7, op_mark_invalid),
    Invalid25:           ("INVALID25",          0xc8, op_mark_invalid),
    Invalid26:           ("INVALID26",          0xc9, op_mark_invalid),
    Invalid27:           ("INVALID27",          0xca, op_mark_invalid),
    Invalid28:           ("INVALID28",          0xcb, op_mark_invalid),
    Invalid29:           ("INVALID29",          0xcc, op_mark_invalid),
    Invalid30:           ("INVALID30",          0xcd, op_mark_invalid),
    Invalid31:           ("INVALID31",          0xce, op_mark_invalid),
    Invalid32:           ("INVALID32",          0xcf, op_mark_invalid),
    Invalid33:           ("INVALID33",          0xd0, op_mark_invalid),
    Invalid34:           ("INVALID34",          0xd1, op_mark_invalid),
    Invalid35:           ("INVALID35",          0xd2, op_mark_invalid),
    Invalid36:           ("INVALID36",          0xd3, op_mark_invalid),
    Invalid37:           ("INVALID37",          0xd4, op_mark_invalid),
    Invalid38:           ("INVALID38",          0xd5, op_mark_invalid),
    Invalid39:           ("INVALID39",          0xd6, op_mark_invalid),
    Invalid40:           ("INVALID40",          0xd7, op_mark_invalid),
    Invalid41:           ("INVALID41",          0xd8, op_mark_invalid),
    Invalid42:           ("INVALID42",          0xd9, op_mark_invalid),
    Invalid43:           ("INVALID43",          0xda, op_mark_invalid),
    Invalid44:           ("INVALID44",          0xdb, op_mark_invalid),
    Invalid45:           ("INVALID45",          0xdc, op_mark_invalid),
    Invalid46:           ("INVALID46",          0xdd, op_mark_invalid),
    Invalid47:           ("INVALID47",          0xde, op_mark_invalid),
    Invalid48:           ("INVALID48",          0xdf, op_mark_invalid),
    Invalid49:           ("INVALID49",          0xe0, op_mark_invalid),
    Invalid50:           ("INVALID50",          0xe1, op_mark_invalid),
    Invalid51:           ("INVALID51",          0xe2, op_mark_invalid),
    Invalid52:           ("INVALID52",          0xe3, op_mark_invalid),
    Invalid53:           ("INVALID53",          0xe4, op_mark_invalid),
    Invalid54:           ("INVALID54",          0xe5, op_mark_invalid),
    Invalid55:           ("INVALID55",          0xe6, op_mark_invalid),
    Invalid56:           ("INVALID56",          0xe7, op_mark_invalid),
    Invalid57:           ("INVALID57",          0xe8, op_mark_invalid),
    Invalid58:           ("INVALID58",          0xe9, op_mark_invalid),
    Invalid59:           ("INVALID59",          0xea, op_mark_invalid),
    Invalid60:           ("INVALID60",          0xeb, op_mark_invalid),
    Invalid61:           ("INVALID61",          0xec, op_mark_invalid),
    Invalid62:           ("INVALID62",          0xed, op_mark_invalid),
    Invalid63:           ("INVALID63",          0xee, op_mark_invalid),
    Invalid64:           ("INVALID64",          0xef, op_mark_invalid),
    Invalid65:           ("INVALID65",          0xf0, op_mark_invalid),
    Invalid66:           ("INVALID66",          0xf1, op_mark_invalid),
    Invalid67:           ("INVALID67",          0xf2, op_mark_invalid),
    Invalid68:           ("INVALID68",          0xf3, op_mark_invalid),
    Invalid69:           ("INVALID69",          0xf4, op_mark_invalid),
    Invalid70:           ("INVALID70",          0xf5, op_mark_invalid),
    Invalid71:           ("INVALID71",          0xf6, op_mark_invalid),
    Invalid72:           ("INVALID72",          0xf7, op_mark_invalid),
    Invalid73:           ("INVALID73",          0xf8, op_mark_invalid),
    Invalid74:           ("INVALID74",          0xf9, op_mark_invalid),
    Invalid75:           ("INVALID75",          0xfa, op_mark_invalid),
    Invalid76:           ("INVALID76",          0xfb, op_mark_invalid),
    Invalid77:           ("INVALID77",          0xfc, op_mark_invalid),
    Invalid78:           ("INVALID78",          0xfd, op_mark_invalid),
    Invalid79:           ("INVALID79",          0xfe, op_mark_invalid),
    Invalid80:           ("INVALID80",          0xff, op_mark_invalid);
    // Advancing op codes
    If, NotIf, Else
);

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::*;

    use rustc_serialize::base64::FromBase64;
    const ZERO : u8 = 0x80;

    fn mock_checksig(_: usize, _: &Vec<u8>, _: &Vec<u8>) -> bool { true }

    fn get_context(stack: Vec<Vec<u8>>) -> Context {
        Context::new(vec![], stack, mock_checksig)
    }

    #[test]
    fn test_op_dup() {
        let context = get_context(vec![vec![0x01]]);
        let output = OpCode::Dup.execute(context);

        assert_eq!(get_context(vec![vec![0x01], vec![0x01]]), output);
    }

    #[test]
    #[should_panic]
    fn test_op_dup_panic() {
        let context = get_context(vec![]);
        OpCode::Dup.execute(context);
    }

    #[test]
    fn test_op_equalverify_zero_false() {
        let context = get_context(vec![vec![], vec![ZERO]]);
        let output = OpCode::EqualVerify.execute(context);
        let mut expected = get_context(vec![]);
        expected.valid = false;

        assert_eq!(expected, output);
    }

    #[test]
    fn test_op_equalverify_true() {
        let context = get_context(vec![vec![0x01], vec![0x01]]);
        let output = OpCode::EqualVerify.execute(context);

        assert_eq!(get_context(vec![]), output);
    }

    #[test]
    fn test_op_equalverify_false() {
        let context = get_context(vec![vec![0x01], vec![0x02]]);
        let output = OpCode::EqualVerify.execute(context);

        let mut expected = get_context(vec![]);
        expected.valid = false;

        assert_eq!(expected, output);
    }

    #[test]
    #[should_panic]
    fn test_op_equalverify_panic() {
        let context = get_context(vec![]);
        OpCode::EqualVerify.execute(context);
    }

    #[test]
    fn test_op_equal_true() {
        let context = get_context(vec![vec![0x01], vec![0x01]]);
        let output = OpCode::Equal.execute(context);

        assert_eq!(get_context(vec![vec![0x01]]), output);
    }

    #[test]
    fn test_op_equal_false() {
        let context = get_context(vec![vec![0x01], vec![0x02]]);
        let output = OpCode::Equal.execute(context);

        assert_eq!(get_context(vec![vec![]]), output);
    }

    fn test_op_hash(op_hash: OpCode, input: &str, expected: &str) {
        let context = get_context(vec![input.from_base64().unwrap()]);
        let output = op_hash.execute(context);

        assert_eq!(get_context(vec![expected.from_base64().unwrap()]),
                   output);
    }

    #[test]
    fn test_op_hash256() {
        test_op_hash(OpCode::Hash256, "YQ==", "v106/7c+/S7Gw2rTES3ZM+/tY8Thy//PqI4nWcFE8tg=");
        test_op_hash(OpCode::Hash256, "", "Xfbg4nYTWdMKgnUFjimfzAOBU0VF9Vz0PkGYP11MlFY=");
        test_op_hash(OpCode::Hash256, "YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXo", "yhObwQwvZg2kJmb3LomiJZNvxg8ZPBYRJKZyBQxDRnE=");
    }

    #[test]
    fn test_op_hash160() {
        test_op_hash(OpCode::Hash160, "", "tHKiZtC9icE3BqQTLM+xb3w7n8s=");
        test_op_hash(OpCode::Hash160, "YQ==", "mUNVGZ5Rb/dsT6Sqs5M3udhM8Ss=");
        test_op_hash(OpCode::Hash160, "YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXo", "woahrwlH9Y0a14c4WxwsSpdvnnE=");
    }

    fn test_nop(nop: OpCode) {
        let context = get_context(vec![vec![0x02], vec![0x03]]);
        let output = nop.execute(context);
        assert_eq!(output, get_context(vec![vec![0x02], vec![0x03]]));
    }

    #[test]
    fn test_op_false() {
        let context = get_context(vec![vec![0x02], vec![0x03]]);
        let output = OpCode::_0.execute(context);

        assert_eq!(output, get_context(vec![vec![0x02], vec![0x03], vec![]]));
    }

    #[test]
    fn test_op_nop() {
        test_nop(OpCode::Nop);
    }

    #[test]
    fn test_op_pushdata4() {
        let script = vec![0x4e, 0x02, 0x00, 0x00, 0x00, 0x03, 0x04];
        let context = Context::new(script.clone(), vec![], mock_checksig);
        let mut expected = Context::new(script, vec![vec![0x03, 0x04]], mock_checksig);
        advance(&mut expected, 6);

        let output = OpCode::PushData4.execute(context);
        assert_eq!(output, expected);
    }

    #[test]
    fn test_op_pushdata2() {
        let script = vec![0x4d, 0x02, 0x00, 0x03, 0x04];
        let context = Context::new(script.clone(), vec![], mock_checksig);
        let mut expected = Context::new(script, vec![vec![0x03, 0x04]], mock_checksig);
        advance(&mut expected, 4);

        let output = OpCode::PushData2.execute(context);
        assert_eq!(output, expected);
    }

    fn advance(context: &mut Context, bytes: usize) {
        for _ in 0..bytes {
            context.script.next();
        }
    }

    #[test]
    fn test_op_pushdata1() {
        let script = vec![0x4c, 0x02, 0x03, 0x04];
        let context = Context::new(script.clone(), vec![], mock_checksig);
        let mut expected = Context::new(script, vec![vec![0x03, 0x04]], mock_checksig);
        advance(&mut expected, 3);

        let output = OpCode::PushData1.execute(context);
        assert_eq!(output, expected);
    }

    #[test]
    fn test_op_pushdata_generic() {
        let context = Context::new(vec![0x01, 0x03], vec![], mock_checksig);
        let mut expected = Context::new(vec![0x01, 0x03], vec![vec![0x03]], mock_checksig);
        advance(&mut expected, 1);

        let output = OpCode::Push1Byte.execute(context);
        assert_eq!(output, expected);
    }

    fn test_push_to_stack(data: u8, push: OpCode) {
        let context = get_context(vec![]);
        let output = push.execute(context);
        assert_eq!(output, get_context(vec![vec![data]]));
    }

    #[test]
    fn test_1negate() { test_push_to_stack(0x81, OpCode::_1Negate); }

    #[test]
    fn test_op_n() {
        test_push_to_stack(0x01, OpCode::_1);
        test_push_to_stack(0x02, OpCode::_2);
        test_push_to_stack(0x03, OpCode::_3);
        test_push_to_stack(0x04, OpCode::_4);
        test_push_to_stack(0x05, OpCode::_5);
        test_push_to_stack(0x06, OpCode::_6);
        test_push_to_stack(0x07, OpCode::_7);
        test_push_to_stack(0x08, OpCode::_8);
        test_push_to_stack(0x09, OpCode::_9);
        test_push_to_stack(0x0a, OpCode::_10);
        test_push_to_stack(0x0b, OpCode::_11);
        test_push_to_stack(0x0c, OpCode::_12);
        test_push_to_stack(0x0d, OpCode::_13);
        test_push_to_stack(0x0e, OpCode::_14);
        test_push_to_stack(0x0f, OpCode::_15);
        test_push_to_stack(0x10, OpCode::_16);
    }

    fn test_op_verify(data: Vec<Vec<u8>>, valid: bool) {
        let context = get_context(data);
        let output = OpCode::Verify.execute(context);

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
    fn test_op_ifdup_false() {
        let context = get_context(vec![vec![]]);
        let output = OpCode::IfDup.execute(context);

        assert_eq!(output, get_context(vec![vec![]]));
    }

    #[test]
    fn test_op_ifdup_true() {
        let context = get_context(vec![vec![0x81]]);
        let output = OpCode::IfDup.execute(context);

        assert_eq!(output, get_context(vec![vec![0x81], vec![0x81]]));
    }

    #[test]
    #[should_panic]
    fn test_op_ifdup_panic() {
        OpCode::IfDup.execute(get_context(vec![]));
    }

    fn test_stack_base(op: OpCode, stack: Vec<Vec<u8>>, expected: Vec<Vec<u8>>) {
        let output = op.execute(get_context(stack));
        assert_eq!(output, get_context(expected));
    }

    #[test]
    fn test_op_depth() {
        test_stack_base(OpCode::Depth, vec![], vec![vec![]]);
        test_stack_base(OpCode::Depth, vec![vec![0x01]], vec![vec![0x01], vec![0x01]]);
        test_stack_base(OpCode::Depth, vec![vec![0x01], vec![0x02]],
                                      vec![vec![0x01], vec![0x02], vec![0x02]]);
        test_stack_base(OpCode::Depth, vec![vec![0x01], vec![0x02], vec![0x03]],
                                      vec![vec![0x01], vec![0x02], vec![0x03], vec![0x03]]);
    }

    #[test]
    fn test_op_drop() {
        test_stack_base(OpCode::_Drop, vec![], vec![]);
        test_stack_base(OpCode::_Drop, vec![vec![0x01]], vec![]);
        test_stack_base(OpCode::_Drop, vec![vec![0x01], vec![0x01]], vec![vec![0x01]]);
    }

    #[test]
    fn test_op_nip() {
        test_stack_base(OpCode::Nip, vec![vec![0x01]], vec![vec![0x01]]);
        test_stack_base(OpCode::Nip, vec![vec![0x02], vec![0x01]], vec![vec![0x01]]);
        test_stack_base(OpCode::Nip, vec![vec![0x03], vec![0x02], vec![0x01]], vec![vec![0x03], vec![0x01]]);
    }

    #[test]
    fn test_op_over() {
        test_stack_base(OpCode::Over, vec![vec![0x02], vec![0x01]], vec![vec![0x02], vec![0x01], vec![0x02]]);
    }

    #[test]
    fn test_op_pick() {
        test_stack_base(OpCode::Pick, vec![vec![0x03], vec![0x02], vec![0x01]], vec![vec![0x03], vec![0x02], vec![0x03]]);
        test_stack_base(OpCode::Pick, vec![vec![0x04], vec![0x03], vec![0x02], vec![0x02]],
                                      vec![vec![0x04], vec![0x03], vec![0x02], vec![0x04]]);
    }

    #[test]
    fn test_op_roll() {
        test_stack_base(OpCode::Roll, vec![vec![0x03], vec![0x02], vec![0x01]], vec![vec![0x02], vec![0x03]]);
        test_stack_base(OpCode::Roll, vec![vec![0x04], vec![0x03], vec![0x02], vec![0x02]],
                                      vec![vec![0x03], vec![0x02], vec![0x04]]);
        test_stack_base(OpCode::Roll, vec![vec![0x04], vec![0x03], vec![0x02], vec![0x01]],
                                      vec![vec![0x04], vec![0x02], vec![0x03]]);
        test_stack_base(OpCode::Roll, vec![vec![0x04], vec![0x03], vec![0x02], vec![]],
                                      vec![vec![0x04], vec![0x03], vec![0x02]]);
    }

    #[test]
    fn test_op_rot() {
        test_stack_base(OpCode::Rot, vec![vec![0x01], vec![0x02], vec![0x03]],
                                     vec![vec![0x02], vec![0x03], vec![0x01]]);
    }

    #[test]
    fn test_op_swap() {
        test_stack_base(OpCode::Swap, vec![vec![0x01], vec![0x02], vec![0x03]],
                                      vec![vec![0x01], vec![0x03], vec![0x02]]);
    }

    #[test]
    fn test_op_tuck() {
        test_stack_base(OpCode::Tuck, vec![vec![0x01], vec![0x02]],
                                      vec![vec![0x02], vec![0x01], vec![0x02]]);
    }

    #[test]
    fn test_op_2drop() {
        test_stack_base(OpCode::_2Drop, vec![vec![0x01], vec![0x02], vec![0x03]],
                                        vec![vec![0x01]]);
        test_stack_base(OpCode::_2Drop, vec![vec![0x01], vec![0x02]],
                                        vec![]);
    }

    #[test]
    fn test_op_2dup() {
        test_stack_base(OpCode::_2Dup, vec![vec![0x01], vec![0x02], vec![0x03]],
                                       vec![vec![0x01], vec![0x02], vec![0x03], vec![0x02], vec![0x03]]);
        test_stack_base(OpCode::_2Dup, vec![vec![0x02], vec![0x03]],
                                       vec![vec![0x02], vec![0x03], vec![0x02], vec![0x03]]);
    }

    #[test]
    fn test_op_3dup() {
        test_stack_base(OpCode::_3Dup, vec![vec![0x01], vec![0x02], vec![0x03]],
                                       vec![vec![0x01], vec![0x02], vec![0x03], vec![0x01], vec![0x02], vec![0x03]]);
    }

    #[test]
    fn test_op_2over() {
        test_stack_base(OpCode::_2Over, vec![vec![0x01], vec![0x02], vec![0x03], vec![0x04]],
                                        vec![vec![0x01], vec![0x02], vec![0x03], vec![0x04], vec![0x01], vec![0x02]]);
    }

    #[test]
    fn test_op_2rot() {
        test_stack_base(OpCode::_2Rot, vec![vec![0x01], vec![0x02], vec![0x03], vec![0x04], vec![0x05], vec![0x06]],
                                       vec![vec![0x03], vec![0x04], vec![0x05], vec![0x06], vec![0x01], vec![0x02]]);
    }

    #[test]
    fn test_op_2swap() {
        test_stack_base(OpCode::_2Swap, vec![vec![0x01], vec![0x02], vec![0x03], vec![0x04]],
                                        vec![vec![0x03], vec![0x04], vec![0x01], vec![0x02]]);
    }

    #[test]
    fn test_op_fromaltstack() {
        let mut context = get_context(vec![]);
        context.altstack = vec![vec![0x01]];

        assert_eq!(get_context(vec![vec![0x01]]), OpCode::FromAltStack.execute(context));
    }

    #[test]
    fn test_op_toaltstack() {
        let mut expected = get_context(vec![]);
        expected.altstack = vec![vec![0x01]];

        let context = get_context(vec![vec![0x01]]);

        assert_eq!(expected, OpCode::ToAltStack.execute(context));
    }

    #[test]
    fn test_op_size() {
        test_stack_base(OpCode::Size, vec![vec![]],
                                      vec![vec![], vec![]]);
        test_stack_base(OpCode::Size, vec![vec![0x01, 0x02, 0x03, 0x04, 0x05]],
                                      vec![vec![0x01, 0x02, 0x03, 0x04, 0x05], vec![0x05]]);
        test_stack_base(OpCode::Size, vec![vec![0x01]],
                                      vec![vec![0x01], vec![0x01]]);
        test_stack_base(OpCode::Size, vec![vec![0x01, 0x02]],
                                      vec![vec![0x01, 0x02], vec![0x02]]);
    }

    #[test]
    fn test_op_codeseparator() {
        let script = vec![0x00, 0x01, 0x02, 0x03, 0x04];
        let mut context = Context::new(script.clone(), vec![], mock_checksig);
        let mut expected = Context::new(script.clone(), vec![], mock_checksig);
        for _ in 0..3 {
            context.script.next();
            expected.script.next();
        }

        expected.codeseparator = 4;

        assert_eq!(expected, OpCode::CodeSeparator.execute(context));
    }
}
