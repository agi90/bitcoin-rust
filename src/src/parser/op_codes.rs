use super::OpCode;
use super::ScriptElement;
use super::BitcoinStack;
use crypto::sha2;
use crypto::ripemd160;
use crypto::digest::Digest;

fn ripemd160(input : Vec<u8>) -> Vec<u8> {
    let mut ripemd160 = ripemd160::Ripemd160::new();
    ripemd160.input(&input[..]);

    let result : &mut [u8] = &mut [];
    ripemd160.result(result);

    let mut result_array = Vec::new();
    result_array.extend(result.iter().cloned());

    return result_array;
}

fn sha256(input : Vec<u8>) -> Vec<u8> {
    let mut sha256 = sha2::Sha256::new();
    sha256.input(&input[..]);

    let result : &mut [u8] = &mut [];
    sha256.result(result);

    let mut result_array = Vec::new();
    result_array.extend(result.iter().cloned());

    return result_array;
}

pub fn OP_DUP(stack: BitcoinStack) -> BitcoinStack {
    let mut new_stack = stack;
    let last = new_stack.stack.last().unwrap().clone();
    new_stack.stack.push(last);

    return new_stack;
}

fn OP_HASH256(stack: BitcoinStack) -> BitcoinStack {
    let mut new_stack = stack;
    let last = new_stack.stack.pop().unwrap();

    new_stack.stack.push(sha256(sha256(last)));
    return new_stack;
}

pub fn OP_HASH160(stack: BitcoinStack) -> BitcoinStack {
    let mut new_stack = stack;
    let last = new_stack.stack.pop().unwrap();

    new_stack.stack.push(ripemd160(sha256(last)));
    return new_stack;
}

fn OP_EQUALVERIFY(stack: BitcoinStack) -> BitcoinStack {
    let mut new_stack = stack;
    let x = new_stack.stack.pop().unwrap();
    let y = new_stack.stack.pop().unwrap();

    new_stack.valid = x.eq(&y);
    return new_stack;
}

fn OP_CHECKSIG(stack: BitcoinStack) -> BitcoinStack {
    // TODO: fix this
    return stack;
}
