use utils::IntUtils;

#[derive(Debug, PartialEq)]
pub struct Input {
    previous_transaction: Vec<u8>,
    index: u32,
    script_sig: Vec<u8>,
    sequence_number: u32,
}

impl Input {
    pub fn new(previous_transaction: Vec<u8>,
               index: u32,
               script_sig: Vec<u8>,
               sequence_number: u32) -> Input {

        Input {
            previous_transaction: previous_transaction,
            index: index,
            script_sig: script_sig,
            sequence_number: sequence_number,
        }
    }
}

#[derive(Debug, PartialEq)]
pub struct Output {
    value: u64,
    script: Vec<u8>,
}

impl Output {
    pub fn new(value: u64, script: Vec<u8>) -> Output {
        Output {
            value: value,
            script: script,
        }
    }
}

#[derive(Debug, PartialEq)]
pub struct Transaction {
    version: u32,
    inputs: Vec<Input>,
    outputs: Vec<Output>,
    lock_time: u32,
}

impl Transaction {
    pub fn new(version: u32, inputs: Vec<Input>, outputs: Vec<Output>,
               lock_time: u32) -> Transaction {
        Transaction {
            version: version,
            inputs: inputs,
            outputs: outputs,
            lock_time: lock_time,
        }
    }
}

pub struct Parser;

impl Parser {
    pub fn parse(data_: Vec<u8>) -> Transaction {
        let mut data = data_;

        data.reverse();
        let version       = Parser::get_fixed_u32(&mut data);
        let number_inputs = Parser::get_variable_length_int(&mut data);
        let mut inputs = vec![];

        assert!(number_inputs > 0);
        for _ in 0..number_inputs {
            inputs.push(Parser::get_input(&mut data));
        }

        let number_outputs = Parser::get_variable_length_int(&mut data);

        assert!(number_outputs > 0);
        let mut outputs = vec![];
        for _ in 0..number_outputs {
            outputs.push(Parser::get_output(&mut data));
        }

        let lock_time = Parser::get_fixed_u32(&mut data);
        assert!(data.len() == 0);

        Transaction::new(version, inputs, outputs, lock_time)
    }

    fn get_output(data: &mut Vec<u8>) -> Output {
        let value         = Parser::get_fixed_u64(data);
        let script_length = Parser::get_variable_length_int(data);
        let script        = Parser::get_bytes(data, script_length);

        Output::new(value, script)
    }

    fn get_input(data: &mut Vec<u8>) -> Input {
        assert!(data.len() > 36);

        let previous_tx    = Parser::get_bytes(data, 32);
        let previous_index = Parser::get_fixed_u32(data);
        let script_length  = Parser::get_variable_length_int(data);
        let script         = Parser::get_bytes(data, script_length);
        let sequence_no    = Parser::get_fixed_u32(data);

        Input::new(previous_tx, previous_index, script, sequence_no)
    }

    fn get_fixed(data: &mut Vec<u8>, bytes: u8) -> u64 {
        assert!(bytes == 4 || bytes == 8);
        assert!(data.len() >= bytes as usize);

        IntUtils::to_u64(&Parser::get_bytes(data, bytes as u64))
    }

    fn get_bytes(data: &mut Vec<u8>, bytes: u64) -> Vec<u8> {
        assert!(data.len() >= bytes as usize);
        let mut bytes_data = vec![];

        for _ in 0..bytes {
            bytes_data.push(data.pop().unwrap());
        }

        bytes_data
    }

    fn get_fixed_u64(data: &mut Vec<u8>) -> u64 {
        Parser::get_fixed(data, 8)
    }

    fn get_fixed_u32(data: &mut Vec<u8>) -> u32 {
        Parser::get_fixed(data, 4) as u32
    }

    fn get_variable_length_int(data: &mut Vec<u8>) -> u64 {
        let last = data.pop().unwrap();

        if last < 0xfd {
            return last as u64;
        }

        let bytes = match last {
            0xfd => 2,
            0xfe => 4,
            0xff => 8,
            _ => unreachable!(),
        };

        IntUtils::to_u64(&Parser::get_bytes(data, bytes))
    }
}

#[cfg(test)]
mod tests {
    use rustc_serialize::hex::FromHex;
    use super::*;

    #[test]
    pub fn test_parser() {
        let transaction = "0100000001c997a5e56e104102fa209c6a852dd90660a20b2d9c352423edce25857fcd3704000000004847304402204e45e16932b8af514961a1d3a1a25fdf3f4f7732e9d624c6c61548ab5fb8cd410220181522ec8eca07de4860a4acdd12909d831cc56cbbac4622082221a8768d1d0901ffffffff0200ca9a3b00000000434104ae1a62fe09c5f51b13905f07f06b99a2f7159b2225f374cd378d71302fa28414e7aab37397f554a7df5f142c21c1b7303b8a0626f1baded5c72a704f7e6cd84cac00286bee0000000043410411db93e1dcdb8a016b49840f8c53bc1eb68a382e97b1482ecad7b148a6909a5cb2e0eaddfb84ccf9744464f82e160bfa9b8b64f9d4c03f999b8643f656b412a3ac00000000".to_string().from_hex().unwrap();

        assert_eq!(Parser::parse(transaction),
                   Transaction::new(
                        1,
                        vec![Input::new(
                            "c997a5e56e104102fa209c6a852dd90660a20b2d9c352423edce25857fcd3704".to_string().from_hex().unwrap(),
                            0,
                            "47304402204e45e16932b8af514961a1d3a1a25fdf3f4f7732e9d624c6c61548ab5fb8cd410220181522ec8eca07de4860a4acdd12909d831cc56cbbac4622082221a8768d1d0901".to_string().from_hex().unwrap(),
                            0xffffffff
                        )],
                        vec![Output::new(
                            1000000000,
                            "4104ae1a62fe09c5f51b13905f07f06b99a2f7159b2225f374cd378d71302fa28414e7aab37397f554a7df5f142c21c1b7303b8a0626f1baded5c72a704f7e6cd84cac".to_string().from_hex().unwrap()
                        ),Output::new(
                            4000000000,
                            "410411db93e1dcdb8a016b49840f8c53bc1eb68a382e97b1482ecad7b148a6909a5cb2e0eaddfb84ccf9744464f82e160bfa9b8b64f9d4c03f999b8643f656b412a3ac".to_string().from_hex().unwrap()
                        )],
                        0));
    }
}
