use net::*;
use net::messages::*;

use utils::Debug;

use std::io::Cursor;
use std::fs::File;

use serialize::{Serialize, Deserialize};

#[test]
fn test_block() {
    let mut block_data = File::open("src/test/block.dat").unwrap();
    BlockMessage::deserialize(&mut block_data).unwrap();
}

#[test]
fn test_version_message() {
    let buffer =
        vec![// version
             0x62, 0xEA, 0x00, 0x00,
             // services
             0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
             // timestamp
             0x11, 0xB2, 0xD0, 0x50, 0x00, 0x00, 0x00, 0x00,
             // addr_recv
             0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
             0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF,
             0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
             // addr_from
             0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
             0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF,
             0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
             // nonce
             0x3B, 0x2E, 0xB3, 0x5D, 0x8C, 0xE6, 0x17, 0x65,
             // user-agent string
             0x0F, 0x2F, 0x53, 0x61, 0x74, 0x6F, 0x73, 0x68, 0x69, 0x3A,
             0x30, 0x2E, 0x37, 0x2E, 0x32, 0x2F,
             // last block id
             0xC0, 0x3E, 0x03, 0x00,
             // relay
             0x00];

    let mut deserializer = Cursor::new(&buffer[..]);
    let message = VersionMessage::deserialize(&mut deserializer).unwrap();

    assert_eq!(message.version, 60002);
    assert_eq!(message.services, Services::new(true));
    assert_eq!(message.user_agent, "/Satoshi:0.7.2/");
    assert_eq!(message.start_height, 212672);
    assert_eq!(message.relay, false);

    let mut result_buffer = Cursor::new(vec![]);
    message.serialize(&mut result_buffer);

    let result = result_buffer.into_inner();
    Debug::print_bytes(&result);

    assert_eq!(result, buffer);
}

#[test]
fn test_complete_message() {
    let buffer = vec![
         // magic number
         0xF9, 0xBE, 0xB4, 0xD9,
         // command
         0x76, 0x65, 0x72, 0x73, 0x69, 0x6F, 0x6E, 0x00, 0x00, 0x00,
         0x00, 0x00,
         // message length
         0x65, 0x00, 0x00, 0x00,
         // checksum
         0x03, 0x0E, 0xCC, 0x57,

         // version
         0x62, 0xEA, 0x00, 0x00,
         // services
         0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
         // timestamp
         0x11, 0xB2, 0xD0, 0x50, 0x00, 0x00, 0x00, 0x00,
         // addr recv
         0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF,
         0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
         // addr from
         0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF,
         0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
         // nonce
         0x3B, 0x2E, 0xB3, 0x5D, 0x8C, 0xE6, 0x17, 0x65,
         // user-agent
         0x0F, 0x2F, 0x53, 0x61, 0x74, 0x6F, 0x73, 0x68, 0x69, 0x3A,
         0x30, 0x2E, 0x37, 0x2E, 0x32, 0x2F,
         // last block height
         0xC0, 0x3E, 0x03, 0x00,
         // relay
         0x00];

    let mut deserializer = Cursor::new(&buffer[..]);
    let header  = MessageHeader::deserialize(&mut deserializer).unwrap();
    assert_eq!(header.network_type, NetworkType::Main);
    assert_eq!(header.command, Command::Version);
    assert_eq!(header.length, 101);

    let message = VersionMessage::deserialize(&mut deserializer).unwrap();

    let serialized = get_serialized_message(NetworkType::Main, Command::Version, Some(Box::new(message)));
    Debug::print_bytes(&serialized);
    Debug::print_bytes(&buffer);

    assert_eq!(buffer, serialized);
}
