extern crate mio;
extern crate rand;

use std::net::SocketAddr;
use mio::tcp;

use super::rpcengine::RPCEngine;
use super::rpcengine;
use super::messages::*;

use super::Services;
use super::IPAddress;

use time;

use std::io::Read;
use std::fs::{File, OpenOptions};
use std::collections::{HashMap, VecDeque};
use std::sync::{Mutex, MutexGuard, Arc};
use std::thread;
use std::mem;

use mio::Token;

use super::store::BlobStore;

struct BitcoinClient {
    version: i32,
    services: Services,
    user_agent: String,
    state: Arc<Mutex<State>>,
}

struct State {
    peers: HashMap<mio::Token, Peer>,
    message_queue: VecDeque<Vec<u8>>,
    network_type: NetworkType,
    tx_store: BlobStore<TxMessage>,
    block_store: BlobStore<BlockMessage>,
}

impl State {
    pub fn new(network_type: NetworkType) -> State {
        State {
            peers: HashMap::new(),
            message_queue: VecDeque::new(),
            network_type: network_type,
            tx_store: Self::get_store("tx.dat"),
            block_store: Self::get_store("block.dat"),
        }
    }

    fn get_store<T: Serialize + Deserialize<File>>(filename: &str) -> BlobStore<T> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .append(true)
            .create(true)
            .open(filename)
            // TODO: handle errors
            .unwrap();

        BlobStore::new(file)
    }

    pub fn add_peer(&mut self, token: mio::Token, version: VersionMessage,
                    connection_type: ConnectionType) {
        self.peers.insert(token, Peer::new(version, connection_type));
    }

    pub fn queue_message(&mut self, command: Command, message: Option<Box<Serialize>>) {
        let to_send = get_serialized_message(self.network_type,
                                             command,
                                             message);

        self.message_queue.push_back(to_send);
    }

    pub fn get_peers(&self) -> &HashMap<mio::Token, Peer> { &self.peers }

    pub fn get_peer(&mut self, token: &mio::Token) -> Option<&mut Peer> {
        self.peers.get_mut(token)
    }

    pub fn has_tx(&self, hash: &[u8; 32]) -> bool {
        self.tx_store.has(hash)
    }

    pub fn add_tx(&mut self, tx: TxMessage) {
        self.tx_store.insert(tx);
    }

    pub fn has_block(&self, hash: &[u8; 32]) -> bool {
        self.block_store.has(hash)
    }

    pub fn add_block(&mut self, block: BlockMessage) {
        self.block_store.insert(block);
    }
}

#[derive(Debug)]
enum ConnectionType {
    Inbound,
    Outbound,
}

#[derive(Debug)]
struct Peer {
    ping_time: time::Tm,
    ping: i64,
    ping_data: u64,
    version: VersionMessage,
    verak_received: bool,
    connection_type: ConnectionType,
}

impl Peer {
    pub fn new(version: VersionMessage, connection_type: ConnectionType) -> Peer {
        Peer {
            ping_time: time::now(),
            ping: -1,
            ping_data: 0,
            version: version,
            verak_received: false,
            connection_type: connection_type,
        }
    }

    pub fn ping_time(&self) -> time::Tm { self.ping_time }

    pub fn received_verack(&mut self) {
        self.verak_received = true;
    }

    pub fn sent_ping(&mut self, ping_data: u64) {
        self.ping_time = time::now();
        self.ping_data = ping_data;
    }

    pub fn got_pong(&mut self, pong_data: u64) {
        if self.ping_data == pong_data {
            self.ping = (time::now() - self.ping_time).num_milliseconds();
        } else {
            println!("Invalid ping!");
        }
    }
}

const VERSION: i32 = 70001;
type StateMutex<'a> = MutexGuard<'a, State>;

impl BitcoinClient {
    fn new(state: Arc<Mutex<State>>) -> BitcoinClient {
        BitcoinClient {
            version: VERSION,
            services: Services::new(true),
            user_agent: "/Agi:0.0.1/".to_string(),
            state: state,
        }
    }

    fn handle_verack(&mut self, token: mio::Token) {
        let mut state = self.state.lock().unwrap();
        state.get_peer(&token).unwrap().received_verack();
        println!("Sending GetAddr");
        state.queue_message(Command::GetAddr, None);

        let mut genesis = [
            0x00,  0x00,  0x00,  0x00,  0x09,  0x33,  0xea,  0x01,  0xad,  0x0e,
            0xe9,  0x84,  0x20,  0x97,  0x79,  0xba,  0xae,  0xc3,  0xce,  0xd9,
            0x0f,  0xa3,  0xf4,  0x08,  0x71,  0x95,  0x26,  0xf8,  0xd7,  0x7f,
            0x49,  0x43];

        genesis.reverse();

        let response = GetHeadersMessage {
            version: VERSION as u32,
            // genesis block
            block_locators: vec![genesis],
            hash_stop: [0; 32],
        };

        println!("Sending GetHeaders.");
        state.queue_message(Command::GetBlocks, Some(Box::new(response)));

        Self::ping(&mut state, token);
    }

    fn ping(state: &mut StateMutex, token: mio::Token) {
        let message = PingMessage::new();
        state.get_peer(&token).unwrap().sent_ping(message.nonce);
        state.queue_message(Command::Ping, Some(Box::new(message)));
    }

    fn generate_version_message(&self, recipient_ip: IPAddress) -> VersionMessage {
        VersionMessage {
            version: self.version,
            services: self.services,
            timestamp: time::now(),
            addr_recv: recipient_ip,
            addr_from: IPAddress::new(
                self.services,
                // TODO: use upnp
                "0:0:0:0:0:ffff:c0a8:3865".parse().unwrap(),
                18334),
            // TODO: figure it out this
            nonce: rand::random::<u64>(),
            user_agent: self.user_agent.clone(),
            start_height: 0,
            relay: true,
        }
    }

    fn handle_version(&mut self, token: mio::Token, message: VersionMessage) {
        let mut state = self.state.lock().unwrap();

        let version = self.generate_version_message(message.addr_recv);
        state.add_peer(token, message, ConnectionType::Inbound);

        state.queue_message(Command::Version, Some(Box::new(version)));
        state.queue_message(Command::Verack, None);
    }

    fn handle_addr(&mut self, _: AddrMessage) {
    }

    fn handle_getaddr(&self) {
        let mut state = self.state.lock().unwrap();

        let mut peers = vec![];
        for peer in state.get_peers().values() {
            peers.push((peer.ping_time(), peer.version.addr_from));
        }

        let response = AddrMessage::new(peers);

        state.queue_message(Command::Addr, Some(Box::new(response)));
    }

    fn handle_headers(&self, message: HeadersMessage) {
        // TODO: actually do something
        println!("Headers: {:?}", message.headers.len());
    }

    fn handle_block(&self, message: BlockMessage) {
        self.lock_state().add_block(message);
    }

    fn handle_getblocks(&self, message: GetHeadersMessage) {
        println!("GetBlocks = {:?}", message);
    }

    fn handle_getheaders(&self, message: GetHeadersMessage) {
        // TODO: actually do something
        for h in message.block_locators {
            let mut clone = h.clone();
            clone.reverse();
        }

        let response = HeadersMessage::new(vec![]);
        self.state.lock().unwrap().queue_message(Command::Headers, Some(Box::new(response)));
    }

    fn handle_tx(&self, message: TxMessage, _: mio::Token) {
        self.lock_state().add_tx(message);
    }

    fn handle_getdata(&self, message: InvMessage, _: mio::Token) {
        // TODO
        println!("Got getdata {:?}", message);
    }

    fn handle_notfound(&self, message: InvMessage, _: mio::Token) {
        println!("Got notfound {:?}", message);
    }

    fn handle_inv(&self, message: InvMessage, _: mio::Token) {
        let mut state = self.state.lock().unwrap();

        let mut new_data = vec![];

        for inventory in message.inventory {
            match inventory.type_ {
                InventoryVectorType::MSG_TX => {
                    if !state.has_tx(&inventory.hash) {
                        new_data.push(InventoryVector::new(
                                InventoryVectorType::MSG_TX,
                                inventory.hash));
                    }
                },
                InventoryVectorType::MSG_BLOCK => {
                    if !state.has_block(&inventory.hash) {
                        new_data.push(InventoryVector::new(
                                InventoryVectorType::MSG_BLOCK,
                                inventory.hash));
                    }
                },
                type_ => println!("Unhandled inv {:?}", type_),
            }
        }

        state.queue_message(Command::GetData,
                            Some(Box::new(InvMessage::new(new_data))));
    }

    fn handle_pong(&self, message: PingMessage, token: mio::Token) {
        self.lock_state().get_peer(&token).map(|p| p.got_pong(message.nonce));
    }

    fn handle_reject(&self, message: RejectMessage) {
        println!("Message = {:?}", message);
        println!("harakiri :-(");
        panic!();
    }

    fn handle_ping(&self, message: PingMessage) {
        self.lock_state()
            .queue_message(Command::Pong, Some(Box::new(message)));
    }

    fn lock_state<'a>(&'a self) -> StateMutex { self.state.lock().unwrap() }

    fn handle_command(&mut self, header: MessageHeader, token: mio::Token,
                      message_bytes: &mut Deserializer<&[u8]>) -> Result<(), String> {

        if *header.magic() != self.lock_state().network_type {
            // This packet is not for the right version :O
            return Err(format!("Received packet for wrong version: {:?}", header.magic()));
        }

        match header.command() {
            &Command::Tx => {
                let message = try!(TxMessage::deserialize(message_bytes, &[]));
                self.handle_tx(message, token);
            },
            &Command::GetData => {
                let message = try!(InvMessage::deserialize(message_bytes, &[]));
                self.handle_getdata(message, token);
            },
            &Command::NotFound => {
                let message = try!(InvMessage::deserialize(message_bytes, &[]));
                self.handle_notfound(message, token);
            },
            &Command::Inv => {
                let message = try!(InvMessage::deserialize(message_bytes, &[]));
                self.handle_inv(message, token);
            },
            &Command::Pong => {
                // Ping and Pong message use the same format
                let message = try!(PingMessage::deserialize(message_bytes, &[]));
                self.handle_pong(message, token);
            },
            &Command::Ping => {
                let message = try!(PingMessage::deserialize(message_bytes, &[]));
                self.handle_ping(message);
            },
            &Command::Version => {
                let message = try!(VersionMessage::deserialize(message_bytes, &[]));
                self.handle_version(token, message);
            },
            &Command::Verack => {
                self.handle_verack(token);
            },
            &Command::GetAddr => {
                self.handle_getaddr();
            },
            &Command::Block => {
                let message = try!(BlockMessage::deserialize(message_bytes, &[]));
                self.handle_block(message);
            },
            &Command::GetBlocks => {
                let message = try!(GetHeadersMessage::deserialize(message_bytes, &[]));
                self.handle_getblocks(message);
            },
            &Command::GetHeaders => {
                let message = try!(GetHeadersMessage::deserialize(message_bytes, &[]));
                self.handle_getheaders(message);
            },
            &Command::Headers => {
                let message = try!(HeadersMessage::deserialize(message_bytes, &[]));
                self.handle_headers(message);
            },
            &Command::Unknown => {
                return Err(format!("Unknown message. {:?}", message_bytes));
            },
            &Command::Addr => {
                let message = try!(AddrMessage::deserialize(message_bytes, &[]));
                self.handle_addr(message);
            },
            &Command::Reject => {
                let message = try!(RejectMessage::deserialize(message_bytes, &[]));
                self.handle_reject(message);
            }
        };

        Ok(())
    }
}

impl rpcengine::MessageHandler for BitcoinClient {
    fn handle(&mut self, token: mio::Token, message: Vec<u8>) -> VecDeque<Vec<u8>> {
        let mut deserializer = Deserializer::new(&message[..]);
        let handled = MessageHeader::deserialize(&mut deserializer, &[])
            .and_then(|m| self.handle_command(m, token, &mut deserializer));

        if let Err(x) = handled {
           println!("Error: {:?}", x);
        };

        let mut state = self.state.lock().unwrap();
        let message_queue = mem::replace(&mut state.message_queue, VecDeque::new());

        message_queue
    }

    fn get_new_messages(&mut self) -> HashMap<mio::Token, Vec<Vec<u8>>> {
        HashMap::new()
    }
}

pub fn start(address: SocketAddr) {
    let server = tcp::TcpListener::bind(&address).unwrap();
    let mut event_loop = mio::EventLoop::new().unwrap();
    event_loop.register(&server, rpcengine::SERVER, mio::EventSet::readable(),
                        mio::PollOpt::edge()).unwrap();

    let state = Arc::new(Mutex::new(State::new(NetworkType::TestNet3)));
    let client = BitcoinClient::new(state.clone());

    println!("running bitcoin server; port=18334");
    let child = thread::spawn(move || {
        let mut engine = RPCEngine::new(server, Box::new(client));
        event_loop.run(&mut engine).unwrap();
    });

    let _ = child.join();
}
