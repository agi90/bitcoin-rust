extern crate mio;
extern crate rand;

use std::net::SocketAddr;
use mio::tcp;

use super::rpcengine::RPCEngine;
use super::rpcengine::Message;
use super::rpcengine;
use super::messages::*;
use super::expiring_cache::ExpiringCache;
use super::expiring_cache::Timeout;

use super::Services;
use super::IPAddress;

use time;
use time::Duration;

use std::io::{Read, Cursor};
use std::fs::{File, OpenOptions};
use std::net::ToSocketAddrs;
use std::collections::HashMap;
use std::sync::{Mutex, MutexGuard, Arc};
use std::thread;

use mio::Token;
use mio::Sender;

use super::store::BlockStore;

use utils::Debug;

struct BitcoinClient {
    version: i32,
    services: Services,
    user_agent: String,
    state: Arc<Mutex<State>>,
    channel: mio::Sender<Message>,
    network_type: NetworkType,
}

struct State {
    peers: HashMap<mio::Token, Peer>,
    tx_store: HashMap<[u8; 32], TxMessage>,
    block_store: BlockStore,
    pending_inv: ExpiringCache<[u8; 32]>,
}

#[derive(PartialEq, Copy, Clone, Debug)]
enum ConnectionType {
    Inbound,
    Outbound,
}

#[derive(Debug)]
struct Peer {
    ping_time: time::Tm,
    ping: i64,
    ping_data: u64,
    version: Option<VersionMessage>,
    verak_received: bool,
    connection_type: ConnectionType,
    waiting_for_blocks: Timeout<bool>,
}

impl State {
    pub fn new(network_type: NetworkType) -> State {
        State {
            peers: HashMap::new(),
            tx_store: HashMap::new(),
            block_store: BlockStore::new(Self::get_store("block.dat"), network_type),
            pending_inv: ExpiringCache::new(Duration::minutes(2), Duration::seconds(10)),
        }
    }

    pub fn add_inv(&mut self, hash: [u8; 32]) {
        print!("inv for ");
        Debug::print_bytes(&hash);
        self.pending_inv.insert(hash);
    }

    pub fn received_data(&mut self, hash: &[u8; 32]) {
        self.pending_inv.remove(hash);
    }

    pub fn pending_inv_len(&self) -> usize { self.pending_inv.len() }

    fn get_store(filename: &str) -> File {
        OpenOptions::new()
            .read(true)
            .write(true)
            .append(true)
            .create(true)
            .open(filename)
            // TODO: handle errors
            .unwrap()
    }

    pub fn height(&self) -> usize { self.block_store.height() }

    pub fn block_locators(&self) -> Vec<[u8; 32]> {
        self.block_store.block_locators()
    }

    pub fn add_peer(&mut self, token: mio::Token, version: Option<VersionMessage>) -> ConnectionType {
        if let Some(peer) = self.peers.get_mut(&token) {
            peer.version = version;
            return ConnectionType::Outbound;
        }

        match version {
            Some(ver) => {
                self.peers.insert(token, Peer::new_inbound(ver));
                ConnectionType::Inbound
            }
            None => {
                self.peers.insert(token, Peer::new_outbound());
                ConnectionType::Outbound
            }
        }
    }

    pub fn get_peers(&self) -> &HashMap<mio::Token, Peer> { &self.peers }

    pub fn get_peer(&mut self, token: &mio::Token) -> Option<&mut Peer> {
        self.peers.get_mut(token)
    }

    pub fn has_tx(&self, hash: &[u8; 32]) -> bool {
        self.tx_store.get(hash).is_some()
    }

    pub fn add_tx(&mut self, tx: TxMessage) {
        self.tx_store.insert(tx.hash(), tx);
    }

    pub fn get_block_metadata(&self, hash: &[u8; 32]) -> Option<&BlockMetadata> {
        self.block_store.get_metadata(hash)
    }

    pub fn block_height(&self, hash: &[u8; 32]) -> Option<usize> {
        self.block_store.get_height(hash)
    }

    pub fn has_block(&self, hash: &[u8; 32]) -> bool {
        self.block_store.has(hash)
    }

    pub fn add_block(&mut self, block: BlockMessage, hash: &[u8; 32], data: &[u8]) {
        self.block_store.insert(block, hash, data);
    }
}

impl Peer {
    pub fn new_inbound(version: VersionMessage) -> Peer {
        Peer {
            ping_time: time::now(),
            ping: -1,
            ping_data: 0,
            version: Some(version),
            verak_received: false,
            connection_type: ConnectionType::Inbound,
            waiting_for_blocks: Timeout::new(),
        }
    }

    pub fn new_outbound() -> Peer {
        Peer {
            ping_time: time::now(),
            ping: -1,
            ping_data: 0,
            version: None,
            verak_received: false,
            connection_type: ConnectionType::Outbound,
            waiting_for_blocks: Timeout::new(),
        }
    }

    pub fn sent_getblocks(&mut self) {
        self.waiting_for_blocks.set(true, Duration::seconds(15));
    }

    pub fn got_inv(&mut self) {
        self.waiting_for_blocks.set(false, Duration::seconds(0));
    }

    pub fn is_waiting_for_blocks(&self) -> bool {
        self.waiting_for_blocks.get()
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
    fn new(state: Arc<Mutex<State>>, channel: Sender<Message>,
           network_type: NetworkType) -> BitcoinClient {
        let client = BitcoinClient {
            version: VERSION,
            services: Services::new(true),
            user_agent: "/Agi:0.0.1/".to_string(),
            state: state,
            channel: channel,
            network_type: network_type,
        };

        client
    }

    fn send_message(&self, command: Command, token: mio::Token,
                         message: Option<Box<Serialize>>) {
        let to_send = get_serialized_message(self.network_type,
                                             command,
                                             message);

        match self.channel.send(Message::SendMessage(token, to_send)) {
            Ok(_) => {},
            Err(e) => {
                println!("Error: {:?}", e);
            }
        }
    }

    fn get_blocks(&self, state: &mut StateMutex, token: mio::Token) {
        if state.pending_inv_len() > 100 {
            return;
        }

        if state.get_peer(&token).unwrap().is_waiting_for_blocks() {
            return;
        }

        state.get_peer(&token).map(|p| p.sent_getblocks());

        let message = GetHeadersMessage {
            version: VERSION as u32,
            block_locators: state.block_locators(),
            hash_stop: [0; 32],
        };

        self.send_message(Command::GetBlocks, token, Some(Box::new(message)));
    }

    fn handle_verack(&self, token: mio::Token) {
        let mut state = self.state.lock().unwrap();
        state.get_peer(&token).unwrap().received_verack();

        self.send_message(Command::GetAddr, token, None);

        self.get_blocks(&mut state, token);
        self.ping(&mut state, token);
    }

    fn ping(&self, state: &mut StateMutex, token: mio::Token) {
        let message = PingMessage::new();
        state.get_peer(&token).unwrap().sent_ping(message.nonce);
        self.send_message(Command::Ping, token, Some(Box::new(message)));
    }

    fn generate_version_message(&self, recipient_ip: IPAddress, start_height: i32) -> VersionMessage {
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
            start_height: start_height,
            relay: true,
        }
    }

    fn handle_version(&self, message: VersionMessage, token: mio::Token) {
        let mut state = self.state.lock().unwrap();

        let version = self.generate_version_message(message.addr_recv, state.height() as i32);
        let connection_type = state.add_peer(token, Some(message));

        if connection_type == ConnectionType::Inbound {
            self.send_message(Command::Version, token, Some(Box::new(version)));
        }
        self.send_message(Command::Verack, token, None);
    }

    fn handle_addr(&self, message: AddrMessage, _: mio::Token) {
        for (_,addr) in message.addr_list {
            for socket in (addr.address, addr.port).to_socket_addrs().unwrap() {
                self.channel.send(Message::Connect(socket)).unwrap();
            }
        }
    }

    fn handle_getaddr(&self, token: mio::Token) {
        let state = self.state.lock().unwrap();

        let mut peers = vec![];
        for peer in state.get_peers().values() {
            if let Some(ref version) = peer.version {
                peers.push((peer.ping_time(), version.addr_from));
            }
        }

        let response = AddrMessage::new(peers);

        self.send_message(Command::Addr, token, Some(Box::new(response)));
    }

    fn handle_headers(&self, message: HeadersMessage, _: mio::Token) {
        // TODO: actually do something
        println!("Headers: {:?}", message.headers.len());
        panic!();
    }

    fn handle_block(&self, message: BlockMessage, token: mio::Token, data: &Cursor<&[u8]>) {
        let hash = message.hash();
        let mut state = self.state.lock().unwrap();
        state.received_data(&hash);
        state.add_block(message, &hash, data.get_ref());

        self.get_blocks(&mut state, token);
    }

    fn handle_getblocks(&self, message: GetHeadersMessage, token: mio::Token) {
        for hash in message.block_locators.iter().rev() {
            if self.lock_state().block_height(hash).is_some() {
                self.send_inv(hash, token);
                break;
            }
        }
    }

    fn send_inv(&self, start_hash: &[u8; 32], token: mio::Token) {
        let state = self.state.lock().unwrap();
        let mut cur_hash = start_hash.clone();
        let mut cur = state.get_block_metadata(&cur_hash).unwrap();
        let mut inv = vec![];

        for _ in 0..500 {
            inv.push(InventoryVector::new(InventoryVectorType::MSG_BLOCK,
                                          cur_hash));
            cur_hash = cur.prev_block;
            cur = state.get_block_metadata(&cur_hash).unwrap();
        }

        self.send_message(Command::Inv, token, Some(Box::new(InvMessage::new(inv))));
    }

    fn handle_getheaders(&self, message: GetHeadersMessage, token: mio::Token) {
        // TODO: actually do something
        for h in message.block_locators {
            let mut clone = h.clone();
            clone.reverse();
        }

        let response = HeadersMessage::new(vec![]);
        self.send_message(Command::Headers, token, Some(Box::new(response)));
    }

    fn handle_tx(&self, message: TxMessage, token: mio::Token) {
        let mut state = self.state.lock().unwrap();
        state.add_tx(message);

        self.get_blocks(&mut state, token);
    }

    fn handle_getdata(&self, message: InvMessage, _: mio::Token) {
        // TODO
        println!("Got getdata {:?}", message);
        panic!();
    }

    fn handle_notfound(&self, message: InvMessage, _: mio::Token) {
        println!("Got notfound {:?}", message);
        panic!();
    }

    fn handle_inv(&self, message: InvMessage, token: mio::Token) {
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
                        state.add_inv(inventory.hash);
                    }
                },
                type_ => println!("Unhandled inv {:?}", type_),
            }
        }

        self.send_message(Command::GetData, token,
                          Some(Box::new(InvMessage::new(new_data))));

        state.get_peer(&token).unwrap().got_inv();
    }

    fn handle_pong(&self, message: PingMessage, token: mio::Token) {
        self.lock_state().get_peer(&token).map(|p| p.got_pong(message.nonce));
    }

    fn handle_reject(&self, message: RejectMessage, _: mio::Token) {
        println!("Message = {:?}", message);
        println!("harakiri :-(");
        panic!();
    }

    fn handle_ping(&self, message: PingMessage, token: mio::Token) {
        self.send_message(Command::Pong, token, Some(Box::new(message)));
    }

    fn lock_state<'a>(&'a self) -> StateMutex { self.state.lock().unwrap() }

    fn handle_command(&self, header: MessageHeader, token: mio::Token,
                      message_bytes: &mut Cursor<&[u8]>) -> Result<(), String> {

        if *header.magic() != self.network_type {
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
                self.handle_ping(message, token);
            },
            &Command::Version => {
                let message = try!(VersionMessage::deserialize(message_bytes, &[]));
                self.handle_version(message, token);
            },
            &Command::Verack => {
                self.handle_verack(token);
            },
            &Command::GetAddr => {
                self.handle_getaddr(token);
            },
            &Command::Block => {
                let message = try!(BlockMessage::deserialize(message_bytes, &[]));
                self.handle_block(message, token, message_bytes);
            },
            &Command::GetBlocks => {
                let message = try!(GetHeadersMessage::deserialize(message_bytes, &[]));
                self.handle_getblocks(message, token);
            },
            &Command::GetHeaders => {
                let message = try!(GetHeadersMessage::deserialize(message_bytes, &[]));
                self.handle_getheaders(message, token);
            },
            &Command::Headers => {
                let message = try!(HeadersMessage::deserialize(message_bytes, &[]));
                self.handle_headers(message, token);
            },
            &Command::Addr => {
                let message = try!(AddrMessage::deserialize(message_bytes, &[]));
                self.handle_addr(message, token);
            },
            &Command::Reject => {
                let message = try!(RejectMessage::deserialize(message_bytes, &[]));
                self.handle_reject(message, token);
            },
            &Command::Unknown => {
                return Err(format!("Unknown message. {:?}", message_bytes));
            },
        };

        Ok(())
    }
}

impl rpcengine::MessageHandler for BitcoinClient {
    fn handle(&self, token: mio::Token, message: Vec<u8>) {
        let mut cursor = Cursor::new(&message[..]);
        let handled = MessageHeader::deserialize(&mut cursor, &[])
            .and_then(|m| self.handle_command(m, token, &mut cursor));

        if let Err(x) = handled {
           println!("Error: {:?}", x);
        };
    }

    fn new_connection(&self, token: mio::Token, addr: SocketAddr) {
        let mut state = self.state.lock().unwrap();

        state.add_peer(token, None);

        let ip = match addr {
            SocketAddr::V4(ipv4) => ipv4.ip().to_ipv6_mapped(),
            SocketAddr::V6(ipv6) => *ipv6.ip(),
        };

        let ip_address = IPAddress::new(Services::new(true), ip, addr.port());
        let version = self.generate_version_message(ip_address, state.height() as i32);

        self.send_message(Command::Version, token, Some(Box::new(version)));
    }
}

pub fn start(address: SocketAddr) {
    let server = tcp::TcpListener::bind(&address).unwrap();
    let mut event_loop = mio::EventLoop::new().unwrap();
    event_loop.register(&server, rpcengine::SERVER, mio::EventSet::readable(),
                        mio::PollOpt::edge()).unwrap();

    let state = Arc::new(Mutex::new(State::new(NetworkType::TestNet3)));

    let client = BitcoinClient::new(state.clone(), event_loop.channel(), NetworkType::TestNet3);

    println!("running bitcoin server; port={}", address.port());
    let child = thread::spawn(move || {
        let mut engine = RPCEngine::new(server, Box::new(client));
        event_loop.run(&mut engine).unwrap();
    });

    let _ = child.join();
}
