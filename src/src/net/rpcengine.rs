// Based on mio example echo server for now.
extern crate mio;
extern crate bytes;

use mio::{TryRead, TryWrite};
use mio::tcp::*;
use mio::util::Slab;
use bytes::Buf;
use std::mem;
use std::io::Cursor;
use std::sync::{Arc, Mutex};

use std::net::SocketAddr;

use serialize::Deserialize;
use super::messages::MessageHeader;

use std::collections::VecDeque;

use utils::Debug;
use std::thread;

use std::cmp;

pub const SERVER: mio::Token = mio::Token(0);

pub trait MessageHandler: Sync + Send {
    fn handle(&self, token: mio::Token, message: Vec<u8>);
    fn new_connection(&self, token: mio::Token, addr: SocketAddr);
}

pub struct RPCEngine {
    server: TcpListener,
    connections: Slab<Connection>,
    handler: Arc<MessageHandler>,
    jobs: Arc<Mutex<VecDeque<(mio::Token, Vec<u8>)>>>,
    threads_counter: Arc<Mutex<usize>>,
}

impl RPCEngine {
    fn spawn_worker(&self) {
        let handler = self.handler.clone();
        let jobs = self.jobs.clone();
        let counter = self.threads_counter.clone();

        thread::spawn(move || {
            *counter.lock().unwrap() += 1;
            loop {
                let job = jobs.lock().unwrap().pop_front();
                match job {
                    Some((token, rpc)) => handler.handle(token, rpc),
                    None => {
                        break;
                    }
                }
            }
            *counter.lock().unwrap() -= 1;
        });
    }

    pub fn new(server: TcpListener, handler: Arc<MessageHandler>) -> RPCEngine {
        // Token 0 is reserver for the server
        let slab = Slab::new_starting_at(mio::Token(1), 1024);
        let engine = RPCEngine {
            server: server,
            connections: slab,
            handler: handler,
            jobs: Arc::new(Mutex::new(VecDeque::new())),
            threads_counter: Arc::new(Mutex::new(0)),
        };

        engine
    }

    fn add_new_peer(&mut self, event_loop: &mut mio::EventLoop<RPCEngine>,
                    socket: TcpStream) -> mio::Token {
        // TODO: handle errors
        let token = self.connections
            .insert_with(|token| Connection::new(socket, token))
            .unwrap();

        event_loop.register(
            &self.connections[token].socket,
            token,
            mio::EventSet::readable(),
            mio::PollOpt::oneshot() | mio::PollOpt::edge()).unwrap();

        token
    }

    fn handle_new_connection(&mut self, event_loop: &mut mio::EventLoop<RPCEngine>) {
        match self.server.accept() {
            Ok(Some((socket, _))) => {
                self.add_new_peer(event_loop, socket);
            }
            Ok(None) => {
                println!("the server socket wasn't actually ready");
            }
            Err(e) => {
                // TODO: handle errors
                println!("encountered error while accepting connection; err={:?}",
                         e);
                event_loop.shutdown();
            }
        }
    }

    fn handle_existing_connection(&mut self, event_loop: &mut mio::EventLoop<RPCEngine>,
                                  token: mio::Token, events: mio::EventSet) {
        if !self.connections.contains(token) {
            // If we're here it means the connection has been closed already
            return;
        }

        let rpc_vec = self.connections[token].ready(event_loop, events);
        if self.connections[token].is_closed() {
            let _ = self.connections.remove(token);
        } else if rpc_vec.len() > 0 {
            let mut jobs = self.jobs.lock().unwrap();
            for rpc in rpc_vec {
                jobs.push_back((token, rpc));
            }

            let threads_needed = cmp::min(200, jobs.len());
            let threads_counter = *self.threads_counter.lock().unwrap();

            for _ in threads_counter..threads_needed {
                self.spawn_worker();
            }
        }
    }

    fn connect(&mut self, event_loop: &mut mio::EventLoop<RPCEngine>, addr: SocketAddr) {
        if let Ok(socket) = TcpStream::connect(&addr) {
            let token = self.add_new_peer(event_loop, socket);

            self.handler.new_connection(token, addr);
        }
    }

    fn send_message(&mut self, event_loop: &mut mio::EventLoop<RPCEngine>,
                    token: mio::Token, data: Vec<u8>) {
        self.connections.get_mut(token).map(|c| c.push_message(event_loop, data));
    }
}

#[derive(Debug)]
pub enum Message {
    Connect(SocketAddr),
    SendMessage(mio::Token, Vec<u8>),
}

impl mio::Handler for RPCEngine {
    type Timeout = ();
    type Message = Message;

    fn ready(&mut self, event_loop: &mut mio::EventLoop<RPCEngine>,
             token: mio::Token, events: mio::EventSet) {
        match token {
            SERVER => self.handle_new_connection(event_loop),
            _ => self.handle_existing_connection(event_loop, token, events),
        }
    }

    fn notify(&mut self, event_loop: &mut mio::EventLoop<RPCEngine>, msg: Message) {
        match msg {
            Message::Connect(addr) => self.connect(event_loop, addr),
            Message::SendMessage(token, data) => self.send_message(event_loop, token, data),
        }
    }
}

#[derive(Debug)]
struct Connection {
    socket: TcpStream,
    token: mio::Token,
    state: State,
}

impl Connection {
    fn new(socket: TcpStream, token: mio::Token) -> Connection {
        Connection {
            socket: socket,
            token: token,
            state: State::new(),
        }
    }

    fn push_message(&mut self, event_loop: &mut mio::EventLoop<RPCEngine>, message: Vec<u8>) {
        self.state.push_message(message);
        self.reregister(event_loop);
    }

    fn ready(&mut self, event_loop: &mut mio::EventLoop<RPCEngine>,
             events: mio::EventSet) -> Vec<Vec<u8>> {
        let mut response = vec![];

        if events.is_readable() {
            response = self.read();
        }

        if events.is_writable() {
            self.write();
        }

        self.reregister(event_loop);

        response
    }

    fn read(&mut self) -> Vec<Vec<u8>> {
        match self.socket.try_read_buf(self.state.mut_read_buf()) {
            Ok(Some(0)) => {
                // The client has closed the read socket, for now
                // we just shutdown the connection
                self.state.close();
                vec![]
            }
            Ok(Some(_)) => {
                let mut done = false;
                let mut result = vec![];
                while !done {
                    let rpc = match self.state.try_get_rpc() {
                        Ok(x) => {
                            x
                        },
                        Err(x) => {
                            println!("Error: {}", x);
                            self.state.close();
                            vec![]
                        }
                    };

                    if rpc.len() > 0 {
                        result.push(rpc);
                    } else {
                        done = true;
                    }
                }

                result
            }
            Ok(None) => {
                vec![]
            }
            Err(_) => {
                self.state.close();
                vec![]
            }
        }
    }

    fn write(&mut self) {
        if !self.state.has_more_messages() {
            return;
        }

        while self.state.has_more_messages() {
            // TODO: handle error
            match self.socket.try_write_buf(self.state.mut_write_buf()) {
                Ok(_) => {
                    self.state.next_message();
                },
                Err(_) => {
                    self.state.close();
                    break;
                }
            }
        }
    }

    fn reregister(&self, event_loop: &mut mio::EventLoop<RPCEngine>) {
        let event_set = if self.state.has_more_messages() {
            mio::EventSet::readable() | mio::EventSet::writable()
        } else if self.state.connection_state() == &ConnectionState::Active {
            mio::EventSet::readable()
        } else {
            mio::EventSet::none()
        };

        event_loop.reregister(&self.socket, self.token, event_set,
                              mio::PollOpt::oneshot() | mio::PollOpt::edge())
                  .unwrap();
    }

    fn is_closed(&self) -> bool {
        match self.state.connection_state() {
            &ConnectionState::Closed => true,
            _ => false,
        }
    }
}

#[derive(Debug, PartialEq)]
enum ConnectionState {
    Active,
    Closed,
}

#[derive(Debug)]
struct State {
    reading_buf: Vec<u8>,
    writing_buf: Cursor<Vec<u8>>,
    writing_queue: VecDeque<Vec<u8>>,
    connection_state: ConnectionState,
}

impl State {
    pub fn new() -> State {
        State {
            reading_buf: vec![],
            writing_buf: Cursor::new(vec![]),
            writing_queue: VecDeque::new(),
            connection_state: ConnectionState::Active,
        }
    }

    pub fn close(&mut self) { self.connection_state = ConnectionState::Closed }

    pub fn connection_state(&self) -> &ConnectionState { &self.connection_state }

    pub fn has_more_messages(&self) -> bool {
        self.writing_queue.len() > 0 || self.writing_buf.has_remaining()
    }

    pub fn push_message(&mut self, message: Vec<u8>) {
        self.writing_queue.push_back(message);
    }

    pub fn next_message(&mut self) {
        if self.writing_buf.has_remaining() {
            return;
        }

        let message = self.writing_queue.pop_front();

        match message {
            Some(m) => {
                mem::replace(&mut self.writing_buf, Cursor::new(m));
            },
            None => {}
        }
    }

    fn try_get_rpc(&mut self) -> Result<Vec<u8>, String> {
        // TODO: handle this assert closing the connection
        // TODO: handle different networks
        // The input is too small to contain the header, let's wait
        if self.reading_buf.len() < 24 {
            return Ok(vec![]);
        }

        if let Some(message_len) = self.get_message_length() {
            // The input doesn't have the full message, let's wait
            if self.reading_buf.len() < 24 + message_len {
                return Ok(vec![]);
            }

            let mut reading_buf = mem::replace(&mut self.reading_buf, vec![]);
            let remaining = reading_buf.split_off(24 + message_len);

            self.reading_buf = remaining;
            Ok(reading_buf)
        } else {
            // At some point this will be just an error, but for now
            // a malformed message is probably just a bug so we need to crash
            println!("Error: malformed message");
            Debug::print_bytes(&self.reading_buf);
            panic!();
        }
    }

    fn get_message_length(&self) -> Option<usize> {
        let mut cursor = Cursor::new(&self.reading_buf);
        MessageHeader::deserialize(&mut cursor)
            .map(|h| Some(h.length as usize)).unwrap_or(None)
    }

    pub fn mut_read_buf(&mut self) -> &mut Vec<u8> {
        assert!(self.connection_state == ConnectionState::Active);

        &mut self.reading_buf
    }

    pub fn mut_write_buf(&mut self) -> &mut Cursor<Vec<u8>> {
        &mut self.writing_buf
    }
}
