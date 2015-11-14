// Based on mio example echo server for now.
extern crate mio;
extern crate bytes;

use mio::{TryRead, TryWrite};
use mio::tcp::*;
use mio::util::Slab;
use bytes::Buf;
use std::mem;
use std::io::Cursor;
use std::collections::{VecDeque, HashMap};

use super::messages::{MessageHeader, Deserialize, Deserializer};

pub const SERVER: mio::Token = mio::Token(0);

pub trait MessageHandler {
    fn handle(&mut self, token: mio::Token, message: Vec<u8>) -> VecDeque<Vec<u8>>;
    fn get_new_messages(&mut self) -> HashMap<mio::Token, Vec<Vec<u8>>>;
}

pub struct RPCEngine {
    server: TcpListener,
    connections: Slab<Connection>,
    handler: Box<MessageHandler>,
}

impl RPCEngine {
    pub fn new(server: TcpListener, handler: Box<MessageHandler>) -> RPCEngine {
        // Token 0 is reserver for the server
        let slab = Slab::new_starting_at(mio::Token(1), 1024);

        RPCEngine {
            server: server,
            connections: slab,
            handler: handler,
        }
    }

    fn handle_rpc(&mut self, event_loop: &mut mio::EventLoop<RPCEngine>,
                  token: mio::Token, rpc: Vec<u8>) {

        let response: Vec<u8> = self.handler.handle(token, rpc)
            .into_iter().flat_map(|l| l.into_iter())
            .collect();

        self.connections[token].push_message(event_loop, response);
    }
}

impl mio::Handler for RPCEngine {
    type Timeout = ();
    type Message = ();

    fn ready(&mut self, event_loop: &mut mio::EventLoop<RPCEngine>,
             token: mio::Token, events: mio::EventSet) {
        match token {
            SERVER => {
                assert!(events.is_readable());

                match self.server.accept() {
                    Ok(Some(socket)) => {
                        // TODO: handle errors
                        let token = self.connections
                            .insert_with(|token| Connection::new(socket, token))
                            .unwrap();

                        event_loop.register_opt(
                            &self.connections[token].socket,
                            token,
                            mio::EventSet::readable(),
                            mio::PollOpt::edge() | mio::PollOpt::oneshot()).unwrap();
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
            _ => {
                if !self.connections.contains(token) {
                    // If we're here it means the connection has been closed already
                    return;
                }

                let rpc = self.connections[token].ready(event_loop, events);
                if self.connections[token].is_closed() {
                    let _ = self.connections.remove(token);
                } else if rpc.len() > 0 {
                    self.handle_rpc(event_loop, token, rpc);
                }
            }
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
             events: mio::EventSet) -> Vec<u8> {
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

    fn read(&mut self) -> Vec<u8> {
        match self.socket.try_read_buf(self.state.mut_read_buf()) {
            Ok(Some(0)) => {
                // The client has closed the read socket, for now
                // we just shutdown the connection
                self.state.close();
                vec![]
            }
            Ok(Some(_)) => {
                match self.state.try_get_rpc() {
                    Ok(x) => {
                        x
                    },
                    Err(x) => {
                        println!("Error: {}", x);
                        self.state.close();
                        vec![]
                    }
                }
            }
            Ok(None) => {
                vec![]
            }
            Err(e) => {
                println!("Got an error trying to read; err={:?}", e);
                println!("closing connection.");

                self.state.close();
                vec![]
            }
        }
    }

    fn write(&mut self) {
        if !self.state.write_buf().has_remaining() {
            return;
        }

        // TODO: handle error
        match self.socket.try_write_buf(self.state.mut_write_buf()) {
            Ok(_) => {
                if !self.state.write_buf().has_remaining() {
                    self.state.clear_write_buf();
                }
            },
            Err(e) => {
                panic!("got an error trying to write; err={:?}", e);
            }
        }
    }

    fn reregister(&self, event_loop: &mut mio::EventLoop<RPCEngine>) {
        let event_set = if self.state.write_buf().has_remaining() {
            mio::EventSet::readable() | mio::EventSet::writable()
        } else if self.state.connection_state() == &ConnectionState::Active {
            mio::EventSet::readable()
        } else {
            mio::EventSet::none()
        };

        event_loop.reregister(&self.socket, self.token, event_set,
                              mio::PollOpt::oneshot())
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
    connection_state: ConnectionState,
}

impl State {
    pub fn new() -> State {
        State {
            reading_buf: vec![],
            writing_buf: Cursor::new(vec![]),
            connection_state: ConnectionState::Active,
        }
    }

    pub fn close(&mut self) { self.connection_state = ConnectionState::Closed }

    pub fn connection_state(&self) -> &ConnectionState { &self.connection_state }

    pub fn push_message(&mut self, message: Vec<u8>) {
        let pos = self.writing_buf.position();
        let mut writing_buf = mem::replace(&mut self.writing_buf, Cursor::new(vec![]))
            .into_inner();

        writing_buf.split_off(pos as usize);
        writing_buf.extend(message.into_iter());

        self.writing_buf = Cursor::new(writing_buf);
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
            Ok(vec![])
        }
    }

    fn get_message_length(&self) -> Option<usize> {
        let mut cursor = Deserializer::new(&self.reading_buf[..]);
        MessageHeader::deserialize(&mut cursor, &[])
            .map(|h| Some(h.len() as usize)).unwrap_or(None)
    }

    pub fn mut_read_buf(&mut self) -> &mut Vec<u8> {
        assert!(self.connection_state == ConnectionState::Active);

        &mut self.reading_buf
    }

    pub fn clear_write_buf(&mut self) {
        self.writing_buf = Cursor::new(vec![]);
    }

    pub fn write_buf(&self) -> &Cursor<Vec<u8>> {
        &self.writing_buf
    }

    pub fn mut_write_buf(&mut self) -> &mut Cursor<Vec<u8>> {
        &mut self.writing_buf
    }
}
