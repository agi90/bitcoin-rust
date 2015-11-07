// Based on mio example echo server for now.
extern crate mio;
extern crate bytes;

use mio::{TryRead, TryWrite};
use mio::tcp::*;
use mio::util::Slab;
use bytes::Buf;
use std::mem;
use std::io::Cursor;
use super::messages;
use std::collections::{VecDeque, HashMap};

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
        println!("socket is ready; token={:?}; events={:?}", token, events);

        match token {
            SERVER => {
                assert!(events.is_readable());

                match self.server.accept() {
                    Ok(Some(socket)) => {
                        println!("accepted a new client socket");

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
        match self.state.connection_state() {
            &ConnectionState::Reading(..) => {
                assert!(events.is_readable(), "unexpected events; events={:?}", events);
                self.read(event_loop)
            }
            &ConnectionState::Writing(..) => {
                assert!(events.is_writable(), "unexpected events; events={:?}", events);
                self.write(event_loop)
            }
            _ => unimplemented!(),
        }
    }

    fn read(&mut self, event_loop: &mut mio::EventLoop<RPCEngine>) -> Vec<u8> {
        match self.socket.try_read_buf(self.state.mut_read_buf()) {
            Ok(Some(0)) => {
                // The client has closed the read socket, for now
                // we just shutdown the connection
                self.state.close();
                vec![]
            }
            Ok(Some(n)) => {
                println!("read {} bytes", n);
                match self.state.try_get_rpc() {
                    Ok(x) => {
                        self.state.try_transition_to_writing();
                        self.reregister(event_loop);
                        x
                    },
                    Err(x) => {
                        println!("Error: {}", x);
                        vec![]
                    }
                }
            }
            Ok(None) => {
                self.reregister(event_loop);
                vec![]
            }
            Err(e) => {
                panic!("got an error trying to read; err={:?}", e);
            }
        }
    }

    fn write(&mut self, event_loop: &mut mio::EventLoop<RPCEngine>) -> Vec<u8> {
        // TODO: handle error
        match self.socket.try_write_buf(self.state.mut_write_buf()) {
            Ok(Some(_)) => {
                let result = self.state.try_transition_to_reading();
                self.reregister(event_loop);
                result
            }
            Ok(None) => {
                self.reregister(event_loop);
                vec![]
            }
            Err(e) => {
                panic!("got an error trying to write; err={:?}", e);
            }
        }
    }

    fn reregister(&self, event_loop: &mut mio::EventLoop<RPCEngine>) {
        let event_set = match self.state.connection_state() {
            &ConnectionState::Reading(..) => mio::EventSet::readable(),
            &ConnectionState::Writing(..) => mio::EventSet::writable(),
            _ => mio::EventSet::none(),
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
    Reading,
    Writing,
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
            connection_state: ConnectionState::Reading,
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
        self.try_transition_to_writing();
    }

    fn try_get_rpc(&mut self) -> Result<Vec<u8>, String> {
        // TODO: handle this assert closing the connection
        // TODO: handle different networks
        // The input is too small to contain the header, let's wait
        if self.reading_buf.len() < 24 {
            return Ok(vec![]);
        }

        // TODO: accept [u8] in deserialize functions
        //       or even a Take<>
        let mut header_bytes = vec![];
        header_bytes.extend(self.reading_buf[0..24].into_iter());
        header_bytes.reverse();

        let header = try!(messages::MessageHeader::deserialize(&mut header_bytes));
        print!("header = {:?}\n", header);

        // The input doesn't have the full message, let's wait
        if self.reading_buf.len() < 24 + header.len() as usize {
            return Ok(vec![]);
        }

        let mut reading_buf = mem::replace(&mut self.reading_buf, vec![]);
        let remaining = reading_buf.split_off(24 + header.len() as usize);

        self.reading_buf = remaining;
        Ok(reading_buf)
    }

    pub fn mut_read_buf(&mut self) -> &mut Vec<u8> {
        assert!(self.connection_state == ConnectionState::Reading);

        &mut self.reading_buf
    }

    pub fn mut_write_buf(&mut self) -> &mut Cursor<Vec<u8>> {
        assert!(self.connection_state == ConnectionState::Writing);

        &mut self.writing_buf
    }

    fn try_transition_to_writing(&mut self) {
        println!("Try transitioning to writing");
        if self.writing_buf.has_remaining() {
            self.connection_state = ConnectionState::Writing;
        }
    }

    fn try_transition_to_reading(&mut self) -> Vec<u8> {
        println!("Try transitioning to reading");
        if !self.writing_buf.has_remaining() {
            self.connection_state = ConnectionState::Reading;

            // There could be an RPC waiting for us already
            match self.try_get_rpc() {
                Ok(x) => x,
                Err(x) => {
                    println!("Error: {}", x);
                    vec![]
                }
            }
        } else {
            vec![]
        }
    }
}

/*
 *
 * ===== TESTS =====
 *
 */

#[cfg(test)]
mod test {
    use std::io::{BufRead, BufReader, Read, Write};
    use std::net::{Shutdown, TcpStream};

    #[test]
    pub fn test_basic_echoing() {
        start_server();

        let mut sock = BufReader::new(TcpStream::connect(HOST).unwrap());
        let mut recv = String::new();

        sock.get_mut().write_all(b"hello world\n").unwrap();
        sock.read_line(&mut recv).unwrap();

        assert_eq!(recv, "hello world\n");

        recv.clear();

        sock.get_mut().write_all(b"this is a line\n").unwrap();
        sock.read_line(&mut recv).unwrap();

        assert_eq!(recv, "this is a line\n");
    }

    #[test]
    pub fn test_handling_client_shutdown() {
        start_server();

        let mut sock = TcpStream::connect(HOST).unwrap();

        sock.write_all(b"hello world").unwrap();
        sock.shutdown(Shutdown::Write).unwrap();

        let mut recv = vec![];
        sock.read_to_end(&mut recv).unwrap();

        assert_eq!(recv, b"hello world");
    }

    const HOST: &'static str = "0.0.0.0:13254";

    fn start_server() {
        use std::thread;
        use std::sync::{Once, ONCE_INIT};

        static INIT: Once = ONCE_INIT;

        INIT.call_once(|| {
            thread::spawn(|| {
                super::start(HOST.parse().unwrap())
            });

            while let Err(_) = TcpStream::connect(HOST) {
                // Loop
            }
        });
    }
}
