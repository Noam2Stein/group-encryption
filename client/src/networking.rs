use std::net::SocketAddr;

use shared::{
    SERVER_PORT,
    networking::{ConnectError, Connection, ReceiveError, SendError},
    protocal::{Request, Response},
};

use crate::SERVER_IP;

pub struct ClientConnection(Connection<Request, Response>);

impl ClientConnection {
    pub fn connect() -> Result<Self, ConnectError> {
        Ok(Self(Connection::connect(SocketAddr::new(
            SERVER_IP,
            SERVER_PORT,
        ))?))
    }

    pub fn send(&mut self, request: Request) -> Result<(), SendError> {
        self.0.send(request)
    }

    pub fn receive(&mut self) -> Result<Option<Response>, ReceiveError> {
        self.0.receive()
    }
}
