use shared::{
    SERVER_PORT,
    networking::{AcceptError, BindError, Connection, Listener, ReceiveError, SendError},
    protocal::{Request, Response},
};

pub struct ServerListener(Listener);

pub struct ServerConnection(Connection<Response, Request>);

impl ServerListener {
    pub fn bind() -> Result<Self, BindError> {
        Ok(Self(Listener::bind(SERVER_PORT)?))
    }

    pub fn accept(&mut self) -> Result<Option<ServerConnection>, AcceptError> {
        self.0.accept().map(|result| result.map(ServerConnection))
    }
}

impl ServerConnection {
    pub fn receive(&mut self) -> Result<Option<Request>, ReceiveError> {
        self.0.receive()
    }

    pub fn send(&mut self, response: Response) -> Result<(), SendError> {
        self.0.send(response)
    }
}
