use std::{
    io::{Read, Write},
    marker::PhantomData,
    net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, TcpStream},
};

use thiserror::Error;
use wincode::{Deserialize, ReadError, Serialize, WriteError, deserialize, serialize};

pub struct Listener(TcpListener);

pub struct Connection<S, R> {
    stream: TcpStream,
    receive_bytes: Vec<u8>,
    _marker: PhantomData<(S, R)>,
}

#[derive(Error, Debug)]
pub enum BindError {
    #[error("networking error:\n{0}")]
    Io(#[from] std::io::Error),
}

#[derive(Error, Debug)]
pub enum AcceptError {
    #[error("networking error:\n{0}")]
    Io(#[from] std::io::Error),
}
#[derive(Error, Debug)]
pub enum ConnectError {
    #[error("networking error:\n{0}")]
    Io(#[from] std::io::Error),
}

#[derive(Error, Debug)]
pub enum SendError {
    #[error("failed to serialize:\n{0}")]
    SerializeFailed(#[from] WriteError),
    #[error("networking error:\n{0}")]
    Io(#[from] std::io::Error),
}

#[derive(Error, Debug)]
pub enum ReceiveError {
    #[error("networking error:\n{0}")]
    Io(#[from] std::io::Error),
    #[error("failed to deserialize:\n{0}")]
    DeserializeFailed(#[from] ReadError),
}

impl Listener {
    pub fn bind(port: u16) -> Result<Self, BindError> {
        let listener = TcpListener::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), port))?;
        listener.set_nonblocking(true)?;

        Ok(Self(listener))
    }

    pub fn accept<S, R>(&mut self) -> Result<Option<Connection<S, R>>, AcceptError> {
        let (stream, _) = match self.0.accept() {
            Ok(ok) => ok,
            Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                return Ok(None);
            }
            Err(err) => return Err(AcceptError::Io(err)),
        };
        stream.set_nonblocking(true)?;

        Ok(Some(Connection {
            stream,
            receive_bytes: Vec::new(),
            _marker: PhantomData,
        }))
    }
}

impl<S, R> Connection<S, R>
where
    S: Serialize<Src = S>,
    R: for<'a> Deserialize<'a, Dst = R>,
{
    pub fn connect(listener_addr: SocketAddr) -> Result<Self, ConnectError> {
        let stream = TcpStream::connect(listener_addr)?;
        stream.set_nonblocking(true)?;

        Ok(Self {
            stream,
            receive_bytes: Vec::new(),
            _marker: PhantomData,
        })
    }

    pub fn send(&mut self, value: S) -> Result<(), SendError> {
        let serialized = serialize(&value)?;

        self.stream
            .write_all(&(serialized.len() as u32).to_le_bytes())?;
        self.stream.write_all(&serialized)?;

        Ok(())
    }

    pub fn receive(&mut self) -> Result<Option<R>, ReceiveError> {
        let mut buf = vec![0; 2401];
        match self.stream.read(&mut buf) {
            Ok(0) => {}
            Ok(n) => self.receive_bytes.extend(&buf[..n]),
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => return Ok(None),
            Err(e) => return Err(e.into()),
        };

        let Some((next_message_size, leftover_bytes)) = self.receive_bytes.split_at_checked(4)
        else {
            return Ok(None);
        };

        let next_message_size = u32::from_le_bytes(
            *next_message_size
                .as_array::<4>()
                .expect("this cannot fail because we split at 4 bytes"),
        ) as usize;

        let Some(next_message) = leftover_bytes.get(..next_message_size) else {
            return Ok(None);
        };

        let next_message = deserialize(next_message)?;
        self.receive_bytes.drain(..4 + next_message_size);

        Ok(Some(next_message))
    }
}
