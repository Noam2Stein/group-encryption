use std::error::Error;

use shared::protocal::{Request, Response};

use crate::networking::ServerListener;

mod networking;

fn main() -> Result<(), Box<dyn Error>> {
    let mut listener = ServerListener::bind()?;
    let mut connections = Vec::new();

    loop {
        loop {
            match listener.accept() {
                Ok(Some(connection)) => connections.push(connection),
                Ok(None) => break,
                Err(err) => {
                    println!("failed to accept client connection:\n{err}");
                    break;
                }
            };
        }

        for connection in &mut connections {
            let request = match connection.receive() {
                Ok(Some(request)) => request,
                Ok(None) => continue,
                Err(err) => {
                    println!("failed to receive client request:\n{err}");
                    continue;
                }
            };

            match request {
                Request::ReturnNumber(number) => match connection.send(Response::Number(number)) {
                    Ok(()) => {}
                    Err(err) => {
                        println!("failed to send response to client:\n{err}");
                    }
                },
            }
        }
    }
}
