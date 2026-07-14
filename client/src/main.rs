use std::{
    error::Error,
    io::{Write, stdin, stdout},
    net::{IpAddr, Ipv4Addr},
    time::{Duration, Instant},
};

use shared::protocal::{Request, Response};

use crate::networking::ClientConnection;

mod networking;

const SERVER_IP: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);

fn main() -> Result<(), Box<dyn Error>> {
    let mut connection = ClientConnection::connect()?;

    'main_loop: loop {
        println!();
        print!("enter a number: ");
        stdout().flush()?;

        let mut user_input = String::new();
        if let Err(err) = stdin().read_line(&mut user_input) {
            println!("failed to read user input:\n{err}");
            continue;
        }

        let number = match user_input.trim().parse() {
            Ok(ok) => ok,
            Err(err) => {
                println!("failed to parse user input:\n{err}");
                continue;
            }
        };

        if let Err(err) = connection.send(Request::ReturnNumber(number)) {
            println!("failed to send request to server:\n{err}");
            continue;
        };

        let start_time = Instant::now();
        while Instant::now().duration_since(start_time) < Duration::from_secs(3) {
            let response = match connection.receive() {
                Ok(Some(response)) => response,
                Ok(None) => continue,
                Err(err) => {
                    println!("failed to receive server response:\n{err}");
                    continue 'main_loop;
                }
            };

            match response {
                Response::Number(number) => {
                    println!("the server returned the number {number}");
                    break;
                }
            }
        }
    }
}
