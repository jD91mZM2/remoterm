#[macro_use] extern crate failure;
extern crate openssl;
extern crate sslhash;
extern crate termion;

use failure::Error;
use openssl::ssl::{SslConnector, SslMethod};
use std::io::prelude::*;
use std::io::{self, ErrorKind as IoErrorKind};
use std::net::{SocketAddr, TcpStream};
use std::thread;
use std::time::Duration;
use termion::raw::IntoRawMode;

#[derive(Debug, Fail)]
#[fail(display = "invalid password")]
struct InvalidPassword;

const PORT: u16 = 53202;

const BUFSIZE: usize = 512;
const PASSLEN: usize = 32;

fn main() {
    if let Err(err) = inner_main() {
        eprintln!("{}", err);
    }
}
fn inner_main() -> Result<(), Error> {
    print!("Server ip:port: ");
    io::stdout().flush().unwrap();
    let mut addr = String::new();
    io::stdin().read_line(&mut addr)?;

    let addr = match parse_addr(&addr) {
        Some(addr) => addr,
        None => {
            eprintln!("invalid address");
            return Ok(());
        }
    };

    print!("Session password: ");
    io::stdout().flush().unwrap();
    let mut password = String::new();
    io::stdin().read_line(&mut password)?;

    let mut split = password.trim().splitn(2, '-');
    let hash      = split.next().ok_or(InvalidPassword)?.to_string();
    let password  = split.next().ok_or(InvalidPassword)?;

    if password.len() != PASSLEN {
        return Err(InvalidPassword.into());
    }

    let ssl = SslConnector::builder(SslMethod::tls())?.build();

    let stream = TcpStream::connect(addr)?;
    let mut stream = sslhash::connect(&ssl, stream, hash)?;

    stream.write_all(password.as_bytes())?;
    stream.flush()?;

    stream.get_mut().set_nonblocking(true)?;

    let mut stdout = io::stdout().into_raw_mode()?;
    stdout.lock();

    let mut stdin = termion::async_stdin();

    loop {
        thread::sleep(Duration::from_millis(100));

        let mut buf = [0; BUFSIZE];
        let read = match stream.read(&mut buf) {
            Err(ref err) if err.kind() == IoErrorKind::WouldBlock => 0,
            x => x?
        };
        if read > 0 {
            stdout.write_all(&buf[..read]).unwrap();
            stdout.flush().unwrap();
        }

        let mut buf = [0; BUFSIZE];
        let read = match stdin.read(&mut buf) {
            Err(ref err) if err.kind() == IoErrorKind::WouldBlock => 0,
            x => x?
        };

        if read > 0 {
            stream.write_all(&buf[..read])?;
            stream.flush()?;
        }
    }
}
fn parse_addr(input: &str) -> Option<SocketAddr> {
    let mut parts = input.rsplitn(2, ':');
    let addr = match (parts.next()?, parts.next()) {
        (port, Some(ip)) => (ip, port.parse().ok()?),
        (ip,   None)     => (ip, PORT)
    };

    use std::net::ToSocketAddrs;
    addr.to_socket_addrs()
        .ok()
        .and_then(|mut addrs| addrs.next())
}
