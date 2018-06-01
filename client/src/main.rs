#[macro_use] extern crate failure;
extern crate mio;
extern crate openssl;
extern crate sslhash;
extern crate termion;

use failure::Error;
use mio::{*, unix::EventedFd};
use openssl::ssl::{SslConnector, SslMethod};
use std::{
    io::{
        self,
        prelude::*,
        ErrorKind as IoErrorKind
    },
    net::{SocketAddr, TcpStream},
    os::unix::io::AsRawFd
};
use termion::raw::IntoRawMode;

#[derive(Debug, Fail)]
#[fail(display = "invalid password")]
struct InvalidPassword;

const PORT: u16 = 53202;

const BUFSIZE: usize = 8 * 1024;
const PASSLEN: usize = 32;

const TOKEN_STREAM: Token = Token(0);
const TOKEN_STDIN:  Token = Token(1);

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

    let addr = match parse_addr(&addr.trim()) {
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

    let stdout = io::stdout().into_raw_mode()?;
    let mut stdout = stdout.lock();

    let mut stdin = io::stdin();

    let poll = Poll::new()?;

    poll.register(&EventedFd(&stream.get_ref().as_raw_fd()), TOKEN_STREAM, Ready::readable(), PollOpt::edge())?;
    poll.register(&EventedFd(&stdin.as_raw_fd()), TOKEN_STDIN, Ready::readable(), PollOpt::edge())?;

    let mut events = Events::with_capacity(1024);
    let mut buf = [0; BUFSIZE];

    loop {
        poll.poll(&mut events, None)?;
        for event in &events {
            match event.token() {
                TOKEN_STREAM => loop {
                    let read = match stream.read(&mut buf) {
                        Ok(0) => return Ok(()),
                        Err(ref err) if err.kind() == IoErrorKind::WouldBlock => break,
                        x => x?
                    };

                    stdout.write_all(&buf[..read]).unwrap();
                    stdout.flush().unwrap();
                },
                TOKEN_STDIN => {
                    // Stdin is blocking, can't loop until WouldBlock.
                    // Let's hope the bufsize is large enough!
                    let read = stdin.read(&mut buf)?;
                    if read == 0 {
                        return Ok(());
                    }

                    stream.write_all(&buf[..read])?;
                    stream.flush()?;
                },
                _ => unreachable!()
            }
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
