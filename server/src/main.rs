extern crate failure;
extern crate mio;
extern crate openssl;
extern crate pty;
extern crate rand;
extern crate sslhash;
extern crate termion;

use failure::Error;
use mio::{*, unix::EventedFd};
use openssl::ssl::{SslAcceptor, SslStream};
use pty::fork::{Fork as PtyFork, Master as PtyMaster};
use rand::{OsRng, Rng};
use sslhash::AcceptorBuilder;
use std::{
    borrow::Cow,
    env,
    io::{
        self,
        prelude::*,
        ErrorKind as IoErrorKind
    },
    net::{TcpListener, TcpStream},
    os::unix::io::AsRawFd,
    process::Command
};
use termion::raw::IntoRawMode;

#[cfg(not(feature = "local"))] const ADDR: &str = "0.0.0.0";
#[cfg(feature = "local")]      const ADDR: &str = "127.0.0.1";
const PORT: u16  = 53202;

const BUFSIZE: usize = 512;
const PASSLEN: usize = 32;

const TOKEN_STREAM: Token = Token(0);
const TOKEN_STDIN:  Token = Token(1);
const TOKEN_PTY:    Token = Token(2);

fn main() {
    let port = env::args().skip(1).next().map(|arg| arg.parse().unwrap_or_else(|_| {
        eprintln!("invalid port, using default");
        PORT
    })).unwrap_or(PORT);

    println!("Welcome to remoterm!");

    let shell = match env::var("SHELL") {
        Ok(shell) => Cow::from(shell),
        Err(err) => {
            eprintln!("failed to get shell: {}", err);
            eprintln!("using bash as default");
            Cow::from("/bin/bash")
        }
    };
    println!("Using shell: {}", shell);

    let (ssl, hash) = match AcceptorBuilder::default().build() {
        Ok(result)  => result,
        Err(err) => {
            eprintln!("failed to build ssl acceptor: {}", err);
            return;
        }
    };

    let listener = match TcpListener::bind((ADDR, port)) {
        Ok(listener) => listener,
        Err(err) => {
            eprintln!("failed to open listener: {}", err);
            return;
        }
    };

    let mut rand = match OsRng::new() {
        Ok(rand) => rand,
        Err(err) => {
            eprintln!("failed to initialize number generator: {}", err);
            return;
        }
    };
    let pass: String = rand.gen_ascii_chars().take(PASSLEN).collect();
    println!("Session password: {}-{}", hash, pass);

    let stream = match connect(&listener, &ssl, &pass) {
        Ok(stream) => stream,
        Err(err) => {
            eprintln!("failed to connect: {}", err);
            return;
        }
    };

    let fork = match PtyFork::from_ptmx() {
        Ok(fork) => fork,
        Err(err) => {
            eprintln!("failed to fork pty: {}", err);
            return;
        }
    };

    let parent = fork.is_parent();
    if parent.is_err() {
        let child = Command::new(&*shell).status();

        if let Err(err) = child {
            eprintln!("failed to execute command: {}", err);
        }
        return;
    }

    if let Err(err) = main_loop(parent.unwrap(), stream) {
        eprintln!("{}", err);
    }
}
fn connect(listener: &TcpListener, ssl: &SslAcceptor, password: &str) -> Result<SslStream<TcpStream>, Error> {
    println!("Waiting for connection...");

    loop {
        let (stream, addr) = listener.accept()?;
        let mut stream = ssl.accept(stream)?;

        let mut pass_guess = [0; PASSLEN];
        stream.read_exact(&mut pass_guess)?;

        if pass_guess != password.as_bytes() {
            eprintln!("connection from {} tried an invalid password", addr);
            continue;
        }

        stream.get_mut().set_nonblocking(true)?;

        println!("Connected to {}", addr);
        break Ok(stream);
    }
}

fn main_loop(mut master: PtyMaster, mut stream: SslStream<TcpStream>) -> Result<(), Error> {
    let mut stdin = io::stdin();
    let stdout = io::stdout().into_raw_mode()?;
    let mut stdout = stdout.lock();

    let poll = Poll::new()?;

    poll.register(&EventedFd(&stream.get_ref().as_raw_fd()), TOKEN_STREAM, Ready::readable(), PollOpt::edge())?;
    poll.register(&EventedFd(&stdin.as_raw_fd()), TOKEN_STDIN, Ready::readable(), PollOpt::edge())?;
    poll.register(&EventedFd(&master.as_raw_fd()), TOKEN_PTY, Ready::readable(), PollOpt::edge())?;

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

                    master.write_all(&buf[..read])?;
                    master.flush()?;
                },
                TOKEN_STDIN => {
                    // Stdin is blocking, can't loop until WouldBlock.
                    // Let's hope the bufsize is large enough!
                    let read = stdin.read(&mut buf)?;
                    if read == 0 {
                        return Ok(());
                    }

                    master.write_all(&buf[..read])?;
                    master.flush()?;
                },
                TOKEN_PTY => {
                    // PTY is blocking, can't loop until WouldBlock.
                    // Let's hope the bufsize is large enough!
                    let read = master.read(&mut buf)?;
                    if read == 0 {
                        return Ok(());
                    }

                    stdout.write_all(&buf[..read]).unwrap();
                    stdout.flush().unwrap();
                    stream.write_all(&buf[..read])?;
                    stream.flush()?;
                },
                _ => unreachable!()
            }
        }
    }
}
