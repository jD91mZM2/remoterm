extern crate common;
extern crate failure;
extern crate mio;
extern crate openssl;
extern crate pseudoterm;
extern crate rand;
extern crate sslhash;
extern crate termion;

use common::*;
use failure::Error;
use mio::{*, unix::EventedFd};
use openssl::ssl::{SslAcceptor, SslStream};
use pseudoterm::{OpenptyOptions, Winsize};
use rand::{OsRng, Rng};
use sslhash::AcceptorBuilder;
use std::{
    borrow::Cow,
    env,
    fs::File,
    io::{
        self,
        prelude::*
    },
    net::{TcpListener, TcpStream},
    os::unix::io::AsRawFd,
    process::Command
};
use termion::raw::IntoRawMode;

#[cfg(not(feature = "local"))] const ADDR: &str = "0.0.0.0";
#[cfg(feature = "local")]      const ADDR: &str = "127.0.0.1";

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

    let (master, slave) = match pseudoterm::openpty(
        &OpenptyOptions::new()
            .with_nonblocking(true)
            .with_size(Winsize {
                cols: 80,
                rows: 32,
            })
    ) {
        Ok(pty) => pty,
        Err(err) => {
            eprintln!("failed to open pseudo-terminal: {}", err);
            return;
        }
    };

    if let Err(err) = pseudoterm::prepare_cmd(slave, &mut Command::new(&*shell)).and_then(|cmd| cmd.spawn()) {
        eprintln!("failed to spawn process: {}", err);
        return;
    }

    if let Err(err) = main_loop(master, stream) {
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

fn main_loop(master: File, stream: SslStream<TcpStream>) -> Result<(), Error> {
    let stdin = MioStdin::new();
    let stdout = io::stdout().into_raw_mode()?;
    let mut stdout = stdout.lock();

    let mut stream = PatientWriter::new(stream);
    let mut master = PatientWriter::new(master);

    let poll = Poll::new()?;

    poll.register(&EventedFd(&stream.get_ref().as_raw_fd()), TOKEN_STREAM, Ready::readable() | Ready::writable(), PollOpt::edge())?;
    poll.register(&stdin.reg, TOKEN_STDIN, Ready::readable(), PollOpt::edge())?;
    poll.register(&EventedFd(&master.as_raw_fd()), TOKEN_PTY, Ready::readable() | Ready::writable(), PollOpt::edge())?;

    let mut events = Events::with_capacity(1024);
    let mut buf = [0; BUFSIZE];

    'main: loop {
        poll.poll(&mut events, None)?;

        for event in &events {
            match event.token() {
                TOKEN_STREAM => {
                    if event.readiness().is_writable() {
                        if stream.write_todo()? {
                            stream.flush()?;
                        }
                    }
                    if event.readiness().is_readable() {
                        while let Some(read) = maybe(stream.read(&mut buf))? {
                            if read == 0 { break 'main; }

                            master.write_all(&buf[..read])?;
                        }
                        master.flush()?;
                    }
                }
                TOKEN_STDIN => {
                    while let Ok(buf) = stdin.rx.try_recv() {
                        master.write_all(&buf)?;
                    }
                    master.flush()?;
                },
                TOKEN_PTY => {
                    if event.readiness().is_writable() {
                        if stream.write_todo()? {
                            stream.flush()?;
                        }
                    }
                    if event.readiness().is_readable() {
                        while let Some(read) = maybe(master.read(&mut buf))? {
                            if read == 0 { break 'main; }

                            stdout.write_all(&buf[..read])?;
                            stream.write_all(&buf[..read])?;
                        }
                        stdout.flush()?;
                        stream.flush()?;
                    }
                },
                _ => ()
            }
        }
    }
    Ok(())
}
