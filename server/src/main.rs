extern crate failure;
extern crate mio;
extern crate nix;
extern crate openssl;
extern crate rand;
extern crate sslhash;
extern crate termion;

use failure::Error;
use mio::{*, unix::EventedFd};
use nix::{
    unistd::setsid,
    pty::{openpty, Winsize}
};
use openssl::ssl::{SslAcceptor, SslStream};
use rand::{OsRng, Rng};
use sslhash::AcceptorBuilder;
use std::{
    borrow::Cow,
    env,
    fs::File,
    io::{
        self,
        prelude::*,
        ErrorKind as IoErrorKind
    },
    net::{TcpListener, TcpStream},
    os::unix::{
        io::{AsRawFd, FromRawFd},
        process::CommandExt
    },
    process::{Command, Stdio}
};
use termion::raw::IntoRawMode;

#[cfg(not(feature = "local"))] const ADDR: &str = "0.0.0.0";
#[cfg(feature = "local")]      const ADDR: &str = "127.0.0.1";
const PORT: u16  = 53202;

const BUFSIZE: usize = 8 * 1024;
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

    let pty = match openpty(Some(&Winsize {
        ws_row: 30,
        ws_col: 80,
        ws_xpixel: 0,
        ws_ypixel: 0
    }), None) {
        Ok(pty) => pty,
        Err(err) => {
            eprintln!("failed to open pseudo-terminal: {}", err);
            return;
        }
    };

    let master = unsafe { File::from_raw_fd(pty.master) };

    if let Err(err) =
        Command::new(&*shell)
            .stdin(unsafe { Stdio::from_raw_fd(pty.slave) })
            .stdout(unsafe { Stdio::from_raw_fd(pty.slave) })
            .stderr(unsafe { Stdio::from_raw_fd(pty.slave) })
            .before_exec(|| {
                setsid().expect("failed to setsid");
                Ok(())
            })
            .spawn() {
        eprintln!("failed to spawn process: {}", err);
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

fn main_loop(mut master: File, mut stream: SslStream<TcpStream>) -> Result<(), Error> {
    let mut stdin = io::stdin();
    let stdout = io::stdout().into_raw_mode()?;
    let mut stdout = stdout.lock();

    let poll = Poll::new()?;

    poll.register(&EventedFd(&stream.get_ref().as_raw_fd()), TOKEN_STREAM, Ready::readable(), PollOpt::edge())?;
    poll.register(&EventedFd(&stdin.as_raw_fd()), TOKEN_STDIN, Ready::readable(), PollOpt::edge())?;
    poll.register(&EventedFd(&master.as_raw_fd()), TOKEN_PTY, Ready::readable(), PollOpt::edge())?;

    let mut events = Events::with_capacity(1024);
    let mut buf = [0; BUFSIZE];
    let mut todo: Vec<u8> = Vec::with_capacity(1024);

    loop {
        poll.poll(&mut events, None)?;

        for event in &events {
            while !todo.is_empty() {
                let written = match stream.write(&todo) {
                    Ok(0) => return Ok(()),
                    Err(ref err) if err.kind() == IoErrorKind::WouldBlock => break,
                    x => x?
                };
                todo.drain(..written);
            }

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

                    let mut written = 0;
                    while written < read {
                        written += match stream.write(&buf[written..read]) {
                            Ok(0) => return Ok(()),
                            Err(ref err) if err.kind() == IoErrorKind::WouldBlock => break,
                            x => x?
                        };
                    }
                    stream.flush()?;
                    if written < read {
                        todo.extend(&buf[written..read]);
                    }
                },
                _ => unreachable!()
            }
        }
    }
}
