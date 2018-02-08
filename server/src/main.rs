extern crate failure;
extern crate openssl;
extern crate pty;
extern crate rand;
extern crate sslhash;
extern crate termion;

use failure::Error;
use openssl::ssl::{SslAcceptor, SslStream};
use pty::fork::{Fork as PtyFork, Master as PtyMaster};
use rand::{OsRng, Rng};
use sslhash::AcceptorBuilder;
use std::borrow::Cow;
use std::env;
use std::io::prelude::*;
use std::io::{self, ErrorKind as IoErrorKind};
use std::net::{TcpListener, TcpStream};
use std::process::Command;
use std::sync::{mpsc, Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;
use termion::raw::IntoRawMode;

#[cfg(not(feature = "local"))] const ADDR: &str = "0.0.0.0";
#[cfg(feature = "local")]      const ADDR: &str = "127.0.0.1";
const PORT: u16  = 53202;

const BUFSIZE: usize = 512;
const PASSLEN: usize = 32;
const DELAY:   usize = 5;

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

struct Defer(mpsc::SyncSender<()>);
impl Drop for Defer {
    fn drop(&mut self) {
        self.0.send(()).unwrap();
    }
}

struct ThreadJoin<T>(Option<JoinHandle<T>>);
impl<T> Drop for ThreadJoin<T> {
    fn drop(&mut self) {
        if let Some(handle) = self.0.take() {
            handle.join().unwrap();
        }
    }
}

fn main_loop(mut master: PtyMaster, stream: SslStream<TcpStream>) -> Result<(), Error> {
    let stream = Arc::new(Mutex::new(stream));

    let mut master_clone = master.clone();
    let stream_clone = Arc::clone(&stream);

    let (tx_stop, rx_stop) = mpsc::sync_channel(1);

    let _thread = ThreadJoin(Some(thread::spawn(move || -> Result<(), Error> {
        let _defer = Defer(tx_stop);

        let mut stdout = io::stdout().into_raw_mode()?;
        stdout.lock();

        loop {
            thread::sleep(Duration::from_millis(DELAY));

            let mut buf = [0; BUFSIZE];
            let read = master_clone.read(&mut buf)?;
            if read == 0 { return Ok(()); }
            stdout.write_all(&buf[..read]).unwrap();
            stdout.flush().unwrap();

            let mut stream = stream_clone.lock().unwrap();
            stream.write_all(&buf[..read])?;
            stream.flush()?;
        }
    })));

    let mut stdin = termion::async_stdin();

    loop {
        thread::sleep(Duration::from_millis(DELAY));

        let mut stream = stream.lock().unwrap();

        let mut buf = [0; BUFSIZE];
        let read = match stream.read(&mut buf) {
            Err(ref err) if err.kind() == IoErrorKind::WouldBlock => 0,
            x => x?
        };
        if read > 0 {
            master.write_all(&buf[..read])?;
            master.flush()?;
        }

        let mut buf = [0; BUFSIZE];
        let read = match stdin.read(&mut buf) {
            Err(ref err) if err.kind() == IoErrorKind::WouldBlock => 0,
            x => x?
        };
        if read > 0 {
            master.write_all(&buf[..read])?;
            master.flush()?;
        }

        if rx_stop.try_recv().is_ok() {
            return Ok(());
        }
    }
}
