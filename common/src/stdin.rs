use mio::{Ready, Registration};
use std::{
    io::{self, prelude::*},
    sync::mpsc::{self, Receiver},
    thread
};

pub struct MioStdin {
    pub reg: Registration,
    pub rx: Receiver<Vec<u8>>
}
impl MioStdin {
    pub fn new() -> Self {
        let (reg, control) = Registration::new2();
        let (tx, rx) = mpsc::channel();

        thread::spawn(move || {
            let stdin = io::stdin();
            let mut stdin = stdin.lock();

            let mut buf = [0; 1024];
            while let Ok(read) = stdin.read(&mut buf) {
                if read == 0 { break; }

                tx.send(buf[..read].to_vec()).unwrap();
                control.set_readiness(Ready::readable()).unwrap();
            }
        });

        Self {
            reg,
            rx
        }
    }
}
