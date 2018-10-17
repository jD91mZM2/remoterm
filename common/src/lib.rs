extern crate mio;

pub const PORT: u16 = 53202;

pub const BUFSIZE: usize = 8 * 1024;
pub const PASSLEN: usize = 32;

mod patient;
mod stdin;

pub use self::patient::PatientWriter;
pub use self::stdin::MioStdin;

use std::io;

pub fn maybe<T>(res: io::Result<T>) -> io::Result<Option<T>> {
    match res {
        Ok(res) => Ok(Some(res)),
        Err(ref err) if err.kind() == io::ErrorKind::WouldBlock => Ok(None),
        Err(err) => Err(err)
    }
}
