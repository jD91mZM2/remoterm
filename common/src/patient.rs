use super::maybe;

use std::{ops, io::{self, prelude::*}};

pub struct PatientWriter<W: Write> {
    todo: Vec<u8>,
    writer: W
}
impl<W: Write> PatientWriter<W> {
    pub fn new(writer: W) -> Self {
        Self {
            todo: Vec::with_capacity(1024),
            writer
        }
    }

    pub fn write_todo(&mut self) -> io::Result<bool> {
        let mut written = 0;
        while written < self.todo.len() {
            match maybe(self.writer.write(&self.todo[written..]))? {
                Some(0) | None => break,
                Some(n) => written += n
            }
        }
        self.todo.drain(..written);
        Ok(written > 0)
    }
}
impl<W: Write> Write for PatientWriter<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        // Ensure everything is in the right order: Try todo first.
        self.write_todo()?;

        let mut written = 0;
        while written < buf.len() {
            match maybe(self.writer.write(&buf[written..]))? {
                Some(0) | None => break,
                Some(n) => written += n
            }
        }

        self.todo.extend_from_slice(&buf[written..]);
        Ok(buf.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        self.writer.flush()
    }
}
impl<W: Write> ops::Deref for PatientWriter<W> {
    type Target = W;

    fn deref(&self) -> &Self::Target {
        &self.writer
    }
}
impl<W: Write> ops::DerefMut for PatientWriter<W> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.writer
    }
}
