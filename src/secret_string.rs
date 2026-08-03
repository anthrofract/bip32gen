use std::{
    io::{self, BufRead as _},
    ops::Deref,
};

use anyhow::{Context, ensure};
use zeroize::{Zeroize, Zeroizing};

pub(crate) struct SecretString(Zeroizing<String>);

impl SecretString {
    const MAX_BYTES: usize = 8 * 1024;

    pub(crate) fn new() -> Self {
        Self(Zeroizing::new(String::with_capacity(Self::MAX_BYTES)))
    }

    pub(crate) fn push_str(&mut self, value: &str) -> anyhow::Result<()> {
        ensure!(
            value.len() <= Self::MAX_BYTES - self.0.len(),
            "secret string exceeds {} bytes",
            Self::MAX_BYTES
        );
        self.0.push_str(value);
        Ok(())
    }

    pub(crate) fn read_line() -> anyhow::Result<Self> {
        let mut line = Self::new();
        let stdin = io::stdin();
        let mut stdin = stdin.lock();

        loop {
            let buffer = stdin.fill_buf().context("failed to read standard input")?;
            ensure!(!buffer.is_empty(), "standard input closed before Enter");

            let newline = buffer.iter().position(|byte| *byte == b'\n');
            let end = newline.unwrap_or(buffer.len());
            let chunk = &buffer[..end];
            line.push_str(str::from_utf8(chunk).context("secret input is not valid UTF-8")?)?;

            stdin.consume(end + usize::from(newline.is_some()));
            if newline.is_some() {
                return Ok(line);
            }
        }
    }
}

impl Deref for SecretString {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        self.0.as_str()
    }
}

impl Zeroize for SecretString {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enforces_maximum_capacity() {
        let mut string = SecretString::new();
        string
            .push_str(&"x".repeat(SecretString::MAX_BYTES))
            .unwrap();

        assert!(string.push_str("x").is_err());
    }
}
