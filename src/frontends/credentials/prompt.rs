use crate::credentials::{Secret, SourceError};
use rustix::{
    fs::{OFlags, fcntl_getfl, fcntl_setfl},
    termios::{LocalModes, OptionalActions, SpecialCodeIndex, Termios, tcgetattr, tcsetattr},
};
use std::{
    fs::File,
    io::{IsTerminal, Read, Write},
    os::fd::AsFd,
    time::Duration,
};
use tokio::io::{Interest, unix::AsyncFd};
use zeroize::{Zeroize, Zeroizing};

pub(super) fn require_foreground_terminal(
    input: &(impl AsFd + IsTerminal),
    output: &impl IsTerminal,
) -> Result<(), SourceError> {
    if !input.is_terminal()
        || !output.is_terminal()
        || !rustix::termios::tcgetpgrp(input).is_ok_and(|group| group == rustix::process::getpgrp())
    {
        return Err(SourceError::InteractionRequired);
    }
    Ok(())
}

pub(super) async fn prompt(maximum: usize) -> Result<Secret, SourceError> {
    enum Input {
        Async(AsyncFd<File>),
        Poll(File),
    }
    impl Input {
        fn file(&self) -> &File {
            match self {
                Self::Async(file) => file.get_ref(),
                Self::Poll(file) => file,
            }
        }
        async fn read_byte(&self, byte: &mut [u8; 1]) -> std::io::Result<usize> {
            match self {
                Self::Async(file) => loop {
                    let mut ready = file.readable().await?;
                    match ready.try_io(|file| file.get_ref().read(byte)) {
                        Ok(result) => return result,
                        Err(_) => continue,
                    }
                },
                Self::Poll(file) => loop {
                    let mut file = file;
                    match file.read(byte) {
                        Ok(result) => return Ok(result),
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                            tokio::time::sleep(Duration::from_millis(10)).await;
                        }
                        Err(error) => return Err(error),
                    }
                },
            }
        }
    }
    struct Terminal {
        input: Input,
        output: File,
        previous: Termios,
        flags: OFlags,
        active: bool,
    }
    impl Drop for Terminal {
        fn drop(&mut self) {
            // Discard unread input, including an oversized secret, before the shell resumes.
            if self.active {
                let _ = tcsetattr(self.input.file(), OptionalActions::Flush, &self.previous);
                let _ = writeln!(self.output);
            }
            let _ = fcntl_setfl(self.input.file(), self.flags);
        }
    }

    let input = File::from(
        std::io::stdin()
            .as_fd()
            .try_clone_to_owned()
            .map_err(|_| SourceError::InteractionRequired)?,
    );
    let output = File::from(
        std::io::stderr()
            .as_fd()
            .try_clone_to_owned()
            .map_err(|_| SourceError::InteractionRequired)?,
    );
    require_foreground_terminal(&input, &output)?;
    let previous = tcgetattr(&input).map_err(|_| SourceError::InteractionRequired)?;
    let mut quiet = previous.clone();
    quiet
        .local_modes
        .remove(LocalModes::ECHO | LocalModes::ECHONL | LocalModes::ICANON);
    quiet.special_codes[SpecialCodeIndex::VMIN] = 1;
    quiet.special_codes[SpecialCodeIndex::VTIME] = 0;
    let flags = fcntl_getfl(&input).map_err(|_| SourceError::InteractionRequired)?;
    fcntl_setfl(&input, flags | OFlags::NONBLOCK).map_err(|_| SourceError::InteractionRequired)?;
    let input = match AsyncFd::try_with_interest(input, Interest::READABLE) {
        Ok(file) => Input::Async(file),
        Err(error) => Input::Poll(error.into_parts().0),
    };
    let mut terminal = Terminal {
        input,
        output,
        previous,
        flags,
        active: false,
    };
    tcsetattr(terminal.input.file(), OptionalActions::Flush, &quiet)
        .map_err(|_| SourceError::InteractionRequired)?;
    terminal.active = true;
    terminal
        .output
        .write_all(b"Password: ")
        .map_err(|_| SourceError::Unavailable)?;
    let mut bytes = Zeroizing::new(Vec::<u8>::with_capacity(maximum + 1));
    loop {
        let mut byte = Zeroizing::new([0u8]);
        let count = terminal
            .input
            .read_byte(&mut byte)
            .await
            .map_err(|_| SourceError::Unavailable)?;
        if count == 0 || byte[0] == b'\n' {
            break;
        }
        match byte[0] {
            b'\x08' | b'\x7f' => {
                // UTF-8 continuation bytes belong to the preceding character.
                let start = bytes
                    .iter()
                    .rposition(|byte| byte & 0xc0 != 0x80)
                    .unwrap_or(0);
                bytes[start..].zeroize();
                bytes.truncate(start);
            }
            b'\x15' => bytes.zeroize(),
            value => bytes.push(value),
        }
        if bytes.len() > maximum {
            return Err(SourceError::InvalidSecret);
        }
    }
    Secret::new(std::mem::take(&mut *bytes))
}
