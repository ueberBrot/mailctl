use crate::credentials::{Secret, SourceError};
use rustix::{
    fs::{OFlags, fcntl_getfl, fcntl_setfl},
    termios::{LocalModes, OptionalActions, Termios, tcgetattr, tcsetattr},
};
use std::{
    fs::File,
    io::{IsTerminal, Read, Write},
    os::fd::AsFd,
    time::Duration,
};
use tokio::io::{Interest, unix::AsyncFd};
use zeroize::{Zeroize, Zeroizing};

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
    }
    struct Terminal {
        input: Input,
        output: File,
        previous: Option<Termios>,
        flags: OFlags,
        active: bool,
    }
    impl Drop for Terminal {
        fn drop(&mut self) {
            // Discard unread input, including an oversized secret, before the shell resumes.
            if self.active {
                if let Some(previous) = &self.previous {
                    let _ = tcsetattr(self.input.file(), OptionalActions::Flush, previous);
                }
                let mut output = &self.output;
                let _ = writeln!(output);
            }
            let _ = fcntl_setfl(self.input.file(), self.flags);
        }
    }
    impl Terminal {
        fn write_prompt(&self) -> std::io::Result<()> {
            let mut output = &self.output;
            output.write_all(b"Password: ")?;
            output.flush()
        }

        async fn read_byte(&self, byte: &mut [u8; 1]) -> std::io::Result<usize> {
            match &self.input {
                Input::Async(file) => loop {
                    let mut ready = file.readable().await?;
                    match ready.try_io(|file| {
                        let mut file = file.get_ref();
                        file.read(byte)
                    }) {
                        Ok(result) => return result,
                        Err(_) => continue,
                    }
                },
                Input::Poll(file) => loop {
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
    if !input.is_terminal() || !output.is_terminal() {
        return Err(SourceError::InteractionRequired);
    }
    let flags = fcntl_getfl(&input).map_err(|_| SourceError::InteractionRequired)?;
    fcntl_setfl(&input, flags | OFlags::NONBLOCK).map_err(|_| SourceError::InteractionRequired)?;
    let input = match AsyncFd::try_with_interest(input, Interest::READABLE) {
        Ok(file) => Input::Async(file),
        Err(error) => Input::Poll(error.into_parts().0),
    };
    let mut terminal = Terminal {
        input,
        output,
        previous: None,
        flags,
        active: false,
    };
    let previous =
        tcgetattr(terminal.input.file()).map_err(|_| SourceError::InteractionRequired)?;
    terminal.previous = Some(previous.clone());
    let mut quiet = previous.clone();
    quiet
        .local_modes
        .remove(LocalModes::ECHO | LocalModes::ECHONL | LocalModes::ICANON);
    tcsetattr(terminal.input.file(), OptionalActions::Flush, &quiet)
        .map_err(|_| SourceError::InteractionRequired)?;
    terminal.active = true;
    terminal
        .write_prompt()
        .map_err(|_| SourceError::Unavailable)?;
    let mut bytes = Zeroizing::new(Vec::<u8>::with_capacity(maximum + 1));
    loop {
        let mut byte = [0u8];
        let count = terminal
            .read_byte(&mut byte)
            .await
            .map_err(|_| SourceError::Unavailable)?;
        if count == 0 || byte[0] == b'\n' {
            break;
        }
        match byte[0] {
            b'\x08' | b'\x7f' => {
                if let Some(last) = bytes.last_mut() {
                    last.zeroize();
                    bytes.pop();
                }
            }
            b'\x15' => bytes.zeroize(),
            value => bytes.push(value),
        }
        byte.zeroize();
        if bytes.len() > maximum {
            return Err(SourceError::InvalidSecret);
        }
    }
    Secret::new(std::mem::take(&mut *bytes))
}
