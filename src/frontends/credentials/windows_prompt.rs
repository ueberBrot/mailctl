use crate::credentials::{Secret, SourceError};
use std::{
    fs::File,
    io::{IsTerminal, Write},
    mem::MaybeUninit,
    os::windows::io::{AsHandle, AsRawHandle},
    time::Duration,
};
use windows_sys::Win32::System::Console::*;
use zeroize::{Zeroize, Zeroizing};

pub(super) fn require_foreground_terminal(
    input: &impl IsTerminal,
    output: &impl IsTerminal,
) -> Result<(), SourceError> {
    if input.is_terminal() && output.is_terminal() {
        Ok(())
    } else {
        Err(SourceError::InteractionRequired)
    }
}

#[allow(
    unsafe_code,
    reason = "Console input modes and UTF-16 key events require Win32 FFI"
)]
mod console {
    use super::*;

    #[derive(Default)]
    struct InputRecord(INPUT_RECORD);
    impl Drop for InputRecord {
        fn drop(&mut self) {
            unsafe {
                std::slice::from_raw_parts_mut(
                    // The record's padding and unused union storage need not
                    // contain initialized bytes after a console read.
                    std::ptr::from_mut(&mut self.0).cast::<MaybeUninit<u8>>(),
                    size_of::<INPUT_RECORD>(),
                )
                .zeroize();
            }
        }
    }

    pub(super) struct Terminal {
        input: File,
        output: File,
        mode: u32,
    }
    impl Terminal {
        pub(super) fn open() -> Result<Self, SourceError> {
            require_foreground_terminal(&std::io::stdin(), &std::io::stderr())?;
            let input = File::from(
                std::io::stdin()
                    .as_handle()
                    .try_clone_to_owned()
                    .map_err(|_| SourceError::InteractionRequired)?,
            );
            let output = File::from(
                std::io::stderr()
                    .as_handle()
                    .try_clone_to_owned()
                    .map_err(|_| SourceError::InteractionRequired)?,
            );
            unsafe {
                let mut mode = 0;
                if GetConsoleMode(input.as_raw_handle(), &mut mode) == 0 {
                    return Err(SourceError::InteractionRequired);
                }
                let quiet = (mode | ENABLE_EXTENDED_FLAGS)
                    & !(ENABLE_ECHO_INPUT | ENABLE_LINE_INPUT | ENABLE_QUICK_EDIT_MODE);
                if SetConsoleMode(input.as_raw_handle(), quiet) == 0 {
                    return Err(SourceError::InteractionRequired);
                }
                let mut terminal = Self {
                    input,
                    output,
                    mode,
                };
                terminal
                    .output
                    .write_all(b"Password: ")
                    .map_err(|_| SourceError::Unavailable)?;
                Ok(terminal)
            }
        }
        pub(super) fn key(&self) -> Result<Option<(u16, u16)>, SourceError> {
            unsafe {
                let mut record = InputRecord::default();
                let mut count = 0;
                if PeekConsoleInputW(self.input.as_raw_handle(), &mut record.0, 1, &mut count) == 0
                {
                    return Err(SourceError::Unavailable);
                }
                if count == 0 {
                    return Ok(None);
                }
                if ReadConsoleInputW(self.input.as_raw_handle(), &mut record.0, 1, &mut count) == 0
                {
                    return Err(SourceError::Unavailable);
                }
                if count != 0 && record.0.EventType == KEY_EVENT as u16 {
                    let key = &record.0.Event.KeyEvent;
                    let value = Zeroizing::new(key.uChar.UnicodeChar);
                    return Ok(
                        (key.bKeyDown != 0 && *value != 0).then_some((*value, key.wRepeatCount))
                    );
                }
                Ok(None)
            }
        }
    }
    impl Drop for Terminal {
        fn drop(&mut self) {
            unsafe {
                FlushConsoleInputBuffer(self.input.as_raw_handle());
                SetConsoleMode(self.input.as_raw_handle(), self.mode);
            }
            let _ = writeln!(self.output);
        }
    }
}

pub(super) async fn prompt(maximum: usize) -> Result<Secret, SourceError> {
    let terminal = console::Terminal::open()?;
    let mut units = Zeroizing::new(Vec::<u16>::with_capacity(maximum + 1));
    loop {
        let Some((key, repeat)) = terminal.key()? else {
            tokio::time::sleep(Duration::from_millis(10)).await;
            continue;
        };
        let key = Zeroizing::new(key);
        if *key == 13 {
            let mut text = Zeroizing::new(String::with_capacity(units.len() * 3));
            for character in char::decode_utf16(units.iter().copied()) {
                text.push(character.map_err(|_| SourceError::InvalidSecret)?);
            }
            if text.len() > maximum {
                return Err(SourceError::InvalidSecret);
            }
            return Secret::new(std::mem::take(&mut *text).into_bytes());
        }
        for _ in 0..repeat {
            match *key {
                8 => {
                    let start = match units.as_slice() {
                        [.., 0xd800..=0xdbff, 0xdc00..=0xdfff] => units.len() - 2,
                        _ => units.len().saturating_sub(1),
                    };
                    units[start..].zeroize();
                    units.truncate(start);
                }
                21 => units.zeroize(),
                3 | 4 | 26 => return Err(SourceError::Unavailable),
                _ => units.push(*key),
            }
            if units.len() > maximum {
                return Err(SourceError::InvalidSecret);
            }
        }
    }
}
