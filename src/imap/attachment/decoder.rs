//! Strict incremental transfer decoding owns carry, output limits, and integrity.
use crate::imap::{Error, Limits};
use sha2::{Digest, Sha256};

pub(super) const WIRE_SLICE_BYTES: usize = 16 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum TransferEncoding {
    Identity,
    Base64,
    QuotedPrintable,
}

pub(super) struct Decoder {
    encoding: TransferEncoding,
    pending: Vec<u8>,
    base64: Vec<u8>,
    base64_padded: bool,
    quoted_printable: Vec<u8>,
    whitespace: Vec<u8>,
    carriage_return: bool,
    decoded_offset: usize,
    decode_steps: usize,
    max_state_bytes: usize,
    digest: Sha256,
}

pub(super) struct DecoderMetrics {
    pub(super) decoded_bytes: usize,
    pub(super) decode_steps: usize,
    pub(super) max_state_bytes: usize,
}

impl Decoder {
    pub(super) fn new(encoding: TransferEncoding) -> Self {
        Self {
            encoding,
            pending: Vec::new(),
            base64: Vec::with_capacity(4),
            base64_padded: false,
            quoted_printable: Vec::with_capacity(2),
            whitespace: Vec::new(),
            carriage_return: false,
            decoded_offset: 0,
            decode_steps: 0,
            max_state_bytes: 0,
            digest: Sha256::new(),
        }
    }

    pub(super) fn push(&mut self, wire: &[u8], limits: &Limits) -> Result<(), Error> {
        self.decode_steps = self
            .decode_steps
            .checked_add(wire.len())
            .ok_or(Error::Limit)?;
        if self.decode_steps > limits.max_decode_steps {
            return Err(Error::Limit);
        }
        match self.encoding {
            TransferEncoding::Identity => self.append(wire, limits),
            TransferEncoding::Base64 => {
                for byte in wire.iter().copied() {
                    if byte.is_ascii_whitespace() {
                        continue;
                    }
                    if self.base64_padded || !(base64_value(byte).is_some() || byte == b'=') {
                        return Err(Error::Protocol);
                    }
                    if self.retained_bytes() >= Self::state_limit(limits) {
                        return Err(Error::Limit);
                    }
                    self.base64.push(byte);
                    if self.base64.len() == 4 {
                        let quartet: [u8; 4] = self
                            .base64
                            .as_slice()
                            .try_into()
                            .map_err(|_| Error::Protocol)?;
                        self.append_base64_quartet(quartet, limits)?;
                        self.base64_padded = quartet[2] == b'=' || quartet[3] == b'=';
                        self.base64.clear();
                    }
                    self.account_state();
                }
                Ok(())
            }
            TransferEncoding::QuotedPrintable => {
                for byte in wire.iter().copied() {
                    self.raw_quoted_printable(byte, limits)?;
                    self.account_state();
                }
                Ok(())
            }
        }
    }

    pub(super) fn finish(&mut self, limits: &Limits) -> Result<(), Error> {
        match self.encoding {
            TransferEncoding::Identity => Ok(()),
            TransferEncoding::Base64 if self.base64.is_empty() => Ok(()),
            TransferEncoding::QuotedPrintable => {
                if self.carriage_return {
                    // A lone CR is data, not a complete transport line ending.
                    self.flush_raw_prefix(limits)?;
                } else {
                    self.whitespace.clear();
                }
                if self.quoted_printable.is_empty() {
                    Ok(())
                } else {
                    Err(Error::Protocol)
                }
            }
            _ => Err(Error::Protocol),
        }
    }

    pub(super) fn take_chunk(&mut self, max: usize) -> Vec<u8> {
        let take = max.min(self.pending.len());
        let bytes: Vec<_> = self.pending.drain(..take).collect();
        self.digest.update(&bytes);
        // append() has already checked this sum against the decoded byte ceiling.
        self.decoded_offset += bytes.len();
        bytes
    }

    pub(super) fn pending_len(&self) -> usize {
        self.pending.len()
    }

    pub(super) fn decoded_offset(&self) -> usize {
        self.decoded_offset
    }

    pub(super) fn snapshot(&self) -> DecoderMetrics {
        DecoderMetrics {
            decoded_bytes: self.decoded_offset + self.pending.len(),
            decode_steps: self.decode_steps,
            max_state_bytes: self.max_state_bytes,
        }
    }

    pub(super) fn integrity(&self) -> (u64, [u8; 32]) {
        (
            self.decoded_offset as u64,
            self.digest.clone().finalize().into(),
        )
    }

    fn raw_quoted_printable(&mut self, byte: u8, limits: &Limits) -> Result<(), Error> {
        if self.carriage_return {
            if byte == b'\n' {
                self.whitespace.clear();
                self.carriage_return = false;
                self.quoted_printable_octet(b'\r', limits)?;
                return self.quoted_printable_octet(b'\n', limits);
            }
            self.flush_raw_prefix(limits)?;
        }
        match byte {
            b' ' | b'\t' => {
                // Raw SP/HT remains undecided until its physical line continues or ends.
                // Retained padding shares the finite output-state budget.
                if self.retained_bytes() >= Self::state_limit(limits) {
                    return Err(Error::Limit);
                }
                self.whitespace.push(byte);
                Ok(())
            }
            b'\r' => {
                if self.retained_bytes() >= Self::state_limit(limits) {
                    return Err(Error::Limit);
                }
                self.carriage_return = true;
                Ok(())
            }
            b'\n' => {
                self.whitespace.clear();
                self.quoted_printable_octet(b'\n', limits)
            }
            _ => {
                self.flush_raw_prefix(limits)?;
                self.quoted_printable_octet(byte, limits)
            }
        }
    }

    fn flush_raw_prefix(&mut self, limits: &Limits) -> Result<(), Error> {
        let whitespace = std::mem::take(&mut self.whitespace);
        for byte in whitespace {
            self.quoted_printable_octet(byte, limits)?;
        }
        if self.carriage_return {
            self.carriage_return = false;
            self.quoted_printable_octet(b'\r', limits)?;
        }
        Ok(())
    }

    fn quoted_printable_octet(&mut self, byte: u8, limits: &Limits) -> Result<(), Error> {
        if self.quoted_printable.is_empty() && byte != b'=' {
            return self.append(&[byte], limits);
        }
        if self.retained_bytes() >= Self::state_limit(limits) {
            return Err(Error::Limit);
        }
        self.quoted_printable.push(byte);
        if self.quoted_printable.len() == 3 {
            let first = self.quoted_printable[1];
            let second = self.quoted_printable[2];
            self.quoted_printable.clear();
            if first == b'\r' && second == b'\n' {
                // Physical-line padding was removed before interpreting this soft break.
            } else if let (Some(first), Some(second)) = (hex(first), hex(second)) {
                self.append(&[first << 4 | second], limits)?;
            } else {
                return Err(Error::Protocol);
            }
        }
        Ok(())
    }

    fn append(&mut self, bytes: &[u8], limits: &Limits) -> Result<(), Error> {
        let used = self
            .decoded_offset
            .checked_add(self.pending.len())
            .ok_or(Error::Limit)?;
        if bytes.len() > limits.max_attachment_decoded_bytes.saturating_sub(used)
            || bytes.len() > Self::state_limit(limits).saturating_sub(self.retained_bytes())
        {
            return Err(Error::Limit);
        }
        self.pending.extend_from_slice(bytes);
        self.account_state();
        Ok(())
    }

    fn state_limit(limits: &Limits) -> usize {
        WIRE_SLICE_BYTES.saturating_add(limits.max_attachment_chunk_bytes)
    }

    fn retained_bytes(&self) -> usize {
        self.pending
            .len()
            .saturating_add(self.base64.len())
            .saturating_add(self.quoted_printable.len())
            .saturating_add(self.whitespace.len())
            .saturating_add(usize::from(self.carriage_return))
    }

    fn account_state(&mut self) {
        self.max_state_bytes = self
            .max_state_bytes
            .max(self.retained_bytes().saturating_add(128));
    }

    fn append_base64_quartet(&mut self, quartet: [u8; 4], limits: &Limits) -> Result<(), Error> {
        let values = [
            base64_value(quartet[0]).ok_or(Error::Protocol)?,
            base64_value(quartet[1]).ok_or(Error::Protocol)?,
        ];
        let mut decoded = [0; 3];
        decoded[0] = (values[0] << 2) | (values[1] >> 4);
        let length = match (quartet[2], quartet[3]) {
            (b'=', b'=') if values[1] & 0b1111 == 0 => 1,
            (third, b'=') => {
                let third = base64_value(third).ok_or(Error::Protocol)?;
                if third & 0b11 != 0 {
                    return Err(Error::Protocol);
                }
                decoded[1] = (values[1] << 4) | (third >> 2);
                2
            }
            (third, fourth) => {
                let third = base64_value(third).ok_or(Error::Protocol)?;
                let fourth = base64_value(fourth).ok_or(Error::Protocol)?;
                decoded[1] = (values[1] << 4) | (third >> 2);
                decoded[2] = (third << 6) | fourth;
                3
            }
        };
        self.append(&decoded[..length], limits)
    }
}

fn base64_value(byte: u8) -> Option<u8> {
    match byte {
        b'A'..=b'Z' => Some(byte - b'A'),
        b'a'..=b'z' => Some(byte - b'a' + 26),
        b'0'..=b'9' => Some(byte - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

fn hex(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}
