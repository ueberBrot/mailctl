//! Strict incremental transfer decoding owns carry, output limits, and integrity.
use crate::imap::{Error, Limits, fetch::MAX_CHUNK_BYTES};
use base64::{Engine, engine::general_purpose::STANDARD};
use sha2::{Digest, Sha256};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum TransferEncoding {
    Identity,
    Base64,
    QuotedPrintable,
}

pub(super) struct Decoder {
    encoding: TransferEncoding,
    pending: Vec<u8>,
    pending_offset: usize,
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
            pending_offset: 0,
            base64: Vec::new(),
            base64_padded: false,
            quoted_printable: Vec::new(),
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
        // Output pages advance a prefix without shifting the remaining bytes.
        // Reclaim that prefix once when another bounded wire slice arrives.
        self.compact_pending();
        match self.encoding {
            TransferEncoding::Identity => self.append(wire, limits),
            TransferEncoding::Base64 => {
                let mut offset = 0;
                while offset < wire.len() {
                    if self.base64.is_empty() && !self.base64_padded {
                        let consumed = self.base64_run(&wire[offset..], limits)?;
                        if consumed != 0 {
                            offset += consumed;
                            continue;
                        }
                    }
                    let byte = wire[offset];
                    offset += 1;
                    if byte.is_ascii_whitespace() {
                        continue;
                    }
                    if self.base64_padded
                        || !(byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/' | b'='))
                    {
                        return Err(Error::Protocol);
                    }
                    if self.retained_bytes() >= Self::state_limit(limits) {
                        return Err(Error::Limit);
                    }
                    self.base64.push(byte);
                    if self.base64.len() == 4 {
                        let mut decoded = [0; 3];
                        let length = STANDARD
                            .decode_slice(&self.base64, &mut decoded)
                            .map_err(|_| Error::Protocol)?;
                        self.append(&decoded[..length], limits)?;
                        self.base64_padded = length < 3;
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
        let bytes = if self.pending_len() <= max {
            // Compact only the final page and move its existing buffer, keeping
            // the complete-page allocation behavior of the original decoder.
            self.compact_pending();
            std::mem::take(&mut self.pending)
        } else {
            let end = self.pending_offset + max;
            let bytes = self.pending[self.pending_offset..end].to_vec();
            self.pending_offset = end;
            bytes
        };
        self.digest.update(&bytes);
        // append() has already checked this sum against the decoded byte ceiling.
        self.decoded_offset += bytes.len();
        bytes
    }

    pub(super) fn pending_len(&self) -> usize {
        self.pending.len() - self.pending_offset
    }

    fn compact_pending(&mut self) {
        if self.pending_offset != 0 {
            let remaining = self.pending_len();
            self.pending.copy_within(self.pending_offset.., 0);
            self.pending.truncate(remaining);
            self.pending_offset = 0;
        }
    }

    pub(super) fn decoded_offset(&self) -> usize {
        self.decoded_offset
    }

    pub(super) fn snapshot(&self) -> DecoderMetrics {
        DecoderMetrics {
            decoded_bytes: self.decoded_offset + self.pending_len(),
            decode_steps: self.decode_steps,
            max_state_bytes: self.max_state_bytes,
        }
    }

    pub(super) fn integrity(self) -> (u64, [u8; 32]) {
        (self.decoded_offset as u64, self.digest.finalize().into())
    }

    fn base64_run(&mut self, wire: &[u8], limits: &Limits) -> Result<usize, Error> {
        // Keep carry, padding, and non-alphabet octets on the strict quartet path.
        // Complete unpadded groups can share one decode and one output growth.
        let groups = wire
            .iter()
            .take_while(|&&byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/'))
            .count()
            / 4;
        let used = self
            .decoded_offset
            .checked_add(self.pending_len())
            .ok_or(Error::Limit)?;
        let available = limits
            .max_attachment_decoded_bytes
            .saturating_sub(used)
            .min(
                Self::state_limit(limits)
                    .saturating_sub(self.retained_bytes())
                    .saturating_sub(4),
            );
        // Reserving four carry octets preserves the scalar path's state ceiling,
        // including the quartet retained while its three decoded octets append.
        let groups = groups.min(available / 3);
        if groups < 2 {
            return Ok(0);
        }
        let decoded = groups * 3;
        let start = self.pending.len();
        self.pending.resize(start + decoded, 0);
        STANDARD
            .decode_slice(&wire[..groups * 4], &mut self.pending[start..])
            .map_err(|_| Error::Protocol)?;
        self.account_state();
        Ok(groups * 4)
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
        let mut whitespace = std::mem::take(&mut self.whitespace);
        for byte in whitespace.drain(..) {
            self.quoted_printable_octet(byte, limits)?;
        }
        self.whitespace = whitespace;
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
            .checked_add(self.pending_len())
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
        MAX_CHUNK_BYTES.saturating_add(limits.max_attachment_chunk_bytes)
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
}

fn hex(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod narrow_page_tests {
    use super::*;

    fn assert_decodes_in_pages(
        encoding: TransferEncoding,
        wire: &[u8],
        expected: &[u8],
        wire_bytes: usize,
        page: usize,
    ) {
        let limits = Limits {
            max_attachment_decoded_bytes: expected.len(),
            max_attachment_chunk_bytes: page,
            ..Limits::default()
        };
        let mut decoder = Decoder::new(encoding);
        let mut offset = 0;
        for chunk in wire.chunks(wire_bytes) {
            decoder.push(chunk, &limits).unwrap();
            while decoder.pending_len() >= page {
                let bytes = decoder.take_chunk(page);
                assert_eq!(bytes.len(), page);
                assert_eq!(bytes, expected[offset..offset + bytes.len()]);
                offset += bytes.len();
            }
        }
        decoder.finish(&limits).unwrap();
        while decoder.pending_len() != 0 {
            let bytes = decoder.take_chunk(page);
            assert_eq!(bytes, expected[offset..offset + bytes.len()]);
            offset += bytes.len();
        }
        assert_eq!(offset, expected.len());
        assert_eq!(decoder.snapshot().decode_steps, wire.len());
        assert_eq!(decoder.snapshot().decoded_bytes, expected.len());
        assert!(decoder.snapshot().max_state_bytes <= MAX_CHUNK_BYTES + page + 128);
        if encoding == TransferEncoding::Identity && MAX_CHUNK_BYTES.is_multiple_of(page) {
            assert!(decoder.snapshot().max_state_bytes <= MAX_CHUNK_BYTES + 128);
        }
        assert_eq!(
            decoder.integrity(),
            (
                expected.len() as u64,
                <[u8; 32]>::from(Sha256::digest(expected))
            )
        );
    }

    #[test]
    fn base64_runs_preserve_whitespace_carry_and_canonical_padding() {
        for size in [64, 65, 66, MAX_CHUNK_BYTES + 5] {
            let expected = (0..size)
                .map(|index| (index.wrapping_mul(31) as u8).wrapping_add(17))
                .collect::<Vec<_>>();
            let wire = STANDARD
                .encode(&expected)
                .into_bytes()
                .chunks(76)
                .collect::<Vec<_>>()
                .join(b" \t\r\n".as_slice());
            for wire_bytes in [1, 3, 7, 76, MAX_CHUNK_BYTES] {
                for page in [1, 7, 1_024] {
                    assert_decodes_in_pages(
                        TransferEncoding::Base64,
                        &wire,
                        &expected,
                        wire_bytes,
                        page,
                    );
                }
            }
        }
    }

    #[test]
    fn base64_runs_preserve_strict_tails_and_limit_error_precedence() {
        let prefix = STANDARD.encode([b'x'; 96]);
        for tail in ["Zh==", "Zm9=", "Zg=A", "A===", "abcd!AAA", "abcdAAAA="] {
            let wire = format!("{prefix}{tail}");
            for wire_bytes in [1, 3, 7, 76, MAX_CHUNK_BYTES] {
                let limits = Limits {
                    max_attachment_chunk_bytes: 7,
                    ..Limits::default()
                };
                let mut decoder = Decoder::new(TransferEncoding::Base64);
                let result = wire.as_bytes().chunks(wire_bytes).try_for_each(|chunk| {
                    decoder.push(chunk, &limits)?;
                    while decoder.pending_len() >= 7 {
                        decoder.take_chunk(7);
                    }
                    Ok(())
                });
                assert_eq!(
                    result.and_then(|()| decoder.finish(&limits)),
                    Err(Error::Protocol)
                );
            }
        }
        for (ceiling, expected) in [(93, Error::Limit), (96, Error::Protocol)] {
            let limits = Limits {
                max_attachment_decoded_bytes: ceiling,
                ..Limits::default()
            };
            let mut decoder = Decoder::new(TransferEncoding::Base64);
            assert_eq!(
                decoder.push(format!("{prefix}!").as_bytes(), &limits),
                Err(expected)
            );
        }
    }

    #[test]
    fn narrow_pages_and_later_wire_chunks_preserve_decoder_carry_and_limits() {
        let expected = (0..32 * 1_024 + 9)
            .map(|index| (index % 256) as u8)
            .collect::<Vec<_>>();
        for encoding in [
            TransferEncoding::Identity,
            TransferEncoding::Base64,
            TransferEncoding::QuotedPrintable,
        ] {
            let wire = match encoding {
                TransferEncoding::Identity => expected.clone(),
                TransferEncoding::Base64 => STANDARD.encode(&expected).into_bytes(),
                TransferEncoding::QuotedPrintable => expected
                    .chunks(24)
                    .map(|line| {
                        line.iter()
                            .map(|byte| format!("={byte:02X}"))
                            .collect::<String>()
                    })
                    .collect::<Vec<_>>()
                    .join("=\r\n")
                    .into_bytes(),
            };
            for page in [1, 7, 1_024, MAX_CHUNK_BYTES] {
                assert_decodes_in_pages(encoding, &wire, &expected, MAX_CHUNK_BYTES, page);
            }
        }
    }
}
