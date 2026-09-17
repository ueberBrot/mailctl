use crate::domain::{AttachmentChunk, AttachmentProgress, Error, ErrorCode};
use base64::{Engine, engine::general_purpose::STANDARD};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
#[cfg(target_os = "macos")]
#[path = "export/macos.rs"]
mod native;
#[cfg(not(target_os = "macos"))]
#[path = "export/unsupported.rs"]
mod native;
use native::NativeFile;

pub struct ExportWriter {
    file: NativeFile,
    active: bool,
    maximum: usize,
    written: u64,
    digest: Sha256,
    reference: Option<String>,
    buffer: Vec<u8>,
}

impl ExportWriter {
    pub fn create(
        approved: &[PathBuf],
        root: &Path,
        name: &str,
        maximum: usize,
    ) -> Result<Self, Error> {
        if !approved.iter().any(|allowed| allowed == root) {
            return Err(Error::new(ErrorCode::PermissionDenied));
        }
        if !safe_name(name) || maximum == 0 || base64::encoded_len(maximum, true).is_none() {
            return Err(Error::new(ErrorCode::InvalidRequest));
        }
        Ok(Self {
            file: NativeFile::create(root, name)?,
            active: true,
            maximum,
            written: 0,
            digest: Sha256::new(),
            reference: None,
            buffer: Vec::new(),
        })
    }

    pub fn write_chunk(
        &mut self,
        chunk: &AttachmentChunk,
    ) -> Result<Option<crate::domain::ExportReceipt>, Error> {
        self.write(chunk).or_else(|error| {
            self.abort()?;
            Err(error)
        })
    }

    fn write(
        &mut self,
        chunk: &AttachmentChunk,
    ) -> Result<Option<crate::domain::ExportReceipt>, Error> {
        if !self.active
            || chunk.decoded_offset != self.written
            || self
                .reference
                .as_ref()
                .is_some_and(|reference| reference != &chunk.attachment_reference)
            || chunk.bytes_base64.len() > self.maximum.div_ceil(3) * 4
        {
            return Err(failed());
        }
        self.buffer.clear();
        STANDARD
            .decode_vec(&chunk.bytes_base64, &mut self.buffer)
            .map_err(|_| failed())?;
        let total = self
            .written
            .checked_add(self.buffer.len() as u64)
            .ok_or_else(failed)?;
        if total > self.maximum as u64 {
            return Err(Error::new(ErrorCode::AttachmentTooLarge));
        }
        if self.buffer.is_empty() && matches!(chunk.progress, AttachmentProgress::Continue { .. }) {
            return Err(failed());
        }
        self.file.write_bytes(&self.buffer)?;
        self.digest.update(&self.buffer);
        self.written = total;
        self.reference
            .get_or_insert_with(|| chunk.attachment_reference.clone());
        match &chunk.progress {
            AttachmentProgress::Continue { .. } => Ok(None),
            AttachmentProgress::Complete {
                total_decoded_bytes,
                sha256,
            } => {
                let actual =
                    crate::encoding::hex(std::mem::take(&mut self.digest).finalize().as_slice());
                if *total_decoded_bytes != total || *sha256 != actual {
                    return Err(failed());
                }
                let (path, filesystem) = self.file.publish()?;
                self.active = false;
                Ok(Some(crate::domain::ExportReceipt {
                    path,
                    filesystem,
                    total_decoded_bytes: total,
                    sha256: actual,
                }))
            }
        }
    }

    pub fn abort(&mut self) -> Result<(), Error> {
        self.active = false;
        self.file.abort()
    }
}

fn safe_name(name: &str) -> bool {
    let valid = !name.is_empty()
        && name.len() <= 200
        && !name.starts_with('.')
        && !name.ends_with(['.', ' '])
        && name
            .chars()
            .all(|c| c.is_alphanumeric() || matches!(c, '.' | '-' | '_' | ' '));
    if !valid {
        return false;
    }
    let stem = name.split('.').next().unwrap_or("");
    !["CON", "PRN", "AUX", "NUL"]
        .iter()
        .any(|reserved| stem.eq_ignore_ascii_case(reserved))
        && !(stem.len() == 4
            && stem.get(..3).is_some_and(|prefix| {
                prefix.eq_ignore_ascii_case("COM") || prefix.eq_ignore_ascii_case("LPT")
            })
            && stem.as_bytes()[3].is_ascii_digit())
}
fn failed() -> Error {
    Error::new(ErrorCode::ExportFailed)
}
#[cfg(target_os = "macos")]
fn cleanup_failed() -> Error {
    Error::new(ErrorCode::ExportCleanupFailed)
}
