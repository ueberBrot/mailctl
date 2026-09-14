use crate::domain::{Error, ErrorCode};
use std::path::{Path, PathBuf};
pub(super) struct NativeFile;
impl NativeFile {
    pub(super) fn create(_: &Path, _: &str) -> Result<Self, Error> {
        Err(Error::new(ErrorCode::UnsupportedCapability))
    }
    pub(super) fn write_bytes(&mut self, _: &[u8]) -> Result<(), Error> {
        Err(Error::new(ErrorCode::UnsupportedCapability))
    }
    pub(super) fn publish(&mut self) -> Result<(PathBuf, String), Error> {
        Err(Error::new(ErrorCode::UnsupportedCapability))
    }
    pub(super) fn abort(&mut self) -> Result<(), Error> {
        Ok(())
    }
}
