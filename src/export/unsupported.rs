use crate::domain::{Error, ErrorCode};
use std::path::{Path, PathBuf};
pub(super) struct NativeFile;
impl NativeFile {
    pub(super) fn create(_: &Path, _: &str) -> Result<Self, Error> {
        Err(Error::new(ErrorCode::UnsupportedCapability))
    }
    #[allow(
        clippy::unused_self,
        reason = "Matches the stateful native export interface"
    )]
    pub(super) fn write_bytes(&mut self, _: &[u8]) -> Result<(), Error> {
        Err(Error::new(ErrorCode::UnsupportedCapability))
    }
    #[allow(
        clippy::unused_self,
        reason = "Matches the stateful native export interface"
    )]
    pub(super) fn publish(&mut self) -> Result<(PathBuf, String), Error> {
        Err(Error::new(ErrorCode::UnsupportedCapability))
    }
    #[allow(
        clippy::unused_self,
        clippy::unnecessary_wraps,
        reason = "Matches the stateful, fallible native export cleanup interface"
    )]
    pub(super) fn abort(&mut self) -> Result<(), Error> {
        Ok(())
    }
}
