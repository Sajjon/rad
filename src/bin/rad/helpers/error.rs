use rad::error::TargetSuffixError;
use thiserror::Error as ThisError;

#[derive(ThisError, Debug)]
pub enum Error {
    #[error("Failed to parse input: {:?}", .0)]
    ParseInput(TargetSuffixError),
}

pub type Result<T, E = Error> = std::result::Result<T, E>;
