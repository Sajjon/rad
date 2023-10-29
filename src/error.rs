use thiserror::Error;
#[derive(Debug, Error, PartialEq)]
pub enum TargetSuffixError {
    #[error("Targets string must not be empty")]
    TargetsStringMustNotBeEmpty,

    #[error("Target Suffix cannot be empty")]
    TargetSuffixMustNotBeEmpty,

    #[error("Invalid target '{0}', contains forbidden character {1}.")]
    InvalidBech32Character(String, char),

    #[error("Invalid target '{0}', must be at most 6 chars long, was: {1}")]
    TooLongTargetSuffix(String, usize),
}
