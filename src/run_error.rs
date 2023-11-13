use thiserror::Error;

#[derive(Debug, Error, PartialEq)]
pub enum RunError {
    #[error("Failed to parse a bip32 path from string")]
    ParseDerivationPath,

    #[error("Failed to derive a child key from a derivation path")]
    DeriveChildKeyFromPath,

    #[error("Failed to parse mnemonic from phrase")]
    MnemonicFromPhrase,

    #[error("Failed to parse PublicKey from bytes")]
    PublicKeyFromBytes,

    #[error("Failed to encode Address from PublicKey")]
    AddressFromPublicKey,

    #[error("Invalid target '{0}', contains forbidden character {1}.")]
    InvalidBech32Character(String, char),
}
