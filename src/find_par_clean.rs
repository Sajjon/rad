use crate::params::{Bip39WordCount, BruteForceInput, MAX_SUFFIX_LENGTH};
use crate::run_config::RunConfig;
use crate::utils::mnemonic_from_u256;
use crate::vanity::Vanity;
use std::collections::BTreeSet;
use std::fmt;
use std::ops::Range;
use std::sync::{Arc, Mutex};
use std::thread;

use ansi_escapes::EraseLines;
use base64::{engine::general_purpose, Engine as _};
use bip32::{ChildNumber, DerivationPath, Seed, XPrv};
use bip39::Mnemonic;
use primitive_types::U256;
use radix_engine_common::prelude::{
    AddressBech32Encoder, ComponentAddress, NetworkDefinition, Secp256k1PublicKey,
};
use std::ops::AddAssign;

use futures::channel::mpsc::channel;
use futures::channel::mpsc::Receiver;
use futures::stream::StreamExt;
use rayon::{
    prelude::{IntoParallelIterator, ParallelIterator},
    range::Iter,
};

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

struct Path {
    index: u32,
    derivation_path: DerivationPath,
}
impl Path {
    fn to_string(&self) -> String {
        self.derivation_path.to_string()
    }
    fn child(&self, index: u32) -> Self {
        Self {
            index,
            derivation_path: format!("{}/{}'", self.derivation_path.to_string(), index)
                .parse()
                .unwrap(),
        }
    }
}

struct HDWallet {
    entropy: U256,
    mnemonic: Mnemonic,
    seed: Seed,
    intermediary_key: ChildKey,
}

impl HDWallet {
    fn mnemonic_phrase(&self) -> String {
        self.mnemonic.to_string()
    }

    fn fingerprint(&self) -> String {
        general_purpose::STANDARD_NO_PAD.encode(&self.seed.as_bytes()[56..])
    }

    fn new(entropy: U256, mnemonic: Mnemonic) -> Result<Self, RunError> {
        let seed = Seed::new(mnemonic.to_seed("")); // bip32 create

        let intermediary_path_ = "m/44'/1022'/0'/0";
        let intermediary_path = intermediary_path_
            .parse()
            .map_err(|_| RunError::ParseDerivationPath)?;
        let key = XPrv::derive_from_path(&seed, &intermediary_path)
            .map_err(|_| RunError::DeriveChildKeyFromPath)?;
        let path = Path {
            index: 0,
            derivation_path: intermediary_path,
        };
        let intermediary_key = ChildKey { path, key };
        Ok(Self {
            entropy,
            mnemonic,
            seed,
            intermediary_key,
        })
    }

    fn from_mnemonic_phrase(mnemonic_phrase: &str) -> Result<Self, RunError> {
        // let mnemonic = Mnemonic::from(mnemonic_phrase);
        let mnemonic =
            Mnemonic::parse(mnemonic_phrase).map_err(|_| RunError::MnemonicFromPhrase)?;
        let entropy_bytes = mnemonic.to_entropy();
        let entropy = U256::from_big_endian(&entropy_bytes.as_slice());
        return Self::new(entropy, mnemonic);
    }

    fn from_entropy(entropy: U256) -> Result<Self, RunError> {
        let mnemonic = mnemonic_from_u256(&entropy, &Bip39WordCount::Twelve);
        return Self::new(entropy, mnemonic);
    }
}

struct ChildKey {
    path: Path,
    key: XPrv,
}

impl ChildKey {
    fn public_key(&self) -> Result<Secp256k1PublicKey, RunError> {
        let child_xpub = self.key.public_key();
        let verification_key = child_xpub.public_key();
        let public_key_point: k256::EncodedPoint = verification_key.to_encoded_point(true);
        let public_key_bytes = public_key_point.as_bytes();
        Secp256k1PublicKey::try_from(public_key_bytes).map_err(|_| RunError::PublicKeyFromBytes)
    }

    fn public_key_hex(&self) -> Result<String, RunError> {
        self.public_key().map(|pk| hex::encode(pk.to_vec()))
    }

    fn address(&self) -> Result<String, RunError> {
        let pubkey = self.public_key()?;
        let address_data = ComponentAddress::virtual_account_from_public_key(&pubkey);
        let address_encoder = AddressBech32Encoder::new(&NetworkDefinition::mainnet());
        address_encoder
            .encode(&address_data.to_vec()[..])
            .map_err(|_| RunError::AddressFromPublicKey)
    }

    fn address_suffix(&self) -> Result<String, RunError> {
        let address = self.address()?;
        let suffix = &address[address.len() - MAX_SUFFIX_LENGTH..];
        return Ok(suffix.to_string());
    }
}

impl HDWallet {
    fn derive_child(&self, index: u32) -> ChildKey {
        let path = self.intermediary_key.path.child(index);

        let key = XPrv::derive_from_path(&self.seed, &path.derivation_path).expect("hd key");

        return ChildKey { path, key };
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn entropy() {
        let wallet = HDWallet::from_entropy(U256::one());
        assert_eq!(wallet.unwrap().entropy, U256::one());
    }

    #[test]
    fn mnemonic() {
        let wallet = HDWallet::from_entropy(U256::zero());
        assert_eq!(wallet.unwrap().mnemonic_phrase(), "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about");
    }

    #[test]
    fn test_key() {
        let wallet = HDWallet::from_mnemonic_phrase(
            "gentle hawk winner rain embrace erosion call update photo frost fatal wrestle",
        )
        .unwrap();
        let key0 = wallet.derive_child(0);
        assert_eq!(key0.path.to_string(), "m/44'/1022'/0'/0/0'");
        // https://github.com/radixdlt/babylon-wallet-ios/blob/40c7b8d671611ca7a8ba52e0b5e82044d9cebd68/RadixWalletTests/ProfileTests/TestVectors/ProfileVersion100/multi_profile_snapshots_test_version_100.json#L494
        assert_eq!(
            key0.public_key_hex().unwrap(),
            "02f669a43024d90fde69351ccc53022c2f86708d9b3c42693640733c5778235da5"
        );
        let key1 = wallet.derive_child(1);
        assert_eq!(key1.path.to_string(), "m/44'/1022'/0'/0/1'");
        // https://github.com/radixdlt/babylon-wallet-ios/blob/40c7b8d671611ca7a8ba52e0b5e82044d9cebd68/RadixWalletTests/ProfileTests/TestVectors/ProfileVersion100/multi_profile_snapshots_test_version_100.json#L542
        assert_eq!(
            key1.public_key_hex().unwrap(),
            "023a41f437972033fa83c3c4df08dc7d68212ccac07396a29aca971ad5ba3c27c8"
        );
    }
}
