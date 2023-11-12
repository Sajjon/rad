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

    #[error("Invalid target '{0}', contains forbidden character {1}.")]
    InvalidBech32Character(String, char),
}

struct Path {
    index: u32,
    derivation_path: DerivationPath,
}
impl Path {
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

    fn new(entropy: U256) -> Result<Self, RunError> {
        let mnemonic = mnemonic_from_u256(&entropy, &Bip39WordCount::Twelve);
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
}

struct ChildKey {
    path: Path,
    key: XPrv,
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
        let wallet = HDWallet::new(U256::one());
        assert_eq!(wallet.unwrap().entropy, U256::one());
    }

    #[test]
    fn mnemonic() {
        let wallet = HDWallet::new(U256::zero());
        assert_eq!(wallet.unwrap().mnemonic_phrase(), "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about");
    }
}
