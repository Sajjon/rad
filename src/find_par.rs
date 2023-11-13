use crate::info::INFO_DONATION_ADDR_ONLY;
use crate::params::{validating_split, Bip39WordCount, BruteForceInput, MAX_SUFFIX_LENGTH};
use crate::run_config::RunConfig;
use crate::utils::mnemonic_from_u256;
use crate::vanity::Vanity;
use base64::{engine::general_purpose, Engine as _};
use bip32::{ChildNumber, DerivationPath, Seed, XPrv};
use bip39::Mnemonic;
use primitive_types::U256;
use radix_engine_common::prelude::{
    AddressBech32Encoder, ComponentAddress, HashSet, NetworkDefinition, Secp256k1PublicKey,
};
use std::ops::Range;
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

use rayon::prelude::{IntoParallelIterator, ParallelIterator};
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

#[derive(Clone)]
pub struct Path {
    pub index: u32,
    pub derivation_path: DerivationPath,
}
impl Path {
    pub fn to_string(&self) -> String {
        self.derivation_path.to_string()
    }
    pub fn child(&self, index: u32) -> Self {
        Self {
            index,
            derivation_path: format!("{}/{}'", self.derivation_path.to_string(), index)
                .parse()
                .unwrap(),
        }
    }
}

pub struct HDWallet {
    pub entropy: U256,
    pub mnemonic: Mnemonic,
    pub intermediary_key_priv: XPrv,
    pub intermediary_key_path: Path,
    pub seed: Seed,
    pub mnemonic_phrase: String,
}

impl HDWallet {
    pub fn fingerprint(&self) -> String {
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
        // let intermediary_key = ChildKey { path, key };
        Ok(Self {
            entropy,
            mnemonic: mnemonic.clone(),
            seed,
            intermediary_key_priv: key,
            intermediary_key_path: path,
            mnemonic_phrase: mnemonic.to_string(),
        })
    }

    pub fn from_mnemonic_phrase(mnemonic_phrase: &str) -> Result<Self, RunError> {
        // let mnemonic = Mnemonic::from(mnemonic_phrase);
        let mnemonic =
            Mnemonic::parse(mnemonic_phrase).map_err(|_| RunError::MnemonicFromPhrase)?;
        let entropy_bytes = mnemonic.to_entropy();
        let entropy = U256::from_big_endian(&entropy_bytes.as_slice());
        return Self::new(entropy, mnemonic);
    }

    pub fn from_entropy(entropy: U256) -> Result<Self, RunError> {
        let mnemonic = mnemonic_from_u256(&entropy, &Bip39WordCount::Twelve);
        return Self::new(entropy, mnemonic);
    }
}

#[derive(Clone)]
pub struct ChildKey {
    pub index: u32,
    pub key: XPrv,
    pub public_key_bytes: Vec<u8>,
    pub address: String,
    pub suffix: String,
}

impl HDWallet {
    pub fn derive_child(&self, index: u32) -> ChildKey {
        // let path = self.intermediary_key_path.child(index);

        let child_xprv = self
            .intermediary_key_priv
            .derive_child(ChildNumber::new(index, true).unwrap())
            .unwrap();

        let child_xpub = child_xprv.public_key();
        let verification_key = child_xpub.public_key();
        let public_key_point: k256::EncodedPoint = verification_key.to_encoded_point(true);
        let public_key_bytes = public_key_point.as_bytes();
        let re_secp256k1_pubkey =
            Secp256k1PublicKey::try_from(public_key_bytes).expect("RE secp256k1 pubkey");
        let address_data = ComponentAddress::virtual_account_from_public_key(&re_secp256k1_pubkey);
        let address_encoder = AddressBech32Encoder::new(&NetworkDefinition::mainnet());
        let address = address_encoder
            .encode(&address_data.to_vec()[..])
            .expect("bech32 account address");

        let suffix = &address[address.len() - MAX_SUFFIX_LENGTH..];

        return ChildKey {
            index,
            key: child_xprv,
            public_key_bytes: re_secp256k1_pubkey.to_vec().clone(),
            address: address.clone(),
            suffix: suffix.to_string(),
        };
    }
}

pub fn vanity_from_childkey(child_key: &ChildKey, target: &str, wallet: &HDWallet) -> Vanity {
    Vanity {
        target: target.to_string(),
        address: child_key.address.clone(),
        address_suffix: child_key.suffix.clone(),
        index: child_key.index,
        public_key_bytes: child_key.public_key_bytes.clone(),
        mnemonic: wallet.mnemonic_phrase.clone(),
        bip39_seed_fingerprint: wallet.fingerprint(),
    }
}

fn par_do_do_find<E, F>(
    range: Range<u32>,
    wallet: &Box<HDWallet>,
    check_stop: E,
    on_childkey: F,
) -> Vec<Vanity>
where
    E: Fn() -> bool + Send + Sync,
    F: Fn(ChildKey) -> Option<Vanity> + Send + Sync,
{
    range
        .into_par_iter()
        .map(|i| {
            if check_stop() {
                None
            } else {
                Some(wallet.derive_child(i))
            }
        })
        .while_some()
        .map(|c| on_childkey(c))
        .filter_map(|x| x)
        .collect()
}

fn par_do_find(
    run_config: RunConfig,
    wallet: Box<HDWallet>,
    end_index: u32,
    targets: Arc<Mutex<HashSet<String>>>,
) -> Vec<Vanity> {
    par_do_do_find(
        0..end_index,
        &wallet,
        || targets.lock().unwrap().is_empty(),
        |c| {
            let suff = c.suffix.clone();

            let mut result: Option<Vanity> = Option::None;
            let mut trgts = targets.lock().unwrap();
            for target in trgts.iter() {
                if suff.ends_with(target) {
                    let vanity = vanity_from_childkey(&c, target, &wallet);
                    if run_config.print_found_vanity_result {
                        // println!(
                        //     "{}\n{}{}\n{}",
                        //     "🎯".repeat(40),
                        //     vanity.to_string(),
                        //     INFO_DONATION_ADDR_ONLY.to_string(),
                        //     "🎯".repeat(40),
                        // );
                        println!("{}", vanity.to_string());
                    }

                    result = Some(vanity);

                    break;
                } else {
                    continue;
                }
            }
            if let Some(v) = &result {
                (*trgts).remove(&v.target);
            }
            return result;
        },
    )
}

fn __par_find(
    run_config: RunConfig,
    wallet: Box<HDWallet>,
    end_index: u32,
    targets_: HashSet<String>,
) -> Vec<Vanity> {
    let targets = Arc::new(Mutex::new(targets_.clone()));
    let now = SystemTime::now();

    let mut vector = par_do_find(run_config.clone(), wallet, end_index, targets);

    let time_elapsed = now.elapsed().unwrap();
    // let end_index_f32 = end_index as f32;
    vector.sort_by(|l, r| l.index.cmp(&r.index));
    if run_config.print_input {
        let highest_index = vector.first().unwrap().index;
        let highest_index_f32 = highest_index as f32;
        let speed = highest_index_f32 / time_elapsed.as_secs_f32();
        println!(
            "✅ ⚡️ Exiting program, ran for '{}' ms, speed: '#{}' iters per second.",
            time_elapsed.as_millis(),
            speed
        );
    }
    return vector;
}
fn _par_find(
    run_config: RunConfig,
    wallet: Box<HDWallet>,
    end_index: u32,
    targets_csv: &str,
) -> Vec<Vanity> {
    let targets_: std::collections::HashSet<String> = validating_split(targets_csv).unwrap();
    __par_find(run_config, wallet, end_index, targets_)
}

pub fn par_find(input: BruteForceInput, run_config: RunConfig) -> Vec<Vanity> {
    if run_config.print_input {
        println!("{}", input);
    }
    let wallet = HDWallet::from_entropy(input.int()).unwrap();
    __par_find(
        run_config,
        Box::new(wallet),
        input.index_end(),
        input.targets,
    )
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
        assert_eq!(wallet.unwrap().mnemonic_phrase, "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about");
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
            hex::encode(key0.public_key_bytes),
            "02f669a43024d90fde69351ccc53022c2f86708d9b3c42693640733c5778235da5"
        );

        let key1 = wallet.derive_child(1);
        assert_eq!(key1.path.to_string(), "m/44'/1022'/0'/0/1'");
        // https://github.com/radixdlt/babylon-wallet-ios/blob/40c7b8d671611ca7a8ba52e0b5e82044d9cebd68/RadixWalletTests/ProfileTests/TestVectors/ProfileVersion100/multi_profile_snapshots_test_version_100.json#L542
        assert_eq!(
            hex::encode(key1.public_key_bytes),
            "023a41f437972033fa83c3c4df08dc7d68212ccac07396a29aca971ad5ba3c27c8"
        );
    }

    #[test]
    fn find_vanity_suffix_xx_yy() {
        let wallet = HDWallet::from_mnemonic_phrase(
            "abandon abandon abandon top fire riot tonight attract gesture infant fringe vibrant",
        )
        .unwrap();

        let run_config = RunConfig::new(false, 0, false, false);
        let vanities = _par_find(run_config, Box::new(wallet), 5000u32, "xx,yy");

        assert_eq!(
            vanities
                .into_iter()
                .map(|v| v.target)
                .collect::<HashSet<String>>(),
            HashSet::from(["xx", "yy"].map(|x| x.to_string()))
        );
    }
}
