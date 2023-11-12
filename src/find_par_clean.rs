use crate::params::{Bip39WordCount, BruteForceInput, MAX_SUFFIX_LENGTH};
use crate::utils::mnemonic_from_u256;
use crate::vanity::Vanity;
use std::collections::BTreeSet;
use std::ops::Range;
use std::thread;

use futures::channel::mpsc::channel;
use futures::channel::mpsc::Receiver;
use futures::stream::StreamExt;

use base64::{engine::general_purpose, Engine as _};
use bip32::{DerivationPath, Seed, XPrv};
use bip39::Mnemonic;
use primitive_types::U256;
use radix_engine_common::prelude::{
    AddressBech32Encoder, ComponentAddress, NetworkDefinition, Secp256k1PublicKey,
};

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

#[derive(Clone)]
pub struct HDWallet {
    pub entropy: U256,
    pub mnemonic: Mnemonic,
    pub intermediary_key: ChildKey,
}

impl HDWallet {
    pub fn seed(&self) -> Seed {
        Seed::new(self.mnemonic.to_seed("")) // bip32 create
    }
    pub fn mnemonic_phrase(&self) -> String {
        self.mnemonic.to_string()
    }

    pub fn fingerprint(&self) -> String {
        general_purpose::STANDARD_NO_PAD.encode(&self.seed().as_bytes()[56..])
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
            // seed,
            intermediary_key,
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
    pub path: Path,
    pub key: XPrv,
}

impl ChildKey {
    pub fn public_key(&self) -> Result<Secp256k1PublicKey, RunError> {
        let child_xpub = self.key.public_key();
        let verification_key = child_xpub.public_key();
        let public_key_point: k256::EncodedPoint = verification_key.to_encoded_point(true);
        let public_key_bytes = public_key_point.as_bytes();
        Secp256k1PublicKey::try_from(public_key_bytes).map_err(|_| RunError::PublicKeyFromBytes)
    }

    pub fn public_key_hex(&self) -> Result<String, RunError> {
        self.public_key().map(|pk| hex::encode(pk.to_vec()))
    }

    fn address_on_network(&self, network: &NetworkDefinition) -> Result<String, RunError> {
        let pubkey = self.public_key()?;
        let address_data = ComponentAddress::virtual_account_from_public_key(&pubkey);
        let address_encoder = AddressBech32Encoder::new(network);
        address_encoder
            .encode(&address_data.to_vec()[..])
            .map_err(|_| RunError::AddressFromPublicKey)
    }

    pub fn address(&self) -> Result<String, RunError> {
        self.address_on_network(&NetworkDefinition::mainnet())
    }

    pub fn address_suffix(&self) -> Result<String, RunError> {
        let address = self.address()?;
        let suffix = &address[address.len() - MAX_SUFFIX_LENGTH..];
        return Ok(suffix.to_string());
    }
}

impl HDWallet {
    fn derive_child(&self, index: u32) -> ChildKey {
        let path = self.intermediary_key.path.child(index);

        let key = XPrv::derive_from_path(&self.seed(), &path.derivation_path).expect("hd key");

        return ChildKey { path, key };
    }
}

pub fn find_par_in_range<F>(range: Range<u32>, wallet: Box<HDWallet>, map_op: F) -> Receiver<Vanity>
where
    F: Fn(ChildKey) -> Result<Option<Vanity>, ()> + Send + Sync + 'static,
{
    let (sender, receiver) = channel(1000);
    thread::spawn(move || {
        range
            .into_par_iter()
            .map(|i| wallet.derive_child(i))
            .flat_map(map_op)
            .try_for_each_with(sender, |s, x| match x {
                Some(v) => s.try_send(v),
                None => Ok(()),
            })
            .expect("No send error");
    });
    return receiver;
}

fn vanity_from_childkey(child_key: &ChildKey, target: &str, wallet: &HDWallet) -> Vanity {
    Vanity {
        target: target.to_string(),
        address: child_key.address().unwrap(),
        address_suffix: child_key.address_suffix().unwrap(),
        derivation_path: child_key.path.to_string(),
        index: child_key.path.index,
        public_key_bytes: child_key.public_key().unwrap().to_vec(),
        mnemonic: wallet.mnemonic_phrase(),
        bip39_seed_fingerprint: wallet.fingerprint(),
    }
}
pub fn find_par_with_wallet(wallet: Box<HDWallet>, targets: BTreeSet<String>) -> Receiver<Vanity> {
    find_par_in_range(0..u32::MAX, wallet.clone(), move |c| {
        if targets.is_empty() {
            return Err(());
        }
        let suff = c.address_suffix().unwrap();
        let mut vanity: Option<Vanity> = Option::None;
        for target in targets.iter() {
            if suff.ends_with(target.as_str()) {
                vanity = Some(vanity_from_childkey(&c, target, &wallet))
            } else {
                continue;
            }
        }
        return Ok(vanity);
    })
}

pub fn find_par_improved(input: BruteForceInput) -> Receiver<Vanity> {
    let wallet = HDWallet::from_entropy(input.int()).unwrap();
    let targets = input.targets;
    find_par_with_wallet(Box::new(wallet), targets)
}

#[cfg(test)]
mod tests {
    use futures::executor::block_on;

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

        assert_eq!(
            key0.address_on_network(&NetworkDefinition::zabanet())
                .unwrap(),
            "account_tdx_e_169s2cfz044euhc4yjg4xe4pg55w97rq2c6jh50zsdcpuz5gk6cag6v"
        );
        let key1 = wallet.derive_child(1);
        assert_eq!(key1.path.to_string(), "m/44'/1022'/0'/0/1'");
        // https://github.com/radixdlt/babylon-wallet-ios/blob/40c7b8d671611ca7a8ba52e0b5e82044d9cebd68/RadixWalletTests/ProfileTests/TestVectors/ProfileVersion100/multi_profile_snapshots_test_version_100.json#L542
        assert_eq!(
            key1.public_key_hex().unwrap(),
            "023a41f437972033fa83c3c4df08dc7d68212ccac07396a29aca971ad5ba3c27c8"
        );
        assert_eq!(
            key1.address_on_network(&NetworkDefinition::zabanet())
                .unwrap(),
            "account_tdx_e_16x88ghu9hd3hz4c9gumqjafrcwqtzk67wmpds7xg6uaz0kf42v5hju"
        );
    }

    #[test]
    fn find_vanity_suffix_9() {
        let wallet = HDWallet::from_mnemonic_phrase(
            "abandon abandon abandon top fire riot tonight attract gesture infant fringe vibrant",
        )
        .unwrap();

        let vanities: Vec<Vanity> = block_on(
            find_par_with_wallet(Box::new(wallet), BTreeSet::from(["9".to_string()]))
                .take(1)
                .collect::<Vec<Vanity>>(),
        );
        let vanity = vanities[0].clone();
        println!("✨ {}", vanity);

        assert_eq!(vanity.target, "9");

        /*
         fn one() {
        let result = _find_one(input_deterministic!("9"));
        assert_eq!(result.target, "9");
        assert_eq!(
            result.mnemonic,
            "abandon abandon abandon top fire riot tonight attract gesture infant fringe vibrant"
        );
        assert_eq!(
            result.address,
            "account_rdx16xx7xu4mel6nae8kphnfsnh2qp24j658huglyamy35u8djmfwxc0a9"
        );
        assert_eq!(result.bip39_seed_fingerprint, "g1E2tnS4bUc");
        assert_eq!(
            result.cap33_export_string_account_part(),
            "S^A7YA0KWtH020Y7skhc2IGszGSi+fp8ROHNKev7mtmkx5^12^g1E2tnS4bUc|9|12}"
        );
        assert_eq!(result.derivation_path, "m/44'/1022'/0'/0/12'");
        assert_eq!(
            result.public_key_hex(),
            "03b600d0a5ad1f4db463bb2485cd881accc64a2f9fa7c44e1cd29ebfb9ad9a4c79"
        );
        assert_eq!(
            result.cap33_export_string(),
            "1^0^12]S^A7YA0KWtH020Y7skhc2IGszGSi+fp8ROHNKev7mtmkx5^12^g1E2tnS4bUc|9|12}"
        );
        */
    }
}
