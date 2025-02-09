use crate::params::{Bip39WordCount, MAX_SUFFIX_LENGTH};
use crate::run_error::RunError;
use crate::utils::mnemonic_from_u256;
use crate::vanity::Vanity;
use base64::engine::general_purpose;
use base64::Engine;
use bip39::Mnemonic;
use hdwallet::secp256k1::Secp256k1;
use hdwallet::{ChainPath, DefaultKeyChain, ExtendedPrivKey, KeyChain};
use primitive_types::U256;
use radix_common::prelude::{
    AddressBech32Encoder, ComponentAddress, NetworkDefinition, Secp256k1PublicKey,
};

pub struct HDWallet {
    pub entropy: U256,
    pub mnemonic: Mnemonic,
    pub intermediary_key_priv_hdwallet: ExtendedPrivKey,
    pub key_chain: DefaultKeyChain,
    pub mnemonic_phrase: String,
    pub finger_print: String,
}

pub const BASE_PATH: &str = "m/44'/1022'/0'/0";

impl HDWallet {
    fn new(entropy: U256, mnemonic: Mnemonic) -> Result<Self, RunError> {
        let seed_bytes = mnemonic.to_seed("");
        let seed_fingerprint = general_purpose::STANDARD_NO_PAD.encode(&seed_bytes[56..]);
        let key_chain =
            DefaultKeyChain::new(ExtendedPrivKey::with_seed(&seed_bytes).expect("master key"));

        let (intermediary_key_priv_hdwallet, _) = key_chain
            .derive_private_key(ChainPath::from(BASE_PATH))
            .expect("fetch key");

        Ok(Self {
            entropy,
            mnemonic: mnemonic.clone(),
            key_chain,
            intermediary_key_priv_hdwallet,
            mnemonic_phrase: mnemonic.to_string(),
            finger_print: seed_fingerprint,
        })
    }

    pub fn from_mnemonic_phrase(mnemonic_phrase: &str) -> Result<Self, RunError> {
        let mnemonic =
            Mnemonic::parse(mnemonic_phrase).map_err(|_| RunError::MnemonicFromPhrase)?;
        let entropy_bytes = mnemonic.to_entropy();
        let entropy = U256::from_big_endian(entropy_bytes.as_slice());
        Self::new(entropy, mnemonic)
    }

    pub fn from_entropy(entropy: U256) -> Result<Self, RunError> {
        let mnemonic = mnemonic_from_u256(&entropy, &Bip39WordCount::Twelve);
        Self::new(entropy, mnemonic)
    }
}

#[derive(Clone)]
pub struct ChildKey {
    pub index: u32,
    pub public_key_bytes: Vec<u8>,
    pub address: String,
    pub suffix: String,
}

fn address_from_public_key(slice: &[u8]) -> String {
    let re_secp256k1_pubkey = Secp256k1PublicKey::try_from(slice).expect("RE secp256k1 pubkey");
    let address_data = ComponentAddress::preallocated_account_from_public_key(&re_secp256k1_pubkey);
    let address_encoder = AddressBech32Encoder::new(&NetworkDefinition::mainnet());
    address_encoder
        .encode(&address_data.to_vec()[..])
        .expect("bech32 account address")
}

impl HDWallet {
    fn public_key(&self, index: u32) -> Vec<u8> {
        let s = Secp256k1::new();
        let key = self
            .intermediary_key_priv_hdwallet
            .derive_private_key(hdwallet::KeyIndex::hardened_from_normalize_index(index).unwrap())
            .unwrap();
        let pubkey = key.private_key.public_key(&s);
        pubkey.serialize().to_vec()
    }

    pub fn derive_child(&self, index: u32) -> ChildKey {
        let public_key_bytes = self.public_key(index);
        let address = address_from_public_key(&public_key_bytes);
        let suffix = address.clone()[address.len() - MAX_SUFFIX_LENGTH..].to_string();

        ChildKey {
            index,
            public_key_bytes,
            address,
            suffix,
        }
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
        bip39_seed_fingerprint: wallet.finger_print.clone(),
    }
}
