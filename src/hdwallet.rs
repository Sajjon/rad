use crate::params::{Bip39WordCount, MAX_SUFFIX_LENGTH};
use crate::run_error::RunError;
use crate::utils::mnemonic_from_u256;
use crate::vanity::Vanity;
use base64::{engine::general_purpose, Engine as _};
use bip32::{ChildNumber, Seed, XPrv};
use bip39::Mnemonic;
use primitive_types::U256;
use radix_engine_common::prelude::{
    AddressBech32Encoder, ComponentAddress, NetworkDefinition, Secp256k1PublicKey,
};

pub struct HDWallet {
    pub entropy: U256,
    pub mnemonic: Mnemonic,
    pub intermediary_key_priv: XPrv,
    pub seed: Seed,
    pub mnemonic_phrase: String,
}

pub const BASE_PATH: &str = "m/44'/1022'/0'/0";

impl HDWallet {
    pub fn fingerprint(&self) -> String {
        general_purpose::STANDARD_NO_PAD.encode(&self.seed.as_bytes()[56..])
    }

    fn new(entropy: U256, mnemonic: Mnemonic) -> Result<Self, RunError> {
        let seed = Seed::new(mnemonic.to_seed("")); // bip32 create

        let intermediary_path = BASE_PATH
            .parse()
            .map_err(|_| RunError::ParseDerivationPath)?;

        let key = XPrv::derive_from_path(&seed, &intermediary_path)
            .map_err(|_| RunError::DeriveChildKeyFromPath)?;

        Ok(Self {
            entropy,
            mnemonic: mnemonic.clone(),
            seed,
            intermediary_key_priv: key,
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
    pub public_key_bytes: Vec<u8>,
    pub address: String,
    pub suffix: String,
}

fn address_from_public_key(slice: &[u8]) -> String {
    let re_secp256k1_pubkey = Secp256k1PublicKey::try_from(slice).expect("RE secp256k1 pubkey");
    let address_data = ComponentAddress::virtual_account_from_public_key(&re_secp256k1_pubkey);
    let address_encoder = AddressBech32Encoder::new(&NetworkDefinition::mainnet());
    address_encoder
        .encode(&address_data.to_vec()[..])
        .expect("bech32 account address")
}

impl HDWallet {
    fn public_key(&self, index: u32) -> Vec<u8> {
        let child_xprv = self
            .intermediary_key_priv
            .derive_child(ChildNumber::new(index, true).unwrap())
            .unwrap();

        let child_xpub = child_xprv.public_key();
        let verification_key = child_xpub.public_key();
        let public_key_point: k256::EncodedPoint = verification_key.to_encoded_point(true);
        public_key_point.as_bytes().to_vec()
    }

    pub fn derive_child(&self, index: u32) -> ChildKey {
        let public_key_bytes = self.public_key(index);
        let address = address_from_public_key(&public_key_bytes);
        let suffix = address.clone()[address.len() - MAX_SUFFIX_LENGTH..].to_string();

        return ChildKey {
            index,
            public_key_bytes,
            address,
            suffix,
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
