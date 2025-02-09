use crate::{
    params::{Bip39WordCount, MAX_SUFFIX_LENGTH},
    run_error::RunError,
    utils::mnemonic_from_u256,
    vanity::Vanity,
};
use base64::{engine::general_purpose, Engine};
use bip39::Mnemonic;
use hdwallet::{secp256k1::Secp256k1, ChainPath, DefaultKeyChain, ExtendedPrivKey, KeyChain};
use primitive_types::U256;
use radix_common::prelude::{
    AddressBech32Encoder, ComponentAddress, NetworkDefinition, Secp256k1PublicKey,
};

pub(crate) const BASE_PATH: &str = "m/44'/1022'/0'/0";

pub struct HDWallet {
    intermediary_key_priv_hdwallet: ExtendedPrivKey,
    pub mnemonic_phrase: String,
    finger_print: String,
}

impl HDWallet {
    fn new(mnemonic: Mnemonic) -> Result<Self, RunError> {
        let seed_bytes = mnemonic.to_seed("");
        let seed_fingerprint = general_purpose::STANDARD_NO_PAD.encode(&seed_bytes[56..]);
        let key_chain =
            DefaultKeyChain::new(ExtendedPrivKey::with_seed(&seed_bytes).expect("master key"));

        let (intermediary_key_priv_hdwallet, _) = key_chain
            .derive_private_key(ChainPath::from(BASE_PATH))
            .expect("fetch key");

        Ok(Self {
            intermediary_key_priv_hdwallet,
            mnemonic_phrase: mnemonic.to_string(),
            finger_print: seed_fingerprint,
        })
    }

    #[allow(dead_code)] // used by integration tests
    pub fn from_mnemonic_phrase(mnemonic_phrase: &str) -> Result<Self, RunError> {
        let mnemonic =
            Mnemonic::parse(mnemonic_phrase).map_err(|_| RunError::MnemonicFromPhrase)?;
        Self::new(mnemonic)
    }

    pub fn from_entropy(entropy: U256) -> Result<Self, RunError> {
        let mnemonic = mnemonic_from_u256(&entropy, &Bip39WordCount::Twelve);
        Self::new(mnemonic)
    }
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

#[derive(Clone)]
pub struct ChildKey {
    pub index: u32,
    public_key_bytes: Vec<u8>,
    address: String,
    pub(crate) suffix: String,
}

fn address_from_public_key(slice: &[u8]) -> String {
    let re_secp256k1_pubkey = Secp256k1PublicKey::try_from(slice).expect("RE secp256k1 pubkey");
    let address_data = ComponentAddress::preallocated_account_from_public_key(&re_secp256k1_pubkey);
    let address_encoder = AddressBech32Encoder::new(&NetworkDefinition::mainnet());
    address_encoder
        .encode(&address_data.to_vec()[..])
        .expect("bech32 account address")
}

pub(crate) fn vanity_from_childkey(
    child_key: &ChildKey,
    target: &str,
    wallet: &HDWallet,
) -> Vanity {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entropy() {
        let wallet = HDWallet::from_entropy(U256::MAX);
        assert_eq!(
            wallet.unwrap().mnemonic_phrase,
            "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong"
        );
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
        assert_eq!(key0.index, 0);
        // https://github.com/radixdlt/babylon-wallet-ios/blob/40c7b8d671611ca7a8ba52e0b5e82044d9cebd68/RadixWalletTests/ProfileTests/TestVectors/ProfileVersion100/multi_profile_snapshots_test_version_100.json#L494
        assert_eq!(
            hex::encode(key0.public_key_bytes),
            "02f669a43024d90fde69351ccc53022c2f86708d9b3c42693640733c5778235da5"
        );

        let key1 = wallet.derive_child(1);
        assert_eq!(key1.index, 1);
        // https://github.com/radixdlt/babylon-wallet-ios/blob/40c7b8d671611ca7a8ba52e0b5e82044d9cebd68/RadixWalletTests/ProfileTests/TestVectors/ProfileVersion100/multi_profile_snapshots_test_version_100.json#L542
        assert_eq!(
            hex::encode(key1.public_key_bytes),
            "023a41f437972033fa83c3c4df08dc7d68212ccac07396a29aca971ad5ba3c27c8"
        );
    }
}
