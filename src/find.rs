use crate::info::INFO_DONATION_ADDR_ONLY;
use crate::params::{BruteForceInput, MAX_SUFFIX_LENGTH};
use crate::run_config::RunConfig;
use crate::utils::mnemonic_from_u256;
use crate::vanity::Vanity;

use ansi_escapes::EraseLines;
use base64::{engine::general_purpose, Engine as _};
use bip32::{ChildNumber, Seed, XPrv};
use primitive_types::U256;
use radix_engine_common::prelude::{
    AddressBech32Encoder, ComponentAddress, NetworkDefinition, Secp256k1PublicKey,
};
use std::ops::AddAssign;

pub fn find<F>(input: BruteForceInput, run_config: RunConfig, mut on_result: F) -> ()
where
    F: FnMut(Vanity) -> bool,
{
    let find_multiple_accounts_per_target = input.find_multiple_accounts_per_target;
    let mut targets_left = input.targets.clone();
    let mut int = input.int();

    let mut attempts_since_last_find = U256::zero();
    println!("{}", input);
    let mut done = false;
    while !done {
        let mnemonic = mnemonic_from_u256(&int, &input.mnemonic_word_count);
        let mnemonic_phrase = mnemonic.to_string(); // bip39 crate (since it support 12 word mnemonics)
        let seed_ = mnemonic.to_seed(""); // bip39 crate (since it support 12 word mnemonics)
        let seed = Seed::new(seed_); // bip32 create
        let seed_fingerprint = general_purpose::STANDARD_NO_PAD.encode(&seed_[56..]);
        let intermediary_path_ = "m/44'/1022'/0'/0";
        let intermediary_path = intermediary_path_.parse().expect("intermediary path");
        let intermediary_xprv = XPrv::derive_from_path(&seed, &intermediary_path).expect("hd key");

        if input.index_end() > 100000 {
            // don't wanna print to often
            println!("🔮 Trying mnemonic: {}\n", mnemonic_phrase);
        }
        for index in 0u32..input.index_end() {
            if done {
                return;
            }
            // Radix Olympia BIP44-LIKE path (last component is incorrectly hardened.)
            let child_xprv = intermediary_xprv
                .derive_child(ChildNumber::new(index, true).unwrap())
                .expect("bip44 LIKE");
            let child_xpub = child_xprv.public_key();
            let verification_key = child_xpub.public_key();
            let public_key_point: k256::EncodedPoint = verification_key.to_encoded_point(true);
            let public_key_bytes = public_key_point.as_bytes();
            let re_secp256k1_pubkey =
                Secp256k1PublicKey::try_from(public_key_bytes).expect("RE secp256k1 pubkey");
            let address_data =
                ComponentAddress::virtual_account_from_public_key(&re_secp256k1_pubkey);
            let address_encoder = AddressBech32Encoder::new(&NetworkDefinition::mainnet());
            let address = address_encoder
                .encode(&address_data.to_vec()[..])
                .expect("bech32 account address");

            let suffix = &address[address.len() - MAX_SUFFIX_LENGTH..];

            let mut to_remove: Vec<String> = Vec::new();
            for target in &targets_left {
                // for target_index in 0..targets_left.len() {
                // let target = &targets_left[target_index];
                if suffix.ends_with(target) {
                    let result = Vanity {
                        target: target.clone(),
                        address: address.clone(),
                        derivation_path: format!("{}/{}'", intermediary_path_, index).to_string(),
                        index: index,
                        mnemonic: mnemonic_phrase.clone(),
                        public_key_bytes: Vec::from(public_key_bytes),
                        bip39_seed_fingerprint: seed_fingerprint.clone(),
                    };
                    attempts_since_last_find = U256::zero();
                    println!(
                        "{}\n{}{}\n{}",
                        "🎯".repeat(40),
                        result.to_string(),
                        INFO_DONATION_ADDR_ONLY.to_string(),
                        "🎯".repeat(40),
                    );
                    if !on_result(result) {
                        done = true;
                    }

                    if !find_multiple_accounts_per_target {
                        to_remove.push(target.clone());
                    }
                }
            }

            if !find_multiple_accounts_per_target {
                targets_left.retain(|t| !to_remove.contains(t));

                if targets_left.is_empty() {
                    done = true;
                    break;
                }
            }

            attempts_since_last_find.add_assign(U256::one());

            if !run_config.print_pulse.is_zero() {
                if attempts_since_last_find.clone() % run_config.print_pulse == U256::zero() {
                    print!("{}", EraseLines(2));
                    println!("⏳ Attempts since last find: {}", attempts_since_last_find);
                }
            }
        }
        int.add_assign(U256::one());
        int = int % input.max_int();
    }
}

pub fn find_all(input: BruteForceInput, run_config: RunConfig) -> () {
    find(input, run_config, |_| {
        return true; // continue
    });
}

pub fn find_n(n: usize, input: BruteForceInput, run_config: RunConfig) -> Vec<Vanity> {
    let mut results: Vec<Vanity> = Vec::new();

    find(input, run_config, |v| {
        results.push(v);
        if results.len() == n {
            return false;
        } else {
            return true;
        }
    });

    return results;
}
