use crate::info::INFO_DONATION_ADDR_ONLY;
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
use bip32::{ChildNumber, ExtendedPrivateKey, Seed, XPrv};
use k256::ecdsa::SigningKey;
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

#[derive(Debug)]
struct NeedleInput {
    outer: U256,
    inner: u32,
    intermediary_xprv: XPrv,
    mnemonic_phrase: String,
    seed_fingerprint: String,
}

impl std::fmt::Display for NeedleInput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "outer: {}, inner: {}",
            self.outer.to_string(),
            self.inner
        )
    }
}

impl NeedleInput {
    fn new(
        outer: U256,
        inner: u32,
        intermediary_xprv: XPrv,
        mnemonic_phrase: String,
        seed_fingerprint: String,
    ) -> Self {
        Self {
            outer,
            inner,
            intermediary_xprv,
            mnemonic_phrase,
            seed_fingerprint,
        }
    }
}

// Custom error type; can be any type which defined in the current crate
// 💡 In here, we use a simple "unit struct" to simplify the example
struct MyError;

// Implement std::fmt::Display for MyError
impl fmt::Display for MyError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "An Error Occurred, Please Try Again!") // user-facing output
    }
}

// Implement std::fmt::Debug for MyError
impl fmt::Debug for MyError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{{ file: {}, line: {} }}", file!(), line!()) // programmer-facing output
    }
}

fn __find<F, G, H, D, T>(
    draining: BTreeSet<D>,
    mut outer: impl Iterator<Item = U256> + Send + 'static,
    inner: Iter<u32>,
    make_candidate: F,
    eval_candidate: G,
    drain_with_candidate: H,
) -> Receiver<T>
where
    F: Fn(&NeedleInput, D) -> T + Send + Sync + Copy + 'static,
    G: Fn(&T) -> bool + Send + Sync + 'static,
    H: Fn(&T) -> D + Send + Sync + 'static,
    D: std::fmt::Debug + Ord + Clone + Send + Sync + 'static,
    T: std::fmt::Debug + Send + 'static,
{
    let (tx, rx) = channel(1000);

    thread::spawn(move || {
        let to_drain_mutex = Arc::new(Mutex::new(draining));
        outer.try_for_each(|o| {
            println!("🔮 outer: {}", o);
            let mnemonic = mnemonic_from_u256(&o, &Bip39WordCount::Twelve);
            let mnemonic_phrase = mnemonic.to_string(); // bip39 crate (since it support 12 word mnemonics)
            let seed_ = mnemonic.to_seed(""); // bip39 crate (since it support 12 word mnemonics)
            let seed = Seed::new(seed_); // bip32 create
            let seed_fingerprint = general_purpose::STANDARD_NO_PAD.encode(&seed_[56..]);
            let intermediary_path_ = "m/44'/1022'/0'/0";
            let intermediary_path = intermediary_path_.parse().expect("intermediary path");
            let intermediary_xprv =
                XPrv::derive_from_path(&seed, &intermediary_path).expect("hd key");

            inner
                .clone()
                .flat_map(|i| {
                    // println!("Inner ✨ {:?}", i);
                    let ni = NeedleInput::new(
                        o.clone(),
                        i.clone(),
                        intermediary_xprv.clone(),
                        mnemonic_phrase.clone(),
                        seed_fingerprint.clone(),
                    );
                    let candidates: Vec<T> = to_drain_mutex
                        .clone()
                        .lock()
                        .unwrap()
                        .clone()
                        .into_iter()
                        .map(|d| make_candidate(&ni, d))
                        .collect();
                    return candidates;
                })
                .filter(|c| eval_candidate(c))
                .try_for_each_with(tx.clone(), |s, x| {
                    let d = drain_with_candidate(&x);
                    println!("Draining 🌱 {:?}", &x);
                    return s.try_send(x).map_err(|_| MyError).and_then(|_| {
                        let mut to_drain = to_drain_mutex.lock().unwrap();
                        to_drain.remove(&d);
                        if to_drain.is_empty() {
                            Err(MyError)
                        } else {
                            Ok(())
                        }
                    });
                })
        })
    });
    return rx;
}

fn _find(draining: BTreeSet<String>, outer_start: U256, inner: Range<u32>) -> Receiver<Vanity> {
    __find(
        draining,
        num_iter::range_step_from(outer_start, U256::from(1)),
        inner.into_par_iter(), // <-- PARALLELIZATION
        |ni, target| {
            // Radix Olympia BIP44-LIKE path (last component is incorrectly hardened.)
            let child_xprv = ni
                .intermediary_xprv
                .derive_child(ChildNumber::new(ni.inner, true).unwrap())
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

            let candidate = Vanity {
                target: target.clone(),
                address: address.clone(),
                derivation_path: format!("{}/{}'", "m/44'/1022'/0'/0", ni.inner).to_string(),
                index: ni.inner,
                mnemonic: ni.mnemonic_phrase.clone(),
                public_key_bytes: Vec::from(public_key_bytes),
                bip39_seed_fingerprint: ni.seed_fingerprint.clone(),
            };

            // let suffix = &address[address.len() - MAX_SUFFIX_LENGTH..];
            return candidate;
        },
        |x| true,
        |x| x.target.clone(),
    )
}

fn finding_all(input: BruteForceInput, run_config: RunConfig) -> Receiver<NeedleInput> {
    // _find(set, U256::zero(), 0u32..u32::MAX)
    // _find(input.)
    todo!();
}

async fn find(take: usize, input: BruteForceInput, run_config: RunConfig) -> Vec<NeedleInput> {
    // finding_all(set).take(take).collect().await
    todo!();
}
