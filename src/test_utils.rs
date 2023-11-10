extern crate default_args;
use crate::{
    error::TargetSuffixError,
    find::{find, find_n},
    find_par::par_find,
    params::{Bip39WordCount, BruteForceInput},
    run_config::RunConfig,
    vanity::Vanity,
};

use std::time::Duration;

use async_std::future;
use futures::executor::block_on;

default_args::default_args! {
    export pub fn crate::test_utils::input(
        targets: &str,
        max_index: u32 = MAX_INDEX,
        find_multiple_accounts_per_target: bool = false,
        mnemonic_word_count: Bip39WordCount = Bip39WordCount::Twelve,
        brute_force_seed: Option<&'static [u8]> = Option::None,
    ) -> Result<BruteForceInput, TargetSuffixError> {
        BruteForceInput::new_splitting_targets(
            targets,
            max_index,
            find_multiple_accounts_per_target,
            mnemonic_word_count,
            brute_force_seed
        )
    }
}

default_args::default_args! {
    export pub fn crate::test_utils::input_deterministic(
        targets: &str,
        max_index: u32 = MAX_INDEX,
        find_multiple_accounts_per_target: bool = false,
        mnemonic_word_count: Bip39WordCount = Bip39WordCount::Twelve,
        brute_force_seed: &'static [u8] = b"rusty vanity",
    ) -> BruteForceInput {
        input!(
            targets,
            max_index,
            find_multiple_accounts_per_target,
            mnemonic_word_count,
            Option::Some(brute_force_seed)
        ).unwrap()
    }
}

pub fn _find<F>(input: BruteForceInput, on_result: F) -> ()
where
    F: FnMut(Vanity) -> bool,
{
    find(input, RunConfig::new(false, 0, false, false), on_result)
}

pub fn _find_one(input: BruteForceInput) -> Vanity {
    let mut result: Option<Vanity> = Option::None;
    _find(input, |v| {
        result = Option::Some(v);
        return false;
    });

    return result.expect("one result");
}

pub fn _find_n(n: usize, input: BruteForceInput) -> Vec<Vanity> {
    find_n(n, input, RunConfig::new(false, 0, false, false))
}

pub fn blocking_find_timeout_after(
    take: usize,
    input: BruteForceInput,
    duration: Duration,
) -> Vec<Vanity> {
    block_on(future::timeout(
        duration,
        par_find(take, input, RunConfig::new(false, 0, false, false)),
    ))
    .expect("Should have found elements within timeout")
}

pub fn blocking_find(take: usize, input: BruteForceInput) -> Vec<Vanity> {
    let duration = Duration::from_millis(1000);
    blocking_find_timeout_after(take, input, duration)
}

pub fn blocking_find_one(input: BruteForceInput) -> Vanity {
    blocking_find(1, input)[0].clone()
}
