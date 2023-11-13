extern crate default_args;
use crate::{
    error::TargetSuffixError,
    params::{Bip39WordCount, BruteForceInput},
};

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
