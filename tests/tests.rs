use rusty_vanity::{
    error::TargetSuffixError,
    find::{find, find_n},
    params::{Bip39WordCount, BruteForceInput, MAX_INDEX},
    run_config::RunConfig,
    vanity::Vanity,
};
extern crate default_args;
use default_args::default_args;
// use test::Bencher;

default_args! {
    fn input(
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

default_args! {
    fn input_deterministic(
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

fn _find<F>(input: BruteForceInput, on_result: F) -> ()
where
    F: FnMut(Vanity) -> bool,
{
    find(input, RunConfig::new(0), on_result)
}

fn _find_one(input: BruteForceInput) -> Vanity {
    let mut result: Option<Vanity> = Option::None;
    _find(input, |v| {
        result = Option::Some(v);
        return false;
    });

    return result.expect("one result");
}

pub fn _find_n(n: usize, input: BruteForceInput) -> Vec<Vanity> {
    find_n(n, input, RunConfig::new(0))
}

#[test]
fn empty_targets_str() {
    assert_eq!(
        input!(""),
        Err(TargetSuffixError::TargetsStringMustNotBeEmpty)
    );
}

#[test]
fn empty_target_suffix_trailing() {
    assert_eq!(
        input!("a,,"),
        Err(TargetSuffixError::TargetSuffixMustNotBeEmpty)
    );
}

#[test]
fn empty_target_suffix_leading() {
    assert_eq!(
        input!(",a"),
        Err(TargetSuffixError::TargetSuffixMustNotBeEmpty)
    );
}

#[test]
fn long_suffix() {
    assert_eq!(
        input!("verylong"),
        Err(TargetSuffixError::TooLongTargetSuffix(
            "verylong".to_string(),
            8
        ))
    );
}

#[test]
fn invalid_char_i() {
    assert_eq!(
        input!("hi"),
        Err(TargetSuffixError::InvalidBech32Character(
            "hi".to_string(),
            'i'
        ))
    );
}

#[test]
fn invalid_char_b() {
    assert_eq!(
        input!("burn"),
        Err(TargetSuffixError::InvalidBech32Character(
            "burn".to_string(),
            'b'
        ))
    );
}

#[test]
fn invalid_char_o() {
    assert_eq!(
        input!("some"),
        Err(TargetSuffixError::InvalidBech32Character(
            "some".to_string(),
            'o'
        ))
    );
}

#[test]
fn invalid_chars() {
    assert_eq!(
        input!("bio"),
        Err(TargetSuffixError::InvalidBech32Character(
            "bio".to_string(),
            'b'
        ))
    );
}

#[test]
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
}

#[test]
fn n_3_find_multiple_accounts_per_target() {
    let n: usize = 3;
    let tx: &str = "tx";
    let ty = "ty";
    let find_multiple_accounts_per_target = true;
    let results = _find_n(
        n,
        input_deterministic!(
            &format!("{tx},{ty}"),
            MAX_INDEX,
            find_multiple_accounts_per_target
        ),
    );

    assert_eq!(results.len(), n);

    assert_eq!(
        results
            .into_iter()
            .map(|v| v.target)
            .collect::<Vec<String>>(),
        Vec::from([tx, ty, ty])
    );
}

#[test]
fn n_3_find_single_accounts_per_target() {
    let n: usize = 3;
    let tx: &str = "tx";
    let ty = "ty";
    let targets = [tx, ty];
    let find_multiple_accounts_per_target = false;
    let results = _find_n(
        n,
        input_deterministic!(
            &targets.join(","),
            MAX_INDEX,
            find_multiple_accounts_per_target
        ),
    );

    assert_eq!(results.len(), targets.len()); // not `n`,

    assert_eq!(
        results
            .into_iter()
            .map(|v| v.target)
            .collect::<Vec<String>>(),
        targets
    );
}

#[test]
fn xrd() {
    assert_eq!(
        _find_one(input_deterministic!("xrd")).address,
        "account_rdx16xl72qyxvhkjtmyxeazl4tcgjh5n3hse6xfnr3ku0utlk9myp47xrd"
    );
}

// #[bench]
// fn deterministic(b: &mut Bencher) {
//     b.iter(|| {
//         assert_eq!(
//             find_one(input_deterministic!("a")).address,
//             "account_rdx16xcsekplyt3cvqdqntcz37zgt8wageuznmgthfzkfrj8ye5ay5k7xa"
//         );
//     });
// }
