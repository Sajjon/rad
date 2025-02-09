use std::collections::HashSet;

use crate::error::TargetSuffixError;
use primitive_types::{U128, U256};
use rand::Rng;
use unindent::unindent;

#[derive(Debug, PartialEq, Clone)]
pub enum Bip39WordCount {
    Twelve,
    #[allow(dead_code)]
    TwentyFour,
}
impl Bip39WordCount {
    pub fn byte_count(&self) -> usize {
        match self {
            Self::Twelve => 16,
            Self::TwentyFour => 32,
        }
    }
    pub fn max_int(&self) -> U256 {
        match self {
            Self::Twelve => U256::from(U128::MAX),
            Self::TwentyFour => U256::MAX,
        }
    }
}

/// Parameters use to control how and which vanity accounts are found.
#[derive(Debug, PartialEq, Clone)]
pub struct BruteForceInput {
    /// The target suffixes to search for, must be validated before set.
    pub targets: HashSet<String>,

    /// Set to `true` if you wanna search for many accounts for the same
    /// target. If `false` we will remove the target once we find a vanity
    /// account ending with it.
    pub find_multiple_accounts_per_target: bool,

    /// BIP39 word count, typically we use 12 words (Radix Olympia standard).
    pub mnemonic_word_count: Bip39WordCount,

    /// Used by tests, don't use it otherwise.
    pub brute_force_seed: Option<&'static [u8]>,

    /// The number of BIP44 address indices to test per mnemonic, typically
    /// we want this to be high (default is high), meaning many vanity accounts
    /// can be found which are all controlled by the same mnemonic => less
    /// mnemonics for you to have to write down. `0` means "use default"
    pub max_index: u32,
}

pub const MAX_INDEX: u32 = 2147483647;
pub const MAX_SUFFIX_LENGTH: usize = 6;

impl BruteForceInput {
    pub fn index_end(&self) -> u32 {
        if self.max_index == 0 {
            MAX_INDEX
        } else {
            self.max_index
        }
    }

    pub fn ent_len(&self) -> usize {
        self.mnemonic_word_count.byte_count()
    }

    pub fn max_int(&self) -> U256 {
        self.mnemonic_word_count.max_int()
    }

    pub fn int(&self) -> U256 {
        match self.brute_force_seed {
            Option::Some(bytes) => U256::from_big_endian(bytes),
            Option::None => {
                let random_bytes = rand::thread_rng().gen::<[u8; 32]>();
                U256::from_big_endian(&random_bytes)
            }
        }
    }
}

impl std::fmt::Display for BruteForceInput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let target_strings: Vec<String> = self.targets.clone().into_iter().collect();
        let targets_string = target_strings.join(",");
        let multi_matches = self.find_multiple_accounts_per_target;
        let matches_str = if multi_matches {
            "👨‍👧‍👧 Multiple accounts per target"
        } else {
            "🙋‍♂️ Single account per target"
        }
        .to_string();

        let description = format!(
            r#"
            🎯 Searching for: '{}'
            {}
            🌱 Seed for brute-force search: 0x{:X}
            🎬 End index: {}
            "#,
            targets_string,
            matches_str,
            self.int(),
            self.index_end()
        );

        write!(f, "{}", unindent(&description)).and(match self.brute_force_seed {
            Option::Some(_) => write!(f, "\n⚠️  Warning deterministic seed used, insecure!"),
            Option::None => Ok(()),
        })
    }
}

const BECH32_ALPHABET: &str = "023456789acdefghjklmnpqrstuvwxyz";

fn invalid_bech32_char(c: &char) -> bool {
    BECH32_ALPHABET.contains(*c)
}

pub fn validating_split(comma_separated: &str) -> Result<HashSet<String>, TargetSuffixError> {
    if comma_separated.is_empty() {
        return Err(TargetSuffixError::TargetsStringMustNotBeEmpty);
    }

    let targets: Vec<String> = comma_separated
        .split(",")
        .map(str::trim)
        .map(str::to_string)
        .collect();

    let mut set: HashSet<String> = HashSet::new();

    for target in &targets {
        if target.is_empty() {
            return Err(TargetSuffixError::TargetSuffixMustNotBeEmpty);
        }

        if target.len() > MAX_SUFFIX_LENGTH {
            return Err(TargetSuffixError::TooLongTargetSuffix(
                target.clone(),
                target.len(),
            ));
        }

        match target.chars().find(|c| !invalid_bech32_char(c)) {
            Option::None => {
                set.insert(target.clone()); // valid
                continue;
            }
            Option::Some(invalid) => {
                return Err(TargetSuffixError::InvalidBech32Character(
                    target.clone(),
                    invalid,
                ))
            }
        }
    }

    Ok(set)
}

impl BruteForceInput {
    pub fn new_splitting_targets(
        targets: &str,
        max_index: u32,
        find_multiple_accounts_per_target: bool,
        mnemonic_word_count: Bip39WordCount,
        brute_force_seed: Option<&'static [u8]>,
    ) -> Result<Self, TargetSuffixError> {
        validating_split(targets).map(|ts| Self {
            targets: ts,
            max_index,
            find_multiple_accounts_per_target,
            mnemonic_word_count,
            brute_force_seed,
        })
    }
}
