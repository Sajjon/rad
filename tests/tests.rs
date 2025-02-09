#[cfg(test)]
mod tests {

    use std::collections::HashSet;

    use primitive_types::U256;
    use rad::{
        error::TargetSuffixError,
        find_par::par_find,
        hdwallet::HDWallet,
        input,
        params::{Bip39WordCount, MAX_INDEX},
        run_config::RunConfig,
    };

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
    fn entropy() {
        let wallet = HDWallet::from_entropy(U256::one());
        assert_eq!(wallet.unwrap().entropy, U256::one());
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

    #[test]
    fn find_vanity_suffix_xx_yy() {
        let vec = par_find(
            input!("xx,yy").unwrap(),
            RunConfig::new(false, 0, false, false),
        );

        assert_eq!(
            vec.into_iter()
                .map(|v| v.target)
                .collect::<HashSet<String>>(),
            HashSet::from(["xx", "yy"].map(|x| x.to_string()))
        );
    }
}
