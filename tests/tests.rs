#[cfg(test)]
mod tests {

    use rad::{
        error::TargetSuffixError,
        input, input_deterministic,
        params::{Bip39WordCount, MAX_INDEX},
        test_utils::{_find_n, _find_one},
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
    fn x() {
        let input = input_deterministic!("x");
        let non_par = _find_one(input.clone());
        let par = blocking_find_one(input);
        assert_eq!(non_par.target, par.target);
    }

    #[test]
    fn xyz() {
        let result = _find_one(input_deterministic!("xyz"));
        assert_eq!(result.index, 178012);
    }

    #[test]
    fn target_2345() {
        let result = _find_one(input_deterministic!("2345"));
        assert_eq!(result.index, 597472);
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

    #[test]
    fn speed() {
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
}
