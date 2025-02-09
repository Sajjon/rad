#[cfg(test)]
mod tests {

    use std::collections::HashSet;

    use rad::{
        error::TargetSuffixError,
        find_par::par_find,
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
