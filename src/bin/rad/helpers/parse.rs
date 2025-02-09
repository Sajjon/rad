use rad::{
    file_reader::suffixes_from_file,
    params::{Bip39WordCount, BruteForceInput},
};

use super::{
    cli::{Cli, TargetSuffixes},
    error::*,
};

pub(super) fn parse_input(cli: Cli) -> Result<BruteForceInput> {
    let csv_string: String = match cli.target_suffixes {
        TargetSuffixes::File { file_path } => suffixes_from_file(file_path),
        TargetSuffixes::Targets { csv } => csv,
    };

    BruteForceInput::new_splitting_targets(
        &csv_string,
        cli.end_index,
        true,
        Bip39WordCount::Twelve,
        None,
    )
    .map_err(Error::ParseInput)
}
