use clap::Parser;
use rad::info::INFO_WITH_DONATION_QR;
use rad::params::BruteForceInput;
use rad::{find_par::par_find, run_config::RunConfig, vanity::Vanity};
use std::time::{Duration, SystemTime};

use super::cli::Cli;
use super::error::Result;
use super::parse::parse_input;

pub fn run() -> Result<(Vec<Vanity>, Duration)> {
    let input = parse_input(Cli::parse())?;
    let run_config = RunConfig::default();
    Ok(search(input, run_config))
}

fn search(input: BruteForceInput, run_config: RunConfig) -> (Vec<Vanity>, Duration) {
    println!("{INFO_WITH_DONATION_QR}");

    let now = SystemTime::now();

    // Kick off the search!
    let outcome = par_find(input, run_config);

    let time_elapsed = now.elapsed().unwrap();
    (outcome, time_elapsed)
}
