use std::task::Poll;

use clap::{Parser, Subcommand};
use futures::future::poll_fn;
use futures::stream::StreamExt;
use rad::file_reader::suffixes_from_file;
use rad::find::{find_all, find_n};
use rad::find_par::{par_find, par_finding_all};
use rad::info::{INFO_DONATION_ADDR_ONLY, INFO_WITH_DONATION_QR};
use rad::params::{Bip39WordCount, BruteForceInput};
use rad::run_config::RunConfig;
use rad::vanity::Vanity;
use std::time::{Duration, SystemTime};

#[derive(Parser)]
#[command(name = "rad", version)]
#[command(author = "Alexander Cyon <alex.cyon@gmail.com>")]
#[command(
about = "Vanity Radix Babylon address generator.",
long_about = format!(r#"
{}
Generate Radix Babylon vanity accounts that you can easily import into the Radix 
Babylon mobile wallet using QR code and inputting the found mnemonic.
{INFO_DONATION_ADDR_ONLY}
"#, "🔮".repeat(40))
)]
struct Cli {
    /// Input for which target suffixes to look for, either file or csv passed in as a string.
    #[command(subcommand)]
    target_suffixes: TargetSuffixes,

    /// If you dont wanna run in parallel
    #[arg(short = 's', long, default_value_t = false)]
    slow: bool,

    /// If we want to continue searching for more vanity accounts for a given
    /// target after we have found one. If `false` is passed, we will remove
    /// the target after first account is found (better performance). If `true`,
    /// the program will find multiple matches per target.
    #[arg(short = 'c', long, default_value_t = false)]
    multi_match_per_target: bool,

    /// How many matches PER MMEMONIC we will search for until program exits,
    /// `0` means run forver. Any other value means stop program after than
    /// many vanity accounts have been found.
    #[arg(short = 'n', long, default_value_t = 0)]
    matches_per_mnemonic: usize,

    /// How often you want the program to print any progress, use `0` to not print any progress.
    /// Since finding accounts can take a very long time if 6 character long targets are used
    /// it can be nice to see some kind of progress, you typicall want this to be a high number
    /// like 10k - 1M, depending on how fast your machine is.
    ///
    /// If you are piping the output to a pager, e.g. `less` you typicall want to specify `0` to
    /// this argument, so not have to scroll meaningless progress prints.
    #[arg(short = 'p', long = "pulse", default_value_t = 10000)]
    print_pulse: u32,

    /// The number of indices to test per mnemonic,
    /// is used, which is convenient if you find a lot of nice vanity account using the same
    /// mnemonic, you have less number of mnemonics you need to manage.
    #[arg(short = 'i', long = "index", default_value_t = 2147483647)]
    end_index: u32,
}

#[derive(Debug, Subcommand)]
enum TargetSuffixes {
    /// Read target suffixes from file, one target per line (without any delimitor).
    #[command(short_flag = 'f', arg_required_else_help = true)]
    File { file_path: String },

    /// A comma seperated string of targets, e.g. "hey,me,yay"
    #[command(short_flag = 't', arg_required_else_help = true)]
    Targets { csv: String },
}

async fn parallell(input: BruteForceInput, run_config: RunConfig, matches_per_mnemonic: usize) {
    let result = match matches_per_mnemonic {
        0 => {
            //find_all(input, run_config),
            let rx = par_finding_all(input, run_config);
            let stop_fut = poll_fn(|_cx| Poll::<Vanity>::Pending);
            let mut stream = rx.take_until(stop_fut);
            stream.by_ref().collect::<Vec<Vanity>>().await
        }
        _ => {
            // find_n(cli.matches_per_mnemonic, input, run_config);
            par_find(matches_per_mnemonic, input, run_config).await
        }
    };
    println!("✅ #{} results", result.len());
}

fn not_par(input: BruteForceInput, run_config: RunConfig, matches_per_mnemonic: usize) {
    match matches_per_mnemonic {
        0 => {
            find_all(input, run_config);
        }
        _ => {
            find_n(matches_per_mnemonic, input, run_config);
        }
    };
}

#[async_std::main]
async fn main() {
    let cli = Cli::parse();

    let csv_string: String = match cli.target_suffixes {
        TargetSuffixes::File { file_path } => suffixes_from_file(file_path),
        TargetSuffixes::Targets { csv } => csv,
    };

    let input = BruteForceInput::new_splitting_targets(
        &csv_string,
        cli.end_index,
        cli.multi_match_per_target,
        Bip39WordCount::Twelve,
        Option::None,
    )
    .expect("Valid input");

    let run_config = RunConfig::new(true, cli.print_pulse, true, true);
    let matches_per_mnemonic = cli.matches_per_mnemonic;
    println!("{}", INFO_WITH_DONATION_QR);
    let now = SystemTime::now();
    if cli.slow {
        println!("‼️ you have disabled parallelisation, this makes the program much much much much slower. Please consider enabling parallelisation");
        not_par(input, run_config, matches_per_mnemonic);
    } else {
        println!("🚀 Running in parallell for maximum speed");
        parallell(input, run_config, matches_per_mnemonic).await;
    }
    let elapsed = now.elapsed().unwrap();
    println!("✅ Exiting program, ran for '{} sec'", elapsed.as_secs());
}
