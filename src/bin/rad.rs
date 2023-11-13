use std::task::Poll;

use clap::{Parser, Subcommand, ValueEnum};
use futures::future::poll_fn;
use futures::stream::StreamExt;
use rad::file_reader::suffixes_from_file;
use rad::find_par::par_find;
use rad::find_serial_orig::{find_all_serial_orig, find_n_serial_orig, find_serial_orig};
use rad::find_serial_wallet::{find_all_serial_wallet, find_n_serial_wallet, find_serial_wallet};
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

    #[arg(value_enum)]
    mode: Mode,

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

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
enum Mode {
    /// Parallel
    Par,

    /// Serial original
    SerOrig,

    /// Serial wallet
    SerWal,
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

fn parallell(input: BruteForceInput, run_config: RunConfig, matches_per_mnemonic: usize) {
    let result = par_find(input, run_config);
    println!("✅ #{} results", result.len());
}

fn serial(orig: bool, input: BruteForceInput, run_config: RunConfig, matches_per_mnemonic: usize) {
    let now = SystemTime::now();
    let mut highest_index = 0;
    match matches_per_mnemonic {
        0 => {
            if orig {
                find_serial_orig(input, run_config, |v| {
                    if v.index > highest_index {
                        highest_index = v.index
                    }
                    return true; // continue
                });
            } else {
                find_serial_wallet(input, run_config, |v| {
                    if v.index > highest_index {
                        highest_index = v.index
                    }
                    return true; // continue
                });
            }
        }
        _ => {
            if orig {
                let mut vec = find_n_serial_orig(matches_per_mnemonic, input, run_config);
                vec.sort_by(|l, r| l.index.cmp(&r.index));
                highest_index = vec.first().unwrap().index;
            } else {
                let mut vec = find_n_serial_wallet(matches_per_mnemonic, input, run_config);
                vec.sort_by(|l, r| l.index.cmp(&r.index));
                highest_index = vec.first().unwrap().index;
            }
        }
    };

    let time_elapsed = now.elapsed().unwrap();
    let highest_index_f32 = highest_index as f32;
    let speed = highest_index_f32 / time_elapsed.as_secs_f32();
    println!(
        "✅ 🐌 Exiting program, ran for '{}' ms, speed: '#{}' iters per second.",
        time_elapsed.as_millis(),
        speed
    );
}

fn main() {
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
        Some(b"very fun coding rust"),
    )
    .expect("Valid input");

    let run_config = RunConfig::new(true, cli.print_pulse, true, true);
    let matches_per_mnemonic = cli.matches_per_mnemonic;
    // println!("{}", INFO_WITH_DONATION_QR);
    let now = SystemTime::now();
    match cli.mode {
        Mode::Par => {
            println!("🚀 Running in parallell for maximum speed");
            parallell(input, run_config, matches_per_mnemonic);
        }
        Mode::SerOrig => {
            println!("‼️ SERIAL orig 🙅🏻‍♀️");
            serial(true, input, run_config, matches_per_mnemonic);
        }
        Mode::SerWal => {
            println!("‼️ Serial WALLET");
            serial(false, input, run_config, matches_per_mnemonic);
        }
    }

    let elapsed = now.elapsed().unwrap();
    println!("✅ Exiting program, ran for '{} sec'", elapsed.as_secs());
}
