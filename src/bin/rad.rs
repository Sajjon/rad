use clap::{Parser, Subcommand};
use rad::file_reader::suffixes_from_file;
use rad::find_par::par_find;
use rad::info::{INFO_DONATION_ADDR_ONLY, INFO_WITH_DONATION_QR};
use rad::params::{Bip39WordCount, BruteForceInput};
use rad::run_config::RunConfig;
use std::time::SystemTime;

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

fn main() {
    let cli = Cli::parse();

    let csv_string: String = match cli.target_suffixes {
        TargetSuffixes::File { file_path } => suffixes_from_file(file_path),
        TargetSuffixes::Targets { csv } => csv,
    };

    let input = BruteForceInput::new_splitting_targets(
        &csv_string,
        cli.end_index,
        true,
        Bip39WordCount::Twelve,
        None,
    )
    .expect("Valid input");

    let run_config = RunConfig::new(true, 0, true, true);
    println!("{INFO_WITH_DONATION_QR}");
    let now = SystemTime::now();
    let vec = par_find(input, run_config);
    let time_elapsed = now.elapsed().unwrap();
    println!(
        "\n✅ Exiting program, ran for '{}' ms, found #{} results",
        time_elapsed.as_millis(),
        vec.len()
    );
}
