use clap::{Parser, Subcommand};
use rad::info::INFO_DONATION_ADDR_ONLY;

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
pub struct Cli {
    /// Input for which target suffixes to look for, either file or csv passed in as a string.
    #[command(subcommand)]
    pub target_suffixes: TargetSuffixes,

    /// The number of indices to test per mnemonic,
    /// is used, which is convenient if you find a lot of nice vanity account using the same
    /// mnemonic, you have less number of mnemonics you need to manage.
    #[arg(short = 'i', long = "index", default_value_t = 2147483647)]
    pub end_index: u32,
}

#[derive(Debug, Subcommand)]
pub enum TargetSuffixes {
    /// Read target suffixes from file, one target per line (without any delimiter).
    #[command(short_flag = 'f', arg_required_else_help = true)]
    File { file_path: String },

    /// A comma separated string of targets, e.g. "hey,me,yay"
    #[command(short_flag = 't', arg_required_else_help = true)]
    Targets { csv: String },
}
