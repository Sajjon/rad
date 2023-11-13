use primitive_types::U256;

/// Configuration controlling how program is run, but not
/// relating to which vanity accounts are found, just how
/// program executes.
#[derive(Clone)]
pub struct RunConfig {
    pub print_found_vanity_result: bool,
    /// `0` means don't print anything
    pub print_pulse: U256,
    pub print_mnemonic: bool,
    pub print_input: bool,
}

impl RunConfig {
    pub fn new(
        print_found_vanity_result: bool,
        print_pulse: u32,
        print_mnemonic: bool,
        print_input: bool,
    ) -> Self {
        Self {
            print_found_vanity_result,
            print_pulse: U256::from(print_pulse),
            print_mnemonic,
            print_input,
        }
    }
}
