use primitive_types::U256;

/// Configuration controlling how program is run, but not
/// relating to which vanity accounts are found, just how
/// program executes.
pub struct RunConfig {
    /// `0` means don't print anything
    pub print_pulse: U256,
}

impl RunConfig {
    pub fn new(print_pulse: u32) -> Self {
        Self {
            print_pulse: U256::from(print_pulse),
        }
    }
}
