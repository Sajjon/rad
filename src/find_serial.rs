use crate::find_par::{cond_print, vanity_from_childkey, HDWallet};
use crate::params::BruteForceInput;
use crate::run_config::RunConfig;
use crate::vanity::Vanity;

use ansi_escapes::EraseLines;
use primitive_types::U256;

use std::ops::AddAssign;

pub fn find_serial<F>(input: BruteForceInput, run_config: RunConfig, mut on_result: F) -> ()
where
    F: FnMut(Vanity) -> bool,
{
    let find_multiple_accounts_per_target = input.find_multiple_accounts_per_target;
    let mut targets_left = input.targets.clone();
    let mut int = input.int();

    let mut attempts_since_last_find = U256::zero();
    if run_config.print_found_vanity_result {
        println!("{}", input);
    }
    let mut done = false;

    while !done {
        let wallet = HDWallet::from_entropy(int).unwrap();

        if input.index_end() > 100000 && run_config.print_found_vanity_result {
            // don't wanna print to often
            println!("🔮 Trying mnemonic: {}\n", wallet.mnemonic_phrase);
        }
        for index in 0u32..input.index_end() {
            if done {
                return;
            }
            // Radix Olympia BIP44-LIKE path (last component is incorrectly hardened.)
            let child = wallet.derive_child(index);
            let suffix = child.suffix.clone();
            let mut to_remove: Vec<String> = Vec::new();
            for target in &targets_left {
                if suffix.ends_with(target) {
                    let result = vanity_from_childkey(&child, target, &wallet);
                    attempts_since_last_find = U256::zero();

                    cond_print(&result, &run_config);

                    if !on_result(result) {
                        done = true;
                    }

                    if !find_multiple_accounts_per_target {
                        to_remove.push(target.clone());
                    }
                }
            }

            if !find_multiple_accounts_per_target {
                targets_left.retain(|t| !to_remove.contains(t));

                if targets_left.is_empty() {
                    done = true;
                    break;
                }
            }

            attempts_since_last_find.add_assign(U256::one());

            if !run_config.print_pulse.is_zero() {
                if attempts_since_last_find.clone() % run_config.print_pulse == U256::zero() {
                    print!("{}", EraseLines(2));
                    println!("⏳ Attempts since last find: {}", attempts_since_last_find);
                }
            }
        }
        int.add_assign(U256::one());
        int = int % input.max_int();
    }
}

pub fn find_all_serial(input: BruteForceInput, run_config: RunConfig) -> () {
    find_serial(input, run_config, |_| {
        return true; // continue
    });
}

pub fn find_n_serial(n: usize, input: BruteForceInput, run_config: RunConfig) -> Vec<Vanity> {
    let mut results: Vec<Vanity> = Vec::new();

    find_serial(input, run_config, |v| {
        results.push(v);
        if results.len() == n {
            return false;
        } else {
            return true;
        }
    });

    return results;
}
