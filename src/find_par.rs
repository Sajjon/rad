use crate::hdwallet::{vanity_from_childkey, ChildKey, HDWallet};
use crate::info::INFO_DONATION_ADDR_ONLY;
use crate::params::BruteForceInput;
use crate::run_config::RunConfig;
use crate::vanity::Vanity;

use std::collections::HashSet;
use std::ops::Range;
use std::sync::{Arc, Mutex};

use rayon::prelude::{IntoParallelIterator, ParallelIterator};

pub fn cond_print(vanity: &Vanity, run_config: &RunConfig) {
    if run_config.print_found_vanity_result {
        print_vanity(vanity);
    }
}
pub fn print_vanity(vanity: &Vanity) {
    println!(
        "{}\n{}{}\n{}",
        "🎯".repeat(40),
        vanity.to_string(),
        INFO_DONATION_ADDR_ONLY.to_string(),
        "🎯".repeat(40),
    );
}

fn par_do_do_find<E, F>(
    range: Range<u32>,
    wallet: &Box<HDWallet>,
    check_if_done: E,
    on_childkey: F,
) -> Vec<Vanity>
where
    E: Fn(u32) -> Option<u32> + Send + Sync,
    F: Fn(ChildKey) -> Option<Vanity> + Send + Sync,
{
    range
        .into_par_iter()
        .map(|i| check_if_done(i))
        .while_some()
        .map(|i| wallet.derive_child(i))
        .map(|c| on_childkey(c))
        .filter_map(|x| x)
        .collect()
}

fn par_do_find(
    run_config: RunConfig,
    wallet: Box<HDWallet>,
    end_index: u32,
    targets: Arc<Mutex<HashSet<String>>>,
) -> Vec<Vanity> {
    par_do_do_find(
        0..end_index,
        &wallet,
        |i| {
            if targets.lock().unwrap().is_empty() {
                None
            } else {
                Some(i)
            }
        },
        |c| {
            let suff = c.suffix.clone();

            let mut result: Option<Vanity> = Option::None;
            let mut trgts = targets.lock().unwrap();
            for target in trgts.iter() {
                if suff.ends_with(target) {
                    let vanity = vanity_from_childkey(&c, target, &wallet);
                    cond_print(&vanity, &run_config);
                    result = Some(vanity);
                    break;
                } else {
                    continue;
                }
            }
            if let Some(v) = &result {
                (*trgts).remove(&v.target);
            }
            return result;
        },
    )
}

fn _par_find(
    run_config: RunConfig,
    wallet: Box<HDWallet>,
    end_index: u32,
    targets_: HashSet<String>,
) -> Vec<Vanity> {
    let targets = Arc::new(Mutex::new(targets_.clone()));
    par_do_find(run_config.clone(), wallet, end_index, targets)
}

pub fn par_find(input: BruteForceInput, run_config: RunConfig) -> Vec<Vanity> {
    if run_config.print_input {
        println!("{}", input);
    }
    let wallet = HDWallet::from_entropy(input.int()).unwrap();
    _par_find(
        run_config,
        Box::new(wallet),
        input.index_end(),
        input.targets,
    )
}
