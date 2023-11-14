use crate::hdwallet::{vanity_from_childkey, HDWallet};
use crate::params::BruteForceInput;
use crate::run_config::RunConfig;
use crate::vanity::*;

use std::collections::HashSet;
use std::ops::Range;
use std::sync::{Arc, Mutex};

use rayon::prelude::{IntoParallelIterator, ParallelIterator};

fn parallel_search<Proto, Match, Invariant, MakeProto, EvalProto>(
    range: Range<u32>,
    loop_invariant: Invariant,
    make_proto: MakeProto,
    eval_proto: EvalProto,
) -> Vec<Match>
where
    Invariant: Fn() -> bool + Sync,
    MakeProto: Fn(u32) -> Proto + Sync,
    EvalProto: Fn(Proto) -> Vec<Match> + Sync,
    Proto: Send,
    Match: Send,
{
    range
        .into_par_iter()
        .take_any_while(|_| loop_invariant())
        .map(|i| make_proto(i))
        .flat_map(|c| eval_proto(c))
        .collect()
}

fn parallel_search_addresses(
    run_config: RunConfig,
    wallet: Box<HDWallet>,
    end_index: u32,
    targets: Arc<Mutex<HashSet<String>>>,
) -> Vec<Vanity> {
    parallel_search(
        0..end_index,
        || !targets.lock().unwrap().is_empty(),
        |i| wallet.derive_child(i),
        |c| {
            let suff = c.suffix.clone();
            let mut targets = targets.lock().unwrap();
            let mut matches = Vec::<Vanity>::new();
            for target in targets.iter() {
                if suff.ends_with(target) {
                    let vanity = vanity_from_childkey(&c, target, &wallet);
                    cond_print(&vanity, &run_config);
                    matches.push(vanity);
                }
            }
            (*targets).retain(|x| matches.iter().all(|v| x != &v.target));
            return matches;
        },
    )
}

pub fn par_find(input: BruteForceInput, run_config: RunConfig) -> Vec<Vanity> {
    if run_config.print_input {
        println!("{input}");
    }
    let wallet = HDWallet::from_entropy(input.clone().int()).unwrap();
    let targets = Arc::new(Mutex::new(input.clone().targets));
    parallel_search_addresses(
        run_config.clone(),
        Box::new(wallet),
        input.index_end(),
        targets,
    )
}
