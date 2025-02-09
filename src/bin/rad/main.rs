mod helpers;
use helpers::*;

fn main() {
    let out = run().unwrap();
    display_outcome(out);
}
