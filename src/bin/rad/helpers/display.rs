use rad::vanity::Vanity;
use std::time::Duration;

pub fn display_outcome((outcome, time_elapsed): (Vec<Vanity>, Duration)) {
    println!(
        "\n✅ Exiting program, ran for '{}' ms, found #{} results",
        time_elapsed.as_millis(),
        outcome.len()
    );
}
