use std::fs;

fn words_by_line<'a>(s: String) -> Vec<String> {
    s.lines()
        .map(|line| line.split_whitespace().collect())
        .collect()
}

pub fn suffixes_from_file(file_path: String) -> String {
    let content =
        fs::read_to_string(file_path).expect("One suffix per line, without any delimitors.");
    words_by_line(content).join(",")
}
