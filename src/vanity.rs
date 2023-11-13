use nu_ansi_term::{
    Color::Black, Color::Cyan, Color::LightGreen, Color::LightPurple, Color::LightRed, Style,
};

use base64::{engine::general_purpose, Engine as _};
use qrencode::{render::unicode, QrCode};

use crate::hdwallet::BASE_PATH;

#[derive(Debug, PartialEq, Clone)]
pub struct Vanity {
    pub target: String,
    pub address: String,
    /// Last 6 chars of the address, stored property for higher performance, used to check match against `target`.
    pub address_suffix: String,
    pub index: u32,
    pub public_key_bytes: Vec<u8>,
    pub mnemonic: String,

    /// Last 8 bytes of BIP39 Seed - base64 encoded. Used in name of account, if it fits,
    /// can be used to visually identify that two accounts come from same mnemonic (before
    /// user renames them in Babylon wallet)
    pub bip39_seed_fingerprint: String,
}

impl Vanity {
    pub fn derivation_path(&self) -> String {
        format!("{}/{}'", BASE_PATH, self.index)
    }
    pub fn public_key_hex(&self) -> String {
        hex::encode(&self.public_key_bytes)
    }
    pub fn public_key_base64(&self) -> String {
        general_purpose::STANDARD_NO_PAD.encode(&self.public_key_bytes)
    }
    pub fn separator_intra() -> String {
        String::from("^")
    }

    pub fn cap33_export_string_account_name(&self) -> String {
        format!(
            "{}|{}|{}",
            self.bip39_seed_fingerprint, self.target, self.index
        )
    }

    pub fn cap33_export_string_account_part(&self) -> String {
        let name_value = self.cap33_export_string_account_name();
        let is_software_account_marker = "S";
        let pubkey = self.public_key_base64();
        let index_str = self.index.to_string();
        let value = [is_software_account_marker, &pubkey, &index_str, &name_value]
            .join(&Vanity::separator_intra());
        let separator_account_name_end = "}";
        return format!("{}{}", value, separator_account_name_end);
    }

    pub fn cap33_export_string(&self) -> String {
        let separator_header_end = "]";
        let mnemonic_word_count = self.mnemonic.split(' ').count();
        let number_of_payloads = 1;
        let payload_index = 0;
        let header = [number_of_payloads, payload_index, mnemonic_word_count]
            .map(|u| u.to_string())
            .join(&Vanity::separator_intra());
        let account = self.cap33_export_string_account_part();
        return format!("{}{}{}", header, separator_header_end, account);
    }

    pub fn cap33_qr_code_string(&self) -> String {
        // Encode some data into bits.
        let code = QrCode::new(self.cap33_export_string().clone()).unwrap();

        return code.render::<unicode::Dense1x2>().quiet_zone(true).build();
    }

    pub fn mnemonic_phrase_grid_string(&self) -> String {
        let words = self
            .mnemonic
            .split(' ')
            .map(|w| String::from(format!("{:<8}", w))) // 8 is max length of English BIP39 word
            .collect::<Vec<String>>();
        let string: String = words.chunks(3).enumerate().fold(String::new(), |s, l| {
            s + color(l.0, Vec::from(l.1).join("\t\t")).as_str() + "\n"
        });
        return string;
    }
}

impl std::fmt::Display for Vanity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Address: {} (🎯 '{}')\nPath: {}\nPublicKey: {}\nIn Babylon mobile app: 'Import from a Legacy Wallet', by scanning:\n{}\n{}",
            self.address, self.target, self.derivation_path(), self.public_key_hex(), self.cap33_qr_code_string(), self.mnemonic_phrase_grid_string()
        )
    }
}

fn color(index: usize, string: String) -> String {
    let discriminator = index % 4;
    let style = Style::new().italic().bold().on(Black);
    let colored = match discriminator {
        0 => style.fg(Cyan).paint(string),
        1 => style.fg(LightRed).paint(string),
        2 => style.fg(LightGreen).paint(string),
        _ => style.fg(LightPurple).paint(string),
    };
    colored.to_string()
}
