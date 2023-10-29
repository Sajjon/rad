use const_format::formatcp;
use qrencode::{render::unicode, QrCode};

const DONATION_ADDRESS: &str = "account_rdx16xlfcpp0vf7e3gqnswv8j9k58n6rjccu58vvspmdva22kf3aplease";

pub fn generate_donate_qr() -> String {
    let code = QrCode::new(DONATION_ADDRESS).unwrap();
    return code.render::<unicode::Dense1x2>().build();
}

const CONSIDER_DONATE_MESSAGE: &str =
    "If you liked this free software please consider making a donation:";

const DONATION_QR: &str = r#"

    █▀▀▀▀▀█ █ ▀▄▀ █ ▀█   █   ▄▀   █▀▀▀▀▀█
    █ ███ █ ▄█▀██▀  █▄▀▀▄ ▄█▀█▄█  █ ███ █
    █ ▀▀▀ █  ▀▀▀ █▄██▄▄█▀ ▄ ▄ ▀▀█ █ ▀▀▀ █
    ▀▀▀▀▀▀▀ █ ▀▄▀▄▀▄▀ ▀▄█ █▄█ ▀ █ ▀▀▀▀▀▀▀
    ▀▄▀▀▄▀▀▀▄▀▀█▀▀██ ▄█ ▄▄█ ▄ ▀▀█ ▀▄ ▀ ▀▀
    █▄██▄▄▀█ ▄▄█▀▄▀ █ ▄▀█▀▀▀███▄█▀▄▀█▀▄▄▄
    ██▄▄▄▀▀███▀ ██▀█▄███ ▄█ █▀▀▄▄████ ▀ █
     ▀ ▀  ▀█▄ ▄▀█▀█ ▀  ▀ ▀ ▄▀▀▄▄▀▀▄▄█▀ ▄▄
    ▄▄▀█▄█▀█▄ ▀█▄ ▄▀ ▀▄█  ██▄█▄█ ▄▄   ▀ ▄
     █ ▀▄▄▀██ ▀▀▄▀▄▄▄▄▄ █▀▄   ▄█ █▀ ▄█ ▀▀
    ▀█▀█▀█▀▄▄▄▀▄▄▄ ▀██ █▀█ ▄█ █ ▄█ ▄ ▀▄▄
    ▄██▄ ▀▀▀▄▄ ▀ ▀█▄▄▄▀ █  █▄▄▀▄  ▄ ▀██▄▄
     ██▀▀▀▀ ▀▄ █▀▄▀▀▀    █▄ ▄▀██▀████▄▀▄█
    ▄▀▄ ▄ ▀ ▄▀▀▀▄▀█▄  ▄▄▄█  █▀  ▀ █ ▀  ▀
       ▀ ▀▀▀█▀ ▀▀  ▄▀ ▀▀▄█▀█▄▀█▄█▀▀▀███▀▄
    █▀▀▀▀▀█ █▀███▄▀█▄▄█▄▀▄▀ █ █ █ ▀ █▄ ▀█
    █ ███ █ ▄▀ ▀▄█▀▄█▄ ▀▀▄ ▄  ▀ ▀▀███   ▄
    █ ▀▀▀ █ ▀██▀▀  █  ▀▄ ▀ ▀█▄▀▄  ▀██▄█
    ▀▀▀▀▀▀▀ ▀▀▀▀▀   ▀▀▀ ▀ ▀  ▀▀▀ ▀▀▀▀ ▀▀▀

"#;

const INFO_SEP: &str =
    "✨ 🙏 ✨ 🙏 ✨ 🙏 ✨ 🙏 ✨ 🙏 ✨ 🙏 ✨ 🙏 ✨ 🙏 ✨ 🙏 ✨ 🙏 ✨ 🙏 ✨ 🙏 ✨ 🙏 ✨";

const DISCLAIMER_MESSAGE: &str = r#"
⚠️  ⚠️  ⚠️  ⚠️  ⚠️  ⚠️  ⚠️  ⚠️  ⚠️  ⚠️  ⚠️  ⚠️  ⚠️  ⚠️  ⚠️  ⚠️  ⚠️  ⚠️  ⚠️  ⚠️  ⚠️  ⚠️  ⚠️  ⚠️  ⚠️  ⚠️  ⚠️  
This software is NOT developed by, endorsed by or otherwise associated with Radix 
Publishing, RDX Works or any entity related to Radix DLT.

The Radix mobile wallet 24 word seed phrase is much safer than the ones 
generated by this software, which might be using INSECURE randomness.

You are responsible for retaining sole possession and ownership of, and for securing 
the seed phrase(s) generated by this software.
"#;

pub const INFO_WITH_DONATION_QR: &str = formatcp!(
    r#"{}
{}
{}
{}
{}
{}
"#,
    DISCLAIMER_MESSAGE,
    INFO_SEP,
    CONSIDER_DONATE_MESSAGE,
    DONATION_ADDRESS,
    DONATION_QR,
    INFO_SEP
);

pub const INFO_DONATION_ADDR_ONLY: &str = formatcp!(
    r#"{}
{}
{}
{}
{}
"#,
    DISCLAIMER_MESSAGE,
    INFO_SEP,
    CONSIDER_DONATE_MESSAGE,
    DONATION_ADDRESS,
    INFO_SEP
);
