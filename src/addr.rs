//! Addresses: `PROVIDER:KIND:SCOPE...`, upper-cased before use.

use crate::Error;

/// Upper-case and validate; the one choke point before any path is built.
pub fn norm(input: &str) -> Result<String, Error> {
    let addr = input.trim().to_uppercase();
    if !valid(&addr) || addr.contains("..") {
        return Err(Error::AddrInvalid(input.to_string()));
    }
    Ok(addr)
}

fn valid(addr: &str) -> bool {
    let segments: Vec<&str> = addr.split(':').collect();
    if !(2..=5).contains(&segments.len()) {
        return false;
    }
    segments.iter().all(|s| valid_segment(s))
}

/// One scope value, upper-cased first: starts alphanumeric, then
/// `A-Z 0-9 _ - @ . +`.
pub fn valid_segment(segment: &str) -> bool {
    let mut chars = segment.chars();
    match chars.next() {
        Some(c) if c.is_ascii_alphanumeric() => {}
        _ => return false,
    }
    chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '@' | '.' | '+' | '-'))
}

/// The env name invented for a wildcard hit: `:` and friends become `_`.
pub fn default_env(addr: &str) -> String {
    addr.chars()
        .map(|c| {
            if c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn norm_uppercases_and_trims() {
        assert_eq!(norm("  telegram:bot:demo ").unwrap(), "TELEGRAM:BOT:DEMO");
    }

    #[test]
    fn norm_accepts_two_to_five_segments() {
        assert!(norm("A:B").is_ok());
        assert!(norm("A:B:C:D:E").is_ok());
        assert!(norm("A").is_err());
        assert!(norm("A:B:C:D:E:F").is_err());
    }

    #[test]
    fn norm_rejects_traversal_and_shape() {
        assert!(norm("A:../B").is_err());
        assert!(norm("A:..").is_err());
        assert!(norm("A:").is_err());
        assert!(norm(":B").is_err());
        assert!(norm("A:B C").is_err());
        assert!(norm("").is_err());
    }

    #[test]
    fn default_env_flattens() {
        assert_eq!(default_env("TELEGRAM:BOT:ME"), "TELEGRAM_BOT_ME");
        assert_eq!(default_env("A:B-C.D@E+F"), "A_B_C_D_E_F");
    }
}
