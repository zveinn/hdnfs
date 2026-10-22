use crate::error::{Error, Result};

pub fn parse_size(input: &str) -> Result<u64> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Err(Error::Message("empty size".into()));
    }
    let lower = trimmed.to_ascii_lowercase();
    let units: &[(&str, u64)] = &[
        ("tib", 1 << 40),
        ("tb", 1 << 40),
        ("gib", 1 << 30),
        ("gb", 1 << 30),
        ("mib", 1 << 20),
        ("mb", 1 << 20),
        ("kib", 1 << 10),
        ("kb", 1 << 10),
        ("t", 1 << 40),
        ("g", 1 << 30),
        ("m", 1 << 20),
        ("k", 1 << 10),
    ];
    let (number, mult) = 'unit: {
        for (suffix, mult) in units {
            if let Some(rest) = lower.strip_suffix(suffix) {
                if rest.is_empty() {
                    return Err(Error::Message(format!("invalid size {input}")));
                }
                break 'unit (rest, *mult);
            }
        }
        (lower.as_str(), 1)
    };
    if number.is_empty() || !number.bytes().all(|b| b.is_ascii_digit()) {
        return Err(Error::Message(format!("invalid size {input}")));
    }
    let value: u64 = number
        .parse()
        .map_err(|_| Error::Message(format!("invalid size {input}")))?;
    value
        .checked_mul(mult)
        .ok_or_else(|| Error::Message("size overflow".into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_binary_units() {
        assert_eq!(parse_size("4096").unwrap(), 4096);
        assert_eq!(parse_size("64M").unwrap(), 64 * 1024 * 1024);
        assert_eq!(parse_size("1GiB").unwrap(), 1024 * 1024 * 1024);
        assert_eq!(parse_size("2kb").unwrap(), 2048);
        assert!(parse_size("1.5G").is_err());
        assert!(parse_size("m").is_err());
    }
}
