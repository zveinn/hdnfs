use zeroize::Zeroize;

use crate::error::{Error, Result};

const WEAK: &[&str] = &[
    "password1234",
    "password12345",
    "password123456",
    "123456789012",
    "1234567890123",
    "12345678901234",
    "qwerty123456",
    "qwertyuiop12",
    "iloveyou1234",
    "letmein12345",
    "welcome12345",
    "admin1234567",
    "changeme1234",
    "passw0rd1234",
    "abc123456789",
    "1q2w3e4r5t6y",
    "qwertyuiopas",
    "passwordpass",
    "aaaaaaaaaaaa",
    "000000000000",
];

pub fn validate_password(password: &str) -> Result<()> {
    if password.len() > 1024 {
        return Err(Error::Password(
            "password must be at most 1024 bytes".into(),
        ));
    }
    if password.chars().count() < 12 || password.len() < 12 {
        return Err(Error::Password(
            "password must be at least 12 characters".into(),
        ));
    }
    if password.bytes().any(|b| b == 0) {
        return Err(Error::Password("password contains a NUL byte".into()));
    }
    let lower = password.to_lowercase();
    if WEAK.iter().any(|w| *w == lower) {
        return Err(Error::Password("password is too common".into()));
    }
    Ok(())
}

/// A password that is wiped when dropped.
pub struct SecretString(String);

impl SecretString {
    pub fn new(value: String) -> Self {
        Self(value)
    }

    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl Drop for SecretString {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

pub fn prompt_password() -> Result<SecretString> {
    let password = rpassword::prompt_password("Enter password: ")?;
    let password = SecretString::new(password);
    validate_password(password.expose())?;
    Ok(password)
}

pub fn prompt_new_password() -> Result<SecretString> {
    let first = SecretString::new(rpassword::prompt_password("Enter password: ")?);
    let second = SecretString::new(rpassword::prompt_password("Confirm password: ")?);
    if first.expose() != second.expose() {
        return Err(Error::Password("passwords do not match".into()));
    }
    validate_password(first.expose())?;
    Ok(first)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_short_and_common_passwords() {
        assert_eq!(validate_password("short").unwrap_err().code(), "password");
        assert_eq!(
            validate_password("password1234").unwrap_err().code(),
            "password"
        );
        assert_eq!(
            validate_password("Password1234").unwrap_err().code(),
            "password"
        );
        validate_password("correct horse battery").unwrap();
    }
}
