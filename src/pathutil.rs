use crate::error::{Error, Result};
use crate::format::{MAX_NAME_BYTES, MAX_PATH_BYTES};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedPath {
    pub components: Vec<String>,
}

pub fn parse_path(input: &str) -> Result<ParsedPath> {
    if input.len() > MAX_PATH_BYTES {
        return Err(Error::InvalidPath("path is longer than 4096 bytes".into()));
    }
    if !input.starts_with('/') {
        return Err(Error::InvalidPath("path must start with /".into()));
    }
    if input != "/" && input.ends_with('/') {
        return Err(Error::InvalidPath("path must not end with /".into()));
    }
    if input == "/" {
        return Ok(ParsedPath {
            components: Vec::new(),
        });
    }
    let mut components = Vec::new();
    for component in input[1..].split('/') {
        validate_component(component)?;
        components.push(component.to_string());
    }
    Ok(ParsedPath { components })
}

pub fn validate_component(name: &str) -> Result<()> {
    if name.is_empty() {
        return Err(Error::InvalidPath("empty path component".into()));
    }
    if name == "." || name == ".." {
        return Err(Error::InvalidPath("'.' and '..' are not allowed".into()));
    }
    if name.len() > MAX_NAME_BYTES {
        return Err(Error::InvalidPath("name is longer than 255 bytes".into()));
    }
    if name.bytes().any(|b| b < 0x20 || b == 0x7f || b == b'/') {
        return Err(Error::InvalidPath(
            "name contains a forbidden character".into(),
        ));
    }
    Ok(())
}

pub fn display_path(components: &[String]) -> String {
    if components.is_empty() {
        return "/".to_string();
    }
    let mut out = String::new();
    for component in components {
        out.push('/');
        out.push_str(component);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_nested_paths_and_rejects_escapes() {
        let path = parse_path("/path1/path2/file").unwrap();
        assert_eq!(
            path.components,
            vec!["path1".to_string(), "path2".to_string(), "file".to_string()]
        );
        assert_eq!(parse_path("/").unwrap().components.len(), 0);
        assert_eq!(parse_path("relative").unwrap_err().code(), "invalid_path");
        assert_eq!(parse_path("/a/../b").unwrap_err().code(), "invalid_path");
        assert_eq!(parse_path("/a//b").unwrap_err().code(), "invalid_path");
        assert_eq!(parse_path("/a/").unwrap_err().code(), "invalid_path");
        assert_eq!(parse_path("/a/./b").unwrap_err().code(), "invalid_path");
    }
}
