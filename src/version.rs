//! Parsing and ordering package versions and dependency requirements.

use std::cmp::Ordering;
use std::fmt;
use std::str::FromStr;

use crate::error::{ArcError, Result};

#[derive(Clone, Debug)]
pub struct Version(String);

impl Version {
    pub fn parse(input: impl Into<String>) -> Result<Self> {
        let input = input.into();
        if input.is_empty() || input.len() > 128 || !input.is_ascii() {
            return Err(ArcError::InvalidMetadata("invalid package version".into()));
        }

        let rest = if let Some((epoch, rest)) = input.split_once(':') {
            if epoch.is_empty()
                || !epoch.bytes().all(|byte| byte.is_ascii_digit())
                || epoch.parse::<u128>().is_err()
                || rest.is_empty()
                || rest.contains(':')
            {
                return Err(ArcError::InvalidMetadata(
                    "a version epoch must be numeric and followed by a version".into(),
                ));
            }
            rest
        } else {
            input.as_str()
        };

        if !rest.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'+' | b'_' | b'~' | b'-')
        }) || !rest.bytes().any(|byte| byte.is_ascii_alphanumeric())
        {
            return Err(ArcError::InvalidMetadata(format!(
                "invalid package version {input:?}"
            )));
        }

        Ok(Self(input))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    fn epoch_and_value(&self) -> (u128, &str) {
        match self.0.split_once(':') {
            Some((epoch, value)) => (epoch.parse().unwrap_or(u128::MAX), value),
            None => (0, &self.0),
        }
    }
}

impl fmt::Display for Version {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

impl FromStr for Version {
    type Err = ArcError;

    fn from_str(value: &str) -> Result<Self> {
        Self::parse(value)
    }
}

impl PartialEq for Version {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other) == Ordering::Equal
    }
}

impl Eq for Version {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Part<'a> {
    Tilde,
    Numeric(&'a [u8]),
    Text(&'a [u8]),
}

fn next_part<'a>(input: &'a [u8], cursor: &mut usize) -> Option<Part<'a>> {
    while *cursor < input.len() {
        let byte = input[*cursor];
        if byte == b'~' {
            *cursor += 1;
            return Some(Part::Tilde);
        }
        if byte.is_ascii_alphanumeric() {
            break;
        }
        *cursor += 1;
    }

    if *cursor == input.len() {
        return None;
    }

    let start = *cursor;
    let numeric = input[start].is_ascii_digit();
    while *cursor < input.len()
        && input[*cursor].is_ascii_alphanumeric()
        && input[*cursor].is_ascii_digit() == numeric
    {
        *cursor += 1;
    }

    Some(if numeric {
        Part::Numeric(&input[start..*cursor])
    } else {
        Part::Text(&input[start..*cursor])
    })
}

fn compare_numeric(first: &[u8], second: &[u8]) -> Ordering {
    let first = first
        .iter()
        .position(|byte| *byte != b'0')
        .map_or(&b"0"[..], |index| &first[index..]);
    let second = second
        .iter()
        .position(|byte| *byte != b'0')
        .map_or(&b"0"[..], |index| &second[index..]);
    first
        .len()
        .cmp(&second.len())
        .then_with(|| first.cmp(second))
}

fn compare_values(first: &str, second: &str) -> Ordering {
    let mut first_cursor = 0;
    let mut second_cursor = 0;
    let first = first.as_bytes();
    let second = second.as_bytes();

    loop {
        let first_part = next_part(first, &mut first_cursor);
        let second_part = next_part(second, &mut second_cursor);
        let ordering = match (first_part, second_part) {
            (None, None) => return Ordering::Equal,
            (Some(Part::Tilde), Some(Part::Tilde)) => Ordering::Equal,
            (Some(Part::Tilde), _) => Ordering::Less,
            (_, Some(Part::Tilde)) => Ordering::Greater,
            (None, Some(_)) => Ordering::Less,
            (Some(_), None) => Ordering::Greater,
            (Some(Part::Numeric(first)), Some(Part::Numeric(second))) => {
                compare_numeric(first, second)
            }
            (Some(Part::Numeric(_)), Some(Part::Text(_))) => Ordering::Greater,
            (Some(Part::Text(_)), Some(Part::Numeric(_))) => Ordering::Less,
            (Some(Part::Text(first)), Some(Part::Text(second))) => first.cmp(second),
        };
        if ordering != Ordering::Equal {
            return ordering;
        }
    }
}

impl Ord for Version {
    fn cmp(&self, other: &Self) -> Ordering {
        let (first_epoch, first) = self.epoch_and_value();
        let (second_epoch, second) = other.epoch_and_value();
        first_epoch
            .cmp(&second_epoch)
            .then_with(|| compare_values(first, second))
    }
}

impl PartialOrd for Version {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Operator {
    Less,
    LessEqual,
    Equal,
    GreaterEqual,
    Greater,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Requirement {
    pub name: String,
    pub operator: Option<Operator>,
    pub version: Option<Version>,
}

impl Requirement {
    pub fn parse(input: &str) -> Result<Self> {
        let input = input.trim();
        if input.is_empty() || input.bytes().any(|byte| byte.is_ascii_whitespace()) {
            return Err(ArcError::InvalidMetadata(format!(
                "invalid dependency {input:?}"
            )));
        }

        let split = input.find(['<', '=', '>']);
        let (name, operator, version) = if let Some(index) = split {
            let tail = &input[index..];
            let (symbol, operator) = if tail.starts_with("<=") {
                ("<=", Operator::LessEqual)
            } else if tail.starts_with(">=") {
                (">=", Operator::GreaterEqual)
            } else if tail.starts_with('<') {
                ("<", Operator::Less)
            } else if tail.starts_with('>') {
                (">", Operator::Greater)
            } else {
                ("=", Operator::Equal)
            };
            let version = &tail[symbol.len()..];
            (
                input[..index].to_owned(),
                Some(operator),
                Some(Version::parse(version)?),
            )
        } else {
            (input.to_owned(), None, None)
        };

        validate_name(&name)?;
        Ok(Self {
            name,
            operator,
            version,
        })
    }

    pub fn matches(&self, candidate: &Version) -> bool {
        match (self.operator, &self.version) {
            (None, None) => true,
            (Some(Operator::Less), Some(version)) => candidate < version,
            (Some(Operator::LessEqual), Some(version)) => candidate <= version,
            (Some(Operator::Equal), Some(version)) => candidate == version,
            (Some(Operator::GreaterEqual), Some(version)) => candidate >= version,
            (Some(Operator::Greater), Some(version)) => candidate > version,
            _ => false,
        }
    }
}

pub fn validate_name(name: &str) -> Result<()> {
    let valid = !name.is_empty()
        && name.len() <= 128
        && name.is_ascii()
        && name
            .bytes()
            .next()
            .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
        && name.bytes().all(|byte| {
            byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || matches!(byte, b'+' | b'-' | b'.' | b'_' | b'@')
        });
    if valid {
        Ok(())
    } else {
        Err(ArcError::InvalidMetadata(format!(
            "invalid package name {name:?}"
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn version(value: &str) -> Version {
        Version::parse(value).unwrap()
    }

    #[test]
    fn versions_compare_numeric_parts_and_epochs() {
        assert!(version("1.10") > version("1.9"));
        assert!(version("2:1.0") > version("1:9999"));
        assert_eq!(version("1.01"), version("1.1"));
    }

    #[test]
    fn tilde_marks_a_prerelease() {
        assert!(version("2.0~rc1") < version("2.0"));
        assert!(version("2.0") < version("2.0-1"));
    }

    #[test]
    fn requirements_match_versions() {
        let requirement = Requirement::parse("libc>=2.40-1").unwrap();
        assert!(requirement.matches(&version("2.41-1")));
        assert!(!requirement.matches(&version("2.39-9")));
    }

    #[test]
    fn malformed_requirements_are_rejected() {
        for value in ["", "Bad", "foo => 1", "foo>=", "foo!=1"] {
            assert!(Requirement::parse(value).is_err(), "accepted {value:?}");
        }
    }
}
