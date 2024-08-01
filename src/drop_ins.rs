use std::path::{Path, PathBuf};

use fancy_regex::Regex;
use serde::{de::Visitor, Deserialize};

#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "kebab-case")]
enum Matcher {
    RecordedHash {
        #[serde(deserialize_with = "hex::serde::deserialize")]
        hash: Vec<u8>,
    },
    PathRegex {
        #[serde(deserialize_with = "deserialize_regex")]
        regex: Regex,
    },
    Path {
        path: PathBuf,
    },
}

#[derive(Deserialize)]
pub struct DropIn {
    matcher: Matcher,
    path: PathBuf,
}

#[derive(Deserialize)]
pub struct DropIns(Vec<DropIn>);

pub trait FindDropIn {
    fn find_drop_in(&self, path: &Path, hash: &[u8]) -> Option<PathBuf>;
}

impl FindDropIn for Option<DropIns> {
    fn find_drop_in(&self, path: &Path, hash: &[u8]) -> Option<PathBuf> {
        match self {
            Some(v) => v.find_drop_in(path, hash),
            None => None,
        }
    }
}

impl FindDropIn for DropIns {
    fn find_drop_in(&self, path: &Path, hash: &[u8]) -> Option<PathBuf> {
        for drop_in in &self.0 {
            if match &drop_in.matcher {
                Matcher::RecordedHash { hash: matcher_hash } => matcher_hash == hash,
                Matcher::PathRegex {
                    regex: matcher_regex,
                } => path
                    .to_str()
                    .is_some_and(|path| matcher_regex.is_match(path).unwrap_or(false)),
                Matcher::Path { path: matcher_path } => path == matcher_path,
            } {
                return Some(drop_in.path.clone());
            }
        }

        None
    }
}

fn deserialize_regex<'de, D>(d: D) -> Result<Regex, D::Error>
where
    D: serde::Deserializer<'de>,
{
    struct RegexVisitor;
    impl<'v> Visitor<'v> for RegexVisitor {
        type Value = Regex;

        fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
            write!(formatter, "a regex string")
        }

        fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            let regex = Regex::new(v);
            regex.map_err(|err| serde::de::Error::custom(err))
        }
    }

    d.deserialize_string(RegexVisitor)
}
