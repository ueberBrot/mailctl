//! Typed AND-only search criteria and their canonical representation.
use super::{Error, ErrorCode};
use chrono::{Datelike, NaiveDate};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SearchMessagesInput {
    /// A mailbox reference returned by discovery in this installation.
    #[serde(deserialize_with = "super::reference")]
    #[schemars(length(min = 1, max = 8192), extend("x-maxUtf8Bytes" = 8192))]
    pub mailbox: String,
    /// AND predicates; an empty array selects all messages. Text values match case-insensitive substrings.
    #[serde(default)]
    pub criteria: SearchCriteria,
    /// Page size within capabilities.limits.search_page; omission uses that ceiling.
    #[serde(default, deserialize_with = "super::page_limit::<_, 200>")]
    #[schemars(range(min = 1, max = 200))]
    pub limit: Option<usize>,
    /// Continue with next_cursor, the same mailbox reference, and the original criteria.
    #[serde(
        default,
        deserialize_with = "super::bounded_optional_string::<_, 8192>"
    )]
    #[schemars(length(min = 1, max = 8192), extend("x-maxUtf8Bytes" = 8192))]
    pub cursor: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, JsonSchema)]
#[serde(transparent)]
pub struct SearchDate(#[schemars(with = "String", pattern(r"^\d{4}-\d{2}-\d{2}$"))] String);
impl SearchDate {
    pub fn as_str(&self) -> &str {
        &self.0
    }
    pub(crate) fn date(&self) -> NaiveDate {
        NaiveDate::parse_from_str(&self.0, "%Y-%m-%d").expect("validated search date")
    }
}
impl TryFrom<String> for SearchDate {
    type Error = Error;
    fn try_from(value: String) -> Result<Self, Error> {
        let date = NaiveDate::parse_from_str(&value, "%Y-%m-%d").map_err(|_| invalid())?;
        if value.len() != 10
            || !(1..=9999).contains(&date.year())
            || date.format("%Y-%m-%d").to_string() != value
        {
            return Err(invalid());
        }
        Ok(Self(value))
    }
}
impl<'de> Deserialize<'de> for SearchDate {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Visitor;
        impl Visitor {
            fn date<E: serde::de::Error>(
                value: impl AsRef<str> + Into<String>,
            ) -> Result<SearchDate, E> {
                if value.as_ref().len() != 10 {
                    return Err(E::custom("invalid search date"));
                }
                SearchDate::try_from(value.into()).map_err(|_| E::custom("invalid search date"))
            }
        }
        impl serde::de::Visitor<'_> for Visitor {
            type Value = SearchDate;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("a string")
            }
            fn visit_str<E: serde::de::Error>(self, value: &str) -> Result<SearchDate, E> {
                Self::date(value)
            }
            fn visit_string<E: serde::de::Error>(self, value: String) -> Result<SearchDate, E> {
                Self::date(value)
            }
            fn visit_bytes<E: serde::de::Error>(self, value: &[u8]) -> Result<SearchDate, E> {
                match std::str::from_utf8(value) {
                    Ok(value) => self.visit_str(value),
                    Err(_) => Err(E::invalid_value(serde::de::Unexpected::Bytes(value), &self)),
                }
            }
            fn visit_byte_buf<E: serde::de::Error>(self, value: Vec<u8>) -> Result<SearchDate, E> {
                match String::from_utf8(value) {
                    Ok(value) => self.visit_string(value),
                    Err(error) => Err(E::invalid_value(
                        serde::de::Unexpected::Bytes(error.as_bytes()),
                        &self,
                    )),
                }
            }
        }
        deserializer.deserialize_string(Visitor)
    }
}

#[derive(
    Clone, Copy, Debug, Deserialize, Serialize, JsonSchema, PartialEq, Eq, PartialOrd, Ord,
)]
#[serde(rename_all = "snake_case")]
pub enum StandardFlag {
    Answered,
    Deleted,
    Draft,
    Flagged,
    Recent,
    Seen,
}
impl StandardFlag {
    pub(crate) fn imap_name(self) -> &'static str {
        match self {
            Self::Answered => "\\Answered",
            Self::Deleted => "\\Deleted",
            Self::Draft => "\\Draft",
            Self::Flagged => "\\Flagged",
            Self::Recent => "\\Recent",
            Self::Seen => "\\Seen",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq, Eq, PartialOrd, Ord)]
#[serde(tag = "field", rename_all = "snake_case", deny_unknown_fields)]
pub enum SearchPredicate {
    /// Include messages received on or after this calendar date (YYYY-MM-DD).
    ReceivedAfter {
        date: SearchDate,
    },
    /// Include messages received before this calendar date (YYYY-MM-DD).
    ReceivedBefore {
        date: SearchDate,
    },
    /// Include messages sent on or after this calendar date (YYYY-MM-DD).
    SentAfter {
        date: SearchDate,
    },
    /// Include messages sent before this calendar date (YYYY-MM-DD).
    SentBefore {
        date: SearchDate,
    },
    From {
        #[serde(deserialize_with = "search_text")]
        #[schemars(length(max = 4096), extend("x-maxUtf8Bytes" = 4096))]
        value: String,
    },
    To {
        #[serde(deserialize_with = "search_text")]
        #[schemars(length(max = 4096), extend("x-maxUtf8Bytes" = 4096))]
        value: String,
    },
    Cc {
        #[serde(deserialize_with = "search_text")]
        #[schemars(length(max = 4096), extend("x-maxUtf8Bytes" = 4096))]
        value: String,
    },
    Bcc {
        #[serde(deserialize_with = "search_text")]
        #[schemars(length(max = 4096), extend("x-maxUtf8Bytes" = 4096))]
        value: String,
    },
    Subject {
        #[serde(deserialize_with = "search_text")]
        #[schemars(length(max = 4096), extend("x-maxUtf8Bytes" = 4096))]
        value: String,
    },
    Text {
        #[serde(deserialize_with = "search_text")]
        #[schemars(length(max = 4096), extend("x-maxUtf8Bytes" = 4096))]
        value: String,
    },
    RequiredFlag {
        flag: StandardFlag,
    },
    ForbiddenFlag {
        flag: StandardFlag,
    },
}

/// Canonical order preserves repeated fields as separate AND terms.
#[derive(Clone, Debug, Default, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(transparent)]
pub struct SearchCriteria(#[schemars(length(max = 32))] Vec<SearchPredicate>);
impl SearchCriteria {
    pub fn predicates(&self) -> &[SearchPredicate] {
        &self.0
    }
}
impl TryFrom<Vec<SearchPredicate>> for SearchCriteria {
    type Error = Error;
    fn try_from(mut predicates: Vec<SearchPredicate>) -> Result<Self, Error> {
        if predicates.len() > 32 {
            return Err(invalid());
        }
        use SearchPredicate::*;
        let mut required = std::collections::BTreeSet::new();
        let mut forbidden = std::collections::BTreeSet::new();
        let mut after = [None, None];
        let mut before = [None, None];
        for predicate in &predicates {
            match predicate {
                From { value }
                | To { value }
                | Cc { value }
                | Bcc { value }
                | Subject { value }
                | Text { value } => {
                    if !valid_search_text(value) {
                        return Err(invalid());
                    }
                }
                RequiredFlag { flag } => {
                    required.insert(flag);
                }
                ForbiddenFlag { flag } => {
                    forbidden.insert(flag);
                }
                ReceivedAfter { date } | SentAfter { date } => {
                    let slot = usize::from(matches!(predicate, SentAfter { .. }));
                    after[slot] = Some(after[slot].map_or(date, |old: &SearchDate| old.max(date)));
                }
                ReceivedBefore { date } | SentBefore { date } => {
                    let slot = usize::from(matches!(predicate, SentBefore { .. }));
                    before[slot] =
                        Some(before[slot].map_or(date, |old: &SearchDate| old.min(date)));
                }
            }
        }
        if !required.is_disjoint(&forbidden)
            || after.into_iter().zip(before).any(|(after, before)| {
                matches!((after, before), (Some(after), Some(before)) if after >= before)
            }) { return Err(invalid()); }
        predicates.sort_unstable();
        Ok(Self(predicates))
    }
}
impl<'de> Deserialize<'de> for SearchCriteria {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let predicates =
            crate::encoding::BoundedVec::<SearchPredicate, 32>::deserialize(deserializer)?;
        Self::try_from(predicates.0)
            .map_err(|_| serde::de::Error::custom("invalid search criteria"))
    }
}
fn valid_search_text(value: &str) -> bool {
    value.len() <= 4096 && !value.contains('\0')
}
fn search_text<'de, D: serde::Deserializer<'de>>(deserializer: D) -> Result<String, D::Error> {
    struct Visitor;
    impl serde::de::Visitor<'_> for Visitor {
        type Value = String;
        fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("at most 4096 UTF-8 bytes without NUL")
        }
        fn visit_str<E: serde::de::Error>(self, value: &str) -> Result<String, E> {
            if !valid_search_text(value) {
                return Err(E::custom("invalid search text"));
            }
            Ok(value.to_owned())
        }
        fn visit_string<E: serde::de::Error>(self, value: String) -> Result<String, E> {
            if !valid_search_text(&value) {
                return Err(E::custom("invalid search text"));
            }
            Ok(value)
        }
    }
    deserializer.deserialize_str(Visitor)
}
fn invalid() -> Error {
    Error::new(ErrorCode::InvalidRequest)
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(
    tag = "status",
    content = "value",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum Metadata<T> {
    Present(T),
    #[default]
    Missing,
    Malformed,
}
impl<T> Metadata<T> {
    pub fn value(&self) -> Option<&T> {
        match self {
            Self::Present(value) => Some(value),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct MessageAddress {
    pub name: Option<String>,
    pub address: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct MessageMetadata {
    pub subject: Metadata<String>,
    pub from: Metadata<Vec<MessageAddress>>,
    pub to: Metadata<Vec<MessageAddress>>,
    pub cc: Metadata<Vec<MessageAddress>>,
    pub received_date: String,
    pub sent_date: Metadata<String>,
    pub flags: Vec<String>,
    pub message_id: Metadata<String>,
    pub size: u32,
}

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
pub struct MessageEnvelope {
    pub reference: String,
    #[serde(flatten)]
    pub metadata: MessageMetadata,
}

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MessageSearch {
    pub account_id: String,
    pub generation: u64,
    pub mailbox_reference: String,
    pub criteria: SearchCriteria,
    pub messages: Vec<MessageEnvelope>,
    pub complete: bool,
    pub next_cursor: Option<String>,
}
