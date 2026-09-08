//! Listener authority and request narrowing are independent of provider adapters.
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Profile {
    #[default]
    ReadOnly,
    DraftsOnly,
    ReadAndDrafts,
}
#[derive(Clone, Copy, Debug, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Permission {
    ListAccounts,
    ListMailboxes,
    SearchMessages,
    ReadMessage,
    ReadAttachment,
    AppendDraft,
    InspectDraftOperation,
}
impl Profile {
    pub fn permissions(self, read_only: bool) -> Vec<Permission> {
        use Permission::*;
        let mut result = vec![ListAccounts];
        if self != Self::DraftsOnly {
            result.extend([ListMailboxes, SearchMessages, ReadMessage, ReadAttachment]);
        }
        if self != Self::ReadOnly && !read_only {
            result.extend([AppendDraft, InspectDraftOperation]);
        }
        result
    }
}
#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Narrowing {
    #[serde(default)]
    pub read_only: bool,
    pub accounts: Option<Vec<String>>,
}
/// Created by the broker after it authenticates a configured listener.
#[derive(Clone, Debug)]
pub struct RequestContext {
    pub(crate) installation: String,
    pub(crate) listener: String,
    pub(crate) accounts: Vec<String>,
    pub(crate) permissions: Vec<Permission>,
}
