//! An Enum used to categorize the expression syntax of a policy set filter.
use super::policy_set_provider::ProviderError;
use crate::private::types::policy_store_filter::PolicyStoreFilter;
use serde_json::Value;

#[derive(Debug)]
/// Three different input syntax's are supported for policy set filters.
pub enum PolicySetFilter<'a> {
    /// Cli shorthand representation
    Cli(&'a str),
    /// JSON representation
    Json(&'a str),
    /// `serde_json::Value`
    Value(Value),
}

impl TryInto<PolicyStoreFilter> for PolicySetFilter<'_> {
    type Error = ProviderError;

    fn try_into(self) -> Result<PolicyStoreFilter, Self::Error> {
        match self {
            PolicySetFilter::Cli(s) => Ok(PolicyStoreFilter::from_cli_str(s)?),
            PolicySetFilter::Json(json) => Ok(PolicyStoreFilter::from_json_str(json)?),
            PolicySetFilter::Value(value) => Ok(PolicyStoreFilter::from_json_value(value)?),
        }
    }
}
