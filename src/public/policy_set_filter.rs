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

#[cfg(test)]
mod tests {
    use crate::private::types::policy_store_filter::PolicyFilterInputError;

    use super::*;

    #[test]
    fn test_cli() {
        let pf = PolicySetFilter::Cli("policyTemplateId=12345");
        let p: PolicyStoreFilter = pf.try_into().unwrap();
        assert_eq!(p.to_string(), "policyTemplateId=12345");
    }
    #[test]
    fn test_json() {
        let p: PolicyStoreFilter = PolicySetFilter::Json("{\"policyTemplateId\":\"12345\"}")
            .try_into()
            .unwrap();
        assert_eq!(p.to_string(), "policyTemplateId=12345");
    }
    #[test]
    fn test_value() {
        let p: PolicyStoreFilter = PolicySetFilter::Value(
            serde_json::from_str("{\"policyTemplateId\":\"12345\"}").unwrap(),
        )
        .try_into()
        .unwrap();
        assert_eq!(p.to_string(), "policyTemplateId=12345");
    }
    #[test]
    fn test_cli_syntax_error() {
        let p: Result<PolicyStoreFilter, _> = PolicySetFilter::Cli("policyTemplateId=").try_into();
        let e = p.unwrap_err();
        assert!(matches!(
            e,
            ProviderError::PolicyFilterInputError(PolicyFilterInputError::ShorthandParseError(_))
        ));
    }
    #[test]
    fn test_cli_content_error() {
        let p: Result<PolicyStoreFilter, _> =
            PolicySetFilter::Cli("policyTemplate=1232456").try_into();
        let e = p.unwrap_err();
        assert!(matches!(
            e,
            ProviderError::PolicyFilterInputError(PolicyFilterInputError::ShorthandContentError(_))
        ));
    }
    #[test]
    fn test_json_syntax_error() {
        let p: Result<PolicyStoreFilter, _> =
            PolicySetFilter::Json("{\"policyTemplateId\":\"12345}").try_into();
        let e = p.unwrap_err();
        assert!(matches!(
            e,
            ProviderError::PolicyFilterInputError(
                PolicyFilterInputError::JsonDeserializationError(_)
            )
        ));
    }
    #[test]
    fn test_json_content_error() {
        let p: Result<PolicyStoreFilter, _> =
            PolicySetFilter::Json("{\"policyTemplate\":\"12345\"}").try_into();
        let e = p.unwrap_err();
        assert!(matches!(
            e,
            ProviderError::PolicyFilterInputError(PolicyFilterInputError::EmptyFilter)
        ));
    }
}
