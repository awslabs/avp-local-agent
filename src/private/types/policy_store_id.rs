//! Structure to represent the `PolicyStoreId` used throughout the crate.

use std::fmt;

use serde_json::Value;

use crate::public::policy_set_provider::ProviderError;

use super::policy_store_filter::PolicyStoreFilter;

/// This Object wraps the aws verified permissions `PolicyStoreID` which is an unique identifier
/// for the policy store.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PolicyStoreId(pub String, pub Option<PolicyStoreFilter>);

/// Formats the `PolicyStoreId` using the given formatter.
impl fmt::Display for PolicyStoreId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)?;
        if let Some(filter) = &self.1 {
            f.write_str(";filter=")?;
            filter.fmt(f)?;
        }
        Ok(())
    }
}

/// Allows for conversion from `String` to `PolicyStoreId`
impl From<String> for PolicyStoreId {
    fn from(item: String) -> Self {
        Self(item, None)
    }
}

impl PolicyStoreId {
    pub fn with_cli_filters<T: AsRef<str>>(mut self, filters: T) -> Result<Self,ProviderError> {
        if self.1.is_some() {
            Err(ProviderError::Configuration("PolicyStoreFilter has already been set".into()))?;
        }
        self.1 = Some(PolicyStoreFilter::from_cli_str(filters.as_ref()).map_err(|e|ProviderError::Configuration(e.to_string()))?);
        Ok(self)
    }

    pub fn with_json_filters<T: AsRef<str>>(mut self, filters: T) -> Result<Self,ProviderError> {
        if self.1.is_some() {
            Err(ProviderError::Configuration("PolicyStoreFilter has already been set".into()))?;
        }
        self.1 = Some(PolicyStoreFilter::from_json_str(filters.as_ref()).map_err(|e|ProviderError::Configuration(e.to_string()))?);
        Ok(self)
    }

    pub fn with_filters(mut self, filters: Value) -> Result<Self,ProviderError> {
        if self.1.is_some() {
            Err(ProviderError::Configuration("PolicyStoreFilter has already been set".into()))?;
        }
        self.1 = Some(PolicyStoreFilter::from_json_value(filters).map_err(|e|ProviderError::Configuration(e.to_string()))?);
        Ok(self)
    }

    pub fn id(&self) -> &str {
        &self.0
    }

    pub fn filters(&self) -> Option<&PolicyStoreFilter> {
        self.1.as_ref()
    }
}

#[cfg(test)]
mod tests {
    use crate::private::types::{policy_store_filter::PolicyStoreFilter, policy_store_id::PolicyStoreId};
    use std::collections::HashMap;

    #[test]
    fn policy_store_id_formats_as_expected() {
        let id = PolicyStoreId::from("id".to_string());
        assert_eq!(id.to_string(), "id");
    }

    #[test]
    fn policy_store_id_empty_string() {
        let id = PolicyStoreId::from(String::new());
        assert_eq!(id.to_string(), "");
    }

    #[test]
    fn policy_store_id_can_be_inserted_into_hashmap() {
        let mut map: HashMap<PolicyStoreId, i32> = HashMap::new();
        assert_eq!(map.insert(PolicyStoreId::from("id".to_string()), 1), None);
        assert_eq!(map.get(&PolicyStoreId::from("id".to_string())), Some(&1));
    }

    #[test]
    fn policy_store_id_is_cloneable() {
        let id = PolicyStoreId::from("id".to_string());
        assert_eq!(id.clone(), id);
    }

    #[test]
    fn policy_store_id_is_equal_to_another_id_with_same_value() {
        assert!(PolicyStoreId::from("id".to_string()).eq(&PolicyStoreId::from("id".to_string())));
    }

    #[test]
    fn policy_store_id_is_not_equal_to_another_id_with_different_value() {
        assert!(
            !PolicyStoreId::from("id".to_string()).eq(&PolicyStoreId::from("other".to_string()))
        );
    }

    #[test]
    fn from_string_to_policy_store_id() {
        assert_eq!(
            PolicyStoreId::from("ps-1".to_string()),
            PolicyStoreId::from("ps-1".to_string())
        );
    }

    // Same tests with filters

    #[test]
    fn policy_store_id_with_filters_formats_as_expected() {
        let id = PolicyStoreId::from("id".to_string()).with_cli_filters("policyTemplateId=mockPolicyTemplate")
            .expect("CLI filter string should parse correctly");
        assert_eq!(
            id.to_string(),
            "id;filter=policyTemplateId=mockPolicyTemplate"
        );
    }

    #[test]
    fn policy_store_id_with_filters_can_be_inserted_into_hashmap() {
        let mut map: HashMap<PolicyStoreId, i32> = HashMap::new();
        let id = PolicyStoreId::from("id".to_string()).with_cli_filters("policyTemplateId=mockPolicyTemplate")
            .expect("CLI filter string should parse correctly");
        let p2 = id.clone();
        assert_eq!(map.insert(id, 1), None);
        assert_eq!(map.get(&p2), Some(&1));
    }

    #[test]
    fn policy_store_id_with_filters_is_cloneable() {
        let id = PolicyStoreId::from("id".to_string()).with_cli_filters("policyTemplateId=mockPolicyTemplate")
            .expect("CLI filter string should parse correctly");
        assert_eq!(id.clone(), id);
    }

    #[test]
    fn policy_store_id_with_filters_is_equal_to_another_id_with_same_value() {
        let id = PolicyStoreId::from("id".to_string()).with_cli_filters("policyTemplateId=mockPolicyTemplate")
            .expect("CLI filter string should parse correctly");
        let id2 = PolicyStoreId::from("id".to_string()).with_cli_filters("policyTemplateId=mockPolicyTemplate")
            .expect("CLI filter string should parse correctly");
    assert!(id.eq(&id2));
    }

    #[test]
    fn policy_store_id_with_filters_is_not_equal_to_another_id_with_different_value() {
        assert!(
            !PolicyStoreId::from("id".to_string()).eq(&PolicyStoreId::from("other".to_string()))
        );
    }
}
