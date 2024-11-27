//! Structure to represent the `PolicyStoreId` used throughout the crate.

use std::fmt;

use super::policy_store_filter::PolicyStoreFilters;

/// This Object wraps the aws verified permissions `PolicyStoreID` which is an unique identifier
/// for the policy store.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PolicyStoreId(pub String, pub Option<PolicyStoreFilters>);

/// Formats the `PolicyStoreId` using the given formatter.
impl fmt::Display for PolicyStoreId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

/// Allows for conversion from `String` to `PolicyStoreId`
impl From<String> for PolicyStoreId {
    fn from(item: String) -> Self {
        Self(item,None)
    }
}

impl PolicyStoreId {
    pub fn with_filters(mut self, filters: Option<PolicyStoreFilters>) -> Self {
        self.1 = filters;
        self
    }

    pub fn id(&self) -> &str {
        &self.0
    }

    pub fn filters(&self) -> Option<&PolicyStoreFilters> {
        self.1.as_ref()
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use crate::private::types::policy_store_id::PolicyStoreId;

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
        assert!(!PolicyStoreId::from("id".to_string()).eq(&PolicyStoreId::from("other".to_string())));
    }

    #[test]
    fn from_string_to_policy_store_id() {
        assert_eq!(
            PolicyStoreId::from("ps-1".to_string()),
            PolicyStoreId::from("ps-1".to_string())
        );
    }
}
