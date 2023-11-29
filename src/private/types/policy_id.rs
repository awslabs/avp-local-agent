//! Structure to represent the `PolicyId` used throughout the crate.

use std::fmt;
use std::fmt::Formatter;

/// This type wraps the AVP policyId String.
#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct PolicyId(pub String);

/// Enables an easy way to call `to_string` on `PolicyId`.
impl fmt::Display for PolicyId {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl From<String> for PolicyId {
    fn from(item: String) -> Self {
        Self(item)
    }
}

#[cfg(test)]
mod test {
    use crate::private::types::policy_id::PolicyId;
    use std::collections::HashMap;

    #[test]
    fn policy_id_formats_as_expected() {
        let key = PolicyId("p-1".to_string());
        assert_eq!(key.to_string(), "p-1");
    }

    #[test]
    fn policy_id_empty_string() {
        let key = PolicyId(String::new());
        assert_eq!(key.to_string(), "");
    }

    #[test]
    fn policy_id_can_be_inserted_into_map() {
        let mut map: HashMap<PolicyId, i32> = HashMap::new();
        assert_eq!(map.insert(PolicyId("p-1".to_string()), 10), None);
        assert_eq!(map.get(&PolicyId("p-1".to_string())), Some(&10));
    }

    #[test]
    fn policy_id_is_cloneable() {
        let key = PolicyId("p-1".to_string());
        assert_eq!(key.clone(), key);
    }

    #[test]
    fn policy_id_equal_to_another_key() {
        assert_eq!(PolicyId("p-1".to_string()), PolicyId("p-1".to_string()));
    }

    #[test]
    fn policy_id_not_equal_to_another_key() {
        assert_ne!(PolicyId("p-2".to_string()), PolicyId("p-1".to_string()));
    }

    #[test]
    fn from_string_to_policy_id() {
        assert_eq!(
            PolicyId("p-1".to_string()),
            PolicyId::from("p-1".to_string())
        )
    }
}
