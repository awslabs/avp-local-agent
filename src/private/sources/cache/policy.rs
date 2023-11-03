//! This module contains the implementation of the policy cache.

use aws_sdk_verifiedpermissions::operation::get_policy::GetPolicyOutput;
use aws_sdk_verifiedpermissions::types::PolicyItem;
use std::collections::HashMap;
use tracing::{debug, instrument};

use crate::private::sources::{Cache, CacheChange};
use crate::private::types::aliases::PolicyCache;
use crate::private::types::policy_id::PolicyId;
use std::collections::hash_map::IterMut;
use std::iter::IntoIterator;

/// An implementation of the policy cache. This caches the raw `GetPolicyOutput` structs
/// from AVP `GetPolicy` calls.
#[derive(Debug)]
pub struct GetPolicyOutputCache {
    /// Policy cache of `PolicyId`, `GetPolicyOutput`
    policy_cache: PolicyCache<GetPolicyOutput>,
}

/// Implements `IntoIterator` for Policy Cache to enable iteration
impl<'a> IntoIterator for &'a mut GetPolicyOutputCache {
    type Item = (&'a PolicyId, &'a mut GetPolicyOutput);
    type IntoIter = IterMut<'a, PolicyId, GetPolicyOutput>;

    fn into_iter(self) -> IterMut<'a, PolicyId, GetPolicyOutput> {
        self.policy_cache.iter_mut()
    }
}

impl Cache for GetPolicyOutputCache {
    type Key = PolicyId;
    type Value = GetPolicyOutput;
    type LoadedItems = HashMap<Self::Key, PolicyItem>;
    type PendingUpdates = HashMap<Self::Key, CacheChange>;

    fn new() -> Self {
        Self {
            policy_cache: HashMap::new(),
        }
    }

    #[instrument(level = "trace", skip(self))]
    fn get(&self, key: &Self::Key) -> Option<&Self::Value> {
        self.policy_cache.get(key)
    }

    #[instrument(level = "trace", skip(self))]
    fn put(&mut self, key: Self::Key, value: Self::Value) -> Option<Self::Value> {
        self.policy_cache.insert(key, value)
    }

    #[instrument(level = "trace", skip(self))]
    fn remove(&mut self, key: &Self::Key) -> Option<Self::Value> {
        self.policy_cache.remove(key)
    }

    #[instrument(level = "trace", skip(self))]
    fn get_pending_updates(&self, ids_map: &Self::LoadedItems) -> Self::PendingUpdates {
        let mut policy_updates: Self::PendingUpdates = HashMap::new();

        for policy_id in self.policy_cache.clone().keys() {
            if !ids_map.contains_key(policy_id) {
                policy_updates.insert(policy_id.clone(), CacheChange::Deleted);
            }
        }

        for (policy_id, policy_item) in ids_map {
            if !self.policy_cache.contains_key(policy_id) {
                policy_updates.insert(policy_id.clone(), CacheChange::Created);
            } else if policy_item.last_updated_date > self.policy_cache[policy_id].last_updated_date
            {
                policy_updates.insert(policy_id.clone(), CacheChange::Updated);
            }
        }

        debug!("Policy Cache Pending Updates: policy_updates={policy_updates:?}");

        policy_updates
    }
}

#[cfg(test)]
mod test {
    use crate::private::sources::cache::policy::GetPolicyOutputCache;
    use crate::private::sources::{Cache, CacheChange};
    use crate::private::types::policy_id::PolicyId;
    use aws_sdk_verifiedpermissions::operation::get_policy::GetPolicyOutput;
    use aws_sdk_verifiedpermissions::types::PolicyItem;
    use aws_smithy_types::DateTime;
    use chrono::{Duration, Utc};
    use std::collections::HashMap;

    #[test]
    fn put_on_a_missing_key_returns_none() {
        let mut policy_cache = GetPolicyOutputCache::new();
        let missing_key = PolicyId("missing_key".to_string());
        let value = GetPolicyOutput::builder().build();
        assert_eq!(policy_cache.put(missing_key, value), None);
    }

    #[test]
    fn put_on_a_present_key_returns_old_value() {
        let mut policy_cache = GetPolicyOutputCache::new();
        let key = PolicyId("key".to_string());
        let value1 = GetPolicyOutput::builder().policy_store_id("ps-1").build();
        let value2 = GetPolicyOutput::builder().policy_store_id("ps-2").build();

        assert_eq!(policy_cache.put(key.clone(), value1.clone()), None);
        assert_eq!(policy_cache.put(key, value2), Some(value1));
    }

    #[test]
    fn get_on_an_empty_cache_returns_none() {
        let policy_cache = GetPolicyOutputCache::new();
        let missing_key = PolicyId("missing_key".to_string());
        assert_eq!(policy_cache.get(&missing_key), None);
    }

    #[test]
    fn get_on_a_missing_key_returns_none() {
        let mut policy_cache = GetPolicyOutputCache::new();
        let key = PolicyId("key".to_string());
        let value = GetPolicyOutput::builder().build();
        let missing_key = PolicyId("missing_key".to_string());

        assert_eq!(policy_cache.put(key, value), None);
        assert_eq!(policy_cache.get(&missing_key), None);
    }

    #[test]
    fn get_on_a_present_key_returns_value() {
        let mut policy_cache = GetPolicyOutputCache::new();
        let key = PolicyId("key".to_string());
        let value = GetPolicyOutput::builder().build();
        assert_eq!(policy_cache.put(key.clone(), value.clone()), None);
        assert_eq!(policy_cache.get(&key), Some(&value));
    }

    #[test]
    fn remove_on_a_missing_key_returns_none() {
        let mut policy_cache = GetPolicyOutputCache::new();
        let missing_key = PolicyId("missing_key".to_string());
        assert!(policy_cache.remove(&missing_key).is_none());
    }

    #[test]
    fn remove_on_a_present_key_returns_value() {
        let mut policy_cache = GetPolicyOutputCache::new();
        let key = PolicyId("key".to_string());
        let value1 = GetPolicyOutput::builder().policy_store_id("ps-1").build();

        assert_eq!(policy_cache.put(key.clone(), value1.clone()), None);
        assert_eq!(policy_cache.remove(&key), Some(value1));
        assert!(policy_cache.get(&key).is_none());
    }

    #[test]
    fn no_new_policy_update() {
        let mut policy_cache = GetPolicyOutputCache::new();
        let mut loaded_policies: HashMap<PolicyId, PolicyItem> = HashMap::new();

        let key = PolicyId("p-1".to_string());
        let policy_output = GetPolicyOutput::builder()
            .policy_id("p-1")
            .last_updated_date(DateTime::from_secs(Utc::now().timestamp()))
            .build();
        let policy_item = PolicyItem::builder()
            .policy_id("p-1")
            .last_updated_date(DateTime::from_secs(Utc::now().timestamp()))
            .build();

        policy_cache.put(key.clone(), policy_output);
        loaded_policies.insert(key, policy_item);

        assert!(policy_cache
            .get_pending_updates(&loaded_policies)
            .is_empty());
    }

    #[test]
    fn return_to_be_deleted_policy() {
        let mut policy_cache = GetPolicyOutputCache::new();
        let loaded_policies: HashMap<PolicyId, PolicyItem> = HashMap::new();

        let key = PolicyId("p-1".to_string());
        let policy_output = GetPolicyOutput::builder()
            .policy_id("p-1")
            .last_updated_date(DateTime::from_secs(Utc::now().timestamp()))
            .build();

        policy_cache.put(key.clone(), policy_output);

        let result = policy_cache.get_pending_updates(&loaded_policies);
        assert!(result.contains_key(&key));
        assert_eq!(*result.get(&key).unwrap(), CacheChange::Deleted);
    }

    #[test]
    fn return_to_be_updated_policy() {
        let mut policy_cache = GetPolicyOutputCache::new();
        let mut loaded_policies: HashMap<PolicyId, PolicyItem> = HashMap::new();

        let key = PolicyId("p-1".to_string());
        let policy_output = GetPolicyOutput::builder()
            .policy_id("p-1")
            .last_updated_date(DateTime::from_secs(Utc::now().timestamp()))
            .build();
        let policy_item = PolicyItem::builder()
            .policy_id("p-1")
            .last_updated_date(DateTime::from_secs(
                (Utc::now() + Duration::minutes(1)).timestamp(),
            ))
            .build();

        policy_cache.put(key.clone(), policy_output);
        loaded_policies.insert(key.clone(), policy_item);

        let result = policy_cache.get_pending_updates(&loaded_policies);
        assert!(result.contains_key(&key));
        assert_eq!(*result.get(&key).unwrap(), CacheChange::Updated);
    }

    #[test]
    fn return_to_be_added_policy() {
        let policy_cache = GetPolicyOutputCache::new();
        let mut loaded_policies: HashMap<PolicyId, PolicyItem> = HashMap::new();

        let key = PolicyId("p-1".to_string());
        let policy_item = PolicyItem::builder()
            .policy_id("p-1")
            .last_updated_date(DateTime::from_secs(Utc::now().timestamp()))
            .build();

        loaded_policies.insert(key.clone(), policy_item);

        let result = policy_cache.get_pending_updates(&loaded_policies);
        assert!(result.contains_key(&key));
        assert_eq!(*result.get(&key).unwrap(), CacheChange::Created);
    }
}
