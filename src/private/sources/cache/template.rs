//! This module contains the implementation of the template cache.
use aws_sdk_verifiedpermissions::operation::get_policy_template::GetPolicyTemplateOutput;
use aws_sdk_verifiedpermissions::types::PolicyTemplateItem;
use std::collections::HashMap;
use tracing::{debug, instrument};

use crate::private::sources::{Cache, CacheChange};
use crate::private::types::aliases::TemplateCache;
use crate::private::types::template_id::TemplateId;
use std::collections::hash_map::IterMut;
use std::iter::IntoIterator;

/// An implementation of the template cache. This caches the raw `GetPolicyTemplateOutput` structs
/// from AVP `GetPolicyTemplate` calls.
#[derive(Debug)]
pub struct PolicyTemplateCache {
    /// Template cache of `PolicyTemplateId`, `GetPolicyTemplateOutput`
    template_cache: TemplateCache<GetPolicyTemplateOutput>,
}

/// An `IntoIterator` implementation for the template cache. This enables iteration of cache values
/// without the need to clone the whole cache
impl<'a> IntoIterator for &'a mut PolicyTemplateCache {
    type Item = (&'a TemplateId, &'a mut GetPolicyTemplateOutput);
    type IntoIter = IterMut<'a, TemplateId, GetPolicyTemplateOutput>;

    fn into_iter(self) -> IterMut<'a, TemplateId, GetPolicyTemplateOutput> {
        self.template_cache.iter_mut()
    }
}

impl Cache for PolicyTemplateCache {
    type Key = TemplateId;
    type Value = GetPolicyTemplateOutput;
    type LoadedItems = HashMap<Self::Key, PolicyTemplateItem>;
    type PendingUpdates = HashMap<Self::Key, CacheChange>;

    fn new() -> Self {
        Self {
            template_cache: HashMap::new(),
        }
    }

    #[instrument(level = "trace", skip(self))]
    fn get(&self, key: &Self::Key) -> Option<&Self::Value> {
        self.template_cache.get(key)
    }

    #[instrument(level = "trace", skip(self, value))]
    fn put(&mut self, key: Self::Key, value: Self::Value) -> Option<Self::Value> {
        self.template_cache.insert(key, value)
    }

    #[instrument(level = "trace", skip(self))]
    fn remove(&mut self, key: &Self::Key) -> Option<Self::Value> {
        self.template_cache.remove(key)
    }

    #[instrument(level = "trace", skip(self))]
    fn get_pending_updates(&self, ids_map: &Self::LoadedItems) -> Self::PendingUpdates {
        let mut template_updates: Self::PendingUpdates = HashMap::new();

        for template_id in self.template_cache.clone().keys() {
            if !ids_map.contains_key(template_id) {
                template_updates.insert(template_id.clone(), CacheChange::Deleted);
            }
        }

        for (template_id, template_item) in ids_map {
            if !self.template_cache.contains_key(template_id) {
                template_updates.insert(template_id.clone(), CacheChange::Created);
            } else if template_item.last_updated_date
                > self.template_cache[template_id].last_updated_date
            {
                template_updates.insert(template_id.clone(), CacheChange::Updated);
            }
        }
        debug!("Template Cache Pending Updates: template_pending_updates={template_updates:?}");
        template_updates
    }
}
#[cfg(test)]
mod test {
    use crate::private::sources::cache::template::PolicyTemplateCache;
    use crate::private::sources::{Cache, CacheChange};
    use crate::private::types::template_id::TemplateId;
    use aws_sdk_verifiedpermissions::operation::get_policy_template::GetPolicyTemplateOutput;
    use aws_sdk_verifiedpermissions::types::PolicyTemplateItem;
    use aws_smithy_types::DateTime;
    use chrono::{Duration, Utc};
    use std::collections::HashMap;

    #[test]
    fn put_on_a_missing_key_returns_none() {
        let mut template_cache = PolicyTemplateCache::new();
        let missing_key = TemplateId("missing_key".to_string());
        let value = GetPolicyTemplateOutput::builder().build();
        assert_eq!(template_cache.put(missing_key, value), None);
    }

    #[test]
    fn put_on_a_present_key_returns_old_value() {
        let mut template_cache = PolicyTemplateCache::new();
        let key = TemplateId("key".to_string());
        let value1 = GetPolicyTemplateOutput::builder()
            .policy_store_id("ps-1")
            .build();
        let value2 = GetPolicyTemplateOutput::builder()
            .policy_store_id("ps-2")
            .build();

        assert_eq!(template_cache.put(key.clone(), value1.clone()), None);
        assert_eq!(template_cache.put(key, value2), Some(value1));
    }

    #[test]
    fn get_on_an_empty_cache_returns_none() {
        let template_cache = PolicyTemplateCache::new();
        let missing_key = TemplateId("missing_key".to_string());
        assert_eq!(template_cache.get(&missing_key), None);
    }

    #[test]
    fn get_on_a_missing_key_returns_none() {
        let mut template_cache = PolicyTemplateCache::new();
        let key = TemplateId("key".to_string());
        let value = GetPolicyTemplateOutput::builder().build();
        let missing_key = TemplateId("missing_key".to_string());

        assert_eq!(template_cache.put(key, value), None);
        assert_eq!(template_cache.get(&missing_key), None);
    }

    #[test]
    fn get_on_a_present_key_returns_value() {
        let mut template_cache = PolicyTemplateCache::new();
        let key = TemplateId("key".to_string());
        let value = GetPolicyTemplateOutput::builder().build();
        assert_eq!(template_cache.put(key.clone(), value.clone()), None);
        assert_eq!(template_cache.get(&key), Some(&value));
    }

    #[test]
    fn remove_on_a_missing_key_returns_none() {
        let mut template_cache = PolicyTemplateCache::new();
        let missing_key = TemplateId("missing_key".to_string());
        assert!(template_cache.remove(&missing_key).is_none());
    }

    #[test]
    fn remove_on_a_present_key_returns_value() {
        let mut template_cache = PolicyTemplateCache::new();
        let key = TemplateId("key".to_string());
        let value1 = GetPolicyTemplateOutput::builder()
            .policy_store_id("ps-1")
            .build();

        assert_eq!(template_cache.put(key.clone(), value1.clone()), None);
        assert_eq!(template_cache.remove(&key), Some(value1));
        assert!(template_cache.get(&key).is_none());
    }

    #[test]
    fn no_new_template_update() {
        let mut template_cache = PolicyTemplateCache::new();
        let mut loaded_templates: HashMap<TemplateId, PolicyTemplateItem> = HashMap::new();

        let key = TemplateId("pt-1".to_string());
        let template_output = GetPolicyTemplateOutput::builder()
            .policy_template_id("pt-1")
            .last_updated_date(DateTime::from_secs(Utc::now().timestamp()))
            .build();
        let template_item = PolicyTemplateItem::builder()
            .policy_template_id("pt-1")
            .last_updated_date(DateTime::from_secs(Utc::now().timestamp()))
            .build();

        template_cache.put(key.clone(), template_output);
        loaded_templates.insert(key, template_item);

        assert!(template_cache
            .get_pending_updates(&loaded_templates)
            .is_empty());
    }

    #[test]
    fn return_to_be_deleted_template() {
        let mut template_cache = PolicyTemplateCache::new();
        let loaded_templates: HashMap<TemplateId, PolicyTemplateItem> = HashMap::new();

        let key = TemplateId("pt-1".to_string());
        let template_output = GetPolicyTemplateOutput::builder()
            .policy_template_id("pt-1")
            .last_updated_date(DateTime::from_secs(Utc::now().timestamp()))
            .build();

        template_cache.put(key.clone(), template_output);

        let result = template_cache.get_pending_updates(&loaded_templates);
        assert!(result.contains_key(&key));
        assert_eq!(*result.get(&key).unwrap(), CacheChange::Deleted);
    }

    #[test]
    fn return_to_be_updated_template() {
        let mut template_cache = PolicyTemplateCache::new();
        let mut loaded_templates: HashMap<TemplateId, PolicyTemplateItem> = HashMap::new();

        let key = TemplateId("pt-1".to_string());
        let template_output = GetPolicyTemplateOutput::builder()
            .policy_template_id("pt-1")
            .last_updated_date(DateTime::from_secs(Utc::now().timestamp()))
            .build();
        let template_item = PolicyTemplateItem::builder()
            .policy_template_id("pt-1")
            .last_updated_date(DateTime::from_secs(
                (Utc::now() + Duration::minutes(1)).timestamp(),
            ))
            .build();

        template_cache.put(key.clone(), template_output);
        loaded_templates.insert(key.clone(), template_item);

        let result = template_cache.get_pending_updates(&loaded_templates);
        assert!(result.contains_key(&key));
        assert_eq!(*result.get(&key).unwrap(), CacheChange::Updated);
    }

    #[test]
    fn return_to_be_added_template() {
        let template_cache = PolicyTemplateCache::new();
        let mut loaded_templates: HashMap<TemplateId, PolicyTemplateItem> = HashMap::new();

        let key = TemplateId("pt-1".to_string());
        let template_item = PolicyTemplateItem::builder()
            .policy_template_id("pt-1")
            .last_updated_date(DateTime::from_secs(Utc::now().timestamp()))
            .build();

        loaded_templates.insert(key.clone(), template_item);

        let result = template_cache.get_pending_updates(&loaded_templates);
        assert!(result.contains_key(&key));
        assert_eq!(*result.get(&key).unwrap(), CacheChange::Created);
    }
}
