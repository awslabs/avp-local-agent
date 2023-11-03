//! Contains type aliases used in the crate.
use crate::private::types::policy_id::PolicyId;
use crate::private::types::template_id::TemplateId;
use std::collections::HashMap;

/// A type to store various pieces of data from an AVP Policy Store. i.e., `Policies`, `Templates`,
/// `Schemas`.
pub type PolicyCache<T> = HashMap<PolicyId, T>;

/// A type alias to store `Templates` from an AVP Policy Store.
pub type TemplateCache<T> = HashMap<TemplateId, T>;
