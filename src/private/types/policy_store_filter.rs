/// Structures necessary to represent `PolicyFilter` as part of a
/// policy source ID (i.e. `PolicySelector`)
///
/// We can't use the native SDK representations because they are non-exhaustive
/// and so can't implement Hash or Eq (required for things that are keys).
///
/// Instead, then, we use our own private representations while closely mapping
/// to the SDK versions so that, at the time of SDK invocations we can easily
/// produce the right structures.
///
use aws_sdk_verifiedpermissions::{
    error::BuildError,
    types::{
        EntityIdentifier, EntityReference as SdkEntityReference, PolicyFilter as SdkPolicyFilter,
        PolicyType,
    },
};
use input::{Entity, PolicyStoreFilterInput};
use serde_json::Value;
use std::{
    fmt::{self, Write},
    hash::{Hash, Hasher},
    str::FromStr,
};
use thiserror::Error;

/// `EntityReference` constrained to be Unspecified or `EntityIdentifier`
#[derive(Debug, Clone, PartialEq)]
struct EntityReference(SdkEntityReference);

impl fmt::Display for EntityReference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_char('{')?;
        match &self.0 {
            SdkEntityReference::Identifier(entity_identifier) => {
                formatter.write_str("identifier={entityType=")?;
                entity_identifier.entity_type().fmt(formatter)?;
                formatter.write_str(",entityId=")?;
                entity_identifier.entity_id().fmt(formatter)?;
                formatter.write_char('}')?;
            }
            SdkEntityReference::Unspecified(b) => {
                formatter.write_str("unspecified=")?;
                b.fmt(formatter)?;
            }
            _ => (),
        }
        formatter.write_char('}')
    }
}
/// Translate the parsed input into the type we use throughout
impl TryFrom<Entity> for EntityReference {
    type Error = PolicyFilterInputError;
    fn try_from(value: Entity) -> Result<Self, Self::Error> {
        Ok(match value {
            Entity::Unspecified(b) => Self(SdkEntityReference::Unspecified(b)),
            Entity::Identifier {
                entity_type,
                entity_id,
            } => Self(SdkEntityReference::Identifier(
                EntityIdentifier::builder()
                    .entity_id(&entity_id)
                    .entity_type(&entity_type)
                    .build()
                    .map_err(|e| {
                        PolicyFilterInputError::InvalidEntityReference(entity_type, entity_id, e)
                    })?,
            )),
        })
    }
}

//
// EntityValueType is effectively a constrained version of EntityReference,
// so a From relationship is simple to implement
//
impl From<&EntityReference> for SdkEntityReference {
    fn from(value: &EntityReference) -> Self {
        value.0.clone()
    }
}

/// Eq because `EntityValueType` is needed for Map keys
impl Eq for EntityReference {}

/// Hash because `EntityValueType` is needed for Map keys
impl Hash for EntityReference {
    fn hash<H: Hasher>(&self, state: &mut H) {
        match &self.0 {
            SdkEntityReference::Unspecified(b) => b.hash(state), // safe unwrap because of new-typing
            SdkEntityReference::Identifier(e) => {
                e.entity_type.hash(state);
                e.entity_id.hash(state);
            }
            _ => (),
        }
    }
}

///
/// A constrained version of the SDK's `PolicyFilter` that is Hash and Eq
///
#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub struct PolicyStoreFilter {
    principal: Option<EntityReference>,
    resource: Option<EntityReference>,
    policy_type: Option<PolicyType>,
    policy_template_id: Option<String>,
}

impl PolicyStoreFilter {
    fn validate(self) -> Result<Self, PolicyFilterInputError> {
        if self.policy_template_id.is_none()
            && self.principal.is_none()
            && self.resource.is_none()
            && self.policy_type.is_none()
        {
            Err(PolicyFilterInputError::EmptyFilter)
        } else {
            Ok(self)
        }
    }
}

/// Formats the `PolicyStoreFilter` as CLI shorthand using the given formatter.
impl fmt::Display for PolicyStoreFilter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut comma = "";
        if let Some(e_ref) = &self.principal {
            f.write_str("principal=")?;
            e_ref.fmt(f)?;
            comma = ",";
        }
        if let Some(e_ref) = &self.resource {
            f.write_str(comma)?;
            f.write_str("resource=")?;
            e_ref.fmt(f)?;
            comma = ",";
        }
        if let Some(policy_type) = &self.policy_type {
            f.write_str(comma)?;
            f.write_str("policyType=")?;
            match policy_type {
                PolicyType::Static => f.write_str("STATIC")?,
                PolicyType::TemplateLinked => f.write_str("TEMPLATE_LINKED")?,
                _ => f.write_str("UNSUPPORTED")?,
            }
            comma = ",";
        }
        if let Some(template_id) = &self.policy_template_id {
            f.write_str(comma)?;
            f.write_str("policyTemplateId=")?;
            template_id.fmt(f)?;
        }
        Ok(())
    }
}

/// Deserialize a CLI JSON-formatted policy filter specification
impl PolicyStoreFilter {
    /// Construct from a JSON Value
    ///
    /// # Errors
    /// If the `Value` does not contain expected structural information
    pub fn from_json_value(json: Value) -> Result<Self, PolicyFilterInputError> {
        serde_json::from_value::<PolicyStoreFilterInput>(json)
            .map_err(PolicyFilterInputError::JsonDeserializationError)
            .and_then(Self::try_from)
            .and_then(Self::validate)
    }
    /// Construct from a JSON string
    ///
    /// # Errors
    /// If the input string fails to parse into valid JSON, or the resultant
    /// JSON does not contain expected structural information
    pub fn from_json_str(json: &str) -> Result<Self, PolicyFilterInputError> {
        serde_json::from_str::<PolicyStoreFilterInput>(json)
            .map_err(PolicyFilterInputError::JsonDeserializationError)
            .and_then(Self::try_from)
            .and_then(Self::validate)
    }
    /// Construct from a CLI shorthand string
    ///
    /// # Errors
    /// If the input string fails to parse into valid structures, or the resultant
    /// parsed data does not contain expected structural information
    pub fn from_cli_str(s: &str) -> Result<Self, PolicyFilterInputError> {
        input::PolicyStoreFilterInput::from_str(s)
            .and_then(Self::try_from)
            .and_then(Self::validate)
    }
}

///
/// Get an SDK `PolicyFilter` from our representation
///
impl From<&PolicyStoreFilter> for SdkPolicyFilter {
    fn from(value: &PolicyStoreFilter) -> Self {
        Self::builder()
            .set_policy_template_id(value.policy_template_id.clone())
            .set_policy_type(value.policy_type.clone())
            .set_principal(value.principal.as_ref().map(SdkEntityReference::from))
            .set_resource(value.resource.as_ref().map(SdkEntityReference::from))
            .build()
    }
}

#[derive(Error, Debug)]
/// The errors that can be experienced when translating a policy store filter
/// expression into the internal form used in AVP SDK invocations.
pub enum PolicyFilterInputError {
    #[error("invalid entity reference {0} {1}: {2}")]
    InvalidEntityReference(String, String, BuildError),
    /// A JSON expression is invalid
    #[error("Empty filter")]
    EmptyFilter,
    /// A JSON expression is invalid
    #[error("JSON error: {0}")]
    JsonDeserializationError(serde_json::Error),
    /// A CLI shorthand expression is invalid
    #[error("shorthand syntax error: {0}")]
    ShorthandParseError(String),
    /// A CLI shorthand expression contains unsupported structures
    #[error("shorthand content error: {0}")]
    ShorthandContentError(String),
}

///
/// Convert the parsed version into a real version
///
impl TryFrom<PolicyStoreFilterInput> for PolicyStoreFilter {
    type Error = PolicyFilterInputError;

    fn try_from(value: PolicyStoreFilterInput) -> Result<Self, Self::Error> {
        Ok(Self {
            principal: value
                .principal
                .map_or(Ok(None), |v| EntityReference::try_from(v).map(Some))?,
            resource: value
                .resource
                .map_or(Ok(None), |v| EntityReference::try_from(v).map(Some))?,
            policy_type: value.policy_type.map(|v| match v {
                input::PolicyTypeInput::Static => PolicyType::Static,
                input::PolicyTypeInput::TemplateLinked => PolicyType::TemplateLinked,
            }),
            policy_template_id: value.policy_template_id,
        })
    }
}

///
/// The goal is to present to the user a simple and familiar syntax that allows
/// for simple declaration of filtering intent.
///
/// Two implementations are supported - serde, and
/// "CLI shorthand" via a custom parser
mod input {
    use crate::private::types::cli_shorthand::{self, Value};
    use serde::Deserialize;
    use std::str::FromStr;

    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    pub enum Entity {
        Unspecified(bool),
        #[serde(rename_all = "camelCase")]
        Identifier {
            entity_type: String,
            entity_id: String,
        },
    }

    /// Transform parsed CLI shorthand input for an `EntityInput` value
    impl<'a> TryFrom<Value<'a>> for Entity {
        type Error = super::PolicyFilterInputError;

        fn try_from(value: Value<'a>) -> Result<Self, Self::Error> {
            if let Value::Struct(c) = value {
                if let [(k, v)] = c.as_slice() {
                    match (*k, v) {
                        ("unspecified", Value::Simple(b)) => Ok(Self::Unspecified(*b == "true")),
                        ("identifier", Value::Struct(v)) if v.len() == 2 => match v.as_slice() {
                            [("entityType", Value::Simple(t)), ("entityId", Value::Simple(i))]
                            | [("entityId", Value::Simple(i)), ("entityType", Value::Simple(t))] => {
                                Ok(Self::Identifier {
                                    entity_type: (*t).to_string(),
                                    entity_id: (*i).to_string(),
                                })
                            }
                            _ => Err(super::PolicyFilterInputError::ShorthandContentError(
                                "unrecognized field or value for Entity identifier".into(),
                            )),
                        },
                        _ => Err(super::PolicyFilterInputError::ShorthandContentError(
                            format!("unrecognized type for Entity reference: {k}"),
                        )),
                    }
                } else {
                    Err(super::PolicyFilterInputError::ShorthandContentError(
                        "invalid content for Entity reference".into(),
                    ))
                }
            } else {
                Err(super::PolicyFilterInputError::ShorthandContentError(
                    "invalid value type for Entity reference".into(),
                ))
            }
        }
    }

    #[derive(Deserialize, Debug)]
    #[cfg_attr(test, derive(PartialEq))]
    #[serde(rename_all = "SCREAMING_SNAKE_CASE")]
    pub(super) enum PolicyTypeInput {
        Static,
        TemplateLinked,
    }

    // PolicyTypeInput From CLI shorthand input
    impl<'a> TryFrom<Value<'a>> for PolicyTypeInput {
        type Error = super::PolicyFilterInputError;

        fn try_from(value: Value<'a>) -> Result<Self, Self::Error> {
            match value.to_string().as_deref() {
                Some("STATIC") => Ok(Self::Static),
                Some("TEMPLATE_LINKED") => Ok(Self::TemplateLinked),
                _ => Err(super::PolicyFilterInputError::ShorthandContentError(
                    "Invalid value for Policy type".into(),
                )),
            }
        }
    }

    // String From CLI shorthand input
    impl<'a> TryFrom<Value<'a>> for String {
        type Error = super::PolicyFilterInputError;

        fn try_from(value: Value<'a>) -> Result<Self, Self::Error> {
            value
                .to_string()
                .ok_or(super::PolicyFilterInputError::ShorthandContentError(
                    "not a string".into(),
                ))
        }
    }

    #[derive(Deserialize, Default)]
    #[serde(rename_all = "camelCase")]
    pub(super) struct PolicyStoreFilterInput {
        #[serde(default)]
        pub(super) principal: Option<Entity>,
        #[serde(default)]
        pub(super) resource: Option<Entity>,
        #[serde(default)]
        pub(super) policy_type: Option<PolicyTypeInput>,
        #[serde(default)]
        pub(super) policy_template_id: Option<String>,
    }

    impl FromStr for PolicyStoreFilterInput {
        type Err = super::PolicyFilterInputError;

        /// `PolicyStoreFiltersInput` from CLI shorthand input
        fn from_str(s: &str) -> Result<Self, Self::Err> {
            let s = s.trim_ascii();
            if s.is_empty() {
                return Ok(Self::default());
            }
            let parsed = cli_shorthand::from_cli_string(s)
                .map_err(|e| super::PolicyFilterInputError::ShorthandParseError(e.to_string()))?;

            let mut principal: Option<Entity> = None;
            let mut resource: Option<Entity> = None;
            let mut policy_type: Option<PolicyTypeInput> = None;
            let mut policy_template_id: Option<String> = None;

            for (k, v) in parsed {
                match k {
                    "principal" => principal = Some(v.try_into()?),
                    "resource" => resource = Some(v.try_into()?),
                    "policyType" => policy_type = Some(v.try_into()?),
                    "policyTemplateId" => policy_template_id = Some(v.try_into()?),
                    _ => {
                        return Err(super::PolicyFilterInputError::ShorthandContentError(
                            format!("unrecognized field for policy filter: {k}"),
                        ))
                    }
                }
            }

            Ok(Self {
                principal,
                resource,
                policy_type,
                policy_template_id,
            })
        }
    }

    #[cfg(test)]
    mod tests {
        use serde_json::json;

        use super::*;

        #[test]
        fn json_all() {
            let json = json!(
                {
                    "principal": {
                      "identifier": {
                        "entityType": "User",
                        "entityId": "nobody"
                      }
                    },
                    "resource": {
                      "identifier": {
                        "entityType": "Path",
                        "entityId": "/one/two/three"
                      }
                    },
                    "policyType": "STATIC",
                    "policyTemplateId": "my-template-id"
                  }
            );
            let p: PolicyStoreFilterInput =
                serde_json::from_value(json).expect("Unable to parse intended format");
            assert_eq!(
                p.policy_template_id.expect("Template ID should be set"),
                "my-template-id"
            );
            assert_eq!(
                p.policy_type.expect("Policy type should be set"),
                PolicyTypeInput::Static
            );
            assert!(
                matches!(p.principal, Some(Entity::Identifier {entity_type, entity_id}) if entity_type == "User" && entity_id == "nobody")
            );
            assert!(
                matches!(p.resource, Some(Entity::Identifier {entity_type, entity_id}) if entity_type == "Path" && entity_id == "/one/two/three")
            );
        }
        #[test]
        fn json_all_with_unspecified() {
            let json = json!(
                {
                    "principal": {
                      "unspecified": true
                    },
                    "resource": {
                      "unspecified": false
                    },
                    "policyType": "TEMPLATE_LINKED",
                    "policyTemplateId": "my-template-id"
                  }
            );
            let p: PolicyStoreFilterInput =
                serde_json::from_value(json).expect("Unable to parse intended format");
            assert_eq!(
                p.policy_template_id.expect("Template ID should be set"),
                "my-template-id"
            );
            assert_eq!(
                p.policy_type.expect("Policy type should be set"),
                PolicyTypeInput::TemplateLinked
            );
            assert!(matches!(p.principal, Some(Entity::Unspecified(true))));
            assert!(matches!(p.resource, Some(Entity::Unspecified(false))));
        }
        #[test]
        fn json_none() {
            let json = json!({});
            let filters: PolicyStoreFilterInput =
                serde_json::from_value(json).expect("Unable to parse intended format");
            assert!(
                matches!(filters, PolicyStoreFilterInput{principal,resource,policy_type,policy_template_id} if principal.is_none() && resource.is_none() && policy_type.is_none() && policy_template_id.is_none())
            );
        }

        #[test]
        fn cli_all() {
            let cli = r"
                principal = {
                    identifier = {
                    entityType = User,
                    entityId = nobody
                    }
                },
                resource = {
                    identifier = {
                    entityType = Path,
                    entityId = /one/two/three
                    }
                },
                policyType = STATIC,
                policyTemplateId = my-template-id
            )";
            let p = PolicyStoreFilterInput::from_str(cli).expect("Unable to parse intended format");
            assert_eq!(
                p.policy_template_id.expect("Template ID should be set"),
                "my-template-id"
            );
            assert_eq!(
                p.policy_type.expect("Policy type should be set"),
                PolicyTypeInput::Static
            );
            assert!(
                matches!(p.principal, Some(Entity::Identifier {entity_type, entity_id}) if entity_type == "User" && entity_id == "nobody")
            );
            assert!(
                matches!(p.resource, Some(Entity::Identifier {entity_type, entity_id}) if entity_type == "Path" && entity_id == "/one/two/three")
            );
        }

        #[test]
        fn cli_all_with_unspecified() {
            let cli = r"
                principal = {
                    unspecified = true
                },
                resource = {
                    unspecified = false
                },
                policyType = TEMPLATE_LINKED,
                policyTemplateId = my-template-id
            ";
            let p: PolicyStoreFilterInput =
                PolicyStoreFilterInput::from_str(cli).expect("Unable to parse intended format");
            assert_eq!(
                p.policy_template_id.expect("Template ID should be set"),
                "my-template-id"
            );
            assert_eq!(
                p.policy_type.expect("Policy type should be set"),
                PolicyTypeInput::TemplateLinked
            );
            assert!(matches!(p.principal, Some(Entity::Unspecified(true))));
            assert!(matches!(p.resource, Some(Entity::Unspecified(false))));
        }

        #[test]
        fn cli_none() {
            let cli = "";
            let filters: PolicyStoreFilterInput =
                PolicyStoreFilterInput::from_str(cli).expect("Unable to parse intended format");
            assert!(
                matches!(filters, PolicyStoreFilterInput{principal,resource,policy_type,policy_template_id} if principal.is_none() && resource.is_none() && policy_type.is_none() && policy_template_id.is_none())
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;

    static FULL_FILTER_CLI: &str = r"
        principal = {
            identifier = {
                entityType = User,
                entityId = nobody
            }
        },
        resource = {
            identifier = {
                entityType = Path,
                entityId = /one/two/three
            }
        },
        policyType = STATIC,
        policyTemplateId = my-template-id
    ";

    static FULL_FILTER_JSON: &str = r#"{
        "principal": {
            "identifier": {
                "entityType": "User",
                "entityId": "nobody"
            }
        },
        "resource": {
            "identifier": {
                "entityType": "Path",
                "entityId": "/one/two/three"
            }
        },
        "policyType": "STATIC",
        "policyTemplateId": "my-template-id"
    }"#;

    #[test]
    fn test_full_filter_from_cli() {
        let filter = PolicyStoreFilter::from_cli_str(FULL_FILTER_CLI)
            .expect("shorthand should be correctly parsed");
        assert_eq!(
            filter
                .policy_template_id
                .expect("Template ID should be set"),
            "my-template-id"
        );
        assert_eq!(
            filter.policy_type.expect("Policy type should be set"),
            PolicyType::Static
        );
        assert!(
            matches!(filter.principal, Some(EntityReference(SdkEntityReference::Identifier(identifier))) if identifier.entity_type() == "User" && identifier.entity_id() == "nobody")
        );
        assert!(
            matches!(filter.resource, Some(EntityReference(SdkEntityReference::Identifier(identifier))) if identifier.entity_type() == "Path" && identifier.entity_id() == "/one/two/three")
        );
    }

    #[test]
    fn test_full_filter_from_json_str() {
        let filter = PolicyStoreFilter::from_json_str(FULL_FILTER_JSON)
            .expect("JSON str should be correctly parsed");
        assert_eq!(
            filter
                .policy_template_id
                .expect("Template ID should be set"),
            "my-template-id"
        );
        assert_eq!(
            filter.policy_type.expect("Policy type should be set"),
            PolicyType::Static
        );
        assert!(
            matches!(filter.principal, Some(EntityReference(SdkEntityReference::Identifier(identifier))) if identifier.entity_type() == "User" && identifier.entity_id() == "nobody")
        );
        assert!(
            matches!(filter.resource, Some(EntityReference(SdkEntityReference::Identifier(identifier))) if identifier.entity_type() == "Path" && identifier.entity_id() == "/one/two/three")
        );
    }

    #[test]
    fn test_full_filter_from_json_value() {
        let value: Value =
            serde_json::from_str(FULL_FILTER_JSON).expect("JSON str should be correctly parsed");
        let filter = PolicyStoreFilter::from_json_value(value)
            .expect("JSON str should represent a valid policy filter");
        assert_eq!(
            filter
                .policy_template_id
                .expect("Template ID should be set"),
            "my-template-id"
        );
        assert_eq!(
            filter.policy_type.expect("Policy type should be set"),
            PolicyType::Static
        );
        assert!(
            matches!(filter.principal, Some(EntityReference(SdkEntityReference::Identifier(identifier))) if identifier.entity_type() == "User" && identifier.entity_id() == "nobody")
        );
        assert!(
            matches!(filter.resource, Some(EntityReference(SdkEntityReference::Identifier(identifier))) if identifier.entity_type() == "Path" && identifier.entity_id() == "/one/two/three")
        );
    }

    #[test]
    fn test_full_filter_equality() {
        let cli_filter = PolicyStoreFilter::from_cli_str(FULL_FILTER_CLI)
            .expect("shorthand should be correctly parsed");
        let json_filter = PolicyStoreFilter::from_json_str(FULL_FILTER_JSON)
            .expect("JSON str should be correctly parsed");
        assert_eq!(cli_filter, json_filter);
    }

    #[test]
    fn test_use_as_hashmap_key() {
        let mut hashmap: HashMap<PolicyStoreFilter, bool> = HashMap::new();
        let cli_filter = PolicyStoreFilter::from_cli_str(FULL_FILTER_CLI)
            .expect("shorthand should be correctly parsed");
        hashmap.insert(cli_filter, true);
        let json_filter = PolicyStoreFilter::from_json_str(FULL_FILTER_JSON)
            .expect("JSON str should be correctly parsed");
        let filter_ref = hashmap.get(&json_filter);
        assert_eq!(Some(&true), filter_ref);
    }
}
