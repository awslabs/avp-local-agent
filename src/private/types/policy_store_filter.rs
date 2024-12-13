use aws_sdk_verifiedpermissions::{
    error::BuildError,
    types::{
        EntityIdentifier, EntityReference as SdkEntityReference, PolicyFilter as SdkPolicyFilter,
        PolicyType,
    },
};
use input::{Entity, PolicyStoreFiltersInput};
use serde_json::Value;
/// Structures necessary to represent `PolicyFilter` as part of a
/// policy source ID (i.e. `PolicyStoreId`)
///
/// We can't use the native SDK representations because they are non-exhaustive
/// and so can't implement Hash or Eq (required for things that are keys).
///
/// Instead, then, we use our own private representations while closely mapping
/// to the SDK versions so that, at the time of SDK invocations we can easily
/// produce the right structures.
///
use std::{
    hash::{Hash, Hasher},
    str::FromStr,
};
use thiserror::Error;

/// `EntityReference` constrained to be Unspecified or `EntityIdentifier`
#[derive(Debug, Clone, PartialEq)]
struct EntityReference(SdkEntityReference);

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
pub struct PolicyStoreFilters {
    principal: Option<EntityReference>,
    resource: Option<EntityReference>,
    policy_type: Option<PolicyType>,
    policy_template_id: Option<String>,
}

/// Deserialize a CLI JSON-formatted policy filter specification
impl PolicyStoreFilters {
    /// Construct from a JSON Value
    ///
    /// # Errors
    /// If the `Value` does not contain expected structural information
    pub fn from_json_value(json: Value) -> Result<Self, PolicyFilterInputError> {
        serde_json::from_value::<PolicyStoreFiltersInput>(json)
            .map_err(PolicyFilterInputError::JsonDeserializationError)
            .and_then(Self::try_from)
    }
    /// Construct from a JSON string
    ///
    /// # Errors
    /// If the input string fails to parse into valid JSON, or the resultant
    /// JSON does not contain expected structural information
    pub fn from_json_str(json: &str) -> Result<Self, PolicyFilterInputError> {
        serde_json::from_str::<PolicyStoreFiltersInput>(json)
            .map_err(PolicyFilterInputError::JsonDeserializationError)
            .and_then(Self::try_from)
    }
    /// Construct from a CLI shorthand string
    ///
    /// # Errors
    /// If the input string fails to parse into valid structures, or the resultant
    /// parsed data does not contain expected structural information
    pub fn from_cli_str(s: &str) -> Result<Self, PolicyFilterInputError> {
        input::PolicyStoreFiltersInput::from_str(s).and_then(Self::try_from)
    }
}

///
/// Get an SDK `PolicyFilter` from our representation
///
impl From<&PolicyStoreFilters> for SdkPolicyFilter {
    fn from(value: &PolicyStoreFilters) -> Self {
        Self::builder()
            .set_policy_template_id(value.policy_template_id.clone())
            .set_policy_type(value.policy_type.clone())
            .set_principal(value.principal.as_ref().map(SdkEntityReference::from))
            .set_resource(value.resource.as_ref().map(SdkEntityReference::from))
            .build()
    }
}

#[derive(Error, Debug)]
pub enum PolicyFilterInputError {
    #[error("invalid entity reference {0} {1}: {2}")]
    InvalidEntityReference(String, String, BuildError),
    #[error("JSON error: {0}")]
    JsonDeserializationError(serde_json::Error),
    #[error("shorthand syntax error: {0}")]
    ShorthandParseError(String),
    #[error("shorthand content error: {0}")]
    ShorthandContentError(String),
}

///
/// Convert the parsed version into a real version
///
impl TryFrom<PolicyStoreFiltersInput> for PolicyStoreFilters {
    type Error = PolicyFilterInputError;

    fn try_from(value: PolicyStoreFiltersInput) -> Result<Self, Self::Error> {
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
    pub(super) struct PolicyStoreFiltersInput {
        #[serde(default)]
        pub(super) principal: Option<Entity>,
        #[serde(default)]
        pub(super) resource: Option<Entity>,
        #[serde(default)]
        pub(super) policy_type: Option<PolicyTypeInput>,
        #[serde(default)]
        pub(super) policy_template_id: Option<String>,
    }

    impl FromStr for PolicyStoreFiltersInput {
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
            let p: PolicyStoreFiltersInput =
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
            let p: PolicyStoreFiltersInput =
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
            let filters: PolicyStoreFiltersInput =
                serde_json::from_value(json).expect("Unable to parse intended format");
            assert!(
                matches!(filters, PolicyStoreFiltersInput{principal,resource,policy_type,policy_template_id} if principal.is_none() && resource.is_none() && policy_type.is_none() && policy_template_id.is_none())
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
            let p =
                PolicyStoreFiltersInput::from_str(cli).expect("Unable to parse intended format");
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
            let p: PolicyStoreFiltersInput =
                PolicyStoreFiltersInput::from_str(cli).expect("Unable to parse intended format");
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
            let filters: PolicyStoreFiltersInput =
                PolicyStoreFiltersInput::from_str(cli).expect("Unable to parse intended format");
            assert!(
                matches!(filters, PolicyStoreFiltersInput{principal,resource,policy_type,policy_template_id} if principal.is_none() && resource.is_none() && policy_type.is_none() && policy_template_id.is_none())
            );
        }
    }
}
