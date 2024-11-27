/// Structures necessary to represent PolicyFilter as part of a 
/// policy source ID (i.e. PolicyStoreId)
/// 
/// We can't use the native SDK representations because they are non-exhaustive
/// and so can't implement Hash or Eq (required for things that are keys).
/// 
/// Instead, then, we use our own private representations while closely mapping
/// to the SDK versions so that, at the time of SDK invocations we can easily
/// produce the right structures.
/// 
use std::{hash::{Hash, Hasher}, str::FromStr};
use aws_sdk_verifiedpermissions::{error::BuildError, types::{EntityIdentifier, EntityReference, PolicyFilter, PolicyType}};
use input::{EntityInput, PolicyStoreFiltersInput};
use serde_json::Value;
use thiserror::Error;

/// EntityReference constrained to be Unspecified or EntityIdentifier
#[derive(Debug, Clone, PartialEq)]
enum EntityValueType {
    Unspecified(EntityReference),
    Entity(EntityReference)
}

/// Translate the parsed input into the type we use throughout
impl TryFrom<EntityInput> for EntityValueType {
    type Error = PolicyFilterInputError;
    fn try_from(value: EntityInput) -> Result<Self, Self::Error> {
        Ok(match value {
            EntityInput::Unspecified(b) => Self::Unspecified(EntityReference::Unspecified(b)),
            EntityInput::Identifier { entity_type, entity_id } => 
                Self::Entity(EntityReference::Identifier(EntityIdentifier::builder()
                    .entity_id(&entity_id)
                    .entity_type(&entity_type)
                    .build()
                    .map_err(|e| PolicyFilterInputError::InvalidEntityReference(entity_type, entity_id,e))?))
        })
    }
}

//
// EntityValueType is effectively a constrained version of EntityReference,
// so a From relationship is simple to implement
//
impl From<&EntityValueType> for EntityReference {
    fn from(value: &EntityValueType) -> Self {
        match value {
            EntityValueType::Unspecified(b) => b.clone(),
            EntityValueType::Entity(e) => e.clone(),
        }
    }
}

/// Eq because EntityValueType is needed for Map keys
impl Eq for EntityValueType {}

/// Hash because EntityValueType is needed for Map keys
impl Hash for EntityValueType {
	fn hash<H: Hasher>(&self, state: &mut H) {
        match self {
            EntityValueType::Unspecified(b) => b.as_unspecified().unwrap().hash(state), // safe unwrap because of new-typing
            EntityValueType::Entity(e) => {
                let e = e.as_identifier().unwrap(); // safe unwrap because of new-typing
        		e.entity_type.hash(state);
		        e.entity_id.hash(state);
            }
        }
	}
}

///
/// A constrained version of the SDK's PolicyFilter that is Hash and Eq
///
#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub struct PolicyStoreFilters {
    principal: Option<EntityValueType>,
    resource: Option<EntityValueType>,
    policy_type: Option<PolicyType>,
    policy_template_id: Option<String>,
}

/// Deserialize a CLI JSON-formatted policy filter specification
impl PolicyStoreFilters {
    /// Construct from a JSON Value
    pub fn from_json_value(json: Value) -> Result<Self, PolicyFilterInputError> {
        serde_json::from_value::<PolicyStoreFiltersInput>(json).map_err(PolicyFilterInputError::JsonDeserializationError).and_then(Self::try_from)
    }
    /// Construct from a JSON string
    pub fn from_json_str(json: &str) -> Result<Self, PolicyFilterInputError> {
        serde_json::from_str::<PolicyStoreFiltersInput>(json).map_err(PolicyFilterInputError::JsonDeserializationError).and_then(Self::try_from)
    }
    /// Construct from a CLI shorthand string
    pub fn from_cli_str(s: &str) -> Result<Self, PolicyFilterInputError> {
        input::PolicyStoreFiltersInput::from_str(s).and_then(Self::try_from)
    }
}

///
/// Get an SDK PolicyFilter from our representation
///
impl From<&PolicyStoreFilters> for PolicyFilter {
	fn from(value: &PolicyStoreFilters) -> Self {
		Self::builder()
			.set_policy_template_id(value.policy_template_id.as_ref().cloned())
			.set_policy_type(value.policy_type.as_ref().cloned())
			.set_principal(value.principal.as_ref().map(EntityReference::from))
			.set_resource(value.resource.as_ref().map(EntityReference::from))
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
            principal: value.principal.map(|v| EntityValueType::try_from(v).map(Some)).unwrap_or(Ok(None))?,
            resource:  value.resource.map(|v| EntityValueType::try_from(v).map(Some)).unwrap_or(Ok(None))?,
            policy_type: value.policy_type .map(|v| {
                match v {
                    input::PolicyTypeInput::Static => PolicyType::Static,
                    input::PolicyTypeInput::TemplateLinked => PolicyType::TemplateLinked,
                }
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
    use std::str::FromStr;
    use serde::Deserialize;
    use crate::private::types::cli_shorthand::{self, CliShorthandValue};

    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    pub enum EntityInput {
        Unspecified(bool),
        #[serde(rename_all = "camelCase")]
        Identifier {
            entity_type: String,
            entity_id: String
        }
    }

    /// Transform parsed CLI shorthand input for an EntityInput value
    impl<'a> TryFrom<CliShorthandValue<'a>> for EntityInput {
        type Error = super::PolicyFilterInputError;
        
        fn try_from(value: CliShorthandValue<'a>) -> Result<Self, Self::Error> {
            if let CliShorthandValue::Struct(c) = value {
                if let [(k, v)] = c.as_slice() {
                    match (*k,v) {
                        ("unspecified", CliShorthandValue::SimpleValue(b)) => Ok(EntityInput::Unspecified(*b == "true")),
                        ("identifier", CliShorthandValue::Struct(v))  if v.len() == 2 => {
                            match v.as_slice() {
                                [("entityType",CliShorthandValue::SimpleValue(t)),("entityId",CliShorthandValue::SimpleValue(i))] | 
                                [("entityId",CliShorthandValue::SimpleValue(i)),("entityType",CliShorthandValue::SimpleValue(t))] => 
                                    Ok(EntityInput::Identifier{entity_type: t.to_string(), entity_id: i.to_string()}),
                                _ => Err(super::PolicyFilterInputError::ShorthandContentError("unrecognized field or value for Entity identifier".into()))
                            }
                        }
                        _ => Err(super::PolicyFilterInputError::ShorthandContentError(format!("unrecognized type for Entity reference: {}",k)))
                    }
                } else {
                    Err(super::PolicyFilterInputError::ShorthandContentError("invalid content for Entity reference".into()))
                }
            } else {
                Err(super::PolicyFilterInputError::ShorthandContentError("invalid value type for Entity reference".into()))
            }
        }
    }

    #[derive(Deserialize,Debug)]
    #[cfg_attr(test, derive(PartialEq))]
    #[serde(rename_all = "SCREAMING_SNAKE_CASE")]
    pub(super) enum PolicyTypeInput {
        Static,
        TemplateLinked
    }

    // PolicyTypeInput From CLI shorthand input
    impl<'a> TryFrom<CliShorthandValue<'a>> for PolicyTypeInput {
        type Error = super::PolicyFilterInputError;
    
        fn try_from(value: CliShorthandValue<'a>) -> Result<Self, Self::Error> {
            match value.to_string().as_deref() {
                Some("STATIC") => Ok(Self::Static),
                Some("TEMPLATE_LINKED") => Ok(Self::TemplateLinked),
                _ => Err(super::PolicyFilterInputError::ShorthandContentError("Invalid value for Policy type".into()))
            }
        }
    }

    // String From CLI shorthand input
    impl<'a> TryFrom<CliShorthandValue<'a>> for String {
        type Error = super::PolicyFilterInputError;
    
        fn try_from(value: CliShorthandValue<'a>) -> Result<Self, Self::Error> {
            value.to_string().ok_or(super::PolicyFilterInputError::ShorthandContentError("not a string".into()))
        }
    }

    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    pub(super) struct PolicyStoreFiltersInput {
        #[serde(default)]
        pub(super) principal: Option<EntityInput>,
        #[serde(default)]
        pub(super) resource: Option<EntityInput>,
        #[serde(default)]
        pub(super) policy_type: Option<PolicyTypeInput>,
        #[serde(default)]
        pub(super) policy_template_id: Option<String>,    
    }

    impl FromStr for PolicyStoreFiltersInput {
        type Err = super::PolicyFilterInputError;

        /// PolicyStoreFiltersInput from CLI shorthand input
        fn from_str(s: &str) -> Result<Self, Self::Err> {
            let parsed = cli_shorthand::from_cli_string(s).map_err(|e| super::PolicyFilterInputError::ShorthandParseError(e.to_string()))?;

            let mut principal: Option<EntityInput> = None;
            let mut resource: Option<EntityInput> = None;
            let mut policy_type: Option<PolicyTypeInput> = None;
            let mut policy_template_id: Option<String> = None;
    
            for (k,v) in parsed {
                match k {
                    "principal" => principal = Some(v.try_into()?),
                    "resource" => resource = Some(v.try_into()?),
                    "policyType" => policy_type = Some(v.try_into()?),
                    "policyTemplateId" => policy_template_id = Some(v.try_into()?),
                    _  => {return Err(super::PolicyFilterInputError::ShorthandContentError(format!("unrecognized field for policy filter: {}", k)))}
                }
            }

            Ok(PolicyStoreFiltersInput {
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
            let p: PolicyStoreFiltersInput = serde_json::from_value(json).expect("Unable to parse intended format");
            assert_eq!(p.policy_template_id.expect("Template ID should be set"), "my-template-id");
            assert_eq!(p.policy_type.expect("Policy type should be set"), PolicyTypeInput::Static);
            assert!(matches!(p.principal, Some(EntityInput::Identifier {entity_type, entity_id}) if entity_type == "User" && entity_id == "nobody"));
            assert!(matches!(p.resource, Some(EntityInput::Identifier {entity_type, entity_id}) if entity_type == "Path" && entity_id == "/one/two/three"));
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
            let p: PolicyStoreFiltersInput = serde_json::from_value(json).expect("Unable to parse intended format");
            assert_eq!(p.policy_template_id.expect("Template ID should be set"), "my-template-id");
            assert_eq!(p.policy_type.expect("Policy type should be set"), PolicyTypeInput::TemplateLinked);
            assert!(matches!(p.principal, Some(EntityInput::Unspecified(true))));
            assert!(matches!(p.resource, Some(EntityInput::Unspecified(false))));
        }
        #[test]
        fn json_none() {
            let json = json!({});
            let p: PolicyStoreFiltersInput = serde_json::from_value(json).expect("Unable to parse intended format");
            assert!(matches!(p, PolicyStoreFiltersInput{principal:a,resource:b,policy_type:c,policy_template_id:d} if a.is_none() && b.is_none() && c.is_none() && d.is_none()));
        }

        #[test]
        fn cli_all() {
            let cli = r#"
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
            )"#;
            let p  = PolicyStoreFiltersInput::from_str(cli).expect("Unable to parse intended format");
            assert_eq!(p.policy_template_id.expect("Template ID should be set"), "my-template-id");
            assert_eq!(p.policy_type.expect("Policy type should be set"), PolicyTypeInput::Static);
            assert!(matches!(p.principal, Some(EntityInput::Identifier {entity_type, entity_id}) if entity_type == "User" && entity_id == "nobody"));
            assert!(matches!(p.resource, Some(EntityInput::Identifier {entity_type, entity_id}) if entity_type == "Path" && entity_id == "/one/two/three"));
        }

        #[test]
        fn cli_all_with_unspecified() {
            let cli = r#"
                principal = {
                    unspecified = true
                },
                resource = {
                    unspecified = false
                },
                policyType = TEMPLATE_LINKED,
                policyTemplateId = my-template-id
            "#;
            let p: PolicyStoreFiltersInput = PolicyStoreFiltersInput::from_str(cli).expect("Unable to parse intended format");
            assert_eq!(p.policy_template_id.expect("Template ID should be set"), "my-template-id");
            assert_eq!(p.policy_type.expect("Policy type should be set"), PolicyTypeInput::TemplateLinked);
            assert!(matches!(p.principal, Some(EntityInput::Unspecified(true))));
            assert!(matches!(p.resource, Some(EntityInput::Unspecified(false))));
        }

        #[test]
        fn cli_none() {
            let cli = "";
            let p: PolicyStoreFiltersInput = PolicyStoreFiltersInput::from_str(cli).expect("Unable to parse intended format");
            assert!(matches!(p, PolicyStoreFiltersInput{principal:a,resource:b,policy_type:c,policy_template_id:d} if a.is_none() && b.is_none() && c.is_none() && d.is_none()));
        }


    }
}
