use crate::private::sources::policy::core::PolicyDefinition;
use crate::private::translator::avp_to_cedar::Policy::{Static, TemplateLinked};
use crate::private::translator::error::TranslatorException;
use crate::private::types::policy_id::PolicyId;
use crate::private::types::template_id::TemplateId;
use aws_sdk_verifiedpermissions::operation::get_policy_template::GetPolicyTemplateOutput;
use aws_sdk_verifiedpermissions::types::{EntityIdentifier, PolicyDefinitionDetail};
use cedar_policy::{EntityId, EntityTypeName, EntityUid, SlotId};
use std::collections::HashMap;
use std::str::FromStr;
use tracing::{debug, instrument};

/// This wraps the cases for `Static` and `TemplateLinked` policies from the `PolicyDefinitionDetail`
/// in order to facilitate cedar translation to Policy Sets.
#[derive(Eq, PartialEq, Debug, Clone)]
pub enum Policy {
    Static(cedar_policy::Policy),
    TemplateLinked(PolicyId, TemplateId, HashMap<SlotId, EntityUid>),
}

///This wraps the cedar `Template` from the, in order to facilitate cedar translation to Policy Sets.
#[derive(Debug)]
pub struct Template(pub(crate) cedar_policy::Template);

///This wraps the cedar `Schema`, in order to facilitate cedar translation to build `AuthorizationData`.
#[derive(Debug)]
pub struct Schema(pub(crate) cedar_policy::Schema);

/// Translates an Amazon Verified Permissions `PolicyDefinition` to a wrapped Cedar static policy or a
/// template linked policy, or returns a `TranslatorException`. The translated policy can help build
/// a policy set
impl TryFrom<PolicyDefinition> for Policy {
    type Error = TranslatorException;

    #[instrument(skip(definition), err(Debug))]
    fn try_from(definition: PolicyDefinition) -> Result<Self, Self::Error> {
        let PolicyDefinition { policy_id, detail } = definition;

        match detail {
            PolicyDefinitionDetail::Static(definition_detail) => {
                let cedar_policy = cedar_policy::Policy::parse(
                    Some(policy_id.clone()),
                    definition_detail.statement,
                )
                .map_err(|_e| TranslatorException::ParsePolicy(policy_id.to_string()))?;
                debug!("Translated AVP Policy Definition to a Cedar Static Policy: policy_id={policy_id:?}");
                Ok(Static(cedar_policy))
            }

            PolicyDefinitionDetail::TemplateLinked(definition_detail) => {
                let template_id = definition_detail.policy_template_id;

                let mut entity_map: HashMap<SlotId, EntityUid> = HashMap::new();
                update_entity_map(
                    policy_id.clone(),
                    &mut entity_map,
                    SlotId::principal(),
                    definition_detail.principal,
                )?;
                update_entity_map(
                    policy_id.clone(),
                    &mut entity_map,
                    SlotId::resource(),
                    definition_detail.resource,
                )?;
                debug!("Translated AVP Policy Definition to a Cedar Template Linked Policy: policy_id={policy_id}: template_id={template_id}");
                Ok(TemplateLinked(
                    PolicyId(policy_id),
                    TemplateId(template_id),
                    entity_map,
                ))
            }
            _ => Err(TranslatorException::InvalidInput()),
        }
    }
}

/// Translates an Amazon Verified Permissions template to a wrapped Cedar template, or returns a
/// `TranslatorException`. The translated can help build a policy set.
impl TryFrom<GetPolicyTemplateOutput> for Template {
    type Error = TranslatorException;

    #[instrument(skip(template_output), err(Debug))]
    fn try_from(template_output: GetPolicyTemplateOutput) -> Result<Self, Self::Error> {
        let policy_template_id = template_output.policy_template_id;

        let cedar_template = cedar_policy::Template::parse(
            Some(policy_template_id.clone()),
            template_output.statement,
        )
        .map_err(|_| TranslatorException::ParseTemplate(policy_template_id.clone()))?;

        debug!(
            "Translated AVP Policy Template to a Cedar Template: template_id={policy_template_id}"
        );
        Ok(Self(cedar_template))
    }
}

/// Translates an Amazon Verified Permissions Schema to a wrapped Cedar schema, or returns a
/// `TranslatorException`
impl TryFrom<&str> for Schema {
    type Error = TranslatorException;

    #[instrument(skip(schema_str), err(Debug))]
    fn try_from(schema_str: &str) -> Result<Self, Self::Error> {
        let cedar_schema = cedar_policy::Schema::from_str(schema_str)
            .map_err(|_e| TranslatorException::ParseSchema())?;
        if let Ok(action_entities) = cedar_schema.action_entities() {
            let schema_entities_ids = action_entities
                .iter()
                .map(cedar_policy::Entity::uid)
                .collect::<Vec<_>>();
            debug!("Translated AVP Schema to a Cedar Schema: entity_ids={schema_entities_ids:?}");
        }
        Ok(Self(cedar_schema))
    }
}

/// Set principal and resource to the entity map
#[instrument(skip_all, err(Debug))]
fn update_entity_map(
    policy_id: String,
    entity_map: &mut HashMap<SlotId, EntityUid>,
    slot_id: SlotId,
    option_identifier: Option<EntityIdentifier>,
) -> Result<(), TranslatorException> {
    if let Some(identifier) = option_identifier {
        let entity_name = EntityTypeName::from_str(&identifier.entity_type)
            .map_err(|_e| TranslatorException::ParseEntity(policy_id.clone()))?;
        let entity_id = EntityId::from_str(&identifier.entity_id)
            .map_err(|_e| TranslatorException::ParseEntity(policy_id))?;
        let entity = EntityUid::from_type_name_and_id(entity_name, entity_id);
        entity_map.insert(slot_id, entity);
    }
    Ok(())
}

#[cfg(test)]
mod test {
    use crate::private::sources::policy::core::PolicyDefinition;
    use crate::private::translator::avp_to_cedar::{Policy, Schema, Template};
    use crate::private::translator::error::TranslatorException;
    use aws_sdk_verifiedpermissions::operation::get_policy_template::GetPolicyTemplateOutput;
    use aws_sdk_verifiedpermissions::types::{
        EntityIdentifier, PolicyDefinitionDetail, StaticPolicyDefinitionDetail,
        TemplateLinkedPolicyDefinitionDetail,
    };
    use aws_smithy_types::DateTime;
    use cedar_policy::Entities;
    use cedar_policy_core::entities::EntitiesError;

    const POLICY_ID: &str = "dummy-policy-id";
    const POLICY_STORE_ID: &str = "dummy-policy-store-id";
    const TEMPLATE_ID: &str = "dummy-template-id";
    const VALID_POLICY: &str = r#"
        permit(
            principal == User::"alice",
            action == Action::"view",
            resource == Photo::"VacationPhoto94.jpg"
        );"#;
    const INVALID_POLICY: &str = r#"
        permit(
            principal == User::"alice",
            action == Action::"view",
        );"#;
    const PRINCIPAL_ENTITY_TYPE: &str = "USER";
    const PRINCIPAL_ENTITY_ID: &str = "alice";
    const RESOURCE_ENTITY_TYPE: &str = "PHOTO";
    const RESOURCE_ENTITY_ID: &str = "VacationPhoto22.jpg";
    const VALID_TEMPLATE: &str = r#"
        permit (
            principal == ?principal,
            action in [Action::"ReadBox"],
            resource == ?resource
        );"#;
    const INVALID_TEMPLATE: &str = r#"
        permit (
            principal == ?principal,
            action in [Action::"Rea
        );"#;
    const VALID_SCHEMA: &str = r#"
    {
    "AvpLocalAgent": {
        "entityTypes": {
            "User": {
                "memberOfTypes": ["UserGroup"],
                "shape": {
                    "type": "Record",
                    "attributes": {
                        "department": {
                            "type": "String"
                        },
                        "jobLevel": {
                            "type": "Long"
                        }
                    }
                }
            },
            "UserGroup": {},
            "Photo": {
                "shape": {
                    "type": "Record",
                    "attributes": {
                        "private": {
                            "type": "Boolean"
                        }
                    }
                }
            }
        },
        "actions": {
            "viewPhoto": {
                "appliesTo": {
                    "principalTypes": ["User"],
                    "resourceTypes": ["Photo"],
                    "context": {
                        "type": "Record",
                        "attributes": {
                            "authenticated": {
                                "type": "Boolean"
                            }
                        }
                    }
                }
            }
        }
    }}"#;
    const INVALID_SCHEMA: &str = r#"
    {
    "AvpLocalAgent": {
        "entityTypo": {},
        "actions": {
            "public": {},
            "like": {
                "memberOf": [{
                    "id": "public"
                }]
            }
        }
    }}"#;

    fn generate_principal_identifier() -> EntityIdentifier {
        EntityIdentifier::builder()
            .entity_id(PRINCIPAL_ENTITY_ID)
            .entity_type(PRINCIPAL_ENTITY_TYPE)
            .build()
            .unwrap()
    }

    fn generate_resource_identifier() -> EntityIdentifier {
        EntityIdentifier::builder()
            .entity_id(RESOURCE_ENTITY_ID)
            .entity_type(RESOURCE_ENTITY_TYPE)
            .build()
            .unwrap()
    }

    fn generate_action_entity() -> Result<Entities, EntitiesError> {
        let action_json =
            r#"[{"uid":{"type":"AvpLocalAgent::Action","id":"viewPhoto"},"attrs":{},"parents":[]}]"#
                .to_string();
        Entities::from_json_str(&action_json, None)
    }

    // Policy Translator Test
    #[test]
    fn static_policy_valid_translation() {
        let definition_detail = StaticPolicyDefinitionDetail::builder()
            .statement(VALID_POLICY)
            .build()
            .unwrap();

        let definition = PolicyDefinition {
            policy_id: POLICY_ID.to_string(),
            detail: PolicyDefinitionDetail::Static(definition_detail),
        };

        let res = Policy::try_from(definition);
        assert!(res.is_ok());
        assert!(matches!(res.ok().unwrap(), Policy::Static(..)));
    }

    #[test]
    fn static_policy_translation_invalid_policy() {
        let definition_detail = StaticPolicyDefinitionDetail::builder()
            .statement(INVALID_POLICY)
            .build()
            .unwrap();

        let definition = PolicyDefinition {
            policy_id: POLICY_ID.to_string(),
            detail: PolicyDefinitionDetail::Static(definition_detail),
        };

        let error = Policy::try_from(definition);
        assert!(matches!(error, Err(TranslatorException::ParsePolicy(..)),));
        assert_eq!(
            error.err().unwrap().to_string(),
            "Error occurred when parsing the policy, policy id: dummy-policy-id.",
        );
    }

    #[test]
    fn template_linked_policy_valid_translation() {
        let definition_detail = TemplateLinkedPolicyDefinitionDetail::builder()
            .policy_template_id(TEMPLATE_ID.to_string())
            .principal(generate_principal_identifier())
            .resource(generate_resource_identifier())
            .build()
            .unwrap();

        let definition = PolicyDefinition {
            policy_id: POLICY_ID.to_string(),
            detail: PolicyDefinitionDetail::TemplateLinked(definition_detail),
        };
        let res = Policy::try_from(definition);
        assert!(res.is_ok());
        assert!(matches!(res.ok().unwrap(), Policy::TemplateLinked(..)));
    }

    // Template Translator Tests
    #[test]
    fn template_translator_valid_translation() {
        let template_output = GetPolicyTemplateOutput::builder()
            .policy_store_id(POLICY_STORE_ID)
            .policy_template_id(TEMPLATE_ID)
            .statement(VALID_TEMPLATE)
            .created_date(DateTime::from_secs(0))
            .last_updated_date(DateTime::from_secs(0))
            .build()
            .unwrap();
        let res = Template::try_from(template_output);
        assert!(res.is_ok());
        let Template(template) = res.unwrap();
        assert_eq!(template.id().to_string(), TEMPLATE_ID);
    }

    #[test]
    fn template_translator_parsing_error() {
        let output = GetPolicyTemplateOutput::builder()
            .policy_store_id(POLICY_STORE_ID)
            .policy_template_id(TEMPLATE_ID)
            .statement(INVALID_TEMPLATE)
            .created_date(DateTime::from_secs(0))
            .last_updated_date(DateTime::from_secs(0))
            .build()
            .unwrap();
        let error = Template::try_from(output);
        assert!(matches!(error, Err(TranslatorException::ParseTemplate(..))));
        assert_eq!(
            error.err().unwrap().to_string(),
            "Error occurred when parsing the template, template id: dummy-template-id.",
        );
    }

    // Schema Translator Tests
    #[test]
    fn schema_translator_valid_translation() {
        let res = Schema::try_from(VALID_SCHEMA);
        assert!(res.is_ok());
        let Schema(schema) = res.unwrap();
        let action_from_translator = schema.action_entities();
        let action_from_json = generate_action_entity();
        assert!(action_from_translator.is_ok());
        assert!(action_from_json.is_ok());
        assert_eq!(action_from_translator.unwrap(), action_from_json.unwrap());
    }

    #[test]
    fn schema_translator_parsing_error() {
        let error = Schema::try_from(INVALID_SCHEMA);
        assert!(matches!(error, Err(TranslatorException::ParseSchema(..))));
        assert_eq!(
            error.err().unwrap().to_string(),
            "Error occurred when parsing the schema",
        );
    }
}
