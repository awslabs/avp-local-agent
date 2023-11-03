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
                let statement = definition_detail
                    .statement
                    .ok_or_else(TranslatorException::StaticPolicyStatementNotFound)?;

                let cedar_policy = cedar_policy::Policy::parse(Some(policy_id.clone()), statement)?;
                debug!("Translated AVP Policy Definition to a Cedar Static Policy: policy_id={policy_id:?}");
                Ok(Static(cedar_policy))
            }

            PolicyDefinitionDetail::TemplateLinked(definition_detail) => {
                let template_id = definition_detail
                    .policy_template_id
                    .ok_or_else(TranslatorException::TemplateIdNotFound)?;

                let mut entity_map: HashMap<SlotId, EntityUid> = HashMap::new();
                update_entity_map(
                    &mut entity_map,
                    SlotId::principal(),
                    definition_detail.principal,
                )?;
                update_entity_map(
                    &mut entity_map,
                    SlotId::resource(),
                    definition_detail.resource,
                )?;
                debug!("Translated AVP Policy Definition to a Cedar Template Linked Policy: policy_id={policy_id:?}: template_id={template_id:?}");
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
        let statement = template_output
            .statement
            .ok_or_else(TranslatorException::TemplateStatementNotFound)?;

        let policy_template_id = template_output.policy_template_id;

        let cedar_template = cedar_policy::Template::parse(policy_template_id.clone(), statement)?;
        debug!("Translated AVP Policy Template to a Cedar Template: template_id={policy_template_id:?}");
        Ok(Self(cedar_template))
    }
}

/// Translates an Amazon Verified Permissions Schema to a wrapped Cedar schema, or returns a
/// `TranslatorException`
impl TryFrom<&str> for Schema {
    type Error = TranslatorException;

    #[instrument(skip(schema_str), err(Debug))]
    fn try_from(schema_str: &str) -> Result<Self, Self::Error> {
        let cedar_schema = cedar_policy::Schema::from_str(schema_str)?;
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
    entity_map: &mut HashMap<SlotId, EntityUid>,
    slot_id: SlotId,
    option_identifier: Option<EntityIdentifier>,
) -> Result<(), TranslatorException> {
    if let Some(identifier) = option_identifier {
        let identifier_type = identifier
            .entity_type
            .ok_or_else(TranslatorException::EntityNameNotFound)?;

        let identifier_id = identifier
            .entity_id
            .ok_or_else(TranslatorException::EntityIdNotFound)?;

        let entity_name = EntityTypeName::from_str(identifier_type.as_str())?;
        let entity_id = EntityId::from_str(identifier_id.as_str())?;
        let entity = EntityUid::from_type_name_and_id(entity_name, entity_id);
        debug!("Set Principal and Resource to the Entity Map: entity_name={identifier_type:?}: entity_id={identifier_id:?}");
        entity_map.insert(slot_id, entity);
    }
    Ok(())
}

#[cfg(test)]
mod test {
    use crate::private::sources::policy::core::PolicyDefinition;
    use crate::private::translator::avp_to_cedar::{update_entity_map, Policy, Schema, Template};
    use crate::private::translator::error::TranslatorException;
    use aws_sdk_verifiedpermissions::operation::get_policy_template::GetPolicyTemplateOutput;
    use aws_sdk_verifiedpermissions::types::{
        EntityIdentifier, PolicyDefinitionDetail, StaticPolicyDefinitionDetail,
        TemplateLinkedPolicyDefinitionDetail,
    };
    use cedar_policy::{Entities, EntityUid, SlotId};
    use cedar_policy_core::entities::EntitiesError;
    use std::collections::HashMap;

    const POLICY_ID: &str = "dummy-policy-id";
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
    }

    fn generate_resource_identifier() -> EntityIdentifier {
        EntityIdentifier::builder()
            .entity_id(RESOURCE_ENTITY_ID)
            .entity_type(RESOURCE_ENTITY_TYPE)
            .build()
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
            .build();

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
            .build();

        let definition = PolicyDefinition {
            policy_id: POLICY_ID.to_string(),
            detail: PolicyDefinitionDetail::Static(definition_detail),
        };

        assert!(matches!(
            Policy::try_from(definition),
            Err(TranslatorException::ParseObject(..)),
        ));
    }

    #[test]
    fn static_policy_translation_without_statement() {
        let definition_detail = StaticPolicyDefinitionDetail::builder().build();

        let definition = PolicyDefinition {
            policy_id: POLICY_ID.to_string(),
            detail: PolicyDefinitionDetail::Static(definition_detail),
        };

        assert!(matches!(
            Policy::try_from(definition),
            Err(TranslatorException::StaticPolicyStatementNotFound(..)),
        ));
    }

    #[test]
    fn template_linked_policy_valid_translation() {
        let definition_detail = TemplateLinkedPolicyDefinitionDetail::builder()
            .policy_template_id(TEMPLATE_ID.to_string())
            .principal(generate_principal_identifier())
            .resource(generate_resource_identifier())
            .build();

        let definition = PolicyDefinition {
            policy_id: POLICY_ID.to_string(),
            detail: PolicyDefinitionDetail::TemplateLinked(definition_detail),
        };
        let res = Policy::try_from(definition);
        assert!(res.is_ok());
        assert!(matches!(res.ok().unwrap(), Policy::TemplateLinked(..)));
    }

    #[test]
    fn template_linked_policy_translation_without_template_id() {
        let definition_detail = TemplateLinkedPolicyDefinitionDetail::builder()
            .principal(generate_principal_identifier())
            .resource(generate_resource_identifier())
            .build();

        let definition = PolicyDefinition {
            policy_id: POLICY_ID.to_string(),
            detail: PolicyDefinitionDetail::TemplateLinked(definition_detail),
        };

        assert!(matches!(
            Policy::try_from(definition),
            Err(TranslatorException::TemplateIdNotFound()),
        ));
    }

    // Template Translator Tests
    #[test]
    fn template_translator_valid_translation() {
        let template_output = GetPolicyTemplateOutput::builder()
            .policy_template_id(TEMPLATE_ID)
            .statement(VALID_TEMPLATE)
            .build();
        let res = Template::try_from(template_output);
        assert!(res.is_ok());
        let Template(template) = res.unwrap();
        assert_eq!(template.id().to_string(), TEMPLATE_ID);
    }

    #[test]
    fn template_translator_template_statement_not_found() {
        let output_without_statement = GetPolicyTemplateOutput::builder()
            .policy_template_id(TEMPLATE_ID)
            .build();
        assert!(matches!(
            Template::try_from(output_without_statement),
            Err(TranslatorException::TemplateStatementNotFound(..))
        ));
    }

    #[test]
    fn template_translator_parsing_error() {
        let output = GetPolicyTemplateOutput::builder()
            .policy_template_id(TEMPLATE_ID)
            .statement(INVALID_TEMPLATE)
            .build();
        assert!(matches!(
            Template::try_from(output),
            Err(TranslatorException::ParseObject(..))
        ));
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
        assert!(matches!(
            Schema::try_from(INVALID_SCHEMA),
            Err(TranslatorException::ParseSchema(..))
        ));
    }

    // Entities Test
    #[test]
    fn set_entities_with_empty_entity_type() {
        let mut entity_map: HashMap<SlotId, EntityUid> = HashMap::new();
        let identifier = EntityIdentifier::builder()
            .entity_id(PRINCIPAL_ENTITY_ID)
            .build();
        assert!(matches!(
            update_entity_map(&mut entity_map, SlotId::principal(), Some(identifier)),
            Err(TranslatorException::EntityNameNotFound(..))
        ));
    }

    #[test]
    fn set_entities_with_empty_entity_id() {
        let mut entity_map: HashMap<SlotId, EntityUid> = HashMap::new();
        let identifier = EntityIdentifier::builder()
            .entity_type(PRINCIPAL_ENTITY_TYPE)
            .build();
        assert!(matches!(
            update_entity_map(&mut entity_map, SlotId::principal(), Some(identifier)),
            Err(TranslatorException::EntityIdNotFound(..))
        ));
    }
}
