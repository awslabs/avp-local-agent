//! Exposes a `PolicySource` trait and a `Policy` enum to package up the disjoint policy cases
//! that are provided in the Verified Permissions response. This also exposes an implementation
//! using Verified Permissions API calls.
use std::collections::HashMap;

use async_trait::async_trait;
use aws_sdk_verifiedpermissions::types::PolicyDefinitionDetail;
use aws_sdk_verifiedpermissions::Client;
use tracing::{debug, instrument};

use crate::private::sources::cache::policy::GetPolicyOutputCache;
use crate::private::sources::policy::{
    error::PolicySourceException,
    loader::ListPolicies,
    reader::{GetPolicy, GetPolicyInput},
};
use crate::private::sources::retry::BackoffStrategy;
use crate::private::sources::{Cache, CacheChange, Load, Read};
use crate::private::translator::avp_to_cedar::Policy;
use crate::private::types::policy_id::PolicyId;
use crate::private::types::policy_store_id::PolicyStoreId;

/// This wraps required AWS Verified Permissions models from `GetPolicyOutput` that need be
/// translated to Cedar models to build the Policy Set
#[derive(Debug, Clone)]
pub struct PolicyDefinition {
    /// The ID of the Policy
    pub policy_id: String,
    /// The Policy Definition
    pub detail: PolicyDefinitionDetail,
}

/// A trait to abstract fetching the most recent `Policy` data from the AVP APIs. This method, must
/// update local caches to minimize API calls.
#[async_trait]
pub trait PolicySource {
    /// The error type that can be returned by the `fetch` method.
    type Error;

    /// This method must call the AVP APIs `ListPolicies` and `GetPolicy` based on a minimal set of
    /// `policy_id`s that have been modified.
    async fn fetch(
        &mut self,
        policy_store_id: PolicyStoreId,
    ) -> Result<HashMap<PolicyId, Policy>, Self::Error>;
}

/// The `VerifiedPermissionsPolicySource` caches the most recent state for remote verified
/// permissions policies and provides a simplified input to the Cedar translation component.
#[derive(Debug)]
pub struct VerifiedPermissionsPolicySource {
    /// A loader to list Policy Ids.
    loader: ListPolicies,

    /// A reader to fetch Policy Template.
    reader: GetPolicy,

    /// A cache used to minimize API calls to `GetPolicies`.
    cache: GetPolicyOutputCache,
}

impl VerifiedPermissionsPolicySource {
    /// Constructs a new `VerifiedPermissionsPolicySource` from a `Client`.
    pub fn from(client: Client) -> Self {
        Self {
            loader: ListPolicies::new(client.clone()),
            reader: GetPolicy::new(client, BackoffStrategy::default()),
            cache: GetPolicyOutputCache::new(),
        }
    }
}

/// Implements `PolicySource`.
#[async_trait]
impl PolicySource for VerifiedPermissionsPolicySource {
    type Error = PolicySourceException;

    #[instrument(skip(self), err(Debug))]
    async fn fetch(
        &mut self,
        policy_store_id: PolicyStoreId,
    ) -> Result<HashMap<PolicyId, Policy>, Self::Error> {
        let mut policy_definitions_map = HashMap::new();

        // Load policies and update policy cache
        let policy_cache_diff_map = self
            .cache
            .get_pending_updates(&self.loader.load(policy_store_id.clone()).await?);
        for (policy_id, cache_change) in policy_cache_diff_map {
            if cache_change == CacheChange::Deleted {
                self.cache.remove(&policy_id);
                debug!("Removed Policy from Cache: policy_id={policy_id:?}");
            } else {
                let read_input = GetPolicyInput::new(policy_store_id.clone(), policy_id.clone());
                let policy_output = self.reader.read(read_input).await?;

                self.cache.put(policy_id.clone(), policy_output);
                debug!("Updated Policy in Cache: policy_id={policy_id:?}");
            }
        }

        for (policy_id, policy_output) in &mut self.cache {
            let definition = policy_output
                .definition
                .as_ref()
                .ok_or_else(PolicySourceException::PolicyDefinitionNotFound)?;

            let cedar_policy = Policy::try_from(PolicyDefinition {
                policy_id: policy_output.policy_id.clone(),
                detail: definition.clone(),
            })?;

            policy_definitions_map.insert(policy_id.clone(), cedar_policy);
            debug!("Fetched Policy: policy_id={policy_id:?}");
        }

        Ok(policy_definitions_map)
    }
}

#[cfg(test)]
pub mod test {
    use aws_sdk_verifiedpermissions::operation::get_policy::GetPolicyOutput;
    use aws_sdk_verifiedpermissions::types::{
        EntityIdentifier, PolicyDefinitionDetail, PolicyType, StaticPolicyDefinitionDetail,
        TemplateLinkedPolicyDefinitionDetail,
    };
    use aws_smithy_types::DateTime;
    use chrono::Utc;
    use serde::{Deserialize, Serialize};

    use crate::private::sources::policy::core::{
        PolicyDefinition, PolicySource, VerifiedPermissionsPolicySource,
    };
    use crate::private::sources::test::{build_client, build_event, StatusCode};
    use crate::private::sources::Cache;
    use crate::private::translator::avp_to_cedar::Policy;
    use crate::private::types::policy_id::PolicyId;
    use crate::private::types::policy_store_id::PolicyStoreId;
    use crate::private::types::template_id::TemplateId;

    const ENTITY_TYPE: &str = "mockEntityType";
    const ENTITY_ID: &str = "mockEntityId";
    const PRINCIPAL_ENTITY_TYPE: &str = "principal_entity_type";
    const PRINCIPAL_ENTITY_ID: &str = "principal_entity_id";
    const RESOURCE_ENTITY_TYPE: &str = "resource_entity_type";
    const RESOURCE_ENTITY_ID: &str = "resource_entity_id";
    const POLICY_DEFINITION_DETAIL_DEFINITION: &str = r#"
        permit(
            principal == User::"alice",
            action == Action::"view",
            resource == Photo::"VacationPhoto94.jpg"
        );"#;
    const POLICY_DEFINITION_DETAIL_STATEMENT: &str = r#"
        permit(
            principal == User::"alice",
            action == Action::"view",
            resource == Photo::"VacationPhoto94.jpg"
        );"#;

    //https://docs.aws.amazon.com/verifiedpermissions/latest/apireference/API_ListPolicies.html#API_ListPolicies_RequestSyntax
    #[derive(Debug, Serialize, Deserialize)]
    pub struct ListPoliciesRequestEntityIdentifier {
        #[serde(rename = "entityId")]
        pub entity_id: String,
        #[serde(rename = "entityType")]
        pub entity_type: String,
    }

    #[derive(Debug, Serialize, Deserialize)]
    pub enum ListPoliciesRequestEntityReference {
        #[serde(rename = "identifier")]
        Identifier(ListPoliciesRequestEntityIdentifier),
        #[serde(rename = "unspecified")]
        Unspecified(bool),
    }

    #[derive(Debug, Serialize, Deserialize)]
    pub enum ListPoliciesRequestPolicyType {
        #[serde(rename = "STATIC")]
        Static,
        #[serde(rename = "TEMPLATE_LINKED")]
        TemplateLinked,
    }

    #[derive(Debug, Serialize, Deserialize, Default)]
    pub struct ListPoliciesRequestFilter {
        #[serde(rename = "policyTemplateId")]
        pub policy_template_id: Option<String>,
        #[serde(rename = "policyType")]
        pub policy_type: Option<ListPoliciesRequestPolicyType>,
        pub principal: Option<ListPoliciesRequestEntityReference>,
        pub resource: Option<ListPoliciesRequestEntityReference>,
    }

    #[derive(Debug, Serialize, Deserialize)]
    pub struct ListPoliciesRequest {
        #[serde(rename = "policyStoreId")]
        pub policy_store_id: String,
        #[serde(rename = "nextToken")]
        pub next_token: Option<String>,
        #[serde(rename = "maxResults")]
        pub max_results: i32,
        pub filter: Option<ListPoliciesRequestFilter>,
    }

    //https://docs.aws.amazon.com/verifiedpermissions/latest/apireference/API_ListPolicies.html#API_ListPolicies_ResponseSyntax
    #[derive(Debug, Serialize, Deserialize)]
    pub struct ListPoliciesResponse {
        #[serde(rename = "policies")]
        pub policies: Option<Vec<PolicyItemRaw>>,
        #[serde(rename = "nextToken")]
        pub next_token: Option<String>,
    }

    #[derive(Debug, Serialize, Deserialize)]
    pub struct PolicyItemRaw {
        #[serde(rename = "policyId")]
        pub policy_id: String,
        #[serde(rename = "policyStoreId")]
        pub policy_store_id: String,
        #[serde(rename = "policyType")]
        pub policy_type: Option<String>,
        #[serde(rename = "principal")]
        pub principal: Option<EntityIdentifierRaw>,
        #[serde(rename = "resource")]
        pub resource: Option<EntityIdentifierRaw>,
        #[serde(rename = "definition")]
        pub definition: Option<String>,
        #[serde(rename = "createdDate")]
        pub created_date: Option<String>,
        #[serde(rename = "lastUpdatedDate")]
        pub last_updated_date: Option<String>,
    }

    #[derive(Debug, Serialize, Deserialize)]
    pub struct EntityIdentifierRaw {
        #[serde(rename = "entityType")]
        entity_type: Option<String>,
        #[serde(rename = "entityId")]
        entity_id: Option<String>,
    }

    pub fn build_policy_item(
        policy_id: &PolicyId,
        policy_store_id: &PolicyStoreId,
        policy_type: Option<String>,
        principal: Option<EntityIdentifierRaw>,
        resource: Option<EntityIdentifierRaw>,
        definition: Option<String>,
    ) -> PolicyItemRaw {
        PolicyItemRaw {
            policy_id: policy_id.to_string(),
            policy_store_id: policy_store_id.to_string(),
            policy_type,
            principal,
            resource,
            definition,
            created_date: Some(Utc::now().to_rfc3339()),
            last_updated_date: Some(Utc::now().to_rfc3339()),
        }
    }

    pub fn build_entity_identifier(entity_type: &str, entity_id: &str) -> EntityIdentifierRaw {
        EntityIdentifierRaw {
            entity_type: Some(entity_type.to_string()),
            entity_id: Some(entity_id.to_string()),
        }
    }

    // https://docs.aws.amazon.com/verifiedpermissions/latest/apireference/API_GetPolicy.html
    #[derive(Debug, Serialize, Deserialize)]
    pub struct GetPolicyRequest {
        #[serde(rename = "policyId")]
        pub policy_id: String,
        #[serde(rename = "policyStoreId")]
        pub policy_store_id: String,
    }

    // https://docs.aws.amazon.com/verifiedpermissions/latest/apireference/API_GetPolicy.html
    #[derive(Debug, Serialize, Deserialize)]
    pub struct GetPolicyResponse {
        #[serde(rename = "policyId")]
        pub policy_id: Option<String>,
        #[serde(rename = "policyStoreId")]
        pub policy_store_id: Option<String>,
        #[serde(rename = "policyType")]
        pub policy_type: Option<String>,
        #[serde(rename = "principal")]
        pub principal: Option<EntityIdentifierRaw>,
        #[serde(rename = "resource")]
        pub resource: Option<EntityIdentifierRaw>,
        #[serde(rename = "definition")]
        pub definition: Option<PolicyDefinitionDetailRaw>,
        #[serde(rename = "createdDate")]
        pub created_date: Option<String>,
        #[serde(rename = "lastUpdatedDate")]
        pub last_updated_date: Option<String>,
    }

    #[derive(Debug, Serialize, Deserialize)]
    pub enum PolicyDefinitionDetailRaw {
        #[serde(rename = "static")]
        Static(StaticPolicyDefinitionDetailRaw),
        #[serde(rename = "templateLinked")]
        TemplateLinked(TemplateLinkedPolicyDefinitionDetailRaw),
        #[serde(rename = "unknown")]
        Unknown,
    }

    #[derive(Debug, Serialize, Deserialize)]
    pub struct StaticPolicyDefinitionDetailRaw {
        #[serde(rename = "description")]
        pub description: Option<String>,
        #[serde(rename = "statement")]
        pub statement: Option<String>,
    }

    #[derive(Debug, Serialize, Deserialize)]
    pub struct TemplateLinkedPolicyDefinitionDetailRaw {
        #[serde(rename = "policyTemplateId")]
        pub policy_template_id: Option<String>,
        #[serde(rename = "principal")]
        pub principal: Option<EntityIdentifierRaw>,
        #[serde(rename = "resource")]
        pub resource: Option<EntityIdentifierRaw>,
    }

    pub fn build_get_policy_response(
        policy_id: &PolicyId,
        policy_store_id: &PolicyStoreId,
        policy_type: &str,
        principal: EntityIdentifierRaw,
        resource: EntityIdentifierRaw,
        definition: PolicyDefinitionDetailRaw,
    ) -> GetPolicyResponse {
        GetPolicyResponse {
            policy_id: Some(policy_id.to_string()),
            policy_store_id: Some(policy_store_id.to_string()),
            policy_type: Some(policy_type.to_string()),
            principal: Some(principal),
            resource: Some(resource),
            definition: Some(definition),
            created_date: Some(Utc::now().to_rfc3339()),
            last_updated_date: Some(Utc::now().to_rfc3339()),
        }
    }

    #[tokio::test]
    async fn test_policy_source_fetch_returns_expected_results_with_mock_client() {
        let policy_store_id: PolicyStoreId = PolicyStoreId::from("mockPolicyStoreId".to_string());
        let policy_id_1 = PolicyId("mockPolicyId1".to_string());
        let policy_id_2 = PolicyId("mockPolicyId2".to_string());
        let policy_type = "STATIC";

        let loader_request = ListPoliciesRequest {
            policy_store_id: policy_store_id.to_string(),
            next_token: None,
            max_results: 1,
            filter: None,
        };

        let loader_response = ListPoliciesResponse {
            policies: Some(vec![build_policy_item(
                &policy_id_1,
                &policy_store_id,
                Some(policy_type.to_string()),
                Some(build_entity_identifier(ENTITY_TYPE, ENTITY_ID)),
                None,
                None,
            )]),
            next_token: None,
        };

        let reader_request = GetPolicyRequest {
            policy_id: policy_id_1.to_string(),
            policy_store_id: policy_store_id.to_string(),
        };

        let reader_response = build_get_policy_response(
            &policy_id_1,
            &policy_store_id,
            policy_type,
            build_entity_identifier(PRINCIPAL_ENTITY_TYPE, PRINCIPAL_ENTITY_ID),
            build_entity_identifier(RESOURCE_ENTITY_TYPE, RESOURCE_ENTITY_ID),
            PolicyDefinitionDetailRaw::Static(StaticPolicyDefinitionDetailRaw {
                description: Some(POLICY_DEFINITION_DETAIL_DEFINITION.to_string()),
                statement: Some(POLICY_DEFINITION_DETAIL_STATEMENT.to_string()),
            }),
        );

        let client = build_client(vec![
            build_event(&loader_request, &loader_response, StatusCode::OK),
            build_event(&reader_request, &reader_response, StatusCode::OK),
        ]);

        let entity_identifier = EntityIdentifier::builder()
            .entity_type(ENTITY_TYPE)
            .entity_id(ENTITY_ID)
            .build()
            .unwrap();

        let static_definition = PolicyDefinition {
            policy_id: policy_id_1.to_string(),
            detail: PolicyDefinitionDetail::Static(
                StaticPolicyDefinitionDetail::builder()
                    .description(POLICY_DEFINITION_DETAIL_DEFINITION.to_string())
                    .statement(POLICY_DEFINITION_DETAIL_STATEMENT.to_string())
                    .build()
                    .unwrap(),
            ),
        };

        let deleted_output = GetPolicyOutput::builder()
            .policy_store_id(policy_store_id.to_string())
            .policy_id(policy_id_2.to_string())
            .policy_type(PolicyType::Static)
            .created_date(DateTime::from_secs(0))
            .last_updated_date(DateTime::from_secs(0))
            .principal(entity_identifier.clone())
            .resource(entity_identifier)
            .definition(PolicyDefinitionDetail::Static(
                StaticPolicyDefinitionDetail::builder()
                    .description(POLICY_DEFINITION_DETAIL_DEFINITION.to_string())
                    .statement(POLICY_DEFINITION_DETAIL_STATEMENT.to_string())
                    .build()
                    .unwrap(),
            ))
            .build()
            .unwrap();

        let mut policy_source = VerifiedPermissionsPolicySource::from(client);
        policy_source.cache.put(policy_id_2.clone(), deleted_output);

        let result = policy_source.fetch(policy_store_id).await.unwrap();

        assert!(!result.contains_key(&policy_id_2));
        assert_eq!(
            result.get(&policy_id_1).unwrap().clone(),
            Policy::try_from(static_definition).unwrap()
        );
    }

    #[tokio::test]
    async fn test_template_linked_policy_source_fetch_returns_expected_results_with_mock_client() {
        let policy_store_id: PolicyStoreId = PolicyStoreId::from("mockPolicyStoreId".to_string());
        let policy_id = PolicyId("mockPolicyId1".to_string());
        let policy_type = "TEMPLATE";
        let policy_template_id = TemplateId("mockPolicyTemplateId".to_string());

        let principal_entity_identifier = EntityIdentifier::builder()
            .entity_type(PRINCIPAL_ENTITY_TYPE)
            .entity_id(PRINCIPAL_ENTITY_ID)
            .build()
            .unwrap();

        let resource_entity_identifier = EntityIdentifier::builder()
            .entity_type(RESOURCE_ENTITY_TYPE)
            .entity_id(RESOURCE_ENTITY_ID)
            .build()
            .unwrap();

        let loader_request = ListPoliciesRequest {
            policy_store_id: policy_store_id.to_string(),
            next_token: None,
            max_results: 1,
            filter: None,
        };

        let loader_response = ListPoliciesResponse {
            policies: Some(vec![build_policy_item(
                &policy_id,
                &policy_store_id,
                Some(policy_type.to_string()),
                Some(build_entity_identifier(ENTITY_TYPE, ENTITY_ID)),
                None,
                None,
            )]),
            next_token: None,
        };

        let reader_request = GetPolicyRequest {
            policy_id: policy_id.to_string(),
            policy_store_id: policy_store_id.to_string(),
        };

        let reader_response = build_get_policy_response(
            &policy_id,
            &policy_store_id,
            policy_type,
            build_entity_identifier(PRINCIPAL_ENTITY_TYPE, PRINCIPAL_ENTITY_ID),
            build_entity_identifier(RESOURCE_ENTITY_TYPE, RESOURCE_ENTITY_ID),
            PolicyDefinitionDetailRaw::TemplateLinked(TemplateLinkedPolicyDefinitionDetailRaw {
                policy_template_id: Some(policy_template_id.to_string()),
                principal: Some(build_entity_identifier(
                    PRINCIPAL_ENTITY_TYPE,
                    PRINCIPAL_ENTITY_ID,
                )),
                resource: Some(build_entity_identifier(
                    RESOURCE_ENTITY_TYPE,
                    RESOURCE_ENTITY_ID,
                )),
            }),
        );

        let client = build_client(vec![
            build_event(&loader_request, &loader_response, StatusCode::OK),
            build_event(&reader_request, &reader_response, StatusCode::OK),
        ]);

        let template_linked_definition = PolicyDefinition {
            policy_id: policy_id.to_string(),
            detail: PolicyDefinitionDetail::TemplateLinked(
                TemplateLinkedPolicyDefinitionDetail::builder()
                    .policy_template_id(policy_template_id.to_string())
                    .principal(principal_entity_identifier.clone())
                    .resource(resource_entity_identifier.clone())
                    .build()
                    .unwrap(),
            ),
        };

        let mut policy_source = VerifiedPermissionsPolicySource::from(client);

        let result = policy_source.fetch(policy_store_id).await.unwrap();

        assert_eq!(
            result.get(&policy_id).unwrap().clone(),
            Policy::try_from(template_linked_definition).unwrap()
        );
    }
}
