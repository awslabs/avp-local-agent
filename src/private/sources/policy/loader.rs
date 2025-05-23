//! This module implements the required functionality to list all policies stored in the specified
//! policy store of Amazon Verified Permission.

use crate::private::sources::policy::error::PolicyException;
use crate::private::sources::Load;
use crate::private::types::{policy_id::PolicyId, policy_selector::PolicySelector};
use async_trait::async_trait;
use aws_sdk_verifiedpermissions::operation::list_policies::ListPoliciesOutput;
use aws_sdk_verifiedpermissions::types::{PolicyFilter, PolicyItem};
use aws_sdk_verifiedpermissions::Client;
use aws_smithy_runtime_api::client::result::SdkError;
use std::collections::HashMap;
use tracing::{debug, instrument};

/// This structure implements the calls to Amazon Verified Permissions for retrieving all policies
/// stored in the specified policy store. These `PolicyId`s are required to query for the policies.
#[derive(Debug, Clone)]
pub struct ListPolicies {
    avp_client: Client,
}

impl ListPolicies {
    /// Create a new `ListPolicies` instance with the given client
    pub fn new(avp_client: Client) -> Self {
        Self { avp_client }
    }
}

#[async_trait]
impl Load for ListPolicies {
    /// Returns a HashMap of `PolicyId`s and `PolicyItem`s that represent all policies stored in
    /// the specified policy store with the given `PolicySelector`.
    type Input = PolicySelector;
    type Output = HashMap<PolicyId, PolicyItem>;
    type Exception = PolicyException;

    #[instrument(skip(self), err(Debug))]
    async fn load(&self, policy_selector: Self::Input) -> Result<Self::Output, Self::Exception> {
        let mut policy_ids_map = HashMap::new();
        let mut client_results = self
            .avp_client
            .list_policies()
            .policy_store_id(policy_selector.id().to_string())
            .set_filter(policy_selector.filters().map(PolicyFilter::from))
            .into_paginator()
            .send();
        while let Some(page) = client_results.next().await {
            let page: ListPoliciesOutput = page.map_err(SdkError::into_service_error)?;
            for policy in page.policies {
                policy_ids_map.insert(PolicyId(policy.policy_id.clone()), policy);
            }
        }
        debug!(
            "Loaded all Policies from Policy Store: policy_ids={:?}",
            policy_ids_map.keys().collect::<Vec<_>>()
        );
        Ok(policy_ids_map)
    }
}

#[cfg(test)]
mod test {
    use crate::private::sources::policy::core::test::{
        build_entity_identifier, build_policy_item, ListPoliciesRequest, ListPoliciesRequestFilter,
        ListPoliciesResponse,
    };
    use crate::private::sources::policy::loader::{ListPolicies, Load};
    use crate::private::sources::test::{build_client, build_empty_event, build_event, StatusCode};
    use crate::private::types::{policy_id::PolicyId, policy_selector::PolicySelector};

    #[tokio::test]
    async fn list_policies_empty_200() {
        let policy_selector = PolicySelector::from("mockPolicyStoreId".to_string());
        let request = ListPoliciesRequest {
            policy_store_id: policy_selector.id().to_string(),
            next_token: None,
            max_results: 1,
            filter: None,
        };
        let response = ListPoliciesResponse {
            policies: None,
            next_token: None,
        };

        let events = vec![build_event(&request, &response, StatusCode::OK)];
        let client = build_client(events);
        let policy_loader = ListPolicies::new(client);
        let result = policy_loader.load(policy_selector).await.unwrap();
        assert_eq!(result.len(), 0);
    }

    #[tokio::test]
    async fn list_policies_200() {
        let policy_selector = PolicySelector::from("mockPolicyStoreId".to_string());
        let policy_id = PolicyId("mockPolicyId".to_string());
        let entity_type = "mockEntityType";
        let entity_id = "mockEntityId";
        let policy_type = "STATIC";

        let request = ListPoliciesRequest {
            policy_store_id: policy_selector.id().to_string(),
            next_token: None,
            max_results: 1,
            filter: None,
        };

        let response = ListPoliciesResponse {
            policies: Some(vec![build_policy_item(
                &policy_id,
                &policy_selector,
                Some(policy_type.to_string()),
                Some(build_entity_identifier(entity_type, entity_id)),
                None,
                None,
            )]),
            next_token: None,
        };
        let events = vec![build_event(&request, &response, StatusCode::OK)];
        let client = build_client(events);
        let policy_loader = ListPolicies::new(client);
        let results = policy_loader.load(policy_selector.clone()).await.unwrap();
        assert_eq!(results.len(), 1);
        assert!(results.contains_key(&PolicyId(policy_id.to_string())));
        let policy = results.get(&PolicyId(policy_id.to_string())).unwrap();
        assert_eq!(policy.policy_type.as_str(), policy_type);
        assert_eq!(policy.principal.as_ref().unwrap().entity_id, entity_id);
        assert_eq!(policy.policy_store_id, policy_selector.id().to_string());
    }

    #[tokio::test]
    async fn list_policies_with_pagination_200() {
        let policy_selector = PolicySelector::from("mockPolicyStoreId".to_string());
        let policy_id_one = PolicyId("mockPolicyIdOne".to_string());
        let policy_id_two = PolicyId("mockPolicyIdTwo".to_string());
        let policy_type_one = "STATIC";
        let policy_type_two = "OTHER";

        let request = ListPoliciesRequest {
            policy_store_id: policy_selector.id().to_string(),
            next_token: None,
            max_results: 1,
            filter: None,
        };

        let response_one = ListPoliciesResponse {
            policies: Some(vec![build_policy_item(
                &policy_id_one,
                &policy_selector,
                Some(policy_type_one.to_string()),
                None,
                None,
                None,
            )]),
            next_token: Some("mockNextToken".to_string()),
        };

        let response_two = ListPoliciesResponse {
            policies: Some(vec![build_policy_item(
                &policy_id_two,
                &policy_selector,
                Some(policy_type_two.to_string()),
                None,
                None,
                None,
            )]),
            next_token: None,
        };

        let events = vec![
            build_event(&request, &response_one, StatusCode::OK),
            build_event(&request, &response_two, StatusCode::OK),
        ];
        let client = build_client(events);
        let policy_loader = ListPolicies::new(client);
        let results = policy_loader.load(policy_selector.clone()).await.unwrap();
        assert_eq!(results.len(), 2);
        assert!(results.contains_key(&PolicyId(policy_id_one.to_string())));
        assert!(results.contains_key(&PolicyId(policy_id_two.to_string())));
        let policy_one = results.get(&PolicyId(policy_id_one.to_string())).unwrap();
        assert_eq!(policy_one.policy_type.as_str(), policy_type_one);
        assert_eq!(policy_one.policy_store_id, policy_selector.id().to_string());
        assert_eq!(policy_one.policy_id, policy_id_one.to_string());
        let policy_two = results.get(&PolicyId(policy_id_two.to_string())).unwrap();
        assert_eq!(policy_two.policy_type.as_str(), policy_type_two);
        assert_eq!(policy_two.policy_store_id, policy_selector.id().to_string());
        assert_eq!(policy_two.policy_id, policy_id_two.to_string());
    }

    #[tokio::test]
    async fn list_policies_400() {
        let policy_selector = PolicySelector::from("mockPolicyStoreId".to_string());

        let request = ListPoliciesRequest {
            policy_store_id: policy_selector.id().to_string(),
            next_token: None,
            max_results: 1,
            filter: None,
        };

        let events = vec![build_empty_event(&request, StatusCode::BAD_REQUEST)];

        let client = build_client(events);
        let policy_loader = ListPolicies::new(client);
        let result = policy_loader.load(policy_selector).await;
        assert!(result.is_err());
    }
    #[tokio::test]
    async fn list_policies_with_filter_200() {
        let policy_selector = PolicySelector::from("mockPolicyStoreId".to_string())
            .with_cli_filters("policyTemplateId=mockPolicyTemplateId")
            .expect("filter should parse correctly");
        let policy_id = PolicyId("mockPolicyId".to_string());
        let entity_type = "mockEntityType";
        let entity_id = "mockEntityId";
        let policy_type = "STATIC";

        let request = ListPoliciesRequest {
            policy_store_id: policy_selector.id().to_string(),
            next_token: None,
            max_results: 1,
            filter: Some(ListPoliciesRequestFilter {
                policy_template_id: Some("mockPolicyTemplateId".to_string()),
                ..Default::default()
            }),
        };

        let response = ListPoliciesResponse {
            policies: Some(vec![build_policy_item(
                &policy_id,
                &policy_selector,
                Some(policy_type.to_string()),
                Some(build_entity_identifier(entity_type, entity_id)),
                None,
                None,
            )]),
            next_token: None,
        };

        let events = vec![build_event(&request, &response, StatusCode::OK)];
        let client = build_client(events);
        let policy_loader = ListPolicies::new(client);
        let results = policy_loader.load(policy_selector.clone()).await.unwrap();
        assert_eq!(results.len(), 1);
        assert!(results.contains_key(&PolicyId(policy_id.to_string())));
        let policy = results.get(&PolicyId(policy_id.to_string())).unwrap();
        assert_eq!(policy.policy_type.as_str(), policy_type);
        assert_eq!(policy.principal.as_ref().unwrap().entity_id, entity_id);
        assert_eq!(policy.policy_store_id, policy_selector.id().to_string());
    }
}
