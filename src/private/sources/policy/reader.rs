//! This module implements the required functionality to read information about a specified policy
//! from Amazon Verified Permissions.

use async_trait::async_trait;
use aws_sdk_verifiedpermissions::operation::get_policy::{GetPolicyError, GetPolicyOutput};
use aws_sdk_verifiedpermissions::Client;
use aws_smithy_runtime_api::client::result::SdkError;
use backon::Retryable;
use tracing::instrument;

use crate::private::sources::policy::error::PolicyException;
use crate::private::sources::Read;
use crate::private::types::policy_id::PolicyId;
use crate::private::types::policy_selector::PolicySelector;

use crate::private::sources::retry::BackoffStrategy;

/// This structure implements the calls to Amazon Verified Permissions for retrieving a policy.
#[derive(Debug)]
pub struct GetPolicy {
    /// Provides a `Client` to fetch policies from AVP.
    avp_client: Client,
    /// `BackoffStrategy` defines how we will perform retries with exponential backoff
    backoff_strategy: BackoffStrategy,
}

impl GetPolicy {
    /// Create a new `GetPolicy` instance
    pub fn new(avp_client: Client, backoff_strategy: BackoffStrategy) -> Self {
        Self {
            avp_client,
            backoff_strategy,
        }
    }

    async fn get_policy(
        &self,
        policy_id: &String,
        policy_store_id: &String,
    ) -> Result<GetPolicyOutput, GetPolicyError> {
        let get_policy_operation = || async {
            let get_policy_result = self
                .avp_client
                .get_policy()
                .policy_id(policy_id)
                .policy_store_id(policy_store_id)
                .send()
                .await
                .map_err(SdkError::into_service_error)?;
            Ok(get_policy_result)
        };
        get_policy_operation
            .retry(self.backoff_strategy.get_backoff())
            .await
    }
}

/// Input required for the AVP `GetPolicy` operation.
#[derive(Debug, Clone)]
pub struct GetPolicyInput {
    policy_selector: PolicySelector,
    policy_id: PolicyId,
}

impl GetPolicyInput {
    /// Create a new `GetPolicyInput` instance with the given `PolicySelector` and `PolicyId`.
    pub fn new(policy_selector: PolicySelector, policy_id: PolicyId) -> Self {
        Self {
            policy_selector,
            policy_id,
        }
    }
}

#[async_trait]
impl Read for GetPolicy {
    /// Returns policy data with the given `PolicyId` and `PolicySelector`.
    type Input = GetPolicyInput;
    type Output = GetPolicyOutput;
    type Exception = PolicyException;

    #[instrument(skip(self), err(Debug))]
    async fn read(&self, input: Self::Input) -> Result<Self::Output, Self::Exception> {
        Ok(self
            .get_policy(
                &input.policy_id.to_string(),
                &input.policy_selector.id().to_string(),
            )
            .await?)
    }
}

#[cfg(test)]
mod tests {
    use crate::private::sources::policy::core::test::{
        build_entity_identifier, build_get_policy_response, GetPolicyRequest,
        PolicyDefinitionDetailRaw, StaticPolicyDefinitionDetailRaw,
    };
    use crate::private::sources::policy::reader::{GetPolicy, GetPolicyInput};
    use crate::private::sources::retry::BackoffStrategy;
    use crate::private::sources::test::{build_client, build_empty_event, build_event, StatusCode};
    use crate::private::sources::Read;
    use crate::private::types::policy_id::PolicyId;
    use crate::private::types::policy_selector::PolicySelector;
    #[tokio::test]
    async fn get_policy_200() {
        let policy_id = PolicyId("mockPolicyId".to_string());
        let policy_selector = PolicySelector::from("mockPolicyStoreId".to_string());
        let policy_type = "STATIC";
        let principal_entity_type = "principal_entity_type";
        let principal_entity_id = "principal_entity_id";
        let resource_entity_type = "resource_entity_type";
        let resource_entity_id = "resource_entity_id";
        let policy_definition_detail_definition = "definition";
        let policy_definition_detail_statement = "statement";

        let request = GetPolicyRequest {
            policy_id: policy_id.to_string(),
            policy_store_id: policy_selector.id().to_string(),
        };

        let response = build_get_policy_response(
            &policy_id,
            &policy_selector,
            policy_type,
            build_entity_identifier(principal_entity_type, principal_entity_id),
            build_entity_identifier(resource_entity_type, resource_entity_id),
            PolicyDefinitionDetailRaw::Static(StaticPolicyDefinitionDetailRaw {
                description: Some(policy_definition_detail_definition.to_string()),
                statement: Some(policy_definition_detail_statement.to_string()),
            }),
        );

        let events = vec![build_event(&request, &response, StatusCode::OK)];

        let client = build_client(events);
        let policy_reader = GetPolicy::new(client, BackoffStrategy::default());
        let read_input = GetPolicyInput {
            policy_selector: policy_selector.clone(),
            policy_id: policy_id.clone(),
        };
        let result = policy_reader.read(read_input).await.unwrap();

        assert_eq!(result.policy_id, policy_id.to_string());
        assert_eq!(result.policy_store_id, policy_selector.id().to_string());
        assert_eq!(result.principal.unwrap().entity_id, principal_entity_id);
        assert_eq!(result.resource.unwrap().entity_id, resource_entity_id);
        assert_eq!(
            result
                .definition
                .unwrap()
                .as_static()
                .unwrap()
                .description
                .as_ref()
                .unwrap(),
            policy_definition_detail_definition
        );
        assert_eq!(result.policy_type.as_str(), policy_type);
    }

    #[tokio::test]
    async fn get_policy_400() {
        let policy_id = PolicyId("mockPolicyId".to_string());
        let policy_selector = PolicySelector::from("mockPolicyStoreId".to_string());

        let request = GetPolicyRequest {
            policy_id: policy_id.to_string(),
            policy_store_id: policy_selector.id().to_string(),
        };

        let events = vec![build_empty_event(&request, StatusCode::BAD_REQUEST)];

        let client = build_client(events);
        let policy_reader = GetPolicy::new(client, BackoffStrategy::default());
        let read_input = GetPolicyInput {
            policy_selector,
            policy_id,
        };
        let result = policy_reader.read(read_input).await;
        assert!(result.is_err());
    }
}
