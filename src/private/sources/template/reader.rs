//! This module implements the required functionality to get policy template contents from amazon
//! verified permissions.

use async_trait::async_trait;
use aws_sdk_verifiedpermissions::operation::get_policy_template::{
    GetPolicyTemplateError, GetPolicyTemplateOutput,
};
use aws_sdk_verifiedpermissions::Client;
use aws_smithy_runtime_api::client::result::SdkError;
use tracing::instrument;

use crate::private::sources::retry::BackoffStrategy;
use crate::private::sources::template::error::TemplateException;
use crate::private::sources::Read;
use crate::private::types::policy_store_id::PolicyStoreId;
use crate::private::types::template_id::TemplateId;

/// This structure implements the calls to Amazon Verified Permissions for retrieving the
/// contents of a single policy template.
#[derive(Debug)]
pub struct GetPolicyTemplate {
    /// Provides a `Client` to fetch policies from AVP.
    avp_client: Client,
    /// `BackoffStrategy` defines how we will perform retries with exponential backoff
    backoff_strategy: BackoffStrategy,
}

impl GetPolicyTemplate {
    /// Create a new `GetPolicyTemplate` instance
    pub fn new(avp_client: Client, backoff_strategy: BackoffStrategy) -> Self {
        Self {
            avp_client,
            backoff_strategy,
        }
    }

    async fn get_policy_template(
        &self,
        policy_template_id: &String,
        policy_store_id: &String,
    ) -> Result<GetPolicyTemplateOutput, GetPolicyTemplateError> {
        let get_policy_template_operation = || async {
            let get_policy_result = self
                .avp_client
                .get_policy_template()
                .policy_store_id(policy_store_id)
                .policy_template_id(policy_template_id)
                .send()
                .await
                .map_err(SdkError::into_service_error)?;
            Ok(get_policy_result)
        };

        backoff::future::retry(
            self.backoff_strategy.get_backoff(),
            get_policy_template_operation,
        )
        .await
    }
}

/// Input required for the AVP `GetPolicyTemplate` operation.
#[derive(Debug, Clone)]
pub struct GetPolicyTemplateInput {
    /// The policy store id
    pub policy_store_id: PolicyStoreId,
    /// The template id
    pub policy_template_id: TemplateId,
}

impl GetPolicyTemplateInput {
    /// Create a new `GetPolicyTemplateInput` instance with the given policy store id and template id.
    pub fn new(policy_store_id: PolicyStoreId, policy_template_id: TemplateId) -> Self {
        Self {
            policy_store_id,
            policy_template_id,
        }
    }
}

#[async_trait]
impl Read for GetPolicyTemplate {
    type Input = GetPolicyTemplateInput;
    type Output = GetPolicyTemplateOutput;
    type Exception = TemplateException;

    #[instrument(skip(self), err(Debug))]
    async fn read(&self, input: Self::Input) -> Result<Self::Output, Self::Exception> {
        Ok(self
            .get_policy_template(
                &input.policy_template_id.to_string(),
                &input.policy_store_id.to_string(),
            )
            .await?)
    }
}

#[cfg(test)]
mod test {
    use crate::private::sources::retry::BackoffStrategy;

    use crate::private::sources::template::core::test::{
        build_get_policy_template_response, GetPolicyTemplateRequest,
    };
    use crate::private::sources::template::reader::{
        GetPolicyTemplate, GetPolicyTemplateInput, Read,
    };
    use crate::private::sources::test::{build_client, build_empty_event, build_event, StatusCode};
    use crate::private::types::policy_store_id::PolicyStoreId;
    use crate::private::types::template_id::TemplateId;

    #[tokio::test]
    async fn get_template_200() {
        let policy_template_id = TemplateId("mockTemplateId".to_string());
        let policy_store_id = PolicyStoreId("mockPolicyStoreId".to_string());
        let template_description = "mockTemplateDescription";
        let statement = "some statement";

        let request = GetPolicyTemplateRequest {
            policy_store_id: policy_store_id.to_string(),
            policy_template_id: policy_template_id.to_string(),
        };

        let response = build_get_policy_template_response(
            &policy_store_id,
            &policy_template_id,
            template_description,
            statement,
        );

        let events = vec![build_event(&request, &response, StatusCode::OK)];

        let client = build_client(events);
        let template_reader = GetPolicyTemplate::new(client, BackoffStrategy::default());
        let read_input = GetPolicyTemplateInput {
            policy_store_id,
            policy_template_id,
        };
        let result = template_reader.read(read_input).await.unwrap();

        assert_eq!(response.statement, result.statement);
    }

    #[tokio::test]
    async fn get_template_400() {
        let policy_template_id = TemplateId("mockTemplateId".to_string());
        let policy_store_id = PolicyStoreId("mockPolicyStoreId".to_string());

        let request = GetPolicyTemplateRequest {
            policy_store_id: policy_store_id.to_string(),
            policy_template_id: policy_template_id.to_string(),
        };

        let events = vec![build_empty_event(&request, StatusCode::BAD_REQUEST)];

        let client = build_client(events);
        let template_reader = GetPolicyTemplate::new(client, BackoffStrategy::default());
        let read_input = GetPolicyTemplateInput {
            policy_store_id,
            policy_template_id,
        };
        let result = template_reader.read(read_input).await;

        assert!(result.is_err());
    }
}
