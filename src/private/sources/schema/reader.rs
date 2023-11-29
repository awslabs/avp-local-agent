//! This module implements the required functionality to read the schema from a specific
//! Amazon Verified Permissions Policy Store.
use crate::private::sources::retry::BackoffStrategy;
use crate::private::sources::schema::error::SchemaException;
use crate::private::sources::Read;
use crate::private::types::policy_store_id::PolicyStoreId;
use async_trait::async_trait;
use aws_sdk_verifiedpermissions::operation::get_schema::{GetSchemaError, GetSchemaOutput};
use aws_sdk_verifiedpermissions::Client;
use aws_smithy_runtime_api::client::result::SdkError;
use tracing::instrument;

/// This structure implements the calls to Amazon Verified Permissions for retrieving the schema.
#[derive(Debug)]
pub struct GetSchema {
    /// Provides a `Client` to fetch policies from AVP.
    avp_client: Client,
    /// `BackoffStrategy` defines how we will perform retries with exponential backoff
    backoff_strategy: BackoffStrategy,
}

impl GetSchema {
    /// Create a new `GetSchema` instance
    pub fn new(avp_client: Client, backoff_strategy: BackoffStrategy) -> Self {
        Self {
            avp_client,
            backoff_strategy,
        }
    }

    async fn get_schema(
        &self,
        policy_store_id: &String,
    ) -> Result<GetSchemaOutput, GetSchemaError> {
        let get_policy_operation = || async {
            let get_policy_result = self
                .avp_client
                .get_schema()
                .policy_store_id(policy_store_id)
                .send()
                .await
                .map_err(SdkError::into_service_error)?;
            Ok(get_policy_result)
        };

        backoff::future::retry(self.backoff_strategy.get_backoff(), get_policy_operation).await
    }
}

#[async_trait]
impl Read for GetSchema {
    type Input = PolicyStoreId;
    type Output = GetSchemaOutput;
    type Exception = SchemaException;

    #[instrument(skip(self), err(Debug))]
    async fn read(&self, policy_store_id: Self::Input) -> Result<Self::Output, Self::Exception> {
        Ok(self.get_schema(&policy_store_id.to_string()).await?)
    }
}

#[cfg(test)]
mod test {
    use crate::private::sources::retry::BackoffStrategy;
    use crate::private::sources::schema::reader::GetSchema;
    use crate::private::sources::test::{build_client, build_empty_event, build_event};
    use crate::private::sources::Read;
    use crate::private::types::policy_store_id::PolicyStoreId;
    use chrono::Utc;
    use http::StatusCode;
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Serialize, Deserialize)]
    struct GetSchemaRequest {
        #[serde(rename = "policyStoreId")]
        policy_store_id: String,
    }

    #[derive(Debug, Serialize, Deserialize)]
    struct GetSchemaResponse {
        #[serde(rename = "createdDate")]
        created_date: String,
        #[serde(rename = "lastUpdatedDate")]
        last_updated_date: String,
        #[serde(rename = "policyStoreId")]
        policy_store_id: String,
        schema: String,
    }

    #[tokio::test]
    async fn get_schema_200() {
        let policy_store_id = PolicyStoreId("ps-1".to_string());
        let schema = "some schema";

        let request = GetSchemaRequest {
            policy_store_id: policy_store_id.to_string(),
        };

        let response = GetSchemaResponse {
            created_date: Utc::now().to_rfc3339(),
            last_updated_date: Utc::now().to_rfc3339(),
            policy_store_id: policy_store_id.to_string(),
            schema: schema.to_string(),
        };

        let events = vec![build_event(&request, &response, StatusCode::OK)];
        let client = build_client(events);
        let schema_reader = GetSchema::new(client, BackoffStrategy::default());
        let result = schema_reader.read(policy_store_id).await.unwrap();

        assert_eq!(response.schema, result.schema);
    }

    #[tokio::test]
    async fn get_schema_400() {
        let policy_store_id = PolicyStoreId("ps-1".to_string());

        let request = GetSchemaRequest {
            policy_store_id: policy_store_id.to_string(),
        };

        let events = vec![build_empty_event(&request, StatusCode::BAD_REQUEST)];

        let client = build_client(events);
        let schema_reader = GetSchema::new(client, BackoffStrategy::default());
        let result = schema_reader.read(policy_store_id).await;
        assert!(result.is_err());
    }
}
