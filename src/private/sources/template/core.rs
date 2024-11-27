//! Exposes a `TemplateSource` trait and an implementation using Verified Permissions API calls.

use crate::private::sources::cache::template::GetPolicyTemplateOutputCache;
use crate::private::sources::template::{
    error::TemplateSourceException,
    loader::ListPolicyTemplates,
    reader::{GetPolicyTemplate, GetPolicyTemplateInput},
};
use crate::private::sources::{Cache, CacheChange, Load, Read};
use crate::private::translator::avp_to_cedar::Template;
use crate::private::types::policy_store_id::PolicyStoreId;
use crate::private::types::template_id::TemplateId;

use crate::private::sources::retry::BackoffStrategy;
use async_trait::async_trait;
use aws_sdk_verifiedpermissions::Client;
use std::collections::HashMap;
use tracing::{debug, instrument};

/// A trait to abstract fetching the most recent `Template` data from the AVP APIs. This method, must
/// update local caches to minimize API calls.
#[async_trait]
pub trait TemplateSource {
    /// The error type that can be returned by the `fetch` method.
    type Error;

    /// This method must call the AVP APIs `ListPolicyTemplates` and `GetPolicyTemplate` based on a
    /// minimal set of `template_id`s that have been modified.
    async fn fetch(
        &mut self,
        policy_store_id: PolicyStoreId,
    ) -> Result<HashMap<TemplateId, Template>, Self::Error>;
}

/// The `VerifiedPermissionsTemplateSource` caches the most recent state for remote verified
/// permissions templates and can be used to fetch the `cedar_policy::Template`s for the upstream
/// cedar translation component.
#[derive(Debug)]
pub struct VerifiedPermissionsTemplateSource {
    /// A loader to list Policy Template Ids.
    loader: ListPolicyTemplates,

    /// A reader to fetch Policy Template.
    reader: GetPolicyTemplate,

    /// A cache used to minimize API calls through `GetPolicyTemplate`.
    cache: GetPolicyTemplateOutputCache,
}

impl VerifiedPermissionsTemplateSource {
    /// Constructs a new `VerifiedPermissionsTemplateSource` from a `Client`.
    pub fn from(client: Client) -> Self {
        Self {
            loader: ListPolicyTemplates::new(client.clone()),
            reader: GetPolicyTemplate::new(client, BackoffStrategy::default()),
            cache: GetPolicyTemplateOutputCache::new(),
        }
    }
}

/// Implements `TemplateSource`.
#[async_trait]
impl TemplateSource for VerifiedPermissionsTemplateSource {
    type Error = TemplateSourceException;

    #[instrument(skip(self), err(Debug))]
    async fn fetch(
        &mut self,
        policy_store_id: PolicyStoreId,
    ) -> Result<HashMap<TemplateId, Template>, Self::Error> {
        let mut cedar_template_map: HashMap<TemplateId, Template> = HashMap::new();

        // Load templates and update template cache
        let template_cache_diff_map = self
            .cache
            .get_pending_updates(&self.loader.load(policy_store_id.clone()).await?);
        for (template_id, cache_change) in template_cache_diff_map {
            if cache_change == CacheChange::Deleted {
                self.cache.remove(&template_id);
                debug!("Removed Template from Cache: template_id={template_id:?}");
            } else {
                let read_input =
                    GetPolicyTemplateInput::new(policy_store_id.clone(), template_id.clone());
                let template_output = self.reader.read(read_input).await?;

                self.cache.put(template_id.clone(), template_output);
                debug!("Updated Template in Cache: template_id={template_id:?}");
            }
        }

        for (template_id, template_output) in &mut self.cache {
            let cedar_template = Template::try_from(template_output.clone())?;
            cedar_template_map.insert(template_id.clone(), cedar_template);
            debug!("Fetched Template: template_id={template_id:?}");
        }
        Ok(cedar_template_map)
    }
}

#[cfg(test)]
pub mod test {
    use crate::private::sources::template::core::{
        TemplateSource, VerifiedPermissionsTemplateSource,
    };
    use crate::private::sources::test::{build_client, build_event, StatusCode};
    use crate::private::sources::Cache;
    use crate::private::translator::avp_to_cedar::Template;
    use crate::private::types::policy_store_id::PolicyStoreId;
    use crate::private::types::template_id::TemplateId;
    use aws_sdk_verifiedpermissions::operation::get_policy_template::GetPolicyTemplateOutput;
    use aws_smithy_types::DateTime;
    use chrono::Utc;
    use serde::{Deserialize, Serialize};

    // https://docs.aws.amazon.com/verifiedpermissions/latest/apireference/API_GetPolicyTemplate.html
    #[derive(Debug, Serialize, Deserialize)]
    pub struct GetPolicyTemplateRequest {
        #[serde(rename = "policyStoreId")]
        pub policy_store_id: String,
        #[serde(rename = "policyTemplateId")]
        pub policy_template_id: String,
    }

    // https://docs.aws.amazon.com/verifiedpermissions/latest/apireference/API_GetPolicyTemplate.html
    #[derive(Debug, Serialize, Deserialize)]
    pub struct GetPolicyTemplateResponse {
        #[serde(rename = "createdDate")]
        created_date: String,
        description: String,
        #[serde(rename = "lastUpdatedDate")]
        last_updated_date: String,
        #[serde(rename = "policyStoreId")]
        policy_store_id: String,
        #[serde(rename = "policyTemplateId")]
        policy_template_id: String,
        pub statement: String,
    }

    // https://docs.aws.amazon.com/verifiedpermissions/latest/apireference/API_ListPolicyTemplates.html
    #[derive(Debug, Serialize, Deserialize)]
    pub struct ListPolicyTemplatesRequest {
        #[serde(rename = "policyStoreId")]
        pub policy_store_id: String,
        #[serde(rename = "nextToken")]
        pub next_token: Option<String>,
        #[serde(rename = "maxResults")]
        pub max_results: i32,
    }

    // https://docs.aws.amazon.com/verifiedpermissions/latest/apireference/API_ListPolicyTemplates.html
    #[derive(Debug, Serialize, Deserialize)]
    pub struct ListPolicyTemplatesResponse {
        #[serde(rename = "nextToken")]
        pub next_token: Option<String>,
        #[serde(rename = "policyTemplates")]
        pub policy_templates: Option<Vec<PolicyTemplateItemRaw>>,
    }

    #[derive(Debug, Serialize, Deserialize)]
    pub struct PolicyTemplateItemRaw {
        #[serde(rename = "createdDate")]
        created_date: String,
        description: String,
        #[serde(rename = "lastUpdatedDate")]
        last_updated_date: String,
        #[serde(rename = "policyStoreId")]
        policy_store_id: String,
        #[serde(rename = "policyTemplateId")]
        policy_template_id: String,
    }

    pub fn build_get_policy_template_response(
        policy_store_id: &PolicyStoreId,
        policy_template_id: &TemplateId,
        template_description: &str,
        statement: &str,
    ) -> GetPolicyTemplateResponse {
        GetPolicyTemplateResponse {
            policy_store_id: policy_store_id.to_string(),
            policy_template_id: policy_template_id.to_string(),
            description: template_description.to_string(),
            statement: statement.to_string(),
            last_updated_date: Utc::now().to_rfc3339(),
            created_date: Utc::now().to_rfc3339(),
        }
    }

    pub fn build_policy_template(
        policy_store_id: &PolicyStoreId,
        policy_template_id: &TemplateId,
        template_description: &str,
    ) -> PolicyTemplateItemRaw {
        PolicyTemplateItemRaw {
            policy_store_id: policy_store_id.to_string(),
            policy_template_id: policy_template_id.to_string(),
            description: template_description.to_string(),
            last_updated_date: Utc::now().to_rfc3339(),
            created_date: Utc::now().to_rfc3339(),
        }
    }

    #[tokio::test]
    async fn test_template_source_fetch_returns_expected_results_with_mock_client() {
        let policy_store_id = PolicyStoreId::from("mockPolicyStoreId".to_string());
        let policy_template_id = TemplateId("mockTemplateId".to_string());
        let policy_template_id_2 = TemplateId("mockTemplateId2".to_string());
        let statement = "\
        permit (
            principal == ?principal,
            action in [Action::\"ReadBox\"],
            resource == ?resource
        );";
        let template_description = "mockDescription";

        let template_loader_request = ListPolicyTemplatesRequest {
            policy_store_id: policy_store_id.to_string(),
            next_token: None,
            max_results: 1,
        };

        let template_loader_response = ListPolicyTemplatesResponse {
            next_token: None,
            policy_templates: Some(vec![build_policy_template(
                &policy_store_id,
                &policy_template_id,
                template_description,
            )]),
        };

        let template_reader_request = GetPolicyTemplateRequest {
            policy_store_id: policy_store_id.to_string(),
            policy_template_id: policy_template_id.to_string(),
        };

        let template_reader_response = build_get_policy_template_response(
            &policy_store_id,
            &policy_template_id,
            template_description,
            statement,
        );

        let client = build_client(vec![
            build_event(
                &template_loader_request,
                &template_loader_response,
                StatusCode::OK,
            ),
            build_event(
                &template_reader_request,
                &template_reader_response,
                StatusCode::OK,
            ),
        ]);

        let updated_output = GetPolicyTemplateOutput::builder()
            .policy_store_id(policy_store_id.to_string())
            .policy_template_id(policy_template_id.to_string())
            .statement(statement)
            .description(template_description)
            .created_date(DateTime::from_secs(0))
            .last_updated_date(DateTime::from_secs(0))
            .build()
            .unwrap();

        let deleted_output = GetPolicyTemplateOutput::builder()
            .policy_store_id(policy_store_id.to_string())
            .policy_template_id(policy_template_id_2.to_string())
            .statement(statement)
            .created_date(DateTime::from_secs(0))
            .last_updated_date(DateTime::from_secs(0))
            .build()
            .unwrap();

        let mut template_source = VerifiedPermissionsTemplateSource::from(client);
        template_source
            .cache
            .put(policy_template_id_2.clone(), deleted_output);

        let result = template_source
            .fetch(PolicyStoreId::from(policy_store_id.to_string()))
            .await
            .unwrap();

        assert!(result.get(&policy_template_id_2).is_none());

        let Template(template_result) = result.get(&policy_template_id).unwrap();
        let Template(template_copy) = Template::try_from(updated_output).unwrap();

        assert_eq!(template_result.clone(), template_copy);
    }
}
