//! This module implements the required functionality to list policy template ids from amazon
//! verified permissions.

use std::collections::HashMap;

use crate::private::sources::Load;
use async_trait::async_trait;
use aws_sdk_verifiedpermissions::operation::list_policy_templates::ListPolicyTemplatesOutput;
use aws_sdk_verifiedpermissions::types::PolicyTemplateItem;
use aws_sdk_verifiedpermissions::Client;
use aws_smithy_http::result::SdkError;
use futures::StreamExt;
use tracing::{debug, instrument};

use crate::private::sources::template::error::TemplateException;
use crate::private::types::policy_store_id::PolicyStoreId;
use crate::private::types::template_id::TemplateId;

/// This structure implements the calls to Amazon Verified Permissions for retrieving a list of
/// policy template ids.  These policy template Ids are required to query for the templates.
#[derive(Debug, Clone)]
pub struct ListPolicyTemplates {
    avp_client: Client,
}

impl ListPolicyTemplates {
    /// Create a new `ListPolicyTemplates` instance with the given client.
    pub fn new(avp_client: Client) -> Self {
        Self { avp_client }
    }
}

#[async_trait]
impl Load for ListPolicyTemplates {
    type Input = PolicyStoreId;
    type Output = HashMap<TemplateId, PolicyTemplateItem>;
    type Exception = TemplateException;

    #[instrument(skip(self), err(Debug))]
    async fn load(&self, policy_store_id: Self::Input) -> Result<Self::Output, Self::Exception> {
        let mut policy_template_ids_map = HashMap::new();

        let mut client_results = self
            .avp_client
            .list_policy_templates()
            .policy_store_id(policy_store_id.to_string())
            .into_paginator()
            .send();

        while let Some(page) = client_results.next().await {
            let page: ListPolicyTemplatesOutput = page.map_err(SdkError::into_service_error)?;

            if let Some(templates) = page.policy_templates {
                for policy_template_item in templates {
                    if let Some(template_id) = policy_template_item.policy_template_id.as_ref() {
                        policy_template_ids_map.insert(
                            TemplateId(template_id.to_string()),
                            policy_template_item.clone(),
                        );
                    }
                }
            }
        }
        debug!(
            "Loaded all Templates from Policy Store: policy_template_ids={:?}",
            policy_template_ids_map.keys().collect::<Vec<_>>()
        );
        Ok(policy_template_ids_map)
    }
}

#[cfg(test)]
mod test {
    use http::StatusCode;

    use crate::private::sources::template::core::test::{
        build_policy_template, ListPolicyTemplatesRequest, ListPolicyTemplatesResponse,
    };
    use crate::private::sources::template::loader::{ListPolicyTemplates, Load};
    use crate::private::sources::test::{build_client, build_event};
    use crate::private::types::policy_store_id::PolicyStoreId;
    use crate::private::types::template_id::TemplateId;

    #[tokio::test]
    async fn list_templates_empty_result_200() {
        let policy_store_id = PolicyStoreId("mockPolicyStore".to_string());

        let request = ListPolicyTemplatesRequest {
            policy_store_id: policy_store_id.to_string(),
            next_token: None,
            max_results: 1,
        };

        let response = ListPolicyTemplatesResponse {
            next_token: None,
            policy_templates: None,
        };

        let events = vec![build_event(&request, &response, StatusCode::OK)];

        let client = build_client(events);
        let template_loader = ListPolicyTemplates::new(client);
        let results = template_loader.load(policy_store_id).await.unwrap();
        assert_eq!(results.len(), 0);
    }

    #[tokio::test]
    async fn list_templates_200() {
        let policy_template_id = TemplateId("mockTemplateId".to_string());
        let policy_store_id = PolicyStoreId("mockPolicyStore".to_string());
        let template_description = "mockDescription";

        let request = ListPolicyTemplatesRequest {
            policy_store_id: policy_store_id.to_string(),
            next_token: None,
            max_results: 1,
        };

        let response = ListPolicyTemplatesResponse {
            next_token: None,
            policy_templates: Some(vec![build_policy_template(
                &policy_store_id,
                &policy_template_id,
                template_description,
            )]),
        };

        let events = vec![build_event(&request, &response, StatusCode::OK)];

        let client = build_client(events);
        let template_loader = ListPolicyTemplates::new(client);
        let results = template_loader.load(policy_store_id.clone()).await.unwrap();
        assert_eq!(results.len(), 1);
        assert!(results.contains_key(&TemplateId(policy_template_id.to_string())));
        let policy_template_item = results
            .get(&TemplateId(policy_template_id.to_string()))
            .unwrap();
        assert_eq!(
            policy_template_item.description.as_ref().unwrap(),
            template_description
        );
        assert_eq!(
            policy_template_item
                .policy_store_id
                .as_ref()
                .unwrap()
                .to_string(),
            policy_store_id.to_string()
        );
    }

    #[tokio::test]
    async fn list_templates_with_pagination_200() {
        let policy_store_id = PolicyStoreId("mockPolicyStore".to_string());
        let policy_template_id = TemplateId("mockTemplateId".to_string());
        let policy_template_id_2 = TemplateId("mockTemplateId2".to_string());
        let policy_template_description = "mockDescription";
        let policy_template_two_description = "mockDescriptionTwo";

        let request = ListPolicyTemplatesRequest {
            policy_store_id: policy_store_id.to_string(),
            next_token: None,
            max_results: 1,
        };

        let response = ListPolicyTemplatesResponse {
            next_token: Some("token".to_string()),
            policy_templates: Some(vec![build_policy_template(
                &policy_store_id,
                &policy_template_id,
                policy_template_description,
            )]),
        };

        let request_two = ListPolicyTemplatesRequest {
            policy_store_id: policy_store_id.to_string(),
            next_token: None,
            max_results: 1,
        };

        let response_two = ListPolicyTemplatesResponse {
            next_token: None,
            policy_templates: Some(vec![build_policy_template(
                &policy_store_id,
                &policy_template_id_2,
                policy_template_two_description,
            )]),
        };

        let events = vec![
            build_event(&request, &response, StatusCode::OK),
            build_event(&request_two, &response_two, StatusCode::OK),
        ];

        let client = build_client(events);
        let template_loader = ListPolicyTemplates::new(client);
        let results = template_loader.load(policy_store_id.clone()).await.unwrap();
        assert_eq!(results.len(), 2);
        assert!(results.contains_key(&TemplateId(policy_template_id.to_string())));
        assert!(results.contains_key(&TemplateId(policy_template_id_2.to_string())));

        let policy_template_item = results
            .get(&TemplateId(policy_template_id.to_string()))
            .unwrap();
        assert_eq!(
            policy_template_item.description.as_ref().unwrap(),
            policy_template_description
        );
        assert_eq!(
            policy_template_item
                .policy_template_id
                .as_ref()
                .unwrap()
                .to_string(),
            policy_template_id.to_string()
        );
        assert_eq!(
            policy_template_item
                .policy_store_id
                .as_ref()
                .unwrap()
                .to_string(),
            policy_store_id.to_string()
        );

        let policy_template_item_two = results
            .get(&TemplateId(policy_template_id_2.to_string()))
            .unwrap();
        assert_eq!(
            policy_template_item_two.description.as_ref().unwrap(),
            policy_template_two_description
        );
        assert_eq!(
            policy_template_item_two
                .policy_template_id
                .as_ref()
                .unwrap()
                .to_string(),
            policy_template_id_2.to_string()
        );
        assert_eq!(
            policy_template_item_two
                .policy_store_id
                .as_ref()
                .unwrap()
                .to_string(),
            policy_store_id.to_string()
        );
    }
}
