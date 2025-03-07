#[cfg(test)]
mod test {
    use aws_sdk_verifiedpermissions::error::SdkError;
    use aws_sdk_verifiedpermissions::operation::create_policy::{
        CreatePolicyError, CreatePolicyOutput,
    };
    use aws_sdk_verifiedpermissions::operation::create_policy_store::{
        CreatePolicyStoreError, CreatePolicyStoreOutput,
    };
    use aws_sdk_verifiedpermissions::Client;
    use std::fs::File;
    use std::sync::Arc;
    use std::time::Duration;

    use aws_sdk_verifiedpermissions::types::{
        EntityIdentifier, PolicyDefinition, StaticPolicyDefinition, TemplateLinkedPolicyDefinition,
        ValidationMode, ValidationSettings,
    };
    use aws_types::region::Region;
    use backoff::ExponentialBackoff;
    use cedar_policy::{Context, Decision, Entities, Request, Schema};

    use avp_local_agent::public::client::verified_permissions_default_credentials;
    use avp_local_agent::public::entity_provider::EntityProvider;
    use avp_local_agent::public::policy_set_provider::PolicySetProvider;
    use cedar_local_agent::public::simple::{Authorizer, AuthorizerConfigBuilder};

    const OWNER_STATIC_POLICY: &str = r#"
        @id("owner-policy")
        permit(principal, action,resource)
        when { principal == resource.owner };
    "#;

    const EDITOR_TEMPLATE_POLICY: &str = r#"
        permit (
            principal == ?principal,
            action in [
                Action::"read",
                Action::"update"
            ],
            resource == ?resource
        );
    "#;

    const VIEWER_TEMPLATE_POLICY: &str = r#"
        permit (
            principal == ?principal,
            action in [
                Action::"read"
            ],
            resource == ?resource
        );
    "#;

    fn build_request(principal: &str, action: &str, resource: i32) -> Request {
        Request::new(
            format!("User::\"{principal}\"").parse().unwrap(),
            format!("Action::\"{action}\"").parse().unwrap(),
            format!("Box::\"{resource}\"").parse().unwrap(),
            Context::empty(),
            None,
        )
        .unwrap()
    }

    fn requests() -> Vec<(Request, Decision)> {
        Vec::from([
            (build_request("Eric", "read", 1), Decision::Allow),
            (build_request("Eric", "read", 2), Decision::Allow),
            (build_request("Eric", "update", 1), Decision::Allow),
            (build_request("Eric", "update", 2), Decision::Deny),
            (build_request("Eric", "delete", 1), Decision::Allow),
            (build_request("Eric", "delete", 2), Decision::Deny),
            (build_request("Mike", "read", 1), Decision::Allow),
            (build_request("Mike", "read", 2), Decision::Allow),
            (build_request("Mike", "update", 1), Decision::Allow),
            (build_request("Mike", "update", 2), Decision::Allow),
            (build_request("Mike", "delete", 1), Decision::Deny),
            (build_request("Mike", "delete", 2), Decision::Allow),
        ])
    }

    async fn validate_requests(
        authorizer: &Authorizer<PolicySetProvider, EntityProvider>,
        evaluation: Vec<(Request, Decision)>,
        entities: &Entities,
    ) {
        for (request, decision) in evaluation {
            let response = authorizer.is_authorized(&request, entities).await.unwrap();
            assert_eq!(response.decision(), decision)
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    #[cfg_attr(not(feature = "integration-tests"), ignore)]
    async fn simple_authorizer_with_valid_data() {
        let client = verified_permissions_default_credentials(Region::new("us-east-1")).await;
        let (policy_store_id, _, _) = setup_policy_store_for_test(&client).await;
        let authorizer = create_authorizer(client.clone(), policy_store_id.clone());

        let entities_file = File::open("tests/data/sweets.entities.json").unwrap();
        let schema_file = File::open("tests/data/sweets.schema.cedar.json").unwrap();
        let schema = Schema::from_json_file(schema_file).unwrap();
        let entities = Entities::from_json_file(entities_file, Some(&schema)).unwrap();

        validate_requests(&authorizer, requests(), &entities).await;

        assert!(client
            .delete_policy_store()
            .policy_store_id(policy_store_id)
            .send()
            .await
            .is_ok())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    #[cfg_attr(not(feature = "integration-tests"), ignore)]
    async fn simple_authorizer_with_many_policies() {
        let client = verified_permissions_default_credentials(Region::new("us-east-1")).await;
        let (policy_store_id, editor_template_id, _) = setup_policy_store_for_test(&client).await;
        let _ = add_200_policies(&client, &policy_store_id, &editor_template_id).await;
        let authorizer = create_authorizer(client.clone(), policy_store_id.clone());

        let entities_file = File::open("tests/data/sweets.entities.json").unwrap();
        let schema_file = File::open("tests/data/sweets.schema.cedar.json").unwrap();
        let schema = Schema::from_json_file(schema_file).unwrap();
        let entities = Entities::from_json_file(entities_file, Some(&schema)).unwrap();

        validate_requests(&authorizer, requests(), &entities).await;

        assert!(client
            .delete_policy_store()
            .policy_store_id(policy_store_id)
            .send()
            .await
            .is_ok())
    }

    async fn setup_policy_store_for_test(client: &Client) -> (String, String, String) {
        let policy_store_id = create_policy_store(client).await.unwrap().policy_store_id;

        let editor_template_id = client
            .create_policy_template()
            .policy_store_id(policy_store_id.clone())
            .statement(EDITOR_TEMPLATE_POLICY)
            .description("Editor")
            .send()
            .await
            .unwrap()
            .policy_template_id;

        let viewer_template_id = client
            .create_policy_template()
            .policy_store_id(policy_store_id.clone())
            .statement(VIEWER_TEMPLATE_POLICY)
            .description("Viewer")
            .send()
            .await
            .unwrap()
            .policy_template_id;

        for (user, box_id) in [("Mike", "1"), ("Eric", "2")] {
            add_policy(
                client,
                &policy_store_id,
                &viewer_template_id,
                &user.to_string(),
                &box_id.to_string(),
            )
            .await
            .unwrap();
        }
        add_policy(
            client,
            &policy_store_id,
            &editor_template_id,
            &"Mike".to_string(),
            &"1".to_string(),
        )
        .await
        .unwrap();

        client
            .create_policy()
            .policy_store_id(policy_store_id.clone())
            .definition(PolicyDefinition::Static(
                StaticPolicyDefinition::builder()
                    .description("Resource Owner Policy")
                    .statement(OWNER_STATIC_POLICY)
                    .build()
                    .unwrap(),
            ))
            .send()
            .await
            .unwrap();
        (policy_store_id, editor_template_id, viewer_template_id)
    }

    fn create_authorizer(
        client: Client,
        policy_store_id: String,
    ) -> Authorizer<PolicySetProvider, EntityProvider> {
        let policy_set_provider =
            PolicySetProvider::from_client(policy_store_id.clone(), client.clone()).unwrap();
        let entity_provider =
            EntityProvider::from_client(policy_store_id.clone(), client.clone()).unwrap();

        let authorizer: Authorizer<PolicySetProvider, EntityProvider> = Authorizer::new(
            AuthorizerConfigBuilder::default()
                .entity_provider(Arc::new(entity_provider))
                .policy_set_provider(Arc::new(policy_set_provider))
                .build()
                .unwrap(),
        );
        authorizer
    }

    async fn add_200_policies(client: &Client, policy_store_id: &String, template_id: &String) {
        let policy_pairs = (100..300).map(|i| ("Mike", i.to_string()));
        for (user, box_id) in policy_pairs {
            let _ = add_policy(
                client,
                policy_store_id,
                template_id,
                &user.to_string(),
                &box_id.to_string(),
            )
            .await;
        }
    }

    async fn add_policy(
        client: &Client,
        policy_store_id: &String,
        template_id: &String,
        user: &String,
        box_id: &String,
    ) -> Result<CreatePolicyOutput, CreatePolicyError> {
        let backoff_strategy = ExponentialBackoff::default();
        let add_policy_operation = || async {
            let result = client
                .create_policy()
                .policy_store_id(policy_store_id)
                .definition(PolicyDefinition::TemplateLinked(
                    TemplateLinkedPolicyDefinition::builder()
                        .policy_template_id(template_id)
                        .principal(
                            EntityIdentifier::builder()
                                .entity_type("User")
                                .entity_id(user)
                                .build()
                                .unwrap(),
                        )
                        .resource(
                            EntityIdentifier::builder()
                                .entity_type("Box")
                                .entity_id(box_id)
                                .build()
                                .unwrap(),
                        )
                        .build()
                        .unwrap(),
                ))
                .send()
                .await
                .map_err(SdkError::into_service_error)?;
            Ok(result)
        };

        backoff::future::retry(backoff_strategy, add_policy_operation).await
    }

    async fn create_policy_store(
        client: &Client,
    ) -> Result<CreatePolicyStoreOutput, CreatePolicyStoreError> {
        let backoff_strategy = ExponentialBackoff::default();
        let create_policy_store_op = || async {
            if backoff_strategy.get_elapsed_time() >= Duration::from_secs(15) {
                panic!("\nError contacting AVP! Try refreshing your token?\n");
            }

            let result = client
                .create_policy_store()
                .validation_settings(
                    ValidationSettings::builder()
                        .mode(ValidationMode::Off)
                        .build()
                        .unwrap(),
                )
                .send()
                .await
                .map_err(SdkError::into_service_error)?;
            Ok(result)
        };
        backoff::future::retry(backoff_strategy.clone(), create_policy_store_op).await
    }
}
