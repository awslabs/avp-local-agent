#[cfg(test)]
mod test {
    use aws_sdk_verifiedpermissions::Client;
    use std::fs::File;
    use std::sync::Arc;

    use aws_sdk_verifiedpermissions::types::{
        EntityIdentifier, PolicyDefinition, StaticPolicyDefinition, TemplateLinkedPolicyDefinition,
        ValidationMode, ValidationSettings,
    };
    use aws_types::region::Region;
    use cedar_policy::{Context, Entities, Request, Schema};
    use cedar_policy_core::authorizer::Decision;

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
            Some(format!("User::\"{principal}\"").parse().unwrap()),
            Some(format!("Action::\"{action}\"").parse().unwrap()),
            Some(format!("Box::\"{resource}\"").parse().unwrap()),
            Context::empty(),
        )
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
        let policy_store_id = setup_policy_store_for_test(&client).await;
        let authorizer = create_authorizer(client.clone(), policy_store_id.clone());

        let entities_file = File::open("tests/data/sweets.entities.json").unwrap();
        let schema_file = File::open("tests/data/sweets.schema.cedar.json").unwrap();
        let schema = Schema::from_file(schema_file).unwrap();
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
    async fn simple_authorizer_with_too_many_entities() {
        let client = verified_permissions_default_credentials(Region::new("us-east-1")).await;
        let policy_store_id = setup_policy_store_for_test(&client).await;
        let authorizer = create_authorizer(client.clone(), policy_store_id.clone());

        let entities_file = File::open("tests/data/too.many.entities.json").unwrap();
        let schema_file = File::open("tests/data/sweets.schema.cedar.json").unwrap();
        let schema = Schema::from_file(schema_file).unwrap();
        let entities = Entities::from_json_file(entities_file, Some(&schema)).unwrap();

        let auth_request = build_request("Eric", "read", 1);
        let result = authorizer.is_authorized(&auth_request, &entities).await;
        assert!(result.is_err());

        assert!(client
            .delete_policy_store()
            .policy_store_id(policy_store_id)
            .send()
            .await
            .is_ok())
    }

    async fn setup_policy_store_for_test(client: &Client) -> String {
        let policy_store_id = client
            .create_policy_store()
            .validation_settings(
                ValidationSettings::builder()
                    .mode(ValidationMode::Off)
                    .build(),
            )
            .send()
            .await
            .unwrap()
            .policy_store_id
            .unwrap();

        let editor_template_id = client
            .create_policy_template()
            .policy_store_id(policy_store_id.clone())
            .statement(EDITOR_TEMPLATE_POLICY)
            .description("Editor")
            .send()
            .await
            .unwrap()
            .policy_template_id
            .unwrap();

        let viewer_template_id = client
            .create_policy_template()
            .policy_store_id(policy_store_id.clone())
            .statement(VIEWER_TEMPLATE_POLICY)
            .description("Viewer")
            .send()
            .await
            .unwrap()
            .policy_template_id
            .unwrap();

        for (user, box_id) in [("Mike", "1"), ("Eric", "2")] {
            client
                .create_policy()
                .policy_store_id(policy_store_id.clone())
                .definition(PolicyDefinition::TemplateLinked(
                    TemplateLinkedPolicyDefinition::builder()
                        .policy_template_id(viewer_template_id.clone())
                        .principal(
                            EntityIdentifier::builder()
                                .entity_type("User")
                                .entity_id(user)
                                .build(),
                        )
                        .resource(
                            EntityIdentifier::builder()
                                .entity_type("Box")
                                .entity_id(box_id)
                                .build(),
                        )
                        .build(),
                ))
                .send()
                .await
                .unwrap();
        }

        client
            .create_policy()
            .policy_store_id(policy_store_id.clone())
            .definition(PolicyDefinition::TemplateLinked(
                TemplateLinkedPolicyDefinition::builder()
                    .policy_template_id(editor_template_id.clone())
                    .principal(
                        EntityIdentifier::builder()
                            .entity_type("User")
                            .entity_id("Mike")
                            .build(),
                    )
                    .resource(
                        EntityIdentifier::builder()
                            .entity_type("Box")
                            .entity_id("1")
                            .build(),
                    )
                    .build(),
            ))
            .send()
            .await
            .unwrap();

        client
            .create_policy()
            .policy_store_id(policy_store_id.clone())
            .definition(PolicyDefinition::Static(
                StaticPolicyDefinition::builder()
                    .description("Resource Owner Policy")
                    .statement(OWNER_STATIC_POLICY)
                    .build(),
            ))
            .send()
            .await
            .unwrap();
        policy_store_id
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
}
