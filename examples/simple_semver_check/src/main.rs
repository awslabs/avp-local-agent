//! This file can be used as a simple example or as a demo to ensure that there are no semver violations
//! Sign in with the AWS CLI so that your credentials are saved either in environment variables or in ~/.aws/credentials.
//! Then, set up AVP in your account and update `POLICY_STORE_ID`

use aws_sdk_verifiedpermissions::Client;
use cedar_local_agent::public::file::entity_provider::EntityProvider;
use cedar_local_agent::public::simple::{Authorizer, AuthorizerConfigBuilder};
use cedar_policy::{Context, Entities, Request};
use aws_config::BehaviorVersion;
use std::env;
use std::sync::Arc;

fn construct_request() -> Request {
    Request::new(
        Some("Test::Entity::\"request\"".parse().unwrap()),
        Some("Test::Action::\"Action\"".parse().unwrap()),
        Some("Test::Entity::\"request\"".parse().unwrap()),
        Context::empty(),
        None,
    )
    .unwrap()
}

#[tokio::main]
async fn main() {
    let mut args: Vec<String> = env::args().collect();
    if args.len() != 2 || args[1].len() != 22 {
        panic!("Error! Usage: simple_semver_check <policy_store_id>");
    }
    let policy_store_id = String::from(args.remove(1));

    let aws_config = aws_config::load_defaults(BehaviorVersion::v2023_11_09()).await;
    let client = Client::new(&aws_config);
    let policy_set_provider =
        avp_local_agent::public::policy_set_provider::PolicySetProvider::from_client(
            policy_store_id,
            client,
        )
        .unwrap();
    let entity_provider = EntityProvider::default();

    let authorizer = Authorizer::new(
        AuthorizerConfigBuilder::default()
            .policy_set_provider(Arc::new(policy_set_provider))
            .entity_provider(Arc::new(entity_provider))
            .build()
            .unwrap(),
    );

    let response = authorizer
        .is_authorized(&construct_request(), &Entities::empty())
        .await
        .unwrap();
    println!("{response:?}")
}
