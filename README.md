# Amazon Verified Permissions (avp) Local Agent

This crate is experimental.

The `avp-local-agent` provides Amazon Verified Permissions policy and entity providers.  These providers are used
to build a [`simple::Authorizer`](https://github.com/cedar-policy/cedar-local-agent/blob/main/src/public/simple.rs).

The `avp-local-agent` will expand in capabilities in future releases.

For more information about the cedar local agent, please take a look at
[`cedar-local-agent`](https://github.com/cedar-policy/cedar-local-agent).

For more information about the Cedar language/project, please take a look
at [cedarpolicy.com](https://www.cedarpolicy.com).

For more information about Amazon Verified Permissions, please take a look at
[`verified-permissions`](https://aws.amazon.com/verified-permissions/).

## Usage

Amazon Verified Permissions agent can be used in your application by depending 
on the `avp-local-agent` crate.

Add `avp-local-agent` as a dependency in your `Cargo.toml` file. For example:

```
[dependencies]
aws-types = "0.56"
aws-config = "0.56"
aws-credential-types = "0.56"
avp-local-agent = "0.1"
```

Note: AWS dependencies required for specifying the region and optionally building
a credentials' provider.

## Quick Start

Build an authorizer that uses an existing Amazon Verified Permissions 
[`policy store`](https://docs.aws.amazon.com/verifiedpermissions/latest/userguide/policy-stores.html).

Build an Amazon Verified Permissions client:
```rust
let client = verified_permissions_default_credentials(Region::new("us-east-1")).await;
```

Build a policy set provider:

```rust
let policy_set_provider = PolicySetProvider::from_client("policy_store_id".to_string(), client.clone())
    .unwrap();
```

Build an entity provider (uses optional policy store schema to generate action entities):

```rust
let entity_provider =
    EntityProvider::from_client("policy_store_id".to_string(), client.clone())
    .unwrap();
```

Build the authorizer:

```rust
let authorizer: Authorizer<PolicySetProvider, EntityProvider> = Authorizer::new(
    AuthorizerConfigBuilder::default()
        .entity_provider(Arc::new(entity_provider))
        .policy_set_provider(Arc::new(policy_set_provider))
        .build()
        .unwrap()
);
```

Evaluate a decision:

```rust
assert_eq!(
    authorizer
        .is_authorized(&Request::new(
            Some(format!("User::\"Cedar\"").parse().unwrap()),
            Some(format!("Action::\"read\"").parse().unwrap()),
            Some(format!("Box::\"3\"").parse().unwrap()),
            Context::empty(),
        ), &Entities::empty())
        .await
        .unwrap()
        .decision(),
    Decision::Deny
);
```

## Updating policy and entity data asynchronously

See [`cedar-local-agent`](https://github.com/cedar-policy/cedar-local-agent/tree/main#updating-filepolicysetprovider-or-fileentityprovider-data) the
same pattern applies.

## Logging

See [`cedar-local-agent`](https://github.com/cedar-policy/cedar-local-agent/tree/main#logging) the
same pattern applies.

## Running integration tests

Integration tests require having valid AWS credentials on the default
credential provider chain.  See [`documentation`](https://docs.aws.amazon.com/sdk-for-rust/latest/dg/credentials.html)
to learn about this chain and how to properly configure your credentials to run
the integration tests.

After credentials have been set run:

```
cargo test --features integration-tests
```

Note: The integration tests create Amazon Verified Permissions resources within the account and region specified `us-east-1`.