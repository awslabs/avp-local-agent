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
avp-local-agent = "2"
```

Note: AWS dependencies required for specifying the region and optionally building
a credentials' provider. See `Managing AWS Credentials` below for more details on how to configure AWS credentials.

### Managing AWS Credentials

The `avp-local-agent` invokes Amazon Verified Permissions APIs through an AWS SDK client in order to fetch remote policy 
data and refresh local caches. For local development of the agent, the recommended practice for managing AWS credentials 
for the AWS SDK client is to store these credentials locally on the machine where the tests will be invoked. For example,

Place AWS credentials in, `~/.aws/credentials`

```
[default]
aws_access_key_id=<aws access key>
aws_secret_access_key=<aws secret access key>
```

Once credentials are stored locally in `~/.aws/credentials` see the `Quick Start` below on how this all fits together. 
In a nutshell here is how the credentials are used to refresh remote policies from AVP,

Build an Amazon Verified Permissions client with a helper:

```rust 
let client = verified_permissions_default_credentials(Region::new("us-east-1")).await;
```

This helper will read the AWS sigV4 credentials from the ~/.aws/credentials file by creating a `SharedCredentialsProvider`. 
Note that the SharedCredentialsProvider is instantiated with a [`DefaultCredentialsChain`](https://docs.rs/aws-config/latest/aws_config/default_provider/credentials/struct.DefaultCredentialsChain.html).

```rust
let creds = SharedCredentialsProvider::new(
    DefaultCredentialsChain::builder()
        .region(region.clone())
        .build()
    .await,
);
```

Overall, credential providers can be used to search for your AWS credentials locally in various locations, 
with resolution orders: 

1. Environment variables: `EnvironmentVariableCredentialsProvider`
2. Shared config (~/.aws/config, ~/.aws/credentials): `SharedConfigCredentialsProvider`
3. Web Identity Tokens
4. ECS (IAM Roles for Tasks) & General HTTP credentials: ecs
5. EC2 IMDSv2

If AWS credentials are stored in environment variables say if the agent deployed and running on an EC2 instance, use
An `EnvironmentVariableCredentialsProvider` instead of a `SharedConfigCredentialsProvider`.

```rust
let creds = SharedCredentialsProvider::new( 
    EnvironmentVariableCredentialsProvider::new()
); 
let client = verified_permissions_with_credentials(Region::new("us-east-1"), creds).await;
```

Any credentials provider can be passed in, or you can make your own credentials provider. 

For more information about specifying credentials see the following AWS Documentation:

[Rust SDK - Specifying Your Credentials and Default Region](https://docs.aws.amazon.com/sdk-for-rust/latest/dg/credentials.html)


#### Recommended IAM Policy

For security purposes, we recommend that you create a user with the least privileged IAM policy for the local agent to connect with. 
Here is an example:

```
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "AVPLocalAgentPolicy",
            "Effect": "Allow",
                "Action": [
                    "verifiedpermissions:ListPolicies",
                    "verifiedpermissions:ListPolicyTemplates",
                    "verifiedpermissions:GetPolicyTemplate",
                    "verifiedpermissions:GetPolicy",
                    "verifiedpermissions:GetSchema"
                ],
            "Resource": "arn:aws:verifiedpermissions::<account_id>:policy-store/<policy store id>"
        }
    ]
}
```

Instructions on how to create an assume IAM policies are available [here](https://repost.aws/knowledge-center/iam-assume-role-cli)

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

## General Security Notes

The following is a high level description of some security concerns to keep in mind when using the `avp-local-agent` 
to enable local evaluation of Cedar policies stored in Amazon Verified Permissions Policy Stores.

### Trusted Computing Environment 

The `avp-local-agent` is a mere library that customers can wrap in say an HTTP server and deploy onto a fleet of hosts.
It is, therefore, left to users to take any and all necessary precautions to ensure those security concerns beyond what 
the `avp-local-agent` is capable of enforcing are met. This includes:

1. Ensuring that AWS Credentials are not stored in any source code that wraps the agent. See [Managing AWS Credentials](#managing-aws-credentials)
2. Filesystem permissions for on-disk locations of OCSF logs follow least-privilege permissions, see [OCSF Log directory permissions](#ocsf-log-directory-permissions).
3. The `avp-local-agent` is configured securely, see [Secure Agent Configuration](#secure-agent-configuration).

### OCSF Log directory permissions


The local authorizer provided in this crate will require **read** and **write** access to the directory where it will write OCFS logs to.

Suppose we have the following directory structure:

```
authz-agent/
  |- authz_daemon (executable)

ocsf-log-dir/
  |- authorization.log.2023-11-15-21-02
  ...
```

Now suppose you have an OS user to execute the **authz_daemon** called **authz-daemon** which should be in a group called "log-reader".

And make **authz-daemon** user the owner of  **ocsf-log-dir** folder with:

```bash
$ chown -R authz-daemon:log-reader ocsf-log-dir
```

We will now make **ocsf-log-dir** readable and writable by the owner but not writable to anyone else.
We allow anyone in the **log-reader** group to read the contents of the folder but not write to it.

```bash
$ chmod u=wrx,g=rx,o= ocsf-log-dir
```

NOTE: We need to allow **execute** permissions in order to access files in the directory.

Any agent that needs to access the logs, such as the [AWS Cloudwatch Agent](https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/Install-CloudWatch-Agent.html) should run as a user in the log-reader group so that they will have the proper access (see [documentation](https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/CloudWatch-Agent-common-scenarios.html) for how to configure the Cloudwatch Agent to run as a certain user).

### Secure Agent Configuration

Users of the agent should ensure that they are following the instructions from the [Managing AWS Credentials](#managing-aws-credentials) section of this README, as well as using an IAM role with the least privilege possible.
We provide an example of a least privilege IAM role in the [Recommended IAM Policy](#recommended-iam-policy) of this document.

As explained in the [`cedar-local-agent`](https://github.com/cedar-policy/cedar-local-agent/tree/main#updating-filepolicysetprovider-or-fileentityprovider-data) documentation, when setting up asynchronous updates of the policy set from AVP, we advise the user to make use of the existing signalers available in the cedar-local-agent crate: 

1. [``clock_ticker_task``](https://github.com/cedar-policy/cedar-local-agent/blob/main/src/public/events/core.rs)
2. [``file_inspector_task``](https://github.com/cedar-policy/cedar-local-agent/blob/main/src/public/events/core.rs)

and in particular, as is explained in the [`cedar-local-agent`](https://github.com/cedar-policy/cedar-local-agent/tree/main#updating-filepolicysetprovider-or-fileentityprovider-data), users should have a ``RefreshRate`` of at least 15 seconds, since any more risks overwhelming AVP and could lead to throttling behaviour. For example:

```rust
let (clock_ticker_signal_thread, receiver) = clock_ticker_task(RefreshRate::FifteenSeconds);
```

## License

This project is licensed under the Apache-2.0 License.
