//! A helper module for building a Verified Permissions `Client` from a `ClientConfig`.
use std::time::Duration;

use aws_config::default_provider::credentials::DefaultCredentialsChain;
use aws_config::retry::RetryConfig;
use aws_config::timeout::TimeoutConfig;
use aws_credential_types::provider::SharedCredentialsProvider;
use aws_sdk_verifiedpermissions::config::SharedAsyncSleep;
use aws_sdk_verifiedpermissions::Client;
use aws_smithy_async::rt::sleep::TokioSleep;
use aws_types::region::Region;
use aws_types::sdk_config::SdkConfig;

/// A const to control the max retry attempts in the `Client`.
pub const AVP_CLIENT_MAX_ATTEMPTS: u32 = 2;
/// A const to control the default timeout in milliseconds for the `Client`.
pub const AVP_CLIENT_DEFAULT_TIMEOUT_MS: u64 = 5000;

/// Builds a new `Client`  from a region and a `SharedCredentialsProvider`.
pub fn verified_permissions_with_credentials(
    region: Region,
    credentials: SharedCredentialsProvider,
) -> Client {
    let timeout_cfg = TimeoutConfig::builder()
        .operation_timeout(Duration::from_millis(
            AVP_CLIENT_DEFAULT_TIMEOUT_MS * u64::from(AVP_CLIENT_MAX_ATTEMPTS),
        ))
        .operation_attempt_timeout(Duration::from_millis(AVP_CLIENT_DEFAULT_TIMEOUT_MS))
        .build();

    Client::new(
        &SdkConfig::builder()
            .region(region)
            .timeout_config(timeout_cfg)
            .credentials_provider(credentials)
            .retry_config(RetryConfig::standard().with_max_attempts(AVP_CLIENT_MAX_ATTEMPTS))
            .sleep_impl(SharedAsyncSleep::new(TokioSleep::new()))
            .build(),
    )
}

/// Amazon Verified Permissions Client from a region using `DefaultCredentialsProvider`
pub async fn verified_permissions_default_credentials(region: Region) -> Client {
    let timeout_cfg = TimeoutConfig::builder()
        .operation_timeout(Duration::from_millis(
            AVP_CLIENT_DEFAULT_TIMEOUT_MS * u64::from(AVP_CLIENT_MAX_ATTEMPTS),
        ))
        .operation_attempt_timeout(Duration::from_millis(AVP_CLIENT_DEFAULT_TIMEOUT_MS))
        .build();

    let creds = SharedCredentialsProvider::new(
        DefaultCredentialsChain::builder()
            .region(region.clone())
            .build()
            .await,
    );

    Client::new(
        &SdkConfig::builder()
            .region(region)
            .timeout_config(timeout_cfg)
            .credentials_provider(creds)
            .retry_config(RetryConfig::standard().with_max_attempts(AVP_CLIENT_MAX_ATTEMPTS))
            .sleep_impl(SharedAsyncSleep::new(TokioSleep::new()))
            .build(),
    )
}
#[cfg(test)]
mod test {
    use aws_config::default_provider::credentials::DefaultCredentialsChain;
    use aws_config::meta::region::ProvideRegion;
    use aws_credential_types::provider::SharedCredentialsProvider;
    use aws_types::region::Region;

    use crate::public::client::{
        verified_permissions_default_credentials, verified_permissions_with_credentials,
    };

    #[tokio::test]
    async fn build_client_with_region_and_creds() {
        let custom_region = Region::new("us-west-1");
        let custom_creds_provider = DefaultCredentialsChain::builder()
            .region(custom_region.clone())
            .build()
            .await;
        let custom_shared_creds_provider = SharedCredentialsProvider::new(custom_creds_provider);
        let avp_client = verified_permissions_with_credentials(
            custom_region.clone(),
            custom_shared_creds_provider,
        );

        assert_eq!(
            avp_client
                .config()
                .region()
                .unwrap()
                .region()
                .await
                .unwrap(),
            custom_region
        );
    }

    #[tokio::test]
    async fn build_client_with_region() {
        let custom_region = Region::new("us-west-1");
        let avp_client = verified_permissions_default_credentials(custom_region.clone()).await;

        assert_eq!(
            avp_client
                .config()
                .region()
                .unwrap()
                .region()
                .await
                .unwrap(),
            custom_region
        );
    }
}
