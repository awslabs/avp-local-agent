use backon::{BackoffBuilder, ExponentialBuilder};
use std::{sync::LazyLock, time::Duration};

/*
    Retry AVP API calls for a max of 10 seconds
    There is some randomness in the exponential backoff algorithm but this will likely result in
    a maximum of around 10 retries in the worst case

    For very specialized needs, this can be modified using the environment variable
    AWS_AVP_SDK_API_RETRY_TIMEOUT
*/
static API_RETRY_TIMEOUT_IN_SECONDS: LazyLock<u64> = LazyLock::new(|| {
    std::env::var("AWS_AVP_SDK_API_RETRY_TIMEOUT").map_or(10, |v| v.parse::<u64>().unwrap_or(10))
});

/**
The purpose of the `BackoffStrategy` is to allow fine grained control of
the Backoff strategy rather than setting a single strategy at the level of the
AVP client.

The reason for this is that there are certain cases where we may need to retry several times
with a long backoff since AVP has very low TPS limits and we expect to be throttled for certain
operations. We do not want to allow these high numbers of retries universally

For more information about the Backoff implementation see: <https://docs.rs/backoff/latest/backoff/>
All defaults are used except `MAX_ELAPSED_TIME_MILLIS` which we are making customizable
Other defaults: <https://docs.rs/backoff/latest/backoff/default/index.html>
 */
#[derive(Debug)]
pub struct BackoffStrategy {
    pub(crate) time_limit_seconds: u64,
}

impl BackoffStrategy {
    pub(crate) fn get_backoff(&self) -> backon::ExponentialBackoff {
        ExponentialBuilder::new()
            .with_max_delay(Duration::from_secs(self.time_limit_seconds))
            .build()
    }
}

impl Default for BackoffStrategy {
    fn default() -> Self {
        Self {
            time_limit_seconds: *API_RETRY_TIMEOUT_IN_SECONDS,
        }
    }
}
