use backoff::ExponentialBackoff;
use once_cell::sync::Lazy;
use std::time::Duration;

/*
    Retry AVP API calls for a max of 10 seconds
    There is some randomness in the exponential backoff algorithm but this will likely result in
    a maximum of around 10 retries in the worst case

    For very specialized needs, this can be modified using the environment variable
    AWS_AVP_SDK_API_RETRY_TIMEOUT
*/
static API_RETRY_TIMEOUT_IN_SECONDS: Lazy<u64> = Lazy::new(|| {
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
    pub(crate) fn get_backoff(&self) -> ExponentialBackoff {
        ExponentialBackoff {
            max_elapsed_time: Option::from(Duration::from_secs(self.time_limit_seconds)),
            ..Default::default()
        }
    }
}

impl Default for BackoffStrategy {
    fn default() -> Self {
        Self {
            time_limit_seconds: *API_RETRY_TIMEOUT_IN_SECONDS,
        }
    }
}
