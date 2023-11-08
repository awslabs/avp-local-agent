use crate::private::sources::API_RETRY_TIMEOUT_IN_SECONDS;
use backoff::ExponentialBackoff;
use std::time::Duration;

/**
The purpose of the `BackoffStrategy` is to allow fine grained control of
the Backoff strategy rather than setting a single strategy at the level of the
AVP client.

The reason for this is that there are certain cases where we may need to retry several times
with a long backoff since AVP has very low TPS limits and we expect to be throttled for certain
operations. We do not want to allow these high numbers of retries universally
 */
pub struct BackoffStrategy {
    pub(crate) time_limit_seconds: u64,
}

impl BackoffStrategy {
    pub(crate) fn get_backoff(&self) -> ExponentialBackoff {
        let mut exponential_backoff = ExponentialBackoff::default();
        exponential_backoff.max_elapsed_time =
            Option::from(Duration::from_secs(self.time_limit_seconds));
        exponential_backoff
    }
}

impl Default for BackoffStrategy {
    fn default() -> Self {
        Self {
            time_limit_seconds: API_RETRY_TIMEOUT_IN_SECONDS,
        }
    }
}
