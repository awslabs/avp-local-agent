//! Implements the `PolicySetSource` for Amazon Verified Permissions.
use async_trait::async_trait;

pub mod cache;
pub mod policy;
mod retry;
pub mod schema;
pub mod template;

/// Type values for cache changes
#[derive(Debug, Eq, PartialEq)]
pub enum CacheChange {
    /// `Created` indicates a new cache item was created
    Created,
    /// `Updated` indicates an existing cache item was updated
    Updated,
    /// `Deleted` indicates an existing cache item was deleted
    Deleted,
}

/// `Load` trait for AVP callers to retrieve lists of policy store data
#[async_trait]
pub trait Load {
    /// `Input` id of policy store data
    type Input;
    /// `Output` collection of AVP "Item" types retrieved with loader such as `PolicyItem`
    type Output;
    /// `Exception` AVP error types mapped to a loader exception
    type Exception;
    /// Loader method to retrieve a list of policy store items from AVP
    async fn load(&self, input: Self::Input) -> Result<Self::Output, Self::Exception>;
}

/// `Read` trait for callers to retrieve policy store data from AVP.
#[async_trait]
pub trait Read {
    /// `Input` id of policy store data
    type Input;
    /// `Output` data value of "GetOutput" types retrieved with reader such as `GetPolicyOutput`
    type Output;
    /// `Exception` AVP error types mapped to a reader exception
    type Exception;

    /// Reader method to retrieve a policy store output from AVP
    async fn read(&self, input: Self::Input) -> Result<Self::Output, Self::Exception>;
}

/// Cache trait that stores various items from the AVP policy store
/// This trait is limited to a non-thread safe cache as the `get` function returns a reference
/// which cannot protect internal state using a Mutex/RwLock
#[async_trait]
pub trait Cache {
    /// `Key` id of policy store data
    type Key;
    /// `Value` data of caches with types from response of AVP read calls such as from the policy reader
    type Value;
    /// `LoadedItems` HashMap of id, value pairings of `Key` and cache item types from
    /// AVP load calls such as `ListPolicies` returning `PolicyItem`
    type LoadedItems;
    /// `PendingUpdates` HashMap of id, value pairings of `Key` and `CacheChange` as a reference for which
    /// cache values need updates
    type PendingUpdates;

    /// Constructor for cache
    fn new() -> Self;

    /// Getter method for cache, returns reference to value in cache which is not thread safe
    #[allow(dead_code)]
    fn get(&self, key: &Self::Key) -> Option<&Self::Value>;

    /// Insert method for cache which takes a `Key` and `Value` pair
    fn put(&mut self, key: Self::Key, value: Self::Value) -> Option<Self::Value>;

    /// Remove method for cache which returns the deleted value
    fn remove(&mut self, key: &Self::Key) -> Option<Self::Value>;

    /// The function responsible for cross checking the values of current cache and returning
    /// a HashMap of values that require an update
    fn get_pending_updates(&self, ids_map: &Self::LoadedItems) -> Self::PendingUpdates;
}

#[cfg(test)]
mod test {
    use aws_credential_types::Credentials;
    use aws_sdk_verifiedpermissions::{Client, Config};
    use aws_smithy_runtime::client::http::test_util::{ReplayEvent, StaticReplayClient};
    use aws_smithy_runtime_api::client::behavior_version::BehaviorVersion;
    use aws_smithy_runtime_api::http::{Request, Response, StatusCode as AwsStatusCode};
    use aws_smithy_types::body::SdkBody;
    use aws_types::region::Region;
    use serde::Serialize;

    #[allow(non_camel_case_types)]
    pub enum StatusCode {
        /// 200 OK
        OK = 200,
        /// 400 Bad Request
        BAD_REQUEST = 400,
        /// 500 Internal Server Error
        INTERNAL_SERVER_ERROR = 500,
    }

    /// Builds a mock AVP client with the provided events
    pub fn build_client(events: Vec<ReplayEvent>) -> Client {
        let http_client = StaticReplayClient::new(events);

        let conf = Config::builder()
            .credentials_provider(Credentials::new("a", "b", Some("c".to_string()), None, "d"))
            .region(Region::new("us-east-1"))
            .http_client(http_client)
            .behavior_version(BehaviorVersion::latest())
            .build();

        Client::from_conf(conf)
    }

    /// Builds an event from the provided serializable request and response and status code to be
    /// used with a mock AVP client.
    ///
    /// # Panics
    ///
    /// Will panic if failing to convert `request` to `SdkBody`
    pub fn build_event<S, T>(request: &S, response: &T, status_code: StatusCode) -> ReplayEvent
    where
        S: ?Sized + Serialize,
        T: ?Sized + Serialize,
    {
        let request = Request::new(SdkBody::from(serde_json::to_string(&request).unwrap()));
        let body = SdkBody::from(serde_json::to_string(&response).unwrap());
        let status_code = AwsStatusCode::try_from(status_code as u16).unwrap();
        let response = Response::new(status_code, body);

        ReplayEvent::new(request, response)
    }

    /// Builds an event from the provided serializable request and status code using an
    /// empty response body.
    ///
    /// # Panics
    ///
    /// Will panic if failing to convert `request` to `SdkBody`
    pub fn build_empty_event<T>(request: &T, status_code: StatusCode) -> ReplayEvent
    where
        T: ?Sized + Serialize,
    {
        let request = Request::new(SdkBody::from(serde_json::to_string(&request).unwrap()));
        let status_code = AwsStatusCode::try_from(status_code as u16).unwrap();
        let response = Response::new(status_code, SdkBody::empty());

        ReplayEvent::new(request, response)
    }
}
