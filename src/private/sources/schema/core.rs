//! Exposes a `SchemaSource` trait and up the disjoint policy cases. This also exposes an
//! implementation using Verified Permissions API calls.
use async_trait::async_trait;
use aws_sdk_verifiedpermissions::Client;
use tracing::{debug, instrument};

use crate::private::sources::retry::BackoffStrategy;
use crate::private::sources::schema::error::SchemaSourceException;
use crate::private::sources::schema::reader::GetSchema;
use crate::private::sources::Read;
use crate::private::translator::avp_to_cedar::Schema;
use crate::private::types::policy_store_id::PolicyStoreId;

/// A trait to abstract fetching the most recent `Schema` data from the AVP APIs. This method, must
/// update local caches to minimize API calls.
#[async_trait]
pub trait SchemaSource {
    /// The error type that can be returned by the `fetch` method.
    type Error;

    /// This method must call the AVP API `GetPolicySchema` and convert the `GetPolicySchema` output
    /// to a `cedar_policy::Schema`.
    async fn fetch(
        &mut self,
        policy_store_id: PolicyStoreId,
    ) -> Result<cedar_policy::Schema, Self::Error>;
}

/// The `VerifiedPermissionsSchemaSource` is responsible for fetching remote verified
/// permissions Schema scoped to a Policy Store and providing a `cedar_policy::Schema`.
#[derive(Debug)]
pub struct VerifiedPermissionsSchemaSource {
    /// A reader to fetch a Policy Schema from a remote Policy Store.
    pub reader: GetSchema,
}

impl VerifiedPermissionsSchemaSource {
    /// Constructs a new `VerifiedPermissionsSchemaSource` from a `Client`.
    pub fn from(client: Client) -> Self {
        Self {
            reader: GetSchema::new(client, BackoffStrategy::default()),
        }
    }
}

#[async_trait]
impl SchemaSource for VerifiedPermissionsSchemaSource {
    type Error = SchemaSourceException;

    #[instrument(skip_all, err(Debug))]
    async fn fetch(
        &mut self,
        policy_store_id: PolicyStoreId,
    ) -> Result<cedar_policy::Schema, Self::Error> {
        let avp_schema = self.reader.read(policy_store_id.clone()).await?.schema;

        let Schema(cedar_schema) = Schema::try_from(avp_schema.as_str())?;
        debug!("Successfully fetched Policy Store Schema: policy_store_id={policy_store_id:?}");
        Ok(cedar_schema)
    }
}

#[cfg(test)]
mod test {
    use chrono::Utc;
    use serde::{Deserialize, Serialize};

    use crate::private::sources::schema::core::{SchemaSource, VerifiedPermissionsSchemaSource};
    use crate::private::sources::test::{build_client, build_empty_event, build_event};
    use crate::private::types::policy_store_id::PolicyStoreId;

    const POLICY_STORE_ID: &str = "ps-123";

    const VALID_SCHEMA: &str = r#"
        {
        "AvpAgent": {
            "entityTypes": {
                "User": {
                    "memberOfTypes": ["UserGroup"],
                    "shape": {
                        "type": "Record",
                        "attributes": {
                            "department": {
                                "type": "String"
                            },
                            "jobLevel": {
                                "type": "Long"
                            }
                        }
                    }
                },
                "UserGroup": {},
                "Photo": {
                    "shape": {
                        "type": "Record",
                        "attributes": {
                            "private": {
                                "type": "Boolean"
                            }
                        }
                    }
                }
            },
            "actions": {
                "viewPhoto": {
                    "appliesTo": {
                        "principalTypes": ["User"],
                        "resourceTypes": ["Photo"],
                        "context": {
                            "type": "Record",
                            "attributes": {
                                "authenticated": {
                                    "type": "Boolean"
                                }
                            }
                        }
                    }
                }
            }
        }}"#;

    #[derive(Debug, Serialize, Deserialize)]
    struct GetSchemaRequest {
        #[serde(rename = "policyStoreId")]
        policy_store_id: String,
    }

    #[derive(Debug, Serialize, Deserialize)]
    struct GetSchemaResponse {
        #[serde(rename = "createdDate")]
        created_date: String,
        #[serde(rename = "lastUpdatedDate")]
        last_updated_date: String,
        #[serde(rename = "policyStoreId")]
        policy_store_id: String,
        schema: String,
    }

    #[tokio::test]
    async fn test_schema_source_fetch_returns_expected_results() {
        let request = GetSchemaRequest {
            policy_store_id: POLICY_STORE_ID.to_string(),
        };

        let response = GetSchemaResponse {
            created_date: Utc::now().to_rfc3339(),
            last_updated_date: Utc::now().to_rfc3339(),
            policy_store_id: POLICY_STORE_ID.to_string(),
            schema: VALID_SCHEMA.to_string(),
        };

        let client = build_client(vec![build_event(&request, &response, 200)]);

        let mut schema_source = VerifiedPermissionsSchemaSource::from(client);
        let result = schema_source
            .fetch(PolicyStoreId(POLICY_STORE_ID.to_string()))
            .await;

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_schema_source_fetch_failure() {
        let request = GetSchemaRequest {
            policy_store_id: POLICY_STORE_ID.to_string(),
        };
        let failed_event = vec![build_empty_event(&request, 500)];
        let client = build_client(failed_event);
        let mut schema_source = VerifiedPermissionsSchemaSource::from(client);

        let result = schema_source
            .fetch(PolicyStoreId(POLICY_STORE_ID.to_string()))
            .await;

        assert!(result.is_err());
    }
}
