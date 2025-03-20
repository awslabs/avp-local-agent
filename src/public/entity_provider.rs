//! Provides an Amazon Verified Permissions Entity provider!
use std::fmt::Debug;
use std::str::FromStr;
use std::sync::Arc;

use async_trait::async_trait;
use aws_sdk_verifiedpermissions::Client;
use cedar_policy::{
    entities_errors::EntitiesError, CedarSchemaError, Entities, Request, Schema, SchemaError,
};
use derive_builder::Builder;
use thiserror::Error;
use tokio::runtime::Handle;
use tokio::sync::{Mutex, RwLock};
use tokio::task;
use tracing::{error, info, instrument};

use cedar_local_agent::public::{
    EntityProviderError, SimpleEntityProvider, UpdateProviderData, UpdateProviderDataError,
};

use crate::private::sources::schema::core::VerifiedPermissionsSchemaSource;
use crate::private::sources::schema::error::SchemaException;
use crate::private::sources::Read;
use crate::private::types::policy_store_filter::PolicyStoreFilter;
use crate::private::types::policy_store_id::PolicyStoreId;

/// `ProviderError` can occur during construction of the `EntityProvider`
#[derive(Error, Debug)]
pub enum ProviderError {
    /// Configuration error
    #[error("The configuration didn't build: {0}")]
    Configuration(String),
    /// Cannot retrieve the schema from Amazon Verified Permissions
    #[error("Failed to get the schema from Amazon Verified Permissions: {0}")]
    RetrieveException(#[from] SchemaException),
    /// Schema file is malformed in some way
    #[error("The Schema file failed to be parsed")]
    SchemaParse(#[from] SchemaError),
    /// Cannot extract entities from the schema
    #[error("Failed to extract entities from the schema")]
    ExtractEntities(#[from] EntitiesError),
    /// Cannot parse Cedar schema
    #[error("Cedar schema cadnno be parsed")]
    CedarSchemaError(#[from] CedarSchemaError),
}

impl From<ConfigBuilderError> for ProviderError {
    fn from(value: ConfigBuilderError) -> Self {
        Self::Configuration(value.to_string())
    }
}

/// Configuration for the Entity Provider used internally for constructing the `EntityProvider`
#[derive(Builder, Debug)]
#[builder(pattern = "owned")]
struct Config {
    /// Retrieves Schema from Amazon Verified Permissions
    pub schema_source: VerifiedPermissionsSchemaSource,
    /// The policy store id to retrieve the schema for
    pub policy_store_id: PolicyStoreId,
}

/// `EntityProvider` structure implements the `SimpleEntityProvider` trait.
#[derive(Debug)]
pub struct EntityProvider {
    /// Entities path, stored to allow refreshing from disk.
    policy_store_id: PolicyStoreId,
    /// Schema Source
    schema_source: Arc<Mutex<VerifiedPermissionsSchemaSource>>,
    /// Entities can be updated through a back ground thread.
    entities: RwLock<Arc<Entities>>,
}

/// Implementation for the Entity Provider
impl EntityProvider {
    #[instrument(skip(verified_permissions_client), err(Debug))]
    fn from_all(
        policy_store_id: String,
        policy_store_filters: Option<PolicyStoreFilter>,
        verified_permissions_client: Client,
    ) -> Result<Self, ProviderError> {
        Self::new(
            ConfigBuilder::default()
                .policy_store_id(
                    PolicyStoreId::from(policy_store_id).with_filters(policy_store_filters),
                )
                .schema_source(VerifiedPermissionsSchemaSource::from(
                    verified_permissions_client,
                ))
                .build()?,
        )
    }
    /// The `from_client` provides a useful method for building the Amazon Verified Permissions
    /// `EntityProvider`.
    ///
    /// # Errors
    ///
    /// Can error if the builder is incorrect or if the `new` constructor fails to gather the
    /// applicable data on initialization.
    #[instrument(skip(verified_permissions_client), err(Debug))]
    pub fn from_client(
        policy_store_id: String,
        verified_permissions_client: Client,
    ) -> Result<Self, ProviderError> {
        Self::from_all(policy_store_id, None, verified_permissions_client)
    }

    /// The `from_client_with_filters` provides a useful method for building the Amazon Verified Permissions
    /// `EntityProvider`, with additional filters constraining the set of policies managed, expressed as
    /// AWS CLI shorthand
    ///
    /// # Errors
    ///
    /// Can error if the builder is incorrect or if the `new` constructor fails to gather the
    /// applicable data on initialization.
    #[instrument(skip(verified_permissions_client), err(Debug))]
    pub fn from_client_with_cli_filters<F: AsRef<str> + Debug>(
        policy_store_id: String,
        policy_store_filters: F,
        verified_permissions_client: Client,
    ) -> Result<Self, ProviderError> {
        Self::from_all(
            policy_store_id,
            Some(
                PolicyStoreFilter::from_cli_str(policy_store_filters.as_ref())
                    .map_err(|e| ProviderError::Configuration(e.to_string()))?,
            ),
            verified_permissions_client,
        )
    }

    /// The `from_client_with_filters` provides a useful method for building the Amazon Verified Permissions
    /// `EntityProvider`, with additional filters constraining the set of policies managed, expressed as
    /// JSON
    ///
    /// # Errors
    ///
    /// Can error if the builder is incorrect or if the `new` constructor fails to gather the
    /// applicable data on initialization.
    #[instrument(skip(verified_permissions_client), err(Debug))]
    pub fn from_client_with_json_filters<F: AsRef<str> + Debug>(
        policy_store_id: String,
        policy_store_filters: F,
        verified_permissions_client: Client,
    ) -> Result<Self, ProviderError> {
        Self::from_all(
            policy_store_id,
            Some(
                PolicyStoreFilter::from_json_str(policy_store_filters.as_ref())
                    .map_err(|e| ProviderError::Configuration(e.to_string()))?,
            ),
            verified_permissions_client,
        )
    }

    #[instrument(skip(config), err(Debug))]
    fn new(config: Config) -> Result<Self, ProviderError> {
        let Config {
            policy_store_id,
            schema_source,
        } = config;

        let schema_source = Arc::new(Mutex::new(schema_source));
        let schema_source_ref = schema_source.clone();
        let policy_store_id_clone = policy_store_id.clone();
        let fetch_schema_result = task::block_in_place(move || {
            Handle::current().block_on(async move {
                schema_source_ref
                    .lock()
                    .await
                    .reader
                    .read(policy_store_id_clone.clone())
                    .await
            })
        });

        match fetch_schema_result {
            Ok(get_schema_output) => {
                let schema = Schema::from_str(&get_schema_output.schema)?;

                Ok(Self {
                    policy_store_id,
                    schema_source,
                    entities: RwLock::new(Arc::new(schema.action_entities()?)),
                })
            }
            Err(error) => match error {
                SchemaException::AccessDenied(_)
                | SchemaException::Validation(_)
                | SchemaException::Retryable(_)
                | SchemaException::Unhandled(_) => {
                    error!("Failed to get the schema on initialization: {error:?}");
                    Err(ProviderError::RetrieveException(error))
                }
                SchemaException::ResourceNotFound(_) => Ok(Self {
                    policy_store_id,
                    schema_source,
                    entities: RwLock::new(Arc::new(Entities::empty())),
                }),
            },
        }
    }
}

#[async_trait]
impl SimpleEntityProvider for EntityProvider {
    #[instrument(skip_all, err(Debug))]
    async fn get_entities(&self, _: &Request) -> Result<Arc<Entities>, EntityProviderError> {
        Ok(self.entities.read().await.clone())
    }
}

#[async_trait]
impl UpdateProviderData for EntityProvider {
    #[instrument(skip(self), err(Debug))]
    async fn update_provider_data(&self) -> Result<(), UpdateProviderDataError> {
        let fetch_schema_result = self
            .schema_source
            .lock()
            .await
            .reader
            .read(self.policy_store_id.clone())
            .await;

        let entities = match fetch_schema_result {
            Ok(get_schema_output) => {
                let schema = Schema::from_str(&get_schema_output.schema).map_err(|e| match e {
                    CedarSchemaError::Schema(err) => {
                        UpdateProviderDataError::General(Box::new(ProviderError::from(err)))
                    }
                    _ => UpdateProviderDataError::General(Box::new(e)),
                })?;
                schema.action_entities().map_err(|e| {
                    UpdateProviderDataError::General(Box::new(ProviderError::from(e)))
                })?
            }
            Err(error) => match error {
                SchemaException::AccessDenied(_)
                | SchemaException::Validation(_)
                | SchemaException::Retryable(_)
                | SchemaException::Unhandled(_) => {
                    return Err(UpdateProviderDataError::General(Box::new(error)));
                }
                SchemaException::ResourceNotFound(_) => Entities::empty(),
            },
        };

        {
            let mut entities_data = self.entities.write().await;
            *entities_data = Arc::new(entities);
        }
        info!("Updated Entity Provider");
        Ok(())
    }
}
