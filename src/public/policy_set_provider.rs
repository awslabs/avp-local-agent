//! Provides an Amazon Verified Permissions Policy Set Provider!
use std::str::FromStr;
use std::sync::Arc;

use async_trait::async_trait;
use aws_sdk_verifiedpermissions::Client;
use cedar_policy::{PolicyId, PolicySet, Request};
use derive_builder::Builder;
use thiserror::Error;
use tokio::runtime::Handle;
use tokio::sync::{Mutex, RwLock};
use tokio::task;
use tracing::{error, info, instrument};

use cedar_local_agent::public::{
    PolicySetProviderError, SimplePolicySetProvider, UpdateProviderData, UpdateProviderDataError,
};

use crate::private::sources::policy::core::{PolicySource, VerifiedPermissionsPolicySource};
use crate::private::sources::policy::error::PolicySourceException;
use crate::private::sources::template::core::{TemplateSource, VerifiedPermissionsTemplateSource};
use crate::private::sources::template::error::TemplateSourceException;
use crate::private::translator::avp_to_cedar::Policy;
use crate::private::types::policy_store_id::PolicyStoreId;

/// `ProviderError` thrown by the constructor of the provider
#[derive(Error, Debug)]
pub enum ProviderError {
    /// Configuration error
    #[error("The configuration didn't build: {0}")]
    Configuration(String),
    /// Cannot create the policy set
    #[error("Cannot create the PolicySet with source Amazon Verified Permissions: {0}")]
    PolicySet(#[from] PolicySetError),
    /// Cannot retrieve the Policies from Amazon Verified Permissions
    #[error("Cannot gather the Policies from Amazon Verified Permissions: {0}")]
    PolicySourceException(#[from] PolicySourceException),
    /// Cannot retrieve the Templates from Amazon Verified Permissions
    #[error("Cannot gather the Policies from Amazon Verified Permissions: {0}")]
    TemplateSourceException(#[from] TemplateSourceException),
}

/// The enum for errors that occur when building the `PolicySet`
#[derive(Error, Debug)]
pub enum PolicySetError {
    ///Cannot add the static policy to the policy set
    #[error("Fail to add the static policy to the policy set, policy id: {0}")]
    StaticPolicy(String),
    ///Cannot link the template linked policy to the policy set
    #[error("Fail to link the template linked policy to the policy set, policy id: {0}, template id: {1}")]
    TemplateLinkedPolicy(String, String),
    ///Cannot add the template to the policy set
    #[error("Fail to add the template to the policy set, template id: {0}")]
    Template(String),
}

impl From<ConfigBuilderError> for ProviderError {
    fn from(value: ConfigBuilderError) -> Self {
        Self::Configuration(value.to_string())
    }
}

#[derive(Builder, Debug)]
#[builder(pattern = "owned")]
struct Config {
    /// Gathers policies from Amazon Verified Permissions
    pub policy_source: VerifiedPermissionsPolicySource,
    /// Gathers templates from Amazon Verified Permissions
    pub template_source: VerifiedPermissionsTemplateSource,
    /// Policy Store Id to gather policies and templates from
    pub policy_store_id: PolicyStoreId,
}

/// `EntityProvider` structure implements the `SimpleEntityProvider` trait.
#[derive(Debug)]
pub struct PolicySetProvider {
    /// Entities path, stored to allow refreshing from disk.
    policy_store_id: PolicyStoreId,
    /// Policy Source
    policy_source: Arc<Mutex<VerifiedPermissionsPolicySource>>,
    /// Policy Source
    template_source: Arc<Mutex<VerifiedPermissionsTemplateSource>>,
    /// Policy Set data that can be updated in a background thread
    policy_set: RwLock<Arc<PolicySet>>,
}

impl PolicySetProvider {
    /// Provides a helper to build the `PolicySetProvider` from an Amazon Verified Permissions
    /// client and policy store id
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
        Self::new(
            ConfigBuilder::default()
                .policy_store_id(PolicyStoreId::from(policy_store_id))
                .policy_source(VerifiedPermissionsPolicySource::from(
                    verified_permissions_client.clone(),
                ))
                .template_source(VerifiedPermissionsTemplateSource::from(
                    verified_permissions_client,
                ))
                .build()?,
        )
    }

    #[instrument(skip(config), err(Debug))]
    fn new(config: Config) -> Result<Self, ProviderError> {
        let Config {
            policy_store_id,
            template_source,
            policy_source,
        } = config;

        let template_source = Arc::new(Mutex::new(template_source));
        let policy_source = Arc::new(Mutex::new(policy_source));

        let mut policy_set = PolicySet::new();
        let policy_store_id_clone = policy_store_id.clone();
        let template_source_ref = template_source.clone();
        let templates = task::block_in_place(move || {
            Handle::current().block_on(async move {
                template_source_ref
                    .lock()
                    .await
                    .fetch(policy_store_id_clone)
                    .await
            })
        })?;

        let policy_store_id_clone = policy_store_id.clone();
        let policy_source_ref = policy_source.clone();
        let policies = task::block_in_place(move || {
            Handle::current().block_on(async move {
                policy_source_ref
                    .lock()
                    .await
                    .fetch(policy_store_id_clone.clone())
                    .await
            })
        })?;

        for (_, template) in templates {
            policy_set
                .add_template(template.0.clone())
                .map_err(|_| PolicySetError::Template(template.0.id().to_string()))?;
        }

        for (_, policy) in policies {
            match policy {
                Policy::Static(cedar_policy) => {
                    let cedar_policy_id = &cedar_policy.id().clone();
                    policy_set
                        .add(cedar_policy)
                        .map_err(|_| PolicySetError::StaticPolicy(cedar_policy_id.to_string()))?;
                }
                Policy::TemplateLinked(policy_id, template_id, entity_map) => {
                    let cedar_policy_id =
                        PolicyId::from_str(&policy_id.to_string()).map_err(|_| {
                            PolicySetError::TemplateLinkedPolicy(
                                policy_id.to_string(),
                                template_id.to_string(),
                            )
                        })?;
                    let cedar_template_id =
                        PolicyId::from_str(&template_id.to_string()).map_err(|_| {
                            PolicySetError::TemplateLinkedPolicy(
                                policy_id.to_string(),
                                template_id.to_string(),
                            )
                        })?;
                    policy_set
                        .link(cedar_template_id, cedar_policy_id, entity_map)
                        .map_err(|_| {
                            PolicySetError::TemplateLinkedPolicy(
                                policy_id.to_string(),
                                template_id.to_string(),
                            )
                        })?;
                }
            }
        }

        Ok(Self {
            policy_store_id,
            template_source,
            policy_source,
            policy_set: RwLock::new(Arc::new(policy_set)),
        })
    }
}

#[async_trait]
impl SimplePolicySetProvider for PolicySetProvider {
    #[instrument(skip_all, err(Debug))]
    async fn get_policy_set(&self, _: &Request) -> Result<Arc<PolicySet>, PolicySetProviderError> {
        Ok(self.policy_set.read().await.clone())
    }
}

#[async_trait]
impl UpdateProviderData for PolicySetProvider {
    #[instrument(skip(self), err(Debug))]
    async fn update_provider_data(&self) -> Result<(), UpdateProviderDataError> {
        let templates;
        {
            templates = self
                .template_source
                .lock()
                .await
                .fetch(self.policy_store_id.clone())
                .await
                .map_err(|e| UpdateProviderDataError::General(Box::new(ProviderError::from(e))))?;
        };

        let policies;
        {
            policies = self
                .policy_source
                .lock()
                .await
                .fetch(self.policy_store_id.clone())
                .await
                .map_err(|e| UpdateProviderDataError::General(Box::new(ProviderError::from(e))))?;
        }

        let mut policy_set_data = PolicySet::new();
        for (_, template) in templates {
            policy_set_data
                .add_template(template.0.clone())
                .map_err(|_| {
                    UpdateProviderDataError::General(Box::new(ProviderError::from(
                        PolicySetError::Template(template.0.id().to_string()),
                    )))
                })?;
        }

        for (_, policy) in policies {
            match policy {
                Policy::Static(cedar_policy) => {
                    let cedar_policy_id = &cedar_policy.id().clone();
                    policy_set_data.add(cedar_policy).map_err(|_| {
                        UpdateProviderDataError::General(Box::new(PolicySetError::StaticPolicy(
                            cedar_policy_id.to_string(),
                        )))
                    })?;
                }
                Policy::TemplateLinked(policy_id, template_id, entity_map) => {
                    let cedar_policy_id =
                        PolicyId::from_str(&policy_id.to_string()).map_err(|_| {
                            UpdateProviderDataError::General(Box::new(
                                PolicySetError::TemplateLinkedPolicy(
                                    policy_id.to_string(),
                                    template_id.to_string(),
                                ),
                            ))
                        })?;
                    let cedar_template_id =
                        PolicyId::from_str(&template_id.to_string()).map_err(|_| {
                            UpdateProviderDataError::General(Box::new(
                                PolicySetError::TemplateLinkedPolicy(
                                    policy_id.to_string(),
                                    template_id.to_string(),
                                ),
                            ))
                        })?;
                    policy_set_data
                        .link(cedar_template_id, cedar_policy_id, entity_map)
                        .map_err(|_| {
                            UpdateProviderDataError::General(Box::new(
                                PolicySetError::TemplateLinkedPolicy(
                                    policy_id.to_string(),
                                    template_id.to_string(),
                                ),
                            ))
                        })?;
                }
            }
        }

        {
            let mut policy_set = self.policy_set.write().await;
            *policy_set = Arc::new(policy_set_data);
        }
        info!("Updated Policy Set Provider");
        Ok(())
    }
}
