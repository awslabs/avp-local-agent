//! Defines the enum for policy errors returned by the AWS Verified Permissions policy reader
//! and loader.

use crate::private::sources::policy::error::PolicyException::{
    AccessDenied, ResourceNotFound, Retryable, Unhandled, Validation,
};
use crate::private::translator::error::TranslatorException;
use aws_sdk_verifiedpermissions::operation::get_policy::GetPolicyError;
use aws_sdk_verifiedpermissions::operation::list_policies::ListPoliciesError;
use thiserror::Error;

/// The enum for policy errors returned by the AWS Verified Permissions policy reader and loader.
#[derive(Error, Debug)]
pub enum PolicyException {
    /// The request failed because the remote Policy or Policy Store does not exist in AVP.
    #[error("Policy Id and/or Policy Store Id not found exception: {0}")]
    ResourceNotFound(#[source] Box<dyn std::error::Error + Send + Sync + 'static>),
    /// The request failed because the user did not have the required permissions to perform
    /// the action.
    #[error("Amazon Verified Permissions Access Denied exception: {0}")]
    AccessDenied(#[source] Box<dyn std::error::Error + Send + Sync + 'static>),
    /// The request failed because one or more input parameters don't satisfy their constraint
    /// requirements.
    #[error("Invalid input exception: {0}")]
    Validation(#[source] Box<dyn std::error::Error + Send + Sync + 'static>),
    /// The request failed because an internal error occurred, or it exceeded a throttling quota.
    /// Try again.
    #[error("Retryable Exception: {0}")]
    Retryable(#[source] Box<dyn std::error::Error + Send + Sync + 'static>),
    /// An unexpected error occurred.
    #[error("An unexpected error occurred: {0}")]
    Unhandled(#[source] Box<dyn std::error::Error + Send + Sync + 'static>),
}

impl From<GetPolicyError> for PolicyException {
    fn from(err: GetPolicyError) -> Self {
        match err {
            GetPolicyError::ResourceNotFoundException(err) => ResourceNotFound(Box::new(err)),
            GetPolicyError::AccessDeniedException(err) => AccessDenied(Box::new(err)),
            GetPolicyError::ValidationException(err) => Validation(Box::new(err)),
            GetPolicyError::InternalServerException(err) => Retryable(Box::new(err)),
            GetPolicyError::ThrottlingException(err) => Retryable(Box::new(err)),
            _ => Unhandled(Box::new(err)),
        }
    }
}

impl From<ListPoliciesError> for PolicyException {
    fn from(err: ListPoliciesError) -> Self {
        match err {
            ListPoliciesError::ResourceNotFoundException(err) => ResourceNotFound(Box::new(err)),
            ListPoliciesError::AccessDeniedException(err) => AccessDenied(Box::new(err)),
            ListPoliciesError::ValidationException(err) => Validation(Box::new(err)),
            ListPoliciesError::InternalServerException(err) => Retryable(Box::new(err)),
            ListPoliciesError::ThrottlingException(err) => Retryable(Box::new(err)),
            _ => Unhandled(Box::new(err)),
        }
    }
}

/// The enum for errors that occur when fetching data from a `PolicySource`.
#[derive(Error, Debug)]
pub enum PolicySourceException {
    /// The policy returned by AVP does not contain a `PolicyId` field.
    #[error("Policy id is not found.")]
    PolicyIdNotFound(),
    /// The policy returned by AVP does not contain a `Definition` field.
    #[error("Policy definition is not found.")]
    PolicyDefinitionNotFound(),
    /// There was an error reading the policy from the source.
    #[error("Data source error {0}")]
    PolicySource(#[source] PolicyException),
    /// There was an error translating the policy from the source to cedar.
    #[error("Translation exception {0}")]
    TranslatorException(#[source] TranslatorException),
}

impl From<PolicyException> for PolicySourceException {
    fn from(error: PolicyException) -> Self {
        Self::PolicySource(error)
    }
}

impl From<TranslatorException> for PolicySourceException {
    fn from(error: TranslatorException) -> Self {
        Self::TranslatorException(error)
    }
}

#[cfg(test)]
mod tests {
    use crate::private::sources::policy::error::{PolicyException, PolicySourceException};
    use crate::private::translator::error::TranslatorException;
    use aws_sdk_verifiedpermissions::operation::get_policy::GetPolicyError;
    use aws_sdk_verifiedpermissions::operation::list_policies::ListPoliciesError;
    use aws_sdk_verifiedpermissions::types::error::{
        AccessDeniedException, InternalServerException, ResourceNotFoundException,
        ThrottlingException, ValidationException,
    };
    use aws_smithy_types::error::Unhandled;

    #[test]
    fn from_get_policy_error_resource_not_found_to_policy_exception_resource_not_found() {
        assert_eq!(
            PolicyException::from(GetPolicyError::ResourceNotFoundException(
                ResourceNotFoundException::builder().build()
            ))
            .to_string(),
            PolicyException::ResourceNotFound(Box::new(
                ResourceNotFoundException::builder().build()
            ))
            .to_string()
        );
    }

    #[test]
    fn from_get_policy_error_access_denied_to_policy_exception_access_denied() {
        assert_eq!(
            PolicyException::from(GetPolicyError::AccessDeniedException(
                AccessDeniedException::builder().build()
            ))
            .to_string(),
            PolicyException::AccessDenied(Box::new(AccessDeniedException::builder().build()))
                .to_string()
        );
    }

    #[test]
    fn from_get_policy_error_validation_to_policy_exception_validation() {
        assert_eq!(
            PolicyException::from(GetPolicyError::ValidationException(
                ValidationException::builder().build()
            ))
            .to_string(),
            PolicyException::Validation(Box::new(ValidationException::builder().build()))
                .to_string()
        );
    }

    #[test]
    fn from_get_policy_error_internal_server_to_policy_exception_retryable() {
        assert_eq!(
            PolicyException::from(GetPolicyError::InternalServerException(
                InternalServerException::builder().build()
            ))
            .to_string(),
            PolicyException::Retryable(Box::new(InternalServerException::builder().build()))
                .to_string()
        );
    }

    #[test]
    fn from_get_policy_error_throttling_to_policy_exception_retryable() {
        assert_eq!(
            PolicyException::from(GetPolicyError::ThrottlingException(
                ThrottlingException::builder().build()
            ))
            .to_string(),
            PolicyException::Retryable(Box::new(ThrottlingException::builder().build()))
                .to_string()
        );
    }

    #[test]
    fn from_get_policy_error_unhandled_to_policy_exception_unhandled() {
        assert_eq!(
            PolicyException::from(GetPolicyError::Unhandled(
                Unhandled::builder()
                    .source(Box::new(ValidationException::builder().build()))
                    .build()
            ))
            .to_string(),
            PolicyException::Unhandled(Box::new(
                Unhandled::builder()
                    .source(Box::new(ValidationException::builder().build()))
                    .build()
            ))
            .to_string()
        );
    }

    #[test]
    fn from_list_policies_error_resource_not_found_to_policy_exception_resource_not_found() {
        assert_eq!(
            PolicyException::from(ListPoliciesError::ResourceNotFoundException(
                ResourceNotFoundException::builder().build()
            ))
            .to_string(),
            PolicyException::ResourceNotFound(Box::new(
                ResourceNotFoundException::builder().build()
            ))
            .to_string()
        );
    }

    #[test]
    fn from_list_policies_error_access_denied_to_policy_exception_access_denied() {
        assert_eq!(
            PolicyException::from(ListPoliciesError::AccessDeniedException(
                AccessDeniedException::builder().build()
            ))
            .to_string(),
            PolicyException::AccessDenied(Box::new(AccessDeniedException::builder().build()))
                .to_string()
        );
    }

    #[test]
    fn from_list_policies_error_validation_to_policy_exception_validation() {
        assert_eq!(
            PolicyException::from(ListPoliciesError::ValidationException(
                ValidationException::builder().build()
            ))
            .to_string(),
            PolicyException::Validation(Box::new(ValidationException::builder().build()))
                .to_string()
        );
    }

    #[test]
    fn from_list_policies_error_internal_server_to_policy_exception_retryable() {
        assert_eq!(
            PolicyException::from(ListPoliciesError::InternalServerException(
                InternalServerException::builder().build()
            ))
            .to_string(),
            PolicyException::Retryable(Box::new(InternalServerException::builder().build()))
                .to_string()
        );
    }

    #[test]
    fn from_list_policies_error_throttling_to_policy_exception_retryable() {
        assert_eq!(
            PolicyException::from(ListPoliciesError::ThrottlingException(
                ThrottlingException::builder().build()
            ))
            .to_string(),
            PolicyException::Retryable(Box::new(ThrottlingException::builder().build()))
                .to_string()
        );
    }

    #[test]
    fn from_list_policies_error_unhandled_to_policy_exception_unhandled() {
        assert_eq!(
            PolicyException::from(ListPoliciesError::Unhandled(
                Unhandled::builder()
                    .source(Box::new(ValidationException::builder().build()))
                    .build()
            ))
            .to_string(),
            PolicyException::Unhandled(Box::new(
                Unhandled::builder()
                    .source(Box::new(ValidationException::builder().build()))
                    .build()
            ))
            .to_string()
        );
    }

    #[test]
    fn from_policy_exception_to_policy_source_exception_policy_source() {
        assert_eq!(
            PolicySourceException::from(PolicyException::ResourceNotFound(Box::new(
                ResourceNotFoundException::builder().build()
            )))
            .to_string(),
            PolicySourceException::PolicySource(PolicyException::ResourceNotFound(Box::new(
                ResourceNotFoundException::builder().build()
            )))
            .to_string()
        );
    }

    #[test]
    fn from_policy_translator_exception_to_policy_source_exception_translator_exception() {
        assert_eq!(
            PolicySourceException::from(TranslatorException::StaticPolicyStatementNotFound())
                .to_string(),
            PolicySourceException::TranslatorException(
                TranslatorException::StaticPolicyStatementNotFound()
            )
            .to_string()
        );
    }
}
