//! Defines the enum for errors returned by the AWS Verified Permissions template reader and loader.
use aws_sdk_verifiedpermissions::operation::get_policy_template::GetPolicyTemplateError;
use aws_sdk_verifiedpermissions::operation::list_policy_templates::ListPolicyTemplatesError;
use thiserror::Error;

use crate::private::sources::template::error::TemplateException::{
    AccessDenied, ResourceNotFound, Retryable, Unhandled, Validation,
};
use crate::private::translator::error::TranslatorException;

/// The enum for errors returned by the AWS Verified Permissions template reader and loader.
#[derive(Error, Debug)]
pub enum TemplateException {
    /// The request failed because the user did not have the required permissions to perform
    /// the action.
    #[error("Amazon Verified Permissions Access Denied exception: {0}")]
    AccessDenied(#[source] Box<dyn std::error::Error + Send + Sync + 'static>),
    /// The request failed because one or more input parameters don't satisfy their constraint
    /// requirements.
    #[error("Invalid Input Exception: {0}")]
    Validation(#[source] Box<dyn std::error::Error + Send + Sync + 'static>),
    /// The request failed because the template does not exist in AVP.
    #[error("Template Id not found exception: {0}")]
    ResourceNotFound(#[source] Box<dyn std::error::Error + Send + Sync + 'static>),
    /// The request failed because an internal error occurred, or it exceeded a throttling quota.
    /// Try again.
    #[error("Retryable Exception: {0}")]
    Retryable(#[source] Box<dyn std::error::Error + Send + Sync + 'static>),
    /// An unexpected error occurred.
    #[error("Internal Exception, something uncaught occurred: {0}")]
    Unhandled(#[source] Box<dyn std::error::Error + Send + Sync + 'static>),
}

impl From<ListPolicyTemplatesError> for TemplateException {
    fn from(error: ListPolicyTemplatesError) -> Self {
        match error {
            ListPolicyTemplatesError::ResourceNotFoundException(error) => {
                ResourceNotFound(Box::new(error))
            }
            ListPolicyTemplatesError::AccessDeniedException(error) => AccessDenied(Box::new(error)),
            ListPolicyTemplatesError::InternalServerException(error) => Retryable(Box::new(error)),
            ListPolicyTemplatesError::ThrottlingException(error) => Retryable(Box::new(error)),
            ListPolicyTemplatesError::ValidationException(error) => Validation(Box::new(error)),
            _ => Unhandled(Box::new(error)),
        }
    }
}

impl From<GetPolicyTemplateError> for TemplateException {
    fn from(error: GetPolicyTemplateError) -> Self {
        match error {
            GetPolicyTemplateError::ResourceNotFoundException(error) => {
                ResourceNotFound(Box::new(error))
            }
            GetPolicyTemplateError::AccessDeniedException(error) => AccessDenied(Box::new(error)),
            GetPolicyTemplateError::InternalServerException(error) => Retryable(Box::new(error)),
            GetPolicyTemplateError::ThrottlingException(error) => Retryable(Box::new(error)),
            GetPolicyTemplateError::ValidationException(error) => Validation(Box::new(error)),
            _ => Unhandled(Box::new(error)),
        }
    }
}

/// The enum for errors that occur when fetching data from a `TemplateSource`.
#[derive(Error, Debug)]
pub enum TemplateSourceException {
    /// There was an error reading the template from the source.
    #[error("Data source error")]
    TemplateSource(#[from] TemplateException),
    /// There was an error translating the template from the source to cedar.
    #[error("Translation exception")]
    TranslatorException(#[from] TranslatorException),
}

#[cfg(test)]
mod test {
    use aws_sdk_verifiedpermissions::operation::get_policy_template::GetPolicyTemplateError;
    use aws_sdk_verifiedpermissions::operation::list_policy_templates::ListPolicyTemplatesError;
    use aws_sdk_verifiedpermissions::types::error::{
        AccessDeniedException, InternalServerException, ResourceNotFoundException,
        ThrottlingException, ValidationException,
    };
    use aws_sdk_verifiedpermissions::types::ResourceType;

    use crate::private::sources::template::error::{TemplateException, TemplateSourceException};
    use crate::private::translator::error::TranslatorException;

    const MESSAGE: &str = "dummy-message";

    #[test]
    fn from_list_policy_templates_error_resource_not_found_to_template_error() {
        assert_eq!(
            TemplateException::from(ListPolicyTemplatesError::ResourceNotFoundException(
                ResourceNotFoundException::builder()
                    .resource_id("id")
                    .resource_type(ResourceType::PolicyTemplate)
                    .message(MESSAGE)
                    .build()
                    .unwrap(),
            ))
            .to_string(),
            TemplateException::ResourceNotFound(Box::new(
                ResourceNotFoundException::builder()
                    .resource_id("id")
                    .resource_type(ResourceType::PolicyTemplate)
                    .message(MESSAGE)
                    .build()
                    .unwrap(),
            ))
            .to_string()
        );
    }

    #[test]
    fn from_list_policy_templates_error_access_denied_to_template_error() {
        assert_eq!(
            TemplateException::from(ListPolicyTemplatesError::AccessDeniedException(
                AccessDeniedException::builder()
                    .message(MESSAGE)
                    .build()
                    .unwrap(),
            ))
            .to_string(),
            TemplateException::AccessDenied(Box::new(
                AccessDeniedException::builder()
                    .message(MESSAGE)
                    .build()
                    .unwrap()
            ))
            .to_string()
        );
    }

    #[test]
    fn from_list_policy_templates_error_internal_server_to_template_error() {
        assert_eq!(
            TemplateException::from(ListPolicyTemplatesError::InternalServerException(
                InternalServerException::builder()
                    .message(MESSAGE)
                    .build()
                    .unwrap(),
            ))
            .to_string(),
            TemplateException::Retryable(Box::new(
                InternalServerException::builder()
                    .message(MESSAGE)
                    .build()
                    .unwrap()
            ))
            .to_string()
        );
    }

    #[test]
    fn from_list_policy_templates_error_throttling_to_template_error() {
        assert_eq!(
            TemplateException::from(ListPolicyTemplatesError::ThrottlingException(
                ThrottlingException::builder()
                    .message(MESSAGE)
                    .build()
                    .unwrap(),
            ))
            .to_string(),
            TemplateException::Retryable(Box::new(
                ThrottlingException::builder()
                    .message(MESSAGE)
                    .build()
                    .unwrap()
            ))
            .to_string()
        );
    }

    #[test]
    fn from_list_policy_templates_error_validation_to_template_error() {
        assert_eq!(
            TemplateException::from(ListPolicyTemplatesError::ValidationException(
                ValidationException::builder()
                    .message(MESSAGE)
                    .build()
                    .unwrap(),
            ))
            .to_string(),
            TemplateException::Validation(Box::new(
                ValidationException::builder()
                    .message(MESSAGE)
                    .build()
                    .unwrap()
            ))
            .to_string()
        );
    }

    #[test]
    fn from_list_policy_templates_error_unhandled_to_template_error() {
        assert_eq!(
            TemplateException::from(ListPolicyTemplatesError::unhandled(
                ValidationException::builder()
                    .message(MESSAGE)
                    .build()
                    .unwrap()
            ))
            .to_string(),
            TemplateException::Unhandled(Box::new(ListPolicyTemplatesError::unhandled(
                ValidationException::builder()
                    .message(MESSAGE)
                    .build()
                    .unwrap()
            )))
            .to_string()
        );
    }

    #[test]
    fn from_get_policy_template_error_resource_not_found_to_template_error() {
        assert_eq!(
            TemplateException::from(GetPolicyTemplateError::ResourceNotFoundException(
                ResourceNotFoundException::builder()
                    .resource_id("id")
                    .resource_type(ResourceType::PolicyTemplate)
                    .message(MESSAGE)
                    .build()
                    .unwrap(),
            ))
            .to_string(),
            TemplateException::ResourceNotFound(Box::new(
                ResourceNotFoundException::builder()
                    .resource_id("id")
                    .resource_type(ResourceType::PolicyTemplate)
                    .message(MESSAGE)
                    .build()
                    .unwrap()
            ))
            .to_string()
        );
    }

    #[test]
    fn from_get_policy_template_error_access_denied_to_template_error() {
        assert_eq!(
            TemplateException::from(GetPolicyTemplateError::AccessDeniedException(
                AccessDeniedException::builder()
                    .message(MESSAGE)
                    .build()
                    .unwrap(),
            ))
            .to_string(),
            TemplateException::AccessDenied(Box::new(
                AccessDeniedException::builder()
                    .message(MESSAGE)
                    .build()
                    .unwrap()
            ))
            .to_string()
        );
    }

    #[test]
    fn from_get_policy_template_error_internal_server_to_template_error() {
        assert_eq!(
            TemplateException::from(GetPolicyTemplateError::InternalServerException(
                InternalServerException::builder()
                    .message(MESSAGE)
                    .build()
                    .unwrap(),
            ))
            .to_string(),
            TemplateException::Retryable(Box::new(
                InternalServerException::builder()
                    .message(MESSAGE)
                    .build()
                    .unwrap()
            ))
            .to_string()
        );
    }

    #[test]
    fn from_get_policy_template_error_throttling_to_template_error() {
        assert_eq!(
            TemplateException::from(GetPolicyTemplateError::ThrottlingException(
                ThrottlingException::builder()
                    .message(MESSAGE)
                    .build()
                    .unwrap(),
            ))
            .to_string(),
            TemplateException::Retryable(Box::new(
                ThrottlingException::builder()
                    .message(MESSAGE)
                    .build()
                    .unwrap()
            ))
            .to_string()
        );
    }

    #[test]
    fn from_get_policy_template_error_validation_to_template_error() {
        assert_eq!(
            TemplateException::from(GetPolicyTemplateError::ValidationException(
                ValidationException::builder()
                    .message(MESSAGE)
                    .build()
                    .unwrap(),
            ))
            .to_string(),
            TemplateException::Validation(Box::new(
                ValidationException::builder()
                    .message(MESSAGE)
                    .build()
                    .unwrap()
            ))
            .to_string()
        );
    }

    #[test]
    fn from_get_policy_template_error_unhandled_to_template_error() {
        assert_eq!(
            TemplateException::from(GetPolicyTemplateError::unhandled(
                ValidationException::builder()
                    .message(MESSAGE)
                    .build()
                    .unwrap()
            ))
            .to_string(),
            TemplateException::Unhandled(Box::new(GetPolicyTemplateError::unhandled(
                ValidationException::builder()
                    .message(MESSAGE)
                    .build()
                    .unwrap()
            )))
            .to_string()
        );
    }

    #[test]
    fn from_template_exception_to_template_source_exception() {
        assert_eq!(
            TemplateSourceException::from(TemplateException::Unhandled(Box::new(
                Unhandled::builder()
                    .source(Box::new(ValidationException::builder().build()))
                    .build()
            )))
            .to_string(),
            TemplateSourceException::TemplateSource(TemplateException::Unhandled(Box::new(
                Unhandled::builder()
                    .source(Box::new(ValidationException::builder().build()))
                    .build()
            )))
            .to_string()
        );
    }

    #[test]
    fn from_translator_exception_to_template_source_exception() {
        assert_eq!(
            TemplateSourceException::from(TranslatorException::InvalidInput()).to_string(),
            TemplateSourceException::TranslatorException(TranslatorException::InvalidInput())
                .to_string()
        );
    }
}
