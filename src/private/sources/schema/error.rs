//! Defines the enum for errors returned by the AWS Verified Permissions schema reader
use crate::private::sources::schema::error::SchemaException::{
    AccessDenied, ResourceNotFound, Retryable, Unhandled, Validation,
};
use crate::private::translator::error::TranslatorException;
use aws_sdk_verifiedpermissions::operation::get_schema::GetSchemaError;
use thiserror::Error;

/// The enum for errors returned by the AWS Verified Permissions schema reader.
#[derive(Error, Debug)]
pub enum SchemaException {
    /// The request failed because the user did not have the required permissions to perform
    /// the action.
    #[error("Amazon Verified Permissions Access Denied exception: {0}")]
    AccessDenied(#[source] Box<dyn std::error::Error + Send + Sync + 'static>),
    /// The request failed because one or more input parameters don't satisfy their constraint
    /// requirements.
    #[error("Invalid Input Exception: {0}")]
    Validation(#[source] Box<dyn std::error::Error + Send + Sync + 'static>),
    /// The request failed because the schema does not exist in AVP.
    #[error("Schema not found exception: {0}")]
    ResourceNotFound(#[source] Box<dyn std::error::Error + Send + Sync + 'static>),
    /// The request failed because an internal error occurred, or it exceeded a throttling quota.
    /// Try again.
    #[error("Retryable Exception: {0}")]
    Retryable(#[source] Box<dyn std::error::Error + Send + Sync + 'static>),
    /// An unexpected error occurred.
    #[error("Internal Exception, something uncaught occurred: {0}")]
    Unhandled(#[source] Box<dyn std::error::Error + Send + Sync + 'static>),
}

impl From<GetSchemaError> for SchemaException {
    fn from(error: GetSchemaError) -> Self {
        match error {
            GetSchemaError::ResourceNotFoundException(error) => ResourceNotFound(Box::new(error)),
            GetSchemaError::AccessDeniedException(error) => AccessDenied(Box::new(error)),
            GetSchemaError::InternalServerException(error) => Retryable(Box::new(error)),
            GetSchemaError::ThrottlingException(error) => Retryable(Box::new(error)),
            GetSchemaError::ValidationException(error) => Validation(Box::new(error)),
            _ => Unhandled(Box::new(error)),
        }
    }
}

/// The enum for errors that occur when fetching data from a `SchemaSource`.
#[derive(Error, Debug)]
pub enum SchemaSourceException {
    /// There was an error reading the policy from the source.
    #[error("Data source error: {0}")]
    SchemaSource(#[source] SchemaException),
    /// There was an error translating the schema from the source to cedar.
    #[error("Translation exception: {0}")]
    TranslatorException(#[source] TranslatorException),
}

impl From<SchemaException> for SchemaSourceException {
    fn from(error: SchemaException) -> Self {
        Self::SchemaSource(error)
    }
}

impl From<TranslatorException> for SchemaSourceException {
    fn from(error: TranslatorException) -> Self {
        Self::TranslatorException(error)
    }
}

#[cfg(test)]
mod tests {
    use crate::private::sources::schema::error::{SchemaException, SchemaSourceException};
    use crate::private::translator;
    use aws_sdk_verifiedpermissions::operation::get_schema::GetSchemaError;
    use aws_sdk_verifiedpermissions::types::error::{
        AccessDeniedException, InternalServerException, ResourceNotFoundException,
        ThrottlingException, ValidationException,
    };
    use aws_sdk_verifiedpermissions::types::ResourceType;

    const MESSAGE: &str = "dummy-message";
    #[test]
    fn from_get_schema_error_resource_not_found_to_schema_exception() {
        assert_eq!(
            SchemaException::from(GetSchemaError::ResourceNotFoundException(
                ResourceNotFoundException::builder()
                    .resource_id("id")
                    .resource_type(ResourceType::Schema)
                    .message(MESSAGE)
                    .build()
                    .unwrap(),
            ))
            .to_string(),
            SchemaException::ResourceNotFound(Box::new(
                ResourceNotFoundException::builder()
                    .resource_id("id")
                    .resource_type(ResourceType::Schema)
                    .message(MESSAGE)
                    .build()
                    .unwrap(),
            ))
            .to_string()
        );
    }

    #[test]
    fn from_get_schema_error_access_denied_to_schema_exception() {
        assert_eq!(
            SchemaException::from(GetSchemaError::AccessDeniedException(
                AccessDeniedException::builder()
                    .message(MESSAGE)
                    .build()
                    .unwrap()
            ))
            .to_string(),
            SchemaException::AccessDenied(Box::new(
                AccessDeniedException::builder()
                    .message(MESSAGE)
                    .build()
                    .unwrap()
            ))
            .to_string()
        );
    }

    #[test]
    fn from_get_schema_error_internal_server_exception_to_schema_exception() {
        assert_eq!(
            SchemaException::from(GetSchemaError::InternalServerException(
                InternalServerException::builder()
                    .message(MESSAGE)
                    .build()
                    .unwrap()
            ))
            .to_string(),
            SchemaException::Retryable(Box::new(
                InternalServerException::builder()
                    .message(MESSAGE)
                    .build()
                    .unwrap()
            ))
            .to_string()
        );
    }

    #[test]
    fn from_get_schema_error_throttling_exception_to_schema_exception() {
        assert_eq!(
            SchemaException::from(GetSchemaError::ThrottlingException(
                ThrottlingException::builder()
                    .message(MESSAGE)
                    .build()
                    .unwrap()
            ))
            .to_string(),
            SchemaException::Retryable(Box::new(
                ThrottlingException::builder()
                    .message(MESSAGE)
                    .build()
                    .unwrap()
            ))
            .to_string()
        );
    }

    #[test]
    fn from_get_schema_error_validation_exception_to_schema_exception() {
        assert_eq!(
            SchemaException::from(GetSchemaError::ValidationException(
                ValidationException::builder()
                    .message(MESSAGE)
                    .build()
                    .unwrap()
            ))
            .to_string(),
            SchemaException::Validation(Box::new(
                ValidationException::builder()
                    .message(MESSAGE)
                    .build()
                    .unwrap()
            ))
            .to_string()
        );
    }

    #[test]
    fn from_get_schema_error_unhandled_to_schema_exception() {
        assert_eq!(
            SchemaException::from(GetSchemaError::unhandled(
                ValidationException::builder()
                    .message(MESSAGE)
                    .build()
                    .unwrap()
            ))
            .to_string(),
            SchemaException::Unhandled(Box::new(GetSchemaError::unhandled(
                ValidationException::builder()
                    .message(MESSAGE)
                    .build()
                    .unwrap()
            )))
            .to_string()
        );
    }

    #[test]
    fn from_translator_exception_to_schema_source_exception() {
        let translator_exception = translator::error::TranslatorException::InvalidInput();
        assert!(matches!(
            SchemaSourceException::from(translator_exception),
            SchemaSourceException::TranslatorException(..)
        ));
    }

    #[test]
    fn from_schema_exception_to_schema_source_exception() {
        let schema_exception = SchemaException::Unhandled(Box::new(GetSchemaError::unhandled(
            ValidationException::builder()
                .message(MESSAGE)
                .build()
                .unwrap(),
        )));
        assert!(matches!(
            SchemaSourceException::from(schema_exception),
            SchemaSourceException::SchemaSource(..)
        ));
    }
}
