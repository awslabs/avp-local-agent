use cedar_policy::SchemaError;
use cedar_policy_core::parser::err::ParseErrors;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum TranslatorException {
    #[error("Static policy statement is not found.")]
    StaticPolicyStatementNotFound(),
    #[error("Template statement is not found.")]
    TemplateStatementNotFound(),
    #[error("Template id is not found.")]
    TemplateIdNotFound(),
    #[error("Entity identifier name is not found.")]
    EntityNameNotFound(),
    #[error("Entity identifier id is not found.")]
    EntityIdNotFound(),
    #[error("Input is invalid.")]
    InvalidInput(),
    #[error("Error occurred when parsing the object: {0}.")]
    ParseObject(#[source] ParseErrors),
    #[error("Error occurred when parsing the schema: {0}")]
    ParseSchema(#[source] SchemaError),
}

impl From<ParseErrors> for TranslatorException {
    fn from(err: ParseErrors) -> Self {
        Self::ParseObject(err)
    }
}

impl From<SchemaError> for TranslatorException {
    fn from(err: SchemaError) -> Self {
        Self::ParseSchema(err)
    }
}
