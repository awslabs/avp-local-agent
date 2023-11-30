use thiserror::Error;

#[derive(Error, Debug)]
pub enum TranslatorException {
    #[error("Input is invalid.")]
    InvalidInput(),
    #[error("Error occurred when parsing the policy, policy id: {0}.")]
    ParsePolicy(String),
    #[error("Error occurred when parsing the entity in the policy, policy id: {0}.")]
    ParseEntity(String),
    #[error("Error occurred when parsing the template, template id: {0}.")]
    ParseTemplate(String),
    #[error("Error occurred when parsing the schema")]
    ParseSchema(),
}
