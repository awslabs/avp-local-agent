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
    #[error("Error occurred when parsing the policy, policy id: {0}.")]
    ParsePolicy(String),
    #[error("Error occurred when parsing the entity in the policy, policy id: {0}.")]
    ParseEntity(String),
    #[error("Error occurred when parsing the template, template id: {0}.")]
    ParseTemplate(String),
    #[error("Error occurred when parsing the schema")]
    ParseSchema(),
}
