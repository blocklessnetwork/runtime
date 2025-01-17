use thiserror::Error;

#[derive(Error, Debug)]
pub enum DescriptorParserError {
    #[error("Empty path")]
    EmptyPath,

    #[error("Path not found")]
    CwdResolve,

    #[error("Empty environment descriptor")]
    EmptyEnvDescriptor,

    #[error("Empty sys descriptor")]
    EmptySysDescriptor,

    #[error("Empty run descriptor")]
    EmptyRunQuery,

    #[error("Path resolve error")]
    PathResolve,
}
