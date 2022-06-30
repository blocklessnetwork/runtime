pub use anyhow::{Context, Error};

#[derive(Debug)]
pub enum ErrorKind {
    ConnectError,
    EofError,
    MemoryNotExport,
    BadFileDescriptor,
    DriverNotFound,
    Addrnotavail,
    DriverBadOpen,
    DriverBadParams,
    PermissionDeny,
    Unknown,
}

impl std::error::Error for ErrorKind {}

impl std::fmt::Display for ErrorKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            &Self::ConnectError => write!(f, "Connect Error."),
            &Self::MemoryNotExport => write!(f, "Memoery not export"),
            &Self::DriverNotFound => write!(f, "Driver not found."),
            &Self::DriverBadOpen => write!(f, "Driver bad open."),
            &Self::BadFileDescriptor => write!(f, "Bad file descriptor."),
            &Self::DriverBadParams => write!(f, "Driver bad params."),
            &Self::Addrnotavail => write!(f, "Address is not avail."),
            &Self::Unknown => write!(f, "Unknown error."),
            &Self::EofError => write!(f, "End of file error."),
            &Self::PermissionDeny => write!(f, "Permision deny."),
        }
    }
}

#[derive(Debug)]
pub enum HttpErrorKind {
    InvalidDriver,
    InvalidHandle,
    MemoryAccessError,
    BufferTooSmall,
    HeaderNotFound,
    Utf8Error,
    DestinationNotAllowed,
    InvalidMethod,
    InvalidEncoding,
    InvalidUrl,
    RequestError,
    RuntimeError,
    TooManySessions,
    PermissionDeny,
}

impl std::error::Error for HttpErrorKind {}

impl std::fmt::Display for HttpErrorKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            &Self::InvalidDriver => write!(f, "Invalid Driver"),
            &Self::InvalidHandle => write!(f, "Invalid Error"),
            &Self::MemoryAccessError => write!(f, "Memoery Access Error"),
            &Self::BufferTooSmall => write!(f, "Buffer too small"),
            &Self::HeaderNotFound => write!(f, "Header not found"),
            &Self::Utf8Error => write!(f, "Utf8 error"),
            &Self::DestinationNotAllowed => write!(f, "Destination not allowed"),
            &Self::InvalidMethod => write!(f, "Invalid method"),
            &Self::InvalidEncoding => write!(f, "Invalid encoding"),
            &Self::InvalidUrl => write!(f, "Invalid url"),
            &Self::RequestError => write!(f, "Request url"),
            &Self::RuntimeError => write!(f, "Runtime error"),
            &Self::TooManySessions => write!(f, "Too many sessions"),
            &Self::PermissionDeny => write!(f, "Permision deny."),
        }
    }
}

#[derive(Debug)]
pub enum IpfsErrorKind {
    InvalidHandle,
    Utf8Error,
    InvalidMethod,
    InvalidEncoding,
    RequestError,
    RuntimeError,
    TooManySessions,
    PermissionDeny,
}

impl std::error::Error for IpfsErrorKind {}

impl std::fmt::Display for IpfsErrorKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            &Self::InvalidHandle => write!(f, "Invalid Error"),
            &Self::Utf8Error => write!(f, "Utf8 error"),
            &Self::InvalidMethod => write!(f, "Invalid method"),
            &Self::InvalidEncoding => write!(f, "Invalid encoding"),
            &Self::RequestError => write!(f, "Request url"),
            &Self::RuntimeError => write!(f, "Runtime error"),
            &Self::TooManySessions => write!(f, "Too many sessions"),
            &Self::PermissionDeny => write!(f, "Permision deny."),
        }
    }
}