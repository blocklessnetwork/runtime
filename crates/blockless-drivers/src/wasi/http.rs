#![allow(non_upper_case_globals)]
use std::str::FromStr;

use crate::{http_driver, HttpErrorKind};
use log::error;
use url::Url;
use wasi_common::WasiCtx;
use wiggle::{GuestMemory, GuestPtr};

wiggle::from_witx!({
    witx: ["$BLOCKLESS_DRIVERS_ROOT/witx/blockless_http.witx"],
    errors: { http_error => HttpErrorKind },
    async: *,
    wasmtime: false,
});

impl types::UserErrorConversion for WasiCtx {
    fn http_error_from_http_error_kind(
        &mut self,
        e: self::HttpErrorKind,
    ) -> wiggle::anyhow::Result<types::HttpError> {
        Ok(e.into())
    }
}

impl From<HttpErrorKind> for types::HttpError {
    fn from(e: HttpErrorKind) -> types::HttpError {
        use types::HttpError;
        match e {
            HttpErrorKind::InvalidHandle => HttpError::InvalidHandle,
            HttpErrorKind::MemoryAccessError => HttpError::MemoryAccessError,
            HttpErrorKind::BufferTooSmall => HttpError::BufferTooSmall,
            HttpErrorKind::HeaderNotFound => HttpError::HeaderNotFound,
            HttpErrorKind::Utf8Error => HttpError::Utf8Error,
            HttpErrorKind::DestinationNotAllowed => HttpError::DestinationNotAllowed,
            HttpErrorKind::InvalidMethod => HttpError::InvalidMethod,
            HttpErrorKind::InvalidEncoding => HttpError::InvalidEncoding,
            HttpErrorKind::InvalidUrl => HttpError::InvalidUrl,
            HttpErrorKind::RequestError => HttpError::RequestError,
            HttpErrorKind::RuntimeError => HttpError::RuntimeError,
            HttpErrorKind::TooManySessions => HttpError::TooManySessions,
            HttpErrorKind::InvalidDriver => HttpError::InvalidDriver,
            HttpErrorKind::PermissionDeny => HttpError::PermissionDeny,
            HttpErrorKind::HeadersValidationError => HttpError::HeadersValidationError,
        }
    }
}

macro_rules! enum_2_u32 {
    ($($t:tt),+) => {
       $(const $t: u32 = types::HttpError::$t as _;)*
    }
}

enum_2_u32!(
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
    PermissionDeny,
    TooManySessions
);

impl From<u32> for HttpErrorKind {
    fn from(i: u32) -> HttpErrorKind {
        match i {
            InvalidHandle => HttpErrorKind::InvalidHandle,
            MemoryAccessError => HttpErrorKind::MemoryAccessError,
            BufferTooSmall => HttpErrorKind::BufferTooSmall,
            HeaderNotFound => HttpErrorKind::HeaderNotFound,
            Utf8Error => HttpErrorKind::Utf8Error,
            DestinationNotAllowed => HttpErrorKind::DestinationNotAllowed,
            InvalidMethod => HttpErrorKind::InvalidMethod,
            InvalidEncoding => HttpErrorKind::InvalidEncoding,
            InvalidUrl => HttpErrorKind::InvalidUrl,
            RuntimeError => HttpErrorKind::RuntimeError,
            RequestError => HttpErrorKind::RequestError,
            TooManySessions => HttpErrorKind::TooManySessions,
            PermissionDeny => HttpErrorKind::PermissionDeny,
            _ => HttpErrorKind::RuntimeError,
        }
    }
}

impl wiggle::GuestErrorType for types::HttpError {
    fn success() -> Self {
        Self::Success
    }
}

#[wiggle::async_trait]
impl blockless_http::BlocklessHttp for WasiCtx {
    async fn http_req(
        &mut self,
        memory: &mut GuestMemory<'_>,
        url: GuestPtr<str>,
        opts: GuestPtr<str>,
    ) -> Result<(types::HttpHandle, types::CodeType), HttpErrorKind> {
        let url: &str = memory
            .as_str(url)
            .map_err(|e| {
                error!("guest url error: {}", e);
                HttpErrorKind::Utf8Error
            })?
            .unwrap();

        let url_ = Url::from_str(url).map_err(|_| HttpErrorKind::InvalidUrl)?;
        if !self.check_url_permissions(&url_, "http_req") {
            error!("Permission Deny");
            return Err(HttpErrorKind::PermissionDeny);
        }
        let opts: &str = memory
            .as_str(opts)
            .map_err(|e| {
                error!("guest options error: {}", e);
                HttpErrorKind::Utf8Error
            })?
            .unwrap();
        let (fd, code) = http_driver::http_req(url, opts).await?;
        Ok((types::HttpHandle::from(fd), types::CodeType::from(code)))
    }

    async fn http_close(
        &mut self,
        _memory: &mut GuestMemory<'_>,
        handle: types::HttpHandle,
    ) -> Result<(), HttpErrorKind> {
        http_driver::http_close(handle.into()).await
    }

    async fn http_read_header(
        &mut self,
        memory: &mut GuestMemory<'_>,
        handle: types::HttpHandle,
        head: GuestPtr<str>,
        buf: GuestPtr<u8>,
        buf_len: u32,
    ) -> Result<u32, HttpErrorKind> {
        let head: &str = memory
            .as_str(head)
            .map_err(|e| {
                error!("guest head error: {}", e);
                HttpErrorKind::Utf8Error
            })?
            .unwrap();
        let mut dest_buf = vec![0; buf_len as _];
        let buf = buf;
        let rs = http_driver::http_read_head(handle.into(), head, &mut dest_buf[..]).await?;
        memory
            .copy_from_slice(&dest_buf[0..rs as _], buf.as_array(rs))
            .map_err(|_| HttpErrorKind::MemoryAccessError)?;
        Ok(rs)
    }

    async fn http_read_body(
        &mut self,
        memory: &mut GuestMemory<'_>,
        handle: types::HttpHandle,
        buf: GuestPtr<u8>,
        buf_len: u32,
    ) -> Result<u32, HttpErrorKind> {
        let mut dest_buf = vec![0; buf_len as _];
        let buf = buf;
        let rs = http_driver::http_read_body(handle.into(), &mut dest_buf[..]).await?;
        if rs > 0 {
            memory
                .copy_from_slice(&dest_buf[0..rs as _], buf.as_array(rs))
                .map_err(|_| HttpErrorKind::MemoryAccessError)?;
        }
        Ok(rs)
    }
}
