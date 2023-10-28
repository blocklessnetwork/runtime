use std::sync::Arc;

use socket2::Domain;
use wasi_cap_std_sync::net::Socket;
use wasi_common::{
    WasiCtx, 
    WasiFile, 
    file::{FileAccessMode, FileEntry}
};

use crate::BlocklessSocketErrorKind;
use wiggle::GuestPtr;
use std::net::{TcpStream, TcpListener};
use log::error;

wiggle::from_witx!({
    witx: ["$BLOCKLESS_DRIVERS_ROOT/witx/blockless_socket.witx"],
    errors: { socket_error => BlocklessSocketErrorKind },
    async: *,
    wasmtime: false,
});

impl types::UserErrorConversion for WasiCtx {

    fn socket_error_from_blockless_socket_error_kind(&mut self,e:self::BlocklessSocketErrorKind) -> wiggle::anyhow::Result<types::SocketError>  {
        e.try_into()
            .map_err(|e| wiggle::anyhow::anyhow!(format!("{:?}", e)))
    }
    
}

impl wiggle::GuestErrorType for types::SocketError {
    fn success() -> Self {
        Self::Success
    }
}

impl From<BlocklessSocketErrorKind> for types::SocketError {
    fn from(e: BlocklessSocketErrorKind) -> types::SocketError {
        use types::SocketError;
        match e {
            BlocklessSocketErrorKind::AddressInUse => SocketError::AddressInUse,
            BlocklessSocketErrorKind::ConnectRefused => SocketError::ConnectionRefused,
            BlocklessSocketErrorKind::ConnectionReset => SocketError::ConnectionReset,
            BlocklessSocketErrorKind::ParameterError => SocketError::ParameterError,
        }
    }
}

async fn tcp_connect(addr: &str) -> Result<Box<dyn WasiFile>, BlocklessSocketErrorKind> {
    let stream = match TcpStream::connect(addr) {
        Ok(s) => s,
        Err(e) => {
            error!("error connect in driver {}: {}", addr, e);
            return Err(BlocklessSocketErrorKind::ConnectRefused);
        }
    };
    let stream = cap_std::net::TcpStream::from_std(stream);
    let socket: Socket = Socket::from(stream);
    let wasi_file: Box<dyn WasiFile> = Box::<dyn WasiFile>::from(socket);
    Ok(wasi_file)
}

async fn tcp_bind(addr: &str) -> Result<Box<dyn WasiFile>, BlocklessSocketErrorKind> {
    let listener = match TcpListener::bind(addr) {
        Ok(s) => s,
        Err(e) => {
            error!("error connect in driver {}: {}", addr, e);
            return Err(BlocklessSocketErrorKind::ConnectRefused);
        }
    };
    let listener = cap_std::net::TcpListener::from_std(listener);
    let socket: Socket = Socket::from(listener);
    let wasi_file: Box<dyn WasiFile> = Box::<dyn WasiFile>::from(socket);
    Ok(wasi_file)
}

impl From<types::AddressFamily> for socket2::Domain {
    fn from(value: types::AddressFamily) -> Self {
        use types::AddressFamily;
        match value {
            AddressFamily::Inet4 | AddressFamily::Unspec => Domain::IPV4,
            AddressFamily::Inet6 => Domain::IPV6,
        }
    }
}

impl From<types::SocketType> for socket2::Type {
    fn from(value: types::SocketType) -> Self {
        use types::SocketType;
        match value {
            SocketType::Datagram | SocketType::Any => socket2::Type::DGRAM,
            SocketType::Stream  => socket2::Type::STREAM,
        }
    }
}

#[wiggle::async_trait]
impl blockless_socket::BlocklessSocket for WasiCtx {
    async fn create_tcp_bind_socket<'a>(
        &mut self,
        bind: &GuestPtr<'a, str>,
    ) -> Result<types::SocketHandle, BlocklessSocketErrorKind> {
        let addr = bind.as_str()
            .map_err(|_| BlocklessSocketErrorKind::ParameterError)?
            .unwrap();
        let mode = FileAccessMode::READ|FileAccessMode::WRITE;
        match tcp_bind(&addr)
            .await
            .map(|f| Arc::new(FileEntry::new(f, mode)))
        {
            Ok(f) => {
                let fd_num = self.table().push(f).unwrap();
                let fd = types::SocketHandle::from(fd_num);
                Ok(fd)
            }
            Err(e) => Err(e),
        }
    }

    async fn tcp_connect<'a>(
        &mut self,
        target: &GuestPtr<'a, str>,
    ) -> Result<types::SocketHandle, BlocklessSocketErrorKind> {
        let addr = target.as_str()
            .map_err(|_| BlocklessSocketErrorKind::ParameterError)?
            .unwrap();
        let mode = FileAccessMode::READ|FileAccessMode::WRITE;
        match tcp_connect(&addr)
            .await
            .map(|f| Arc::new(FileEntry::new(f, mode)))
        {
            Ok(f) => {
                let fd_num = self.table().push(f).unwrap();
                let fd = types::SocketHandle::from(fd_num);
                Ok(fd)
            }
            Err(e) => Err(e),
        }
    }

    async fn socket_create (
        &mut self,
        family: types::AddressFamily,
        socket_type: types::SocketType,
    ) -> Result<types::SocketHandle, BlocklessSocketErrorKind> {
        let sock = socket2::Socket::new(family.into(), socket_type.into(), None);
        todo!()
    }

}