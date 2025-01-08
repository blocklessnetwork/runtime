use std::borrow::Cow;
use std::path::Path;
use std::path::PathBuf;
use std::sync::Arc;

use bls_permissions::AnyError;
use bls_permissions::BlsPermissionsContainer;
use bls_permissions::CheckSpecifierKind;
use bls_permissions::ChildPermissionsArg;
use bls_permissions::ModuleSpecifier;
use bls_permissions::PermissionDescriptorParser;
use bls_permissions::PermissionState;
use bls_permissions::Permissions as BlsPermissions;
use bls_permissions::RunQueryDescriptor;
use bls_permissions::Url;

use super::init_tty_prompter;

#[derive(Clone, Debug, PartialEq)]
pub struct Permission {
    pub url: String,
    pub schema: String,
}

impl Permission {
    pub fn is_permision(&self, url: &str) -> bool {
        url.to_ascii_lowercase().starts_with(&self.url)
    }
}

#[derive(Clone, Debug)]
pub struct BlsRuntimePermissionsContainer(pub bls_permissions::BlsPermissionsContainer);

impl BlsRuntimePermissionsContainer {
    pub fn new(descriptor_parser: Arc<dyn PermissionDescriptorParser>, perms: BlsPermissions) -> Self {
        init_tty_prompter();
        Self(BlsPermissionsContainer::new(descriptor_parser, perms))
    }

    pub fn create_child_permissions(
        &self,
        child_permissions_arg: ChildPermissionsArg,
    ) -> Result<BlsRuntimePermissionsContainer, AnyError> {
        Ok(BlsRuntimePermissionsContainer(self.0.create_child_permissions(child_permissions_arg)?))
    }

    pub fn allow_all(descriptor_parser: Arc<dyn PermissionDescriptorParser>) -> Self {
        Self::new(descriptor_parser, BlsPermissions::allow_all())
    }

    #[inline(always)]
    pub fn check_specifier(
        &self,
        specifier: &ModuleSpecifier,
        kind: CheckSpecifierKind,
    ) -> Result<(), AnyError> {
        self.0.check_specifier(specifier, kind)
    }

    #[inline(always)]
    pub fn check_read(&self, path: &str, api_name: &str) -> Result<PathBuf, AnyError> {
        self.0.check_read(path, api_name)
    }

    #[inline(always)]
    pub fn check_read_with_api_name(
        &self,
        path: &str,
        api_name: Option<&str>,
    ) -> Result<PathBuf, AnyError> {
        self.0.check_read_with_api_name(path, api_name)
    }

    #[inline(always)]
    pub fn check_read_path<'a>(
        &self,
        path: &'a Path,
        api_name: Option<&str>,
    ) -> Result<Cow<'a, Path>, AnyError> {
        self.0.check_read_path(path, api_name)
    }

    /// As `check_read()`, but permission error messages will anonymize the path
    /// by replacing it with the given `display`.
    #[inline(always)]
    pub fn check_read_blind(
        &mut self,
        path: &Path,
        display: &str,
        api_name: &str,
    ) -> Result<(), AnyError> {
        self.0.check_read_blind(path, display, api_name)
    }

    #[inline(always)]
    pub fn check_read_all(&self, api_name: &str) -> Result<(), AnyError> {
        self.0.check_read_all(api_name)
    }

    #[inline(always)]
    pub fn query_read_all(&self) -> bool {
        self.0.query_read_all()
    }

    #[inline(always)]
    pub fn check_write(&self, path: &str, api_name: &str) -> Result<PathBuf, AnyError> {
        self.0.check_write(path, api_name)
    }

    #[inline(always)]
    pub fn check_write_with_api_name(
        &self,
        path: &str,
        api_name: Option<&str>,
    ) -> Result<PathBuf, AnyError> {
        self.0.check_write_with_api_name(path, api_name)
    }

    #[inline(always)]
    pub fn check_write_path<'a>(
        &self,
        path: &'a Path,
        api_name: &str,
    ) -> Result<Cow<'a, Path>, AnyError> {
        self.0.check_write_path(path, api_name)
    }

    #[inline(always)]
    pub fn check_write_all(&self, api_name: &str) -> Result<(), AnyError> {
        self.0.check_write_all(api_name)
    }

    /// As `check_write()`, but permission error messages will anonymize the path
    /// by replacing it with the given `display`.
    #[inline(always)]
    pub fn check_write_blind(
        &self,
        path: &Path,
        display: &str,
        api_name: &str,
    ) -> Result<(), AnyError> {
        self.0.check_write_blind(path, display, api_name)
    }

    #[inline(always)]
    pub fn check_write_partial(&mut self, path: &str, api_name: &str) -> Result<PathBuf, AnyError> {
        self.0.check_write_partial(path, api_name)
    }

    #[inline(always)]
    pub fn check_run(&mut self, cmd: &RunQueryDescriptor, api_name: &str) -> Result<(), AnyError> {
        self.0.check_run(cmd, api_name)
    }

    #[inline(always)]
    pub fn check_run_all(&mut self, api_name: &str) -> Result<(), AnyError> {
        self.0.check_run_all(api_name)
    }

    #[inline(always)]
    pub fn query_run_all(&mut self, api_name: &str) -> bool {
        self.0.query_run_all(api_name)
    }

    #[inline(always)]
    pub fn check_sys(&self, kind: &str, api_name: &str) -> Result<(), AnyError> {
        self.0.check_sys(kind, api_name)
    }

    #[inline(always)]
    pub fn check_env(&mut self, var: &str) -> Result<(), AnyError> {
        self.0.check_env(var)
    }

    #[inline(always)]
    pub fn check_env_all(&mut self) -> Result<(), AnyError> {
        self.0.check_env_all()
    }

    #[inline(always)]
    pub fn check_sys_all(&mut self) -> Result<(), AnyError> {
        self.0.check_sys_all()
    }

    #[inline(always)]
    pub fn check_ffi_all(&mut self) -> Result<(), AnyError> {
        self.0.check_ffi_all()
    }

    /// This checks to see if the allow-all flag was passed, not whether all
    /// permissions are enabled!
    #[inline(always)]
    pub fn check_was_allow_all_flag_passed(&mut self) -> Result<(), AnyError> {
        self.0.check_was_allow_all_flag_passed()
    }

    /// Checks special file access, returning the failed permission type if
    /// not successful.
    pub fn check_special_file(&mut self, path: &Path, api_name: &str) -> Result<(), &'static str> {
        self.0.check_special_file(path, api_name)
    }

    #[inline(always)]
    pub fn check_net_url(&mut self, url: &Url, api_name: &str) -> Result<(), AnyError> {
        self.0.check_net_url(url, api_name)
    }

    #[inline(always)]
    pub fn check_net<T: AsRef<str>>(
        &mut self,
        host: &(T, Option<u16>),
        api_name: &str,
    ) -> Result<(), AnyError> {
        self.0.check_net(host, api_name)
    }

    #[inline(always)]
    pub fn check_ffi(&mut self, path: &str) -> Result<PathBuf, AnyError> {
        self.0.check_ffi(path)
    }

    #[inline(always)]
    pub fn check_ffi_partial_no_path(&mut self) -> Result<(), AnyError> {
        self.0.check_ffi_partial_no_path()
    }

    #[inline(always)]
    pub fn check_ffi_partial_with_path(&mut self, path: &str) -> Result<PathBuf, AnyError> {
        self.0.check_ffi_partial_with_path(path)
    }

    // query

    #[inline(always)]
    pub fn query_read(&self, path: Option<&str>) -> Result<PermissionState, AnyError> {
        self.0.query_read(path)
    }

    #[inline(always)]
    pub fn query_write(&self, path: Option<&str>) -> Result<PermissionState, AnyError> {
        self.0.query_write(path)
    }

    #[inline(always)]
    pub fn query_net(&self, host: Option<&str>) -> Result<PermissionState, AnyError> {
        self.0.query_net(host)
    }

    #[inline(always)]
    pub fn query_env(&self, var: Option<&str>) -> PermissionState {
        self.0.query_env(var)
    }

    #[inline(always)]
    pub fn query_sys(&self, kind: Option<&str>) -> Result<PermissionState, AnyError> {
        self.0.query_sys(kind)
    }

    #[inline(always)]
    pub fn query_run(&self, cmd: Option<&str>) -> Result<PermissionState, AnyError> {
        self.0.query_run(cmd)
    }

    #[inline(always)]
    pub fn query_ffi(&self, path: Option<&str>) -> Result<PermissionState, AnyError> {
        self.0.query_ffi(path)
    }

    // revoke

    #[inline(always)]
    pub fn revoke_read(&self, path: Option<&str>) -> Result<PermissionState, AnyError> {
        self.0.revoke_read(path)
    }

    #[inline(always)]
    pub fn revoke_write(&self, path: Option<&str>) -> Result<PermissionState, AnyError> {
        self.0.revoke_write(path)
    }

    #[inline(always)]
    pub fn revoke_net(&self, host: Option<&str>) -> Result<PermissionState, AnyError> {
        self.0.revoke_net(host)
    }

    #[inline(always)]
    pub fn revoke_env(&self, var: Option<&str>) -> PermissionState {
        self.0.revoke_env(var)
    }

    #[inline(always)]
    pub fn revoke_sys(&self, kind: Option<&str>) -> Result<PermissionState, AnyError> {
        self.0.revoke_sys(kind)
    }

    #[inline(always)]
    pub fn revoke_run(&self, cmd: Option<&str>) -> Result<PermissionState, AnyError> {
        self.0.revoke_run(cmd)
    }

    #[inline(always)]
    pub fn revoke_ffi(&self, path: Option<&str>) -> Result<PermissionState, AnyError> {
        self.0.revoke_ffi(path)
    }

    // request

    #[inline(always)]
    pub fn request_read(&self, path: Option<&str>) -> Result<PermissionState, AnyError> {
        self.0.request_read(path)
    }

    #[inline(always)]
    pub fn request_write(&self, path: Option<&str>) -> Result<PermissionState, AnyError> {
        self.0.revoke_write(path)
    }

    #[inline(always)]
    pub fn request_net(&self, host: Option<&str>) -> Result<PermissionState, AnyError> {
        self.0.request_net(host)
    }

    #[inline(always)]
    pub fn request_env(&self, var: Option<&str>) -> PermissionState {
        self.0.request_env(var)
    }

    #[inline(always)]
    pub fn request_sys(&self, kind: Option<&str>) -> Result<PermissionState, AnyError> {
        self.0.request_sys(kind)
    }

    #[inline(always)]
    pub fn request_run(&self, cmd: Option<&str>) -> Result<PermissionState, AnyError> {
        self.0.request_run(cmd)
    }

    #[inline(always)]
    pub fn request_ffi(&self, path: Option<&str>) -> Result<PermissionState, AnyError> {
        self.0.request_ffi(path)
    }
}