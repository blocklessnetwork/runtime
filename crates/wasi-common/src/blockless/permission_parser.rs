use super::DescriptorParserError;
use anyhow::Error as AnyError;
use bls_permissions::normalize_path;
use bls_permissions::AllowRunDescriptor;
use bls_permissions::AllowRunDescriptorParseResult;
use bls_permissions::DenyRunDescriptor;
use bls_permissions::EnvDescriptor;
use bls_permissions::FfiDescriptor;
use bls_permissions::ImportDescriptor;
use bls_permissions::NetDescriptor;
use bls_permissions::PathQueryDescriptor;
use bls_permissions::PermissionDescriptorParser;
use bls_permissions::ReadDescriptor;
use bls_permissions::RunQueryDescriptor;
use bls_permissions::SysDescriptor;
use bls_permissions::WriteDescriptor;
use std::path::PathBuf;

#[derive(Debug)]
pub struct EnvCurrentDir {
    pub current_dir: Option<String>,
}

#[derive(Debug)]
pub struct RuntimePermissionDescriptorParser {
    current_dir: EnvCurrentDir,
}

impl RuntimePermissionDescriptorParser {
    pub fn new(current_dir: EnvCurrentDir) -> Self {
        Self { current_dir }
    }

    fn resolve_from_cwd(&self, path: &str) -> Result<PathBuf, DescriptorParserError> {
        if path.is_empty() {
            return Err(DescriptorParserError::EmptyPath.into());
        }
        let path = PathBuf::from(path);
        if path.is_absolute() {
            Ok(normalize_path(path))
        } else {
            let cwd = self.resolve_cwd()?;
            Ok(normalize_path(cwd.join(path)))
        }
    }

    fn resolve_cwd(&self) -> Result<PathBuf, DescriptorParserError> {
        self.current_dir
            .current_dir
            .as_ref()
            .map(PathBuf::from)
            .ok_or(DescriptorParserError::CwdResolve)
    }
}

impl PermissionDescriptorParser for RuntimePermissionDescriptorParser {
    fn parse_read_descriptor(&self, text: &str) -> Result<ReadDescriptor, AnyError> {
        Ok(ReadDescriptor(self.resolve_from_cwd(text)?))
    }

    fn parse_write_descriptor(&self, text: &str) -> Result<WriteDescriptor, AnyError> {
        Ok(WriteDescriptor(self.resolve_from_cwd(text)?))
    }

    fn parse_net_descriptor(&self, text: &str) -> Result<NetDescriptor, AnyError> {
        NetDescriptor::parse(text)
    }

    fn parse_import_descriptor(&self, text: &str) -> Result<ImportDescriptor, AnyError> {
        ImportDescriptor::parse(text)
    }

    fn parse_env_descriptor(&self, text: &str) -> Result<EnvDescriptor, AnyError> {
        if text.is_empty() {
            Err(DescriptorParserError::EmptyEnvDescriptor.into())
        } else {
            Ok(EnvDescriptor::new(text))
        }
    }

    fn parse_sys_descriptor(&self, text: &str) -> Result<SysDescriptor, AnyError> {
        if text.is_empty() {
            Err(DescriptorParserError::EmptySysDescriptor.into())
        } else {
            Ok(SysDescriptor::parse(text.to_string())?)
        }
    }

    fn parse_allow_run_descriptor(
        &self,
        text: &str,
    ) -> Result<AllowRunDescriptorParseResult, AnyError> {
        Ok(AllowRunDescriptor::parse(text, &self.resolve_cwd()?)?)
    }

    fn parse_deny_run_descriptor(&self, text: &str) -> Result<DenyRunDescriptor, AnyError> {
        Ok(DenyRunDescriptor::parse(text, &self.resolve_cwd()?))
    }

    fn parse_ffi_descriptor(&self, text: &str) -> Result<FfiDescriptor, AnyError> {
        Ok(FfiDescriptor(self.resolve_from_cwd(text)?))
    }

    fn parse_path_query(&self, path: &str) -> Result<PathQueryDescriptor, AnyError> {
        Ok(PathQueryDescriptor {
            resolved: self.resolve_from_cwd(path)?,
            requested: path.to_string(),
        })
    }

    fn parse_run_query(&self, requested: &str) -> Result<RunQueryDescriptor, AnyError> {
        if requested.is_empty() {
            return Err(DescriptorParserError::EmptyRunQuery.into());
        }
        RunQueryDescriptor::parse(requested).map_err(|_| DescriptorParserError::PathResolve.into())
    }
}
