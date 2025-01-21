#![allow(unused)]
use anyhow::{bail, Result};
use blockless::{
    BlocklessConfig, BlocklessModule, BlsNnGraph, BlsOptions, ModuleType, OptimizeOpts,
    OptionParser, Permission, PermissionGrant, PermissionsConfig, Stderr, Stdin, Stdout,
};
use clap::{
    builder::{TypedValueParser, ValueParser},
    Arg, ArgMatches, Command, Parser,
};
use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr, TcpListener, ToSocketAddrs},
    option,
    path::{Path, PathBuf},
    str::FromStr,
};
use url::Url;

use crate::config::CliConfig;

const INPUT_HELP: &str = "The input file can be a WASM file, a configuration file, or a CAR file.";

const DEBUG_INFO_HELP: &str = "Runtime debugging information.";

const APP_ARGS_HELP: &str = "Application arguments will be passed into the app.";

const FS_ROOT_PATH_HELP: &str = "The root directory for the runtime.";

const DRIVERS_ROOT_PATH_HELP: &str = "The root directory for the runtime's drivers.";

const RUNTIME_LOGGER_HELP: &str = "The log file for the runtime.";

const LIMITED_MEMORY_HELP: &str =
    "The runtime's memory is limited, with the default set to infinite.";

const RUN_TIME_HELP: &str = "The runtime's time limit, with the default set to infinite.";

const ENTRY_HELP: &str = "The entry point for the WASM, default is _start.";

const LIMITED_FUEL_HELP: &str = "The limited fuel for runtime, default is infine";

const ENVS_HELP: &str = "Application environment variables will be passed into the app.";

const ENV_FILE_HELP: &str = "Path to an environment file (.env) to load variables from";

const OPTS_HELP: &str = "Optimization and tuning related options for wasm performance";

const PERMISSION_HELP: &str = "The permissions for app";

const MODULES_HELP: &str = "The modules used by app";

const STDOUT_HELP: &str =
    "The app's stdout setting, which can be configured to one of the following values: inherit, null, or a specific file name.";

const STDERR_HELP: &str =
    "The app's stderr setting, which can be configured to one of the following values: inherit, null, or a specific file name";

const STDIN_HELP: &str =
    "The app's stdin setting, which can be configured to one of the following values: inherit or a fixed input string.";

const MAP_DIR_HELP: &str =
    "Grant access to a host directory for a guest. If specified as HOST_DIR, the corresponding directory on the host will be made available within the guest.";

const V86_HELP: &str =
    "V86 model flag when the v86 flag the car file must be v86 configure and image.";

const THREAD_SUPPORT_HELP: &str =
    "Enables multi-threading in the runtime. When set, the runtime can spawn threads, allowing concurrent task execution for improved performance and scalability.";

const TCP_LISTEN_HELP: &str = "Grant access to the given TCP listen socket. ";

const UNKNOW_IMPORTS_TRAP_HELP: &str = "Allow the main module to import unknown functions.";

const CLI_EXIT_WITH_CODE_HELP: &str =
    "Enable WASI APIs marked as: @unstable(feature = cli-exit-with-code).";

const NETWORK_ERROR_CODE_HELP: &str =
    "Enable WASI APIs marked as: @unstable(feature = network-error-code).";

const MAX_MEMORY_SIZE_HELP: &str = "The max memory size limited.";

const NN_HELP: &str = "Enable support for WASI neural network imports .";

const NN_GRAPH_HELP: &str =
    "Pre-load machine learning graphs (i.e., models) for use by wasi-nn.  \
Each use of the flag will preload a ML model from the host directory using the given model encoding";

const ALLOW_READ_HELP: &str = "Allow the app to read permissions.";

const ALLOW_READ_ALL_HELP: &str = "Allow the app to all read permissions.";

const ALLOW_WRITE_HELP: &str = "Allow the app to write permissions.";

const ALLOW_NET_HELP: &str = "Allow the app to net accessing permissions.";

const DENY_READ_HELP: &str = "Deny the app to read permissions.";

const DENY_WRITE_HELP: &str = "Deny the app to write permissions.";

const DENY_NET_HELP: &str = "Deny the app to  net accessing permissions.";

const ALLOW_WRITE_ALL_HELP: &str = "Allow the app to all write permissions.";

fn parse_envs(envs: &str) -> Result<(String, String)> {
    let parts: Vec<_> = envs.splitn(2, "=").collect();
    if parts.len() != 2 {
        bail!("must be of the form `key=value`")
    }
    Ok((parts[0].to_string(), parts[1].to_string()))
}

fn parse_nn_graph(envs: &str) -> Result<BlsNnGraph> {
    let parts: Vec<_> = envs.splitn(2, "=").collect();
    if parts.len() != 2 {
        bail!("must be of the form `key=value`")
    }
    Ok(BlsNnGraph {
        format: parts[0].to_string(),
        dir: parts[1].to_string(),
    })
}

fn parse_opts(opt: &str) -> Result<OptimizeOpts> {
    let kvs: Vec<_> = opt.splitn(2, ",").collect();
    if kvs.len() == 1 {
        if kvs[0] == "help" {
            let mut max = 0;
            let options = OptimizeOpts::OPTIONS;
            for d in options {
                max = max.max(d.opt_name.len() + d.opt_docs.len());
            }
            for d in options {
                print!("   -O     {}", d.opt_name);
                print!(" --");
                for line in d.opt_docs.lines().map(|s| s.trim()) {
                    if line.is_empty() {
                        break;
                    }
                    print!(" {line}");
                }
                println!();
            }
            std::process::exit(0);
        }
    }
    let mut parsed = vec![];
    for kv in kvs.iter() {
        let parts: Vec<_> = kv.splitn(2, "=").collect();
        if parts.len() == 1 {
            bail!("must be of the form `key=value,`");
        }
        parsed.push((parts[0].to_string(), parts[1].to_string()));
    }
    let mut opt = OptimizeOpts::default();
    opt.config(parsed)?;
    Ok(opt)
}

fn parse_permission(permsion: &str) -> Result<Permission> {
    let url = Url::from_str(permsion)?;
    Ok(Permission {
        schema: url.scheme().into(),
        url: permsion.into(),
    })
}

fn parser_allow(allow: &str) -> Result<PermissionGrant> {
    PermissionGrant::parse(&allow)
}

fn parse_module(module: &str) -> Result<BlocklessModule> {
    let mods: Vec<_> = module.splitn(2, "=").collect();
    Ok(BlocklessModule {
        module_type: ModuleType::Module,
        name: mods[0].into(),
        file: mods[1].into(),
        md5: String::new(), //didn't need check.
    })
}

fn parse_stdout(stdout: &str) -> Result<Stdout> {
    let stdout = Some(stdout);
    Ok(stdio_cfg!(stdout, Stdout, FileName))
}

fn parse_stderr(stderr: &str) -> Result<Stderr> {
    let stderr = Some(stderr);
    Ok(stdio_cfg!(stderr, Stderr, FileName))
}

fn parse_stdin(stdin: &str) -> Result<Stdin> {
    if stdin == "inherit" {
        Ok(Stdin::Inherit)
    } else {
        Ok(Stdin::Fixed(stdin.to_string()))
    }
}

fn parse_listen(s: &str) -> Result<(SocketAddr, Option<u32>)> {
    let splitn = s.splitn(2, "::");
    let saddrs = splitn.collect::<Vec<_>>();
    if saddrs.len() < 2 {
        let addrs = s.to_socket_addrs()?;
        for addr in addrs {
            return Ok((addr, None));
        }
    } else {
        let port: u32 = saddrs[1].parse()?;
        let addrs = saddrs[0].to_socket_addrs()?;
        for addr in addrs {
            return Ok((addr, Some(port)));
        }
    }
    bail!("could not resolve to any addresses")
}

fn parse_dirs(s: &str) -> Result<(String, String)> {
    let mut parts = s.split("::");
    let host = parts.next().unwrap();
    let guest = match parts.next() {
        Some(guest) => guest,
        None => host,
    };
    Ok((host.into(), guest.into()))
}

#[derive(Debug)]
pub enum RuntimeType {
    V86,
    Wasm,
}

#[derive(Parser, Debug)]
pub struct PermissionFlags {
    #[clap(long = "allow-read", id="allow-read", num_args=(0..), action=clap::ArgAction::Append, value_name = "[PATH[,]]", help = ALLOW_READ_HELP, value_parser = parser_allow)]
    pub allow_read: Option<PermissionGrant>,

    #[clap(long = "allow-write", id="allow-write", num_args=(0..) , value_name = "PATH[,]", help = ALLOW_WRITE_HELP, value_parser = parser_allow)]
    pub allow_write: Option<PermissionGrant>,

    #[clap(long = "allow-net", id="allow-net", num_args=(0..) , value_name = "PATH[,]", help = ALLOW_NET_HELP, value_parser = parser_allow)]
    pub allow_net: Option<PermissionGrant>,

    #[clap(long = "deny-read", id="deny-read", num_args=(0..) , value_name = "PATH[,]", help = DENY_READ_HELP, value_parser = parser_allow)]
    pub deny_read: Option<PermissionGrant>,

    #[clap(long = "deny-write", id="deny-write", num_args=(0..) , value_name = "PATH[,]", help = DENY_WRITE_HELP, value_parser = parser_allow)]
    pub deny_write: Option<PermissionGrant>,

    #[clap(long = "deny-net", id="deny-net", num_args=(0..) , value_name = "URL[,]", help = DENY_NET_HELP, value_parser = parser_allow)]
    pub deny_net: Option<PermissionGrant>,

    #[clap(long = "allow-all", id = "allow-all", help = "Allow all permissions.")]
    pub allow_all: bool,
}

impl Into<PermissionsConfig> for PermissionFlags {
    fn into(self) -> PermissionsConfig {
        let mut permissions = PermissionsConfig {
            allow_read: self.allow_read,
            deny_read: self.deny_read,
            allow_write: self.allow_write,
            deny_write: self.deny_write,
            deny_net: self.deny_net,
            allow_net: self.allow_net,
            allow_all: self.allow_all,
        };
        permissions
    }
}

#[derive(Parser, Debug)]
pub struct StdioFlags {
    #[clap(long = "stdout", value_name = "STDOUT", help = STDOUT_HELP, value_parser = parse_stdout)]
    pub stdout: Option<Stdout>,

    #[clap(long = "stdin", value_name = "STDIN", help = STDIN_HELP, value_parser = parse_stdin)]
    pub stdin: Option<Stdin>,

    #[clap(long = "stderr", value_name = "STDERR", help = STDERR_HELP, value_parser = parse_stderr)]
    pub stderr: Option<Stderr>,
}

/// The latest version from Cargo.toml
pub(crate) const SHORT_VERSION: &str = concat!("v", env!("CARGO_PKG_VERSION"));

pub fn get_styles() -> clap::builder::Styles {
    clap::builder::Styles::styled()
        .usage(
            anstyle::Style::new()
                .bold()
                .underline()
                .fg_color(Some(anstyle::Color::Ansi(anstyle::AnsiColor::Yellow))),
        )
        .header(
            anstyle::Style::new()
                .bold()
                .underline()
                .fg_color(Some(anstyle::Color::Ansi(anstyle::AnsiColor::Yellow))),
        )
        .literal(
            anstyle::Style::new().fg_color(Some(anstyle::Color::Ansi(anstyle::AnsiColor::Green))),
        )
        .invalid(
            anstyle::Style::new()
                .bold()
                .fg_color(Some(anstyle::Color::Ansi(anstyle::AnsiColor::Red))),
        )
        .error(
            anstyle::Style::new()
                .bold()
                .fg_color(Some(anstyle::Color::Ansi(anstyle::AnsiColor::Red))),
        )
        .valid(
            anstyle::Style::new()
                .bold()
                .underline()
                .fg_color(Some(anstyle::Color::Ansi(anstyle::AnsiColor::Green))),
        )
        .placeholder(
            anstyle::Style::new().fg_color(Some(anstyle::Color::Ansi(anstyle::AnsiColor::White))),
        )
}

#[derive(Parser, Debug)]
#[command(author, version = SHORT_VERSION, styles=get_styles(), arg_required_else_help = true, long_version = SHORT_VERSION, about = "Blockless WebAssembly Runtime")]
pub(crate) struct CliCommandOpts {
    #[clap(long = "v86", value_name = "V86", required = false, help = V86_HELP )]
    pub v86: bool,

    #[clap(value_name = "INPUT", required = true, help = INPUT_HELP )]
    pub input: String,

    #[clap(long = "debug-info", value_name = "DEBUG-INFO", help = DEBUG_INFO_HELP)]
    pub debug_info: bool,

    #[clap(long = "feature-thread", value_name = "SUPPORT-THREAD", help = THREAD_SUPPORT_HELP)]
    pub feature_thread: bool,

    #[clap(long = "fs-root-path", value_name = "FS-ROOT-PATH", help = FS_ROOT_PATH_HELP)]
    pub fs_root_path: Option<String>,

    /// Grant access of a host directory to a guest.
    /// If specified as just `HOST_DIR` then the same directory name on the
    /// host is made available within the guest.
    #[arg(long = "dir", value_name = "HOST_DIR[::GUEST_DIR]", help = MAP_DIR_HELP,value_parser = parse_dirs)]
    pub dirs: Vec<(String, String)>,

    #[clap(long = "drivers-root-path", value_name = "DRIVERS-ROOT-PATH", help = DRIVERS_ROOT_PATH_HELP)]
    pub drivers_root_path: Option<String>,

    #[clap(long = "runtime-logger", value_name = "RUNTIME-LOGGER", help = RUNTIME_LOGGER_HELP)]
    pub runtime_logger: Option<String>,

    #[clap(long = "limited-memory", value_name = "LIMITED-MEMORY", help = LIMITED_MEMORY_HELP)]
    pub limited_memory: Option<u64>,

    #[clap(long = "run-time", value_name = "RUN-TIME", help = RUN_TIME_HELP)]
    pub run_time: Option<u64>,

    #[clap(long = "entry", value_name = "ENTERY", help = ENTRY_HELP)]
    pub entry: Option<String>,

    #[clap(flatten)]
    pub stdio: StdioFlags,

    #[clap(long = "limited-fuel", value_name = "LIMITED-FUEL", help = LIMITED_FUEL_HELP)]
    pub limited_fuel: Option<u64>,

    #[clap(long = "env", value_name = "ENV=VAL", help = ENVS_HELP, number_of_values = 1, value_parser = parse_envs)]
    pub envs: Vec<(String, String)>,

    #[clap(long = "env-file", value_name = "ENV_FILE", help = ENV_FILE_HELP)]
    pub env_file: Option<PathBuf>,

    #[clap(long = "opt", short = 'O', value_name = "OPT=VAL,", help = OPTS_HELP,  value_parser = parse_opts)]
    pub opts: Option<OptimizeOpts>,

    #[clap(long = "permission", value_name = "PERMISSION", help = PERMISSION_HELP, value_parser = parse_permission)]
    pub permissions: Vec<Permission>,

    #[clap(long = "module", value_name = "MODULE-NAME=MODULE-PATH", help = MODULES_HELP, value_parser = parse_module)]
    pub modules: Vec<BlocklessModule>,

    #[clap(long = "tcplisten", value_name = "TCPLISTEN[::LISTENFD]", help = TCP_LISTEN_HELP, value_parser = parse_listen)]
    pub tcp_listens: Vec<(SocketAddr, Option<u32>)>,

    #[clap(value_name = "ARGS", help = APP_ARGS_HELP)]
    pub args: Vec<String>,

    #[clap(long = "unknown_imports_trap", value_name = "UNKNOWN_IMPORTS_TRAP", help = UNKNOW_IMPORTS_TRAP_HELP)]
    pub unknown_imports_trap: bool,

    #[clap(long = "cli_exit_with_code", value_name = "CLI_EXIT_WITH_CODE", help = CLI_EXIT_WITH_CODE_HELP)]
    pub cli_exit_with_code: bool,

    #[clap(long = "network_error_code", value_name = "NETWORK_ERROR_CODE", help = NETWORK_ERROR_CODE_HELP)]
    pub network_error_code: bool,

    #[clap(long = "max_memory_size", value_name = "MAX_MEMORY_SIZE", help = MAX_MEMORY_SIZE_HELP)]
    pub max_memory_size: Option<u64>,

    #[clap(flatten)]
    pub permission_flags: PermissionFlags,

    #[clap(long = "nn", value_name = "NN", help = NN_HELP)]
    pub nn: bool,

    #[clap(long = "nn-graph", value_name = "NN_GRAPH", value_parser = parse_nn_graph, help = NN_GRAPH_HELP)]
    pub nn_graph: Vec<BlsNnGraph>,
}

impl CliCommandOpts {
    #[inline(always)]
    pub fn fs_root_path(&self) -> Option<&String> {
        self.fs_root_path.as_ref()
    }

    #[inline(always)]
    pub fn runtime_type(&self) -> RuntimeType {
        if self.v86 {
            RuntimeType::V86
        } else {
            RuntimeType::Wasm
        }
    }

    #[inline(always)]
    pub fn input_ref(&self) -> &str {
        &self.input
    }

    pub fn into_config(self, conf: &mut CliConfig) -> Result<()> {
        let envs = self.load_environment_vars()?;

        conf.0.set_debug_info(self.debug_info);
        conf.0.set_fs_root_path(self.fs_root_path);
        conf.0.set_runtime_logger(self.runtime_logger);
        conf.0.limited_memory(self.limited_memory);
        conf.0.limited_fuel(self.limited_fuel);
        conf.0.set_run_time(self.run_time);
        conf.0.set_stdin_args(self.args);
        conf.0.set_map_dirs(self.dirs);
        conf.0.set_feature_thread(self.feature_thread);
        conf.0.limited_memory(self.max_memory_size);
        conf.0.permissions_config = self.permission_flags.into();

        // Handle IO settings
        if let Some(stderr) = self.stdio.stderr {
            conf.0.stdio.stderr(stderr);
        }
        if let Some(stdout) = self.stdio.stdout {
            conf.0.stdio.stdout(stdout);
        }
        if let Some(stdin) = self.stdio.stdin {
            conf.0.stdio.stdin(stdin);
        }
        if self.permissions.len() > 0 {
            conf.0.set_permisions(self.permissions);
        }

        // Handle environment variables
        conf.0.set_envs(envs);

        conf.0.set_drivers_root_path(self.drivers_root_path);
        let mut modules = self.modules;
        let mut has_entry = false;
        self.entry.map(|e| {
            has_entry = true;
            conf.0.set_entry(e)
        });
        if modules.len() > 0 {
            modules.push(BlocklessModule {
                module_type: ModuleType::Entry,
                name: String::new(),
                file: self.input,
                md5: String::new(),
            });
            conf.0.set_modules(modules);
            if !has_entry {
                conf.0.reset_modules_model_entry();
            }
            conf.0
                .set_version(blockless::BlocklessConfigVersion::Version1);
        }
        conf.0.nn = self.nn;
        conf.0.tcp_listens = self.tcp_listens;
        conf.0.network_error_code = self.network_error_code;
        conf.0.unknown_imports_trap = self.unknown_imports_trap;
        conf.0.nn_graph = self.nn_graph;
        Ok(())
    }

    /// Load and merge environment variables from both the environment file and explicit --env arguments.
    /// Explicit environment variables take precedence over those from the file.
    /// The environment variables are sorted by key.
    fn load_environment_vars(&self) -> Result<Vec<(String, String)>> {
        let mut final_envs = Vec::new();

        // Load vars from env file if specified
        if let Some(env_file) = &self.env_file {
            let env_path = Path::new(env_file);
            if env_path.exists() {
                // Read variables from the env file
                let file_vars = dotenvy::from_path_iter(env_path)?
                    .filter_map(Result::ok)
                    .collect::<Vec<(String, String)>>();
                // Add all variables from the file
                final_envs.extend(file_vars);
            }
        }

        // Add explicit environment variables, overwriting any duplicates from the file
        for env_var in &self.envs {
            // Remove any existing variable with the same name
            if let Some(index) = final_envs.iter().position(|(key, _)| key == &env_var.0) {
                final_envs.remove(index);
            }
            final_envs.push(env_var.clone());
        }

        // Sort environment variables by key
        final_envs.sort_by(|(a_key, _), (b_key, _)| a_key.cmp(b_key));

        Ok(final_envs)
    }
}

#[cfg(test)]
mod test {
    #[allow(unused)]
    use super::*;
    use blockless::BlocklessConfigVersion;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_cli_command_v86() {
        let cli = CliCommandOpts::try_parse_from(["cli", "test", "--v86"]).unwrap();
        assert_eq!(cli.v86, true);
    }

    #[test]
    fn test_cli_command() {
        let cli = CliCommandOpts::try_parse_from(["cli", "test", "--", "--test=10"]).unwrap();
        assert_eq!(cli.input.as_str(), "test");
        assert_eq!(cli.args.len(), 1);
        assert_eq!(cli.args[0], "--test=10");
    }

    #[test]
    fn test_cli_command_env() {
        let cli = CliCommandOpts::try_parse_from(["cli", "test", "--env", "a=1", "--env", "b=2"])
            .unwrap();
        assert_eq!(cli.input.as_str(), "test");
        assert_eq!(cli.envs.len(), 2);
        assert_eq!(cli.envs[0], ("a".to_string(), "1".to_string()));
        assert_eq!(cli.envs[1], ("b".to_string(), "2".to_string()));
    }

    #[test]
    fn test_cli_command_env_file_loading_and_sorting() -> Result<()> {
        // Create temp env file with variables including interpolation
        let mut env_file = NamedTempFile::new()?;
        writeln!(
            env_file,
            r#"COMMON_VAR=from_file
ZOO_VAR=zebra
BASE_URL=https://api.example.com
SERVICE_URL=${{BASE_URL}}/v1"#
        )?;

        let cli = CliCommandOpts::try_parse_from([
            "cli",
            "test.wasm", // required input argument
            "--env-file",
            env_file.path().to_str().unwrap(),
            "--env",
            "COMMON_VAR=from_cli",
            "--env",
            "APP_VAR=test",
        ])
        .unwrap();

        let envs = cli.load_environment_vars()?;

        assert_eq!(
            envs,
            vec![
                ("APP_VAR".to_string(), "test".to_string()),
                (
                    "BASE_URL".to_string(),
                    "https://api.example.com".to_string()
                ),
                ("COMMON_VAR".to_string(), "from_cli".to_string()), // CLI value takes precedence
                (
                    "SERVICE_URL".to_string(),
                    "https://api.example.com/v1".to_string()
                ), // interpolated value
                ("ZOO_VAR".to_string(), "zebra".to_string()),
            ]
        );

        Ok(())
    }

    #[test]
    fn test_cli_command_permisson() {
        let cli = CliCommandOpts::try_parse_from([
            "cli",
            "test",
            "--permission",
            "http://www.google.com",
        ])
        .unwrap();
        assert_eq!(cli.input.as_str(), "test");
        assert_eq!(cli.permissions.len(), 1);
        let perm = Permission {
            schema: "http".to_string(),
            url: "http://www.google.com".to_string(),
        };
        assert_eq!(cli.permissions[0], perm);
    }

    #[test]
    fn test_cli_command_input() {
        let command_line = r#"blockless_cli test.wasm"#;
        let command_line = command_line
            .split(" ")
            .map(str::to_string)
            .collect::<Vec<String>>();
        let cli_opts = CliCommandOpts::try_parse_from(command_line).unwrap();
        let pat = cli_opts.input.as_str();
        assert_eq!(pat, "test.wasm");
    }

    #[test]
    fn test_cli_command_runtime_log() {
        let command_line = r#"blockless_cli test.wasm --runtime-logger runtime.log"#;
        let command_line = command_line
            .split(" ")
            .map(str::to_string)
            .collect::<Vec<String>>();
        let cli_opts = CliCommandOpts::try_parse_from(command_line).unwrap();
        let pat = cli_opts.runtime_logger.as_ref().unwrap().as_str();
        assert_eq!(pat, "runtime.log");
    }

    #[test]
    fn test_cli_command_fs_root_path() {
        let command_line = r#"blockless_cli test.wasm --fs-root-path /"#;
        let command_line = command_line
            .split(" ")
            .map(str::to_string)
            .collect::<Vec<String>>();
        let cli_opts = CliCommandOpts::try_parse_from(command_line).unwrap();
        let pat = cli_opts.fs_root_path.as_ref().unwrap().as_str();
        assert_eq!(pat, "/");
    }

    #[test]
    fn test_cli_command_signal_wasm() {
        let command_line = r#"blockless_cli test.wasm --fs-root-path /"#;
        let command_line = command_line
            .split(" ")
            .map(str::to_string)
            .collect::<Vec<String>>();
        let cli_opts = CliCommandOpts::try_parse_from(command_line).unwrap();
        let mut cli_conf = CliConfig(BlocklessConfig::new("/a.wasm"));
        cli_opts.into_config(&mut cli_conf);
        assert_eq!(cli_conf.0.entry_ref(), "/a.wasm");
        assert!(matches!(
            cli_conf.0.version(),
            BlocklessConfigVersion::Version0
        ));
    }

    #[test]
    fn test_cli_command_modules_wasm() {
        let command_line = r#"blockless_cli test.wasm --fs-root-path / --module=test=/module.wasm"#;
        let command_line = command_line
            .split(" ")
            .map(str::to_string)
            .collect::<Vec<String>>();
        let cli_opts = CliCommandOpts::try_parse_from(command_line).unwrap();
        let mut cli_conf = CliConfig(BlocklessConfig::new("/a.wasm"));
        cli_opts.into_config(&mut cli_conf);
        assert_eq!(cli_conf.0.entry_ref(), "_start");
        assert!(matches!(
            cli_conf.0.version(),
            BlocklessConfigVersion::Version1
        ));
    }

    #[test]
    fn test_cli_command_modules_wasm_with_entry() {
        let command_line =
            r#"blockless_cli test.wasm --fs-root-path / --module=test=/module.wasm --entry=run"#;
        let command_line = command_line
            .split(" ")
            .map(str::to_string)
            .collect::<Vec<String>>();
        let cli_opts = CliCommandOpts::try_parse_from(command_line).unwrap();
        let mut cli_conf = CliConfig(BlocklessConfig::new("/a.wasm"));
        cli_opts.into_config(&mut cli_conf);
        assert_eq!(cli_conf.0.entry_ref(), "run");
        assert!(matches!(
            cli_conf.0.version(),
            BlocklessConfigVersion::Version1
        ));
    }
}
