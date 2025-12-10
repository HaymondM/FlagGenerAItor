//! Process isolation system for secure execution of external tools

use crate::Result;
use anyhow::anyhow;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::{Duration, Instant};
use tokio::process::Command as TokioCommand;
use tokio::time::timeout;
use tracing::{debug, warn, error};

/// Configuration for process isolation
#[derive(Debug, Clone)]
pub struct IsolationConfig {
    /// Maximum execution time for external processes
    pub timeout: Duration,
    /// Maximum memory usage in bytes (if supported by platform)
    pub max_memory: Option<u64>,
    /// Maximum CPU time in seconds (if supported by platform)
    pub max_cpu_time: Option<u64>,
    /// Working directory for the process
    pub working_dir: Option<PathBuf>,
    /// Environment variables to set
    pub env_vars: HashMap<String, String>,
    /// Whether to capture stdout
    pub capture_stdout: bool,
    /// Whether to capture stderr
    pub capture_stderr: bool,
    /// Maximum output size in bytes
    pub max_output_size: usize,
}

impl Default for IsolationConfig {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(30),
            max_memory: Some(512 * 1024 * 1024), // 512MB
            max_cpu_time: Some(30), // 30 seconds
            working_dir: None,
            env_vars: HashMap::new(),
            capture_stdout: true,
            capture_stderr: true,
            max_output_size: 10 * 1024 * 1024, // 10MB
        }
    }
}

/// Result of isolated process execution
#[derive(Debug, Clone)]
pub struct IsolationResult {
    /// Exit code of the process
    pub exit_code: Option<i32>,
    /// Standard output (if captured)
    pub stdout: Option<String>,
    /// Standard error (if captured)
    pub stderr: Option<String>,
    /// Execution time
    pub execution_time: Duration,
    /// Whether the process was terminated due to timeout
    pub timed_out: bool,
    /// Whether the process was terminated due to resource limits
    pub resource_limited: bool,
}

/// Process isolation manager
pub struct ProcessIsolation {
    config: IsolationConfig,
    temp_dir: Option<PathBuf>,
}

impl ProcessIsolation {
    /// Create a new process isolation manager with default configuration
    pub fn new() -> Self {
        Self {
            config: IsolationConfig::default(),
            temp_dir: None,
        }
    }

    /// Create a new process isolation manager with custom configuration
    pub fn with_config(config: IsolationConfig) -> Self {
        Self {
            config,
            temp_dir: None,
        }
    }

    /// Set up a secure temporary directory for process execution
    pub async fn setup_temp_directory(&mut self) -> Result<&Path> {
        if self.temp_dir.is_none() {
            let temp_dir = self.create_secure_temp_dir().await?;
            self.temp_dir = Some(temp_dir);
        }
        
        Ok(self.temp_dir.as_ref().unwrap())
    }

    /// Execute a command in an isolated environment
    pub async fn execute_isolated<I, S>(&self, program: &str, args: I) -> Result<IsolationResult>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<std::ffi::OsStr>,
    {
        let start_time = Instant::now();
        
        // Convert args to a vector for logging and reuse
        let args_vec: Vec<_> = args.into_iter().collect();
        debug!("Executing isolated command: {} with args: {:?}", program, 
               args_vec.iter().map(|s| s.as_ref().to_string_lossy().to_string()).collect::<Vec<_>>());

        // Validate the program path to prevent command injection
        self.validate_program_path(program)?;

        // Create the command
        let mut cmd = TokioCommand::new(program);
        cmd.args(&args_vec);

        // Configure process isolation
        self.configure_process_isolation(&mut cmd).await?;

        // Execute with timeout
        let execution_result = timeout(self.config.timeout, cmd.output()).await;

        let execution_time = start_time.elapsed();

        match execution_result {
            Ok(Ok(output)) => {
                let stdout = if self.config.capture_stdout {
                    let stdout_bytes = if output.stdout.len() > self.config.max_output_size {
                        warn!("Stdout truncated due to size limit");
                        &output.stdout[..self.config.max_output_size]
                    } else {
                        &output.stdout
                    };
                    Some(String::from_utf8_lossy(stdout_bytes).to_string())
                } else {
                    None
                };

                let stderr = if self.config.capture_stderr {
                    let stderr_bytes = if output.stderr.len() > self.config.max_output_size {
                        warn!("Stderr truncated due to size limit");
                        &output.stderr[..self.config.max_output_size]
                    } else {
                        &output.stderr
                    };
                    Some(String::from_utf8_lossy(stderr_bytes).to_string())
                } else {
                    None
                };

                Ok(IsolationResult {
                    exit_code: output.status.code(),
                    stdout,
                    stderr,
                    execution_time,
                    timed_out: false,
                    resource_limited: false,
                })
            }
            Ok(Err(e)) => {
                error!("Process execution failed: {}", e);
                Err(anyhow!("Process execution failed: {}", e).into())
            }
            Err(_) => {
                warn!("Process timed out after {:?}", self.config.timeout);
                Ok(IsolationResult {
                    exit_code: None,
                    stdout: None,
                    stderr: Some("Process timed out".to_string()),
                    execution_time,
                    timed_out: true,
                    resource_limited: false,
                })
            }
        }
    }

    /// Execute a shell command in an isolated environment
    pub async fn execute_shell_command(&self, command: &str) -> Result<IsolationResult> {
        // Sanitize the shell command to prevent injection
        let sanitized_command = self.sanitize_shell_command(command)?;
        
        #[cfg(unix)]
        let result = self.execute_isolated("sh", ["-c", &sanitized_command]).await;
        
        #[cfg(windows)]
        let result = self.execute_isolated("cmd", ["/C", &sanitized_command]).await;
        
        result
    }

    /// Create a secure temporary directory
    async fn create_secure_temp_dir(&self) -> Result<PathBuf> {
        use std::fs;
        use uuid::Uuid;

        let temp_base = std::env::temp_dir();
        let temp_name = format!("ctf_isolated_{}", Uuid::new_v4());
        let temp_path = temp_base.join(temp_name);

        fs::create_dir_all(&temp_path)
            .map_err(|e| anyhow!("Failed to create temp directory: {}", e))?;

        // Set restrictive permissions on Unix systems
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = fs::metadata(&temp_path)?.permissions();
            perms.set_mode(0o700); // Owner read/write/execute only
            fs::set_permissions(&temp_path, perms)?;
        }

        debug!("Created secure temp directory: {}", temp_path.display());
        Ok(temp_path)
    }

    /// Configure process isolation settings
    async fn configure_process_isolation(&self, cmd: &mut TokioCommand) -> Result<()> {
        // Set working directory
        if let Some(ref working_dir) = self.config.working_dir {
            cmd.current_dir(working_dir);
        } else if let Some(ref temp_dir) = self.temp_dir {
            cmd.current_dir(temp_dir);
        }

        // Set environment variables
        for (key, value) in &self.config.env_vars {
            cmd.env(key, value);
        }

        // Clear potentially dangerous environment variables
        let dangerous_env_vars = [
            "LD_PRELOAD", "LD_LIBRARY_PATH", "DYLD_INSERT_LIBRARIES",
            "DYLD_LIBRARY_PATH", "PATH", "PYTHONPATH", "PERL5LIB"
        ];
        
        for var in &dangerous_env_vars {
            cmd.env_remove(var);
        }

        // Set minimal PATH for security
        #[cfg(unix)]
        cmd.env("PATH", "/usr/bin:/bin");
        
        #[cfg(windows)]
        cmd.env("PATH", r"C:\Windows\System32");

        // Configure stdio
        if self.config.capture_stdout {
            cmd.stdout(Stdio::piped());
        } else {
            cmd.stdout(Stdio::null());
        }

        if self.config.capture_stderr {
            cmd.stderr(Stdio::piped());
        } else {
            cmd.stderr(Stdio::null());
        }

        cmd.stdin(Stdio::null());

        // Platform-specific resource limits
        #[cfg(unix)]
        self.configure_unix_limits(cmd).await?;

        #[cfg(windows)]
        self.configure_windows_limits(cmd).await?;

        Ok(())
    }

    /// Configure resource limits on Unix systems
    #[cfg(unix)]
    async fn configure_unix_limits(&self, _cmd: &mut TokioCommand) -> Result<()> {
        // Note: Setting resource limits in Rust is complex and platform-specific
        // In a production system, you might want to use external tools like:
        // - systemd-run with resource limits
        // - firejail for sandboxing
        // - docker containers
        // - cgroups directly
        
        // For now, we rely on timeout and output size limits
        // which are implemented in the execute_isolated method
        
        debug!("Unix resource limits configured (timeout-based)");
        Ok(())
    }

    /// Configure resource limits on Windows systems
    #[cfg(windows)]
    async fn configure_windows_limits(&self, _cmd: &mut TokioCommand) -> Result<()> {
        // Windows resource limiting is even more complex
        // In production, you might use:
        // - Job Objects
        // - Windows Sandbox
        // - Hyper-V containers
        
        debug!("Windows resource limits configured (timeout-based)");
        Ok(())
    }

    /// Validate program path to prevent command injection
    fn validate_program_path(&self, program: &str) -> Result<()> {
        // Check for obvious command injection attempts
        if program.contains(';') || program.contains('|') || program.contains('&') {
            return Err(anyhow!("Program path contains dangerous characters").into());
        }

        // Check for path traversal attempts
        if program.contains("..") || program.contains("./") || program.contains(".\\") {
            return Err(anyhow!("Program path contains path traversal sequences").into());
        }

        // Ensure the program name doesn't contain spaces (unless properly quoted)
        if program.contains(' ') && !(program.starts_with('"') && program.ends_with('"')) {
            return Err(anyhow!("Program path with spaces must be quoted").into());
        }

        Ok(())
    }

    /// Sanitize shell command to prevent injection
    fn sanitize_shell_command(&self, command: &str) -> Result<String> {
        // Basic sanitization - in production, you'd want more sophisticated filtering
        let dangerous_patterns = [
            ";", "|", "&", "$(", "`", "&&", "||", ">", "<", ">>", "<<",
            "rm -rf", "del /f", "format", "fdisk", "mkfs"
        ];

        let command_lower = command.to_lowercase();
        for pattern in &dangerous_patterns {
            if command_lower.contains(pattern) {
                return Err(anyhow!("Command contains dangerous pattern: {}", pattern).into());
            }
        }

        // Limit command length
        if command.len() > 1000 {
            return Err(anyhow!("Command too long").into());
        }

        Ok(command.to_string())
    }

    /// Clean up temporary directory and resources
    pub async fn cleanup(&mut self) -> Result<()> {
        if let Some(temp_dir) = self.temp_dir.take() {
            if temp_dir.exists() {
                std::fs::remove_dir_all(&temp_dir)
                    .map_err(|e| anyhow!("Failed to cleanup temp directory: {}", e))?;
                debug!("Cleaned up temp directory: {}", temp_dir.display());
            }
        }
        Ok(())
    }
}

impl Drop for ProcessIsolation {
    fn drop(&mut self) {
        if let Some(ref temp_dir) = self.temp_dir {
            if temp_dir.exists() {
                if let Err(e) = std::fs::remove_dir_all(temp_dir) {
                    error!("Failed to cleanup temp directory in Drop: {}", e);
                }
            }
        }
    }
}

/// Builder for creating process isolation configurations
pub struct IsolationConfigBuilder {
    config: IsolationConfig,
}

impl IsolationConfigBuilder {
    pub fn new() -> Self {
        Self {
            config: IsolationConfig::default(),
        }
    }

    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.config.timeout = timeout;
        self
    }

    pub fn max_memory(mut self, max_memory: u64) -> Self {
        self.config.max_memory = Some(max_memory);
        self
    }

    pub fn max_cpu_time(mut self, max_cpu_time: u64) -> Self {
        self.config.max_cpu_time = Some(max_cpu_time);
        self
    }

    pub fn working_dir<P: Into<PathBuf>>(mut self, working_dir: P) -> Self {
        self.config.working_dir = Some(working_dir.into());
        self
    }

    pub fn env_var<K: Into<String>, V: Into<String>>(mut self, key: K, value: V) -> Self {
        self.config.env_vars.insert(key.into(), value.into());
        self
    }

    pub fn capture_stdout(mut self, capture: bool) -> Self {
        self.config.capture_stdout = capture;
        self
    }

    pub fn capture_stderr(mut self, capture: bool) -> Self {
        self.config.capture_stderr = capture;
        self
    }

    pub fn max_output_size(mut self, max_size: usize) -> Self {
        self.config.max_output_size = max_size;
        self
    }

    pub fn build(self) -> IsolationConfig {
        self.config
    }
}

impl Default for IsolationConfigBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[tokio::test]
    async fn test_process_isolation_creation() {
        let isolation = ProcessIsolation::new();
        assert_eq!(isolation.config.timeout, Duration::from_secs(30));
    }

    #[tokio::test]
    async fn test_config_builder() {
        let config = IsolationConfigBuilder::new()
            .timeout(Duration::from_secs(10))
            .max_memory(256 * 1024 * 1024)
            .env_var("TEST_VAR", "test_value")
            .build();

        assert_eq!(config.timeout, Duration::from_secs(10));
        assert_eq!(config.max_memory, Some(256 * 1024 * 1024));
        assert_eq!(config.env_vars.get("TEST_VAR"), Some(&"test_value".to_string()));
    }

    #[tokio::test]
    async fn test_validate_program_path() {
        let isolation = ProcessIsolation::new();

        // Valid paths
        assert!(isolation.validate_program_path("ls").is_ok());
        assert!(isolation.validate_program_path("/usr/bin/ls").is_ok());
        assert!(isolation.validate_program_path("\"program with spaces\"").is_ok());

        // Invalid paths
        assert!(isolation.validate_program_path("ls; rm -rf /").is_err());
        assert!(isolation.validate_program_path("ls | cat").is_err());
        assert!(isolation.validate_program_path("../../../bin/ls").is_err());
        assert!(isolation.validate_program_path("program with spaces").is_err());
    }

    #[tokio::test]
    async fn test_sanitize_shell_command() {
        let isolation = ProcessIsolation::new();

        // Valid commands
        assert!(isolation.sanitize_shell_command("echo hello").is_ok());
        assert!(isolation.sanitize_shell_command("ls -la").is_ok());

        // Invalid commands
        assert!(isolation.sanitize_shell_command("echo hello; rm -rf /").is_err());
        assert!(isolation.sanitize_shell_command("ls | grep test").is_err());
        assert!(isolation.sanitize_shell_command("$(malicious_command)").is_err());
    }

    #[tokio::test]
    async fn test_temp_directory_creation() {
        let mut isolation = ProcessIsolation::new();
        let temp_dir = isolation.setup_temp_directory().await.unwrap().to_path_buf();
        
        assert!(temp_dir.exists());
        assert!(temp_dir.is_dir());
        
        // Cleanup
        isolation.cleanup().await.unwrap();
        assert!(!temp_dir.exists());
    }

    #[tokio::test]
    async fn test_simple_command_execution() {
        let isolation = ProcessIsolation::new();
        
        #[cfg(unix)]
        let result = isolation.execute_isolated("echo", ["hello"]).await.unwrap();
        
        #[cfg(windows)]
        let result = isolation.execute_isolated("cmd", ["/C", "echo hello"]).await.unwrap();

        assert_eq!(result.exit_code, Some(0));
        assert!(result.stdout.is_some());
        assert!(!result.timed_out);
    }

    #[tokio::test]
    async fn test_timeout_handling() {
        let config = IsolationConfigBuilder::new()
            .timeout(Duration::from_millis(100))
            .build();
        
        let isolation = ProcessIsolation::with_config(config);
        
        #[cfg(unix)]
        let result = isolation.execute_isolated("sleep", ["1"]).await.unwrap();
        
        #[cfg(windows)]
        let result = isolation.execute_isolated("ping", ["-n", "10", "127.0.0.1"]).await.unwrap();

        assert!(result.timed_out);
    }
}