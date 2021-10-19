//! shell.rs

use std::{
    ffi::OsStr,
    process::{ChildStdin, Command, ExitStatus, Output, Stdio},
};
use thiserror::Error;

/// Repersents an Error that can occur when running a shell command
#[derive(Debug, Error)]
pub enum ShellCommandError {
    #[error("expected stdin to be piped but no pipe was found")]
    StdinNotPresent,

    /// Input/Output error when launching the shell command
    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),

    /// Exited with a non-zero status
    #[error("command failed with error code {0}; stdout: {1}; stderr: {2}")]
    Failed(ExitStatus, String, String),
}

/// A simple wrapper around a command that makes it easier to interact with and launch commands
/// quickly while still capturing the output
pub struct ShellCommand {
    cmd: Command,
}

impl ShellCommand {
    /// Returns a new shell command that will execute `cmd`
    ///
    /// # Arguments
    /// * `cmd` - Command to execute
    pub fn new<S: AsRef<OsStr>>(cmd: S) -> Self {
        ShellCommand {
            cmd: Command::new(cmd),
        }
    }

    /// Adds an argument to this shell command
    ///
    /// # Arguments
    /// * `arg` - Argument to add to the shell command
    pub fn arg<S: AsRef<OsStr>>(&mut self, arg: S) {
        self.cmd.arg(arg);
    }

    /// Helper function to parse the output from a shell command
    ///
    /// # Arguments
    /// * `output` - the captured output from stdout/stderr
    ///
    /// # Errors
    /// * `ShellCommandError::Io` - If launching/forking the command fails
    /// * `ShellCommandError::Failed` - If the return code is non-zero
    fn parse_output(output: Output) -> Result<String, ShellCommandError> {
        let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&output.stderr).into_owned();

        if !stdout.is_empty() {
            tracing::debug!("command stdout:\n{}", stdout);
        }

        if !stderr.is_empty() {
            tracing::debug!("command stderr:\n{}", stderr);
        }

        match output.status.success() {
            true => Ok(stdout),
            false => Err(ShellCommandError::Failed(output.status, stdout, stderr)),
        }
    }

    /// Executes the command, capturing the output (stdin/stderr) for logging
    ///
    /// # Errors
    /// * `ShellCommandError::Io` - If launching/forking the command fails
    /// * `ShellCommandError::Failed` - If the return code is non-zero
    pub fn execute(mut self) -> Result<String, ShellCommandError> {
        tracing::debug!("command: {:?}", self.cmd);
        let output = self.cmd.output()?;
        Self::parse_output(output)
    }

    /// Spawns the command and allows for writing to the child process's stdin and captures
    /// stdout/stderr for logging
    ///
    /// # Arguments
    /// * `f` - Funtion that can write to stdin
    ///
    /// # Errors
    /// * `ShellCommandError::StdinNotPresent` - If a handle/pipe to stdin could not be created
    /// * `ShellCommandError::Io` - If launching/forking the command fails
    /// * `ShellCommandError::Failed` - If the return code is non-zero
    pub fn spawn<F>(mut self, f: F) -> Result<String, ShellCommandError>
    where
        F: Fn(ChildStdin) -> Result<(), std::io::Error>,
    {
        tracing::debug!("command: {:?}", self.cmd);

        // by default `spawn()` will inhereit stdout/stderr and print to the active terminal, we
        // don't want want so we'll create pipes to them so we can capture the output later.
        //
        // We also want to be able to write to stdin, so we'll create a pipe to that too and then
        // pass the stdin handle to out callback/closure
        let mut child = self
            .cmd
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;

        // unpack the handle to stdin. `take()` will extract the value from the option, leaving `None`
        // in its place, thus not causing a partial move/invalidating `child`.  This is necessary
        // because we call `child.wait_with_output()` later
        let stdin = child
            .stdin
            .take()
            .ok_or(ShellCommandError::StdinNotPresent)?;

        // write to stdin through the provided closure
        f(stdin)?;

        let output = child.wait_with_output()?;
        Self::parse_output(output)
    }
}
