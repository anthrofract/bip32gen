use std::process::{Command, Output, Stdio};

use anyhow::{Context, bail, ensure};

/// Verify a required external command can be launched at all.
pub(crate) fn validate_command(command: &str) -> anyhow::Result<()> {
    let status = Command::new(command)
        .arg("--version")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .with_context(|| format!("required command '{command}' was not found on PATH"))?;

    ensure!(
        status.success(),
        "required command '{command}' failed with status {status}"
    );
    Ok(())
}

/// Bail with the command's trimmed stderr, or its exit status when stderr is empty.
pub(crate) fn check_command_output(command: &str, output: &Output) -> anyhow::Result<()> {
    if output.status.success() {
        return Ok(());
    }

    let stderr = String::from_utf8_lossy(&output.stderr);
    let stderr = stderr.trim();
    if stderr.is_empty() {
        bail!("{command} failed with status {}", output.status);
    }
    bail!("{command} failed: {stderr}");
}
