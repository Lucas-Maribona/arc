//! A bounded wait helper for hooks and triggers.

use std::process::{Child, ExitStatus};
use std::thread;
use std::time::{Duration, Instant};

use crate::error::{ArcError, Result};

const EXECUTION_TIMEOUT: Duration = Duration::from_secs(5 * 60);
const POLL_INTERVAL: Duration = Duration::from_millis(20);

pub(crate) fn wait_with_timeout(child: &mut Child, description: &str) -> Result<ExitStatus> {
    wait_for(child, description, EXECUTION_TIMEOUT)
}

fn wait_for(child: &mut Child, description: &str, timeout: Duration) -> Result<ExitStatus> {
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(status) = child.try_wait()? {
            return Ok(status);
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return Err(ArcError::Transaction(format!(
                "{description} exceeded the five-minute execution limit"
            )));
        }
        thread::sleep(POLL_INTERVAL.min(timeout));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;

    #[test]
    fn runaway_children_are_terminated() {
        let mut child = Command::new("/bin/sleep").arg("2").spawn().unwrap();
        let result = wait_for(&mut child, "test process", Duration::from_millis(10));
        assert!(result.is_err());
        assert!(child.try_wait().unwrap().is_some());
    }
}
