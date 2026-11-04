//! When to start the upstream server again after it exited.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RestartMode {
    /// Never restart: when the child is gone the gateway answers 503 until it is restarted by hand.
    Never,
    /// Restart after a crash or a non-zero exit, not after a clean exit.
    OnFailure,
    /// Restart whatever the exit status was.
    Always,
}

impl RestartMode {
    pub fn parse(text: &str) -> Option<RestartMode> {
        match text {
            "never" => Some(RestartMode::Never),
            "on-failure" => Some(RestartMode::OnFailure),
            "always" => Some(RestartMode::Always),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RestartDecision {
    Restart { delay_ms: u64 },
    GiveUp(&'static str),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RestartPolicy {
    pub mode: RestartMode,
    /// Consecutive failed runs after which the gateway gives up.
    pub max_restarts: u32,
    pub backoff_ms: u64,
    pub max_backoff_ms: u64,
}

impl RestartPolicy {
    /// `clean_exit` is true when the child exited with status 0. `failures` counts the restarts
    /// since the last run that stayed up long enough to count as healthy.
    pub fn decide(&self, clean_exit: bool, failures: u32) -> RestartDecision {
        match self.mode {
            RestartMode::Never => return RestartDecision::GiveUp("restarts are disabled"),
            RestartMode::OnFailure if clean_exit => {
                return RestartDecision::GiveUp("the server exited normally")
            }
            _ => {}
        }
        if failures >= self.max_restarts {
            return RestartDecision::GiveUp("the restart limit was reached");
        }
        let factor = 1u64.checked_shl(failures).unwrap_or(u64::MAX);
        RestartDecision::Restart {
            delay_ms: self
                .backoff_ms
                .saturating_mul(factor)
                .min(self.max_backoff_ms),
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::indexing_slicing,
        clippy::panic
    )]
    use super::*;

    fn policy(mode: RestartMode) -> RestartPolicy {
        RestartPolicy {
            mode,
            max_restarts: 3,
            backoff_ms: 100,
            max_backoff_ms: 500,
        }
    }

    #[test]
    fn modes() {
        assert_eq!(RestartMode::parse("never"), Some(RestartMode::Never));
        assert_eq!(
            RestartMode::parse("on-failure"),
            Some(RestartMode::OnFailure)
        );
        assert_eq!(RestartMode::parse("always"), Some(RestartMode::Always));
        assert_eq!(RestartMode::parse("sometimes"), None);
    }

    #[test]
    fn never_gives_up() {
        assert!(matches!(
            policy(RestartMode::Never).decide(false, 0),
            RestartDecision::GiveUp(_)
        ));
    }

    #[test]
    fn on_failure_restarts_crashes_only() {
        let p = policy(RestartMode::OnFailure);
        assert!(matches!(p.decide(true, 0), RestartDecision::GiveUp(_)));
        assert_eq!(
            p.decide(false, 0),
            RestartDecision::Restart { delay_ms: 100 }
        );
    }

    #[test]
    fn always_restarts_clean_exits_too() {
        assert_eq!(
            policy(RestartMode::Always).decide(true, 0),
            RestartDecision::Restart { delay_ms: 100 }
        );
    }

    #[test]
    fn backoff_doubles_up_to_the_cap_and_the_limit_stops_it() {
        let p = policy(RestartMode::Always);
        assert_eq!(
            p.decide(false, 1),
            RestartDecision::Restart { delay_ms: 200 }
        );
        assert_eq!(
            p.decide(false, 2),
            RestartDecision::Restart { delay_ms: 400 }
        );
        assert!(matches!(p.decide(false, 3), RestartDecision::GiveUp(_)));
        let many = RestartPolicy {
            max_restarts: 200,
            ..p
        };
        assert_eq!(
            many.decide(false, 100),
            RestartDecision::Restart { delay_ms: 500 }
        );
        assert_eq!(
            many.decide(false, 199),
            RestartDecision::Restart { delay_ms: 500 }
        );
    }
}
