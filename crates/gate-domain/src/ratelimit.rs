//! A token-bucket rate limiter over explicit time.
//!
//! Each key has a bucket that holds up to `burst` requests and refills at `per_minute` requests
//! per minute. The state is integer arithmetic only: a bucket level is counted in 1/60000
//! requests, so that one millisecond adds exactly `per_minute` units and there is no rounding.
//! The caller passes the monotonic time in milliseconds; the limiter never reads a clock.

use std::collections::HashMap;

/// Level units per request.
const UNITS: u64 = 60_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RateDecision {
    Allowed,
    /// The request is over the limit; the next one can pass after this many milliseconds.
    Limited {
        retry_after_ms: u64,
    },
}

#[derive(Debug, Clone, Copy)]
struct Bucket {
    level: u64,
    last_ms: u64,
}

#[derive(Debug)]
pub struct RateLimiter {
    per_minute: u64,
    capacity: u64,
    buckets: HashMap<String, Bucket>,
}

impl RateLimiter {
    /// `per_minute` and `burst` are clamped to at least 1.
    pub fn new(per_minute: u32, burst: u32) -> RateLimiter {
        RateLimiter {
            per_minute: u64::from(per_minute.max(1)),
            capacity: u64::from(burst.max(1)) * UNITS,
            buckets: HashMap::new(),
        }
    }

    pub fn check(&mut self, key: &str, now_ms: u64) -> RateDecision {
        let (per_minute, capacity) = (self.per_minute, self.capacity);
        let bucket = self.buckets.entry(key.to_string()).or_insert(Bucket {
            level: capacity,
            last_ms: now_ms,
        });
        // a clock that steps backwards adds nothing and does not rewind the bucket
        let elapsed = now_ms.saturating_sub(bucket.last_ms);
        bucket.last_ms = bucket.last_ms.max(now_ms);
        bucket.level = bucket
            .level
            .saturating_add(elapsed.saturating_mul(per_minute))
            .min(capacity);
        if bucket.level >= UNITS {
            bucket.level -= UNITS;
            RateDecision::Allowed
        } else {
            RateDecision::Limited {
                retry_after_ms: (UNITS - bucket.level).div_ceil(per_minute),
            }
        }
    }

    pub fn tracked_keys(&self) -> usize {
        self.buckets.len()
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

    #[test]
    fn a_burst_passes_then_the_limit_applies() {
        let mut l = RateLimiter::new(60, 3);
        for _ in 0..3 {
            assert_eq!(l.check("a", 0), RateDecision::Allowed);
        }
        assert_eq!(
            l.check("a", 0),
            RateDecision::Limited {
                retry_after_ms: 1000
            }
        );
        assert_eq!(
            l.check("a", 999),
            RateDecision::Limited { retry_after_ms: 1 }
        );
        assert_eq!(l.check("a", 1000), RateDecision::Allowed);
        assert_eq!(
            l.check("a", 1000),
            RateDecision::Limited {
                retry_after_ms: 1000
            }
        );
    }

    #[test]
    fn keys_are_independent() {
        let mut l = RateLimiter::new(1, 1);
        assert_eq!(l.check("a", 0), RateDecision::Allowed);
        assert_eq!(l.check("b", 0), RateDecision::Allowed);
        assert!(matches!(l.check("a", 1), RateDecision::Limited { .. }));
        assert_eq!(l.tracked_keys(), 2);
    }

    #[test]
    fn the_bucket_never_holds_more_than_the_burst() {
        let mut l = RateLimiter::new(60, 2);
        assert_eq!(l.check("a", 0), RateDecision::Allowed);
        // an hour of idle time refills to the burst, not beyond it
        let t = 3_600_000;
        assert_eq!(l.check("a", t), RateDecision::Allowed);
        assert_eq!(l.check("a", t), RateDecision::Allowed);
        assert!(matches!(l.check("a", t), RateDecision::Limited { .. }));
    }

    #[test]
    fn a_clock_that_goes_backwards_is_harmless() {
        let mut l = RateLimiter::new(60, 1);
        assert_eq!(l.check("a", 10_000), RateDecision::Allowed);
        assert!(matches!(l.check("a", 5_000), RateDecision::Limited { .. }));
        // no free refill from going back and forth
        assert!(matches!(l.check("a", 10_500), RateDecision::Limited { .. }));
        assert_eq!(l.check("a", 11_000), RateDecision::Allowed);
    }

    #[test]
    fn a_slow_rate_reports_a_long_retry() {
        let mut l = RateLimiter::new(1, 1);
        assert_eq!(l.check("a", 0), RateDecision::Allowed);
        assert_eq!(
            l.check("a", 0),
            RateDecision::Limited {
                retry_after_ms: 60_000
            }
        );
        assert_eq!(
            l.check("a", 59_999),
            RateDecision::Limited { retry_after_ms: 1 }
        );
        assert_eq!(l.check("a", 60_000), RateDecision::Allowed);
    }

    #[test]
    fn long_run_rate_stays_within_the_configured_rate() {
        // 120/min with a burst of 10 over 10 minutes at 100 ms spacing: at most burst + rate * time
        let mut l = RateLimiter::new(120, 10);
        let allowed = (0..6000u64)
            .filter(|i| l.check("k", i * 100) == RateDecision::Allowed)
            .count();
        assert!(allowed <= 10 + 120 * 10, "{allowed}");
        assert!(allowed >= 120 * 10 - 10, "{allowed}");
    }

    #[test]
    fn zero_arguments_are_clamped() {
        let mut l = RateLimiter::new(0, 0);
        assert_eq!(l.check("a", 0), RateDecision::Allowed);
        assert!(matches!(l.check("a", 0), RateDecision::Limited { .. }));
    }

    #[test]
    fn extreme_times_do_not_overflow() {
        let mut l = RateLimiter::new(u32::MAX, u32::MAX);
        assert_eq!(l.check("a", 0), RateDecision::Allowed);
        assert_eq!(l.check("a", u64::MAX), RateDecision::Allowed);
    }
}
