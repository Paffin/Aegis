//! REQ: SEC-01, INV-6 — wrapper that never prints or serializes its content.

use std::fmt;
use zeroize::Zeroize;

/// Holds a value that must not reach logs, metrics, audit or error messages.
/// `Debug` and `Display` print a fixed redaction. The value is zeroized on drop.
pub struct Sensitive<T: Zeroize>(T);

impl<T: Zeroize> Sensitive<T> {
    pub fn new(value: T) -> Self {
        Self(value)
    }

    /// Explicit access to the value. Every call site is a review point.
    pub fn expose(&self) -> &T {
        &self.0
    }
}

impl<T: Zeroize + Clone> Clone for Sensitive<T> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl<T: Zeroize> Drop for Sensitive<T> {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl<T: Zeroize> fmt::Debug for Sensitive<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Sensitive(<redacted>)")
    }
}

impl<T: Zeroize> fmt::Display for Sensitive<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("<redacted>")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // REQ: SEC-01
    #[test]
    fn never_prints_value() {
        let s = Sensitive::new(String::from("hunter2"));
        assert!(!format!("{s:?}").contains("hunter2"));
        assert!(!format!("{s}").contains("hunter2"));
        assert_eq!(s.expose(), "hunter2");
    }
}
