//! REQ: SEC-02 — process hardening: no core dumps, not ptrace-able/dumpable.
//!
//! A crash dump of the gateway would contain request bodies in clear text. Memory locking
//! (`mlock`) needs `unsafe` and is left to the deployment (encrypted or disabled swap).

#[derive(Debug, PartialEq, Eq)]
pub struct Hardening {
    pub core_dumps_disabled: bool,
    pub non_dumpable: bool,
}

#[cfg(target_os = "linux")]
pub fn apply() -> Hardening {
    use rustix::process::{setrlimit, Resource, Rlimit};
    let core_dumps_disabled = setrlimit(
        Resource::Core,
        Rlimit {
            current: Some(0),
            maximum: Some(0),
        },
    )
    .is_ok();
    let non_dumpable =
        rustix::process::set_dumpable_behavior(rustix::process::DumpableBehavior::NotDumpable)
            .is_ok();
    Hardening {
        core_dumps_disabled,
        non_dumpable,
    }
}

#[cfg(not(target_os = "linux"))]
pub fn apply() -> Hardening {
    Hardening {
        core_dumps_disabled: false,
        non_dumpable: false,
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;

    // REQ: SEC-02
    #[test]
    fn dumps_are_disabled() {
        assert_eq!(
            apply(),
            Hardening {
                core_dumps_disabled: true,
                non_dumpable: true
            }
        );
        let lim = rustix::process::getrlimit(rustix::process::Resource::Core);
        assert_eq!((lim.current, lim.maximum), (Some(0), Some(0)));
        assert_eq!(
            rustix::process::dumpable_behavior().ok(),
            Some(rustix::process::DumpableBehavior::NotDumpable)
        );
    }
}
