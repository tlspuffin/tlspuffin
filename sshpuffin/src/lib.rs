//! SSH support for puffin: the protocol types and term signature, the seeds, the
//! C harnesses of the SSH PUTs (libssh, wolfSSH) and the differential hooks.
//! The `sshpuffin` binary (`main.rs`) is the fuzzer's command line on top of it.

pub mod claim;
pub mod cput;
pub mod protocol;
pub mod put_registry;
pub mod query;
pub mod ssh;
pub mod violation;
