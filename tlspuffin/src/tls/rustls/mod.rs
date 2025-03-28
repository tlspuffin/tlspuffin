//! Extracted from `rustls`.
//!
//! See [rustls](https://github.com/tlspuffin/rustls/commit/0678516b124e3edf12a7d147a824db9e0fd0f5ec) fork.
//! Upstreaming this fork is becoming unfeasible and there are no benefits in keeping up with the
//! latest version of rustls. If we want to support fuzzing new features of upcomping TLS versions
//! then we have to manually integrate them.
//!
//! This module contains primitives required to perform TLS 1.2 and 1.3 handshakes.
//!
//!
//! License of rustls:
//!
//! ```text
//! Copyright (c) 2016 Joseph Birr-Pixton <jpixton@gmail.com>
//!
//! Permission is hereby granted, free of charge, to any
//! person obtaining a copy of this software and associated
//! documentation files (the "Software"), to deal in the
//! Software without restriction, including without
//! limitation the rights to use, copy, modify, merge,
//! publish, distribute, sublicense, and/or sell copies of
//! the Software, and to permit persons to whom the Software
//! is furnished to do so, subject to the following
//! conditions:
//!
//! The above copyright notice and this permission notice
//! shall be included in all copies or substantial portions
//! of the Software.
//!
//! THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF
//! ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED
//! TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A
//! PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT
//! SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
//! CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
//! OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR
//! IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
//! DEALINGS IN THE SOFTWARE.
//! ```

pub mod anchors;
pub mod cipher;
pub mod conn;
pub mod error;
pub mod hash_hs;
pub mod key;
pub mod key_log;
pub mod kx;
pub mod limited_cache;
pub mod msgs;
pub mod rand;
pub mod record_layer;
/// Message signing interfaces and implementations.
pub mod sign;
pub mod suites;
pub mod ticketer;
pub mod tls12;
pub mod tls13;
pub mod vecbuf;
pub mod verify;
pub mod versions;
pub mod x509;

/// Items for use in a client.
pub mod client {
    pub mod client_conn;
}

/// Items for use in a server.
pub mod server {
    pub mod server_conn;
}

/// APIs for implementing QUIC TLS
pub mod quic;
