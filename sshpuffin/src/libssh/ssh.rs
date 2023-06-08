use std::{
    ffi::{c_char, c_void, CStr, CString},
    mem,
    os::{raw::c_int, unix::io::RawFd},
    ptr,
    ptr::null,
    time::Duration,
};

use foreign_types::{foreign_type, ForeignType, ForeignTypeRef};
use libssh_sys::{self, ssh_options_e};

#[derive(PartialEq)]
pub enum SshResult {
    Ok,
    Again,
    Unknown(c_int),
}

#[derive(PartialEq)]
pub enum SshAuthResult {
    Success,
    Again,
    Partial,
    Denied,
    Unknown(c_int),
}

pub type AuthState = libssh_sys::ssh_auth_state_e;
pub type SessionState = libssh_sys::ssh_session_state_e;

foreign_type! {
    pub unsafe type SshSession: Sync + Send {
        type CType = libssh_sys::ssh_session_struct;
        fn drop = libssh_sys::ssh_free;
    }
}

impl SshSession {
    pub fn new() -> Result<Self, String> {
        unsafe {
            let ptr = libssh_sys::ssh_new();

            if ptr.is_null() {
                return Err("Failed to initialize session".to_string());
            }

            let mut session = Self::from_ptr(ptr);
            Ok(session)
        }
    }
}

impl SshSessionRef {
    /// `ssh_set_blocking`
    pub fn set_blocking(&mut self, blocking: bool) {
        unsafe {
            libssh_sys::ssh_set_blocking(self.as_ptr(), blocking as i32);
        }
    }

    /// TODO
    pub fn session_state(&self) -> SessionState {
        unsafe { (*self.as_ptr()).session_state }
    }
    pub fn auth_state(&self) -> AuthState {
        unsafe { (*self.as_ptr()).auth.state }
    }

    /// `ssh_options_set`
    pub fn set_options_str(&mut self, typ: SessionOption, value: &str) -> Result<(), String> {
        unsafe {
            let value = CString::new(value).map_err(|err| err.to_string())?;
            cvt_n(
                libssh_sys::ssh_options_set(self.as_ptr(), typ, value.as_ptr() as *const c_void),
                self,
            )
            .map(|_| ())
        }
    }

    /// `ssh_options_set`
    pub fn set_options_int(&mut self, typ: SessionOption, value: i32) -> Result<(), String> {
        unsafe {
            let value: *const i32 = &value;
            cvt_n(
                libssh_sys::ssh_options_set(
                    self.as_ptr(),
                    typ as ssh_options_e,
                    value as *const c_void,
                ),
                self,
            )
            .map(|_| ())
        }
    }

    /// `ssh_connect`
    pub fn connect(&mut self) -> Result<SshResult, String> {
        unsafe { cvt_io(libssh_sys::ssh_connect(self.as_ptr()), self) }
    }

    /// `ssh_blocking_flush`
    pub fn blocking_flush(&mut self, duration: Duration) -> Result<SshResult, String> {
        unsafe {
            cvt_io(
                libssh_sys::ssh_blocking_flush(self.as_ptr(), duration.as_millis() as i32),
                self,
            )
        }
    }

    /// `ssh_is_connected`
    pub fn is_connected(&self) -> bool {
        unsafe { libssh_sys::ssh_is_connected(self.as_ptr()) != 0 }
    }

    /// `ssh_handle_key_exchange`
    pub fn handle_key_exchange(&mut self) -> Result<SshResult, String> {
        unsafe { cvt_io(libssh_sys::ssh_handle_key_exchange(self.as_ptr()), self) }
    }

    /// `ssh_userauth_password`
    pub fn userauth_password(
        &mut self,
        username: Option<&str>,
        password: &str,
    ) -> Result<SshAuthResult, String> {
        unsafe {
            let username = username.map(|username| CString::new(username).unwrap());
            let password = CString::new(password).map_err(|err| err.to_string())?;
            let username = match username {
                None => null() as *const c_char,
                Some(username) => username.as_ptr(),
            };
            cvt_auth(
                libssh_sys::ssh_userauth_password(
                    self.as_ptr(),
                    username,
                    password.as_ptr() as *const i8,
                ),
                self,
            )
        }
    }

    /// `ssh_message_get`
    pub fn get_message(&mut self) -> Option<SshMessage> {
        unsafe {
            let message = libssh_sys::ssh_message_get(self.as_ptr());
            if message.is_null() {
                None
            } else {
                Some(SshMessage::from_ptr(message))
            }
        }
    }

    /// `ssh_disconnect`
    pub fn disconnect(&mut self) {
        unsafe { libssh_sys::ssh_disconnect(self.as_ptr()) }
    }
}

impl Fallible for SshSessionRef {
    type Error = String;

    /// `ssh_get_error`
    fn get_error(&self) -> Self::Error {
        unsafe {
            CStr::from_ptr(libssh_sys::ssh_get_error(self.as_ptr() as *mut c_void))
                .to_str()
                .map(|message| {
                    if message.is_empty() {
                        "Unknown error in session"
                    } else {
                        message
                    }
                })
                .unwrap_or("Failed to decode libssh error string")
                .to_string()
        }
    }
}

pub type SessionOption = libssh_sys::ssh_options_e;

foreign_type! {
    pub unsafe type SshBind: Sync + Send {
        type CType = libssh_sys::ssh_bind_struct;
        fn drop = libssh_sys::ssh_bind_free;
    }
}

impl SshBind {
    pub fn new() -> Result<Self, String> {
        unsafe {
            let ptr = libssh_sys::ssh_bind_new();

            if ptr.is_null() {
                return Err("Failed to initialize bind".to_string());
            }

            let mut session = Self::from_ptr(ptr);
            Ok(session)
        }
    }
}

impl SshBindRef {
    /// `ssh_bind_options_set`
    pub fn set_options_str(&mut self, typ: SshBindOption, value: &str) -> Result<(), String> {
        unsafe {
            let value = CString::new(value).map_err(|err| err.to_string())?;
            cvt_n(
                libssh_sys::ssh_bind_options_set(
                    self.as_ptr(),
                    typ,
                    value.as_ptr() as *const c_void,
                ),
                self,
            )
            .map(|_| ())
        }
    }

    /// `ssh_bind_options_set`
    pub fn set_options_int(&mut self, typ: SshBindOption, value: i32) -> Result<(), String> {
        unsafe {
            let value: *const i32 = &value;
            cvt_n(
                libssh_sys::ssh_bind_options_set(self.as_ptr(), typ, value as *const c_void),
                self,
            )
            .map(|_| ())
        }
    }

    /// `ssh_bind_options_set`
    pub fn set_options_key(&mut self, typ: SshBindOption, value: SshKey) -> Result<(), String> {
        unsafe {
            let result = cvt_n(
                libssh_sys::ssh_bind_options_set(
                    self.as_ptr(),
                    typ,
                    value.as_ptr() as *const c_void,
                ),
                self,
            )
            .map(|_| {
                mem::forget(value);
                ()
            });

            result
        }
    }

    /// `ssh_bind_set_blocking`
    pub fn set_blocking(&mut self, blocking: bool) {
        unsafe { libssh_sys::ssh_bind_set_blocking(self.as_ptr(), blocking as c_int) }
    }

    /// `ssh_bind_accept_fd`
    pub fn accept_fd(&mut self, session: &SshSessionRef, fd: RawFd) -> Result<(), String> {
        unsafe {
            cvt_n(
                libssh_sys::ssh_bind_accept_fd(self.as_ptr(), session.as_ptr(), fd),
                self,
            )
            .map(|_| ())
        }
    }
}

impl Fallible for SshBindRef {
    type Error = String;

    /// `ssh_get_error
    fn get_error(&self) -> Self::Error {
        unsafe {
            CStr::from_ptr(libssh_sys::ssh_get_error(self.as_ptr() as *mut c_void))
                .to_str()
                .map(|message| {
                    if message.is_empty() {
                        "Unknown error in bind"
                    } else {
                        message
                    }
                })
                .unwrap_or("Failed to decode libssh error string")
                .to_string()
        }
    }
}

pub type SshRequest = libssh_sys::ssh_requests_e;

fn from_raw(value: u32) -> Option<SshRequest> {
    const AUTH: u32 = SshRequest::SSH_REQUEST_AUTH as u32;
    const CHANNEL_OPEN: u32 = SshRequest::SSH_REQUEST_CHANNEL_OPEN as u32;
    const CHANNEL: u32 = SshRequest::SSH_REQUEST_CHANNEL as u32;
    const SERVICE: u32 = SshRequest::SSH_REQUEST_SERVICE as u32;
    const GLOBAL: u32 = SshRequest::SSH_REQUEST_GLOBAL as u32;
    match value {
        AUTH => Some(SshRequest::SSH_REQUEST_AUTH),
        CHANNEL_OPEN => Some(SshRequest::SSH_REQUEST_CHANNEL_OPEN),
        CHANNEL => Some(SshRequest::SSH_REQUEST_CHANNEL),
        SERVICE => Some(SshRequest::SSH_REQUEST_SERVICE),
        GLOBAL => Some(SshRequest::SSH_REQUEST_GLOBAL),
        _ => None,
    }
}

pub type SshBindOption = libssh_sys::ssh_bind_options_e;

foreign_type! {
    pub unsafe type SshMessage: Sync + Send {
        type CType = libssh_sys::ssh_message_struct;
        fn drop = libssh_sys::ssh_message_free;
    }
}

impl SshMessageRef {
    /// `ssh_message_reply_default`
    pub fn reply_default(&mut self) -> Result<(), String> {
        unsafe { cvt_auth(libssh_sys::ssh_message_reply_default(self.as_ptr()), self).map(|_| ()) }
    }

    /// `ssh_message_auth_reply_success`
    pub fn auth_reply_success(&mut self, partial: i32) -> Result<(), String> {
        unsafe {
            cvt_auth(
                libssh_sys::ssh_message_auth_reply_success(self.as_ptr(), partial),
                self,
            )
            .map(|_| ())
        }
    }

    /// `ssh_message_type`
    pub fn typ(&self) -> Result<Option<SshRequest>, String> {
        unsafe {
            Ok(from_raw(
                cvt_n(libssh_sys::ssh_message_type(self.as_ptr()), self)? as u32,
            ))
        }
    }
    /// `ssh_message_auth_user`
    pub fn auth_user(&self) -> Option<&str> {
        unsafe {
            let user = libssh_sys::ssh_message_auth_user(self.as_ptr());

            if user.is_null() {
                None
            } else {
                Some(CStr::from_ptr(user).to_str().unwrap())
            }
        }
    }

    /// `ssh_message_auth_password`
    pub fn auth_password(&self) -> Result<&str, String> {
        unsafe {
            cvt_pointer(libssh_sys::ssh_message_auth_password(self.as_ptr()), self)
                .map(|password| CStr::from_ptr(password).to_str().unwrap())
        }
    }
}

impl Fallible for SshMessageRef {
    type Error = String;

    fn get_error(&self) -> Self::Error {
        "Error with ssh message".to_string()
    }
}

foreign_type! {
    pub unsafe type SshKey: Sync + Send {
        type CType = libssh_sys::ssh_key_struct;
        fn drop = libssh_sys::ssh_key_free;
    }
}

impl SshKey {
    pub fn from_base64(base64: &str) -> Result<Self, String> {
        unsafe {
            let mut ssh_key: libssh_sys::ssh_key = ptr::null_mut();

            let base64 = CString::new(base64).unwrap();

            let output: *mut libssh_sys::ssh_key = &mut ssh_key as *mut libssh_sys::ssh_key;

            let r = libssh_sys::ssh_pki_import_privkey_base64(
                base64.as_ptr(),
                ptr::null(),
                None,
                ptr::null_mut(),
                output,
            );

            if r < 0 {
                Err("Failed to import key".to_string())
            } else {
                Ok(SshKey::from_ptr(ssh_key))
            }
        }
    }
}

impl SshKeyRef {}

/// `ssh_set_log_level`
pub fn set_log_level(level: i32) {
    unsafe {
        libssh_sys::ssh_set_log_level(level);
    }
}

pub fn version() -> String {
    format!(
        "{}.{}.{}",
        libssh_sys::LIBSSH_VERSION_MAJOR,
        libssh_sys::LIBSSH_VERSION_MINOR,
        libssh_sys::LIBSSH_VERSION_MICRO
    )
}

trait Fallible {
    type Error;

    fn get_error(&self) -> Self::Error;
}

fn cvt_pointer_mut<T, F: Fallible>(r: *mut T, failable: &F) -> Result<*mut T, F::Error> {
    if r.is_null() {
        Err(failable.get_error())
    } else {
        Ok(r)
    }
}

fn cvt_pointer<T, F: Fallible>(r: *const T, fallible: &F) -> Result<*const T, F::Error> {
    if r.is_null() {
        Err(fallible.get_error())
    } else {
        Ok(r)
    }
}

fn cvt_n<F: Fallible>(r: c_int, fallible: &F) -> Result<c_int, F::Error> {
    if r < 0 {
        Err(fallible.get_error())
    } else {
        Ok(r)
    }
}

const LIBSSH_OK: i32 = libssh_sys::SSH_OK as i32;
const LIBSSH_AUTH_ERROR: i32 = libssh_sys::ssh_auth_e_SSH_AUTH_ERROR as i32;
const LIBSSH_AUTH_SUCCESS: i32 = libssh_sys::ssh_auth_e_SSH_AUTH_SUCCESS as i32;
const LIBSSH_AUTH_AGAIN: i32 = libssh_sys::ssh_auth_e_SSH_AUTH_AGAIN as i32;
const LIBSSH_AUTH_PARTIAL: i32 = libssh_sys::ssh_auth_e_SSH_AUTH_PARTIAL as i32;
const LIBSSH_AUTH_DENIED: i32 = libssh_sys::ssh_auth_e_SSH_AUTH_DENIED as i32;

fn cvt_io<F: Fallible>(r: c_int, fallible: &F) -> Result<SshResult, F::Error> {
    if r == libssh_sys::SSH_ERROR {
        Err(fallible.get_error())
    } else {
        Ok(match r {
            LIBSSH_OK => SshResult::Ok,
            libssh_sys::SSH_AGAIN => SshResult::Again,
            code => SshResult::Unknown(code),
        })
    }
}

fn cvt_auth<F: Fallible>(r: c_int, fallible: &F) -> Result<SshAuthResult, F::Error> {
    if r == LIBSSH_AUTH_ERROR {
        Err(fallible.get_error())
    } else {
        Ok(match r {
            LIBSSH_AUTH_SUCCESS => SshAuthResult::Success,
            LIBSSH_AUTH_DENIED => SshAuthResult::Denied,
            LIBSSH_AUTH_PARTIAL => SshAuthResult::Partial,
            LIBSSH_AUTH_AGAIN => SshAuthResult::Again,
            code => SshAuthResult::Unknown(code),
        })
    }
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        os::unix::{
            io::IntoRawFd,
            net::{SocketAddr, UnixListener, UnixStream},
        },
    };

    use crate::libssh::ssh::{
        set_log_level, SessionOption, SshBind, SshBindOption, SshKey, SshSession,
    };
    const OPENSSH_RSA_PRIVATE_KEY: &'static str = "-----BEGIN OPENSSH PRIVATE KEY-----
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
-----END OPENSSH PRIVATE KEY-----
";

    #[test]
    fn test() {
        set_log_level(100);

        // FIXME: Switch to UDS with stabilization in Rust 1.70
        //let addr = SocketAddr::from_abstract_namespace(b"\0socket_test").unwrap();
        //let listener = UnixListener::bind_addr(&addr).unwrap();
        let path = "socket_test";
        let listener = UnixListener::bind(path).unwrap();
        listener.set_nonblocking(true).unwrap();

        // FIXME: Switch to UDS with stabilization in Rust 1.70
        //let mut client_stream = UnixStream::connect_addr(&addr).unwrap();
        let mut client_stream = UnixStream::connect(path).unwrap();
        // Unlink directly as we have the addresses now
        fs::remove_file(&path).unwrap();

        client_stream.set_nonblocking(true).unwrap();
        let server_stream = listener.incoming().next().unwrap().unwrap();

        let mut server = SshSession::new().unwrap();
        server.set_blocking(false);
        server
            .set_options_int(SessionOption::SSH_OPTIONS_PROCESS_CONFIG, 0)
            .unwrap();

        let mut bind = SshBind::new().unwrap();

        /*bind.set_options_str(
            SshBindOption::RSAKEY,
            "/home/max/projects/tlspuffin/ssh_host_rsa_key",
        )
        .unwrap();*/

        let key = SshKey::from_base64(OPENSSH_RSA_PRIVATE_KEY).unwrap();
        bind.set_options_key(SshBindOption::SSH_BIND_OPTIONS_IMPORT_KEY, key)
            .unwrap();

        bind.set_blocking(false);

        bind.accept_fd(&server, server_stream.into_raw_fd())
            .unwrap();

        // ---- Initialize client session

        let mut client = SshSession::new().unwrap();
        client.set_blocking(false);
        client
            .set_options_str(SessionOption::SSH_OPTIONS_HOST, "dummy")
            .unwrap();
        client
            .set_options_int(SessionOption::SSH_OPTIONS_FD, client_stream.into_raw_fd())
            .unwrap();
        client
            .set_options_int(SessionOption::SSH_OPTIONS_PROCESS_CONFIG, 0)
            .unwrap();

        // ------

        assert!(!client.is_connected());
        assert!(!server.is_connected());

        // Banner exchange
        client.connect().unwrap();
        server.handle_key_exchange().unwrap();

        assert!(client.is_connected());
        assert!(server.is_connected());

        // Starting handshake

        // Server: Send SSH_MSG_KEXINIT
        server.handle_key_exchange().unwrap();

        // Client: Send SSH_MSG_KEXINIT
        // Client: Send SSH_MSG_KEX_ECDH_INIT
        client.connect().unwrap();

        // Server: Receive SSH_MSG_KEXINIT
        // Server: Receive SSH_MSG_KEXDH_INIT
        // Server: Send SSH_MSG_KEX_ECDH_REPLY
        // Server: Send SSH_MSG_NEWKEYS
        server.handle_key_exchange().unwrap();

        // Client: Receive SSH_MSG_KEX_ECDH_REPLY
        // Client: Send SSH_MSG_NEWKEYS
        // Client: Receive SSH_MSG_KEXINIT
        // Client: Receive SSH_MSG_NEWKEYS
        client.connect().unwrap();

        // Server: Receive SSH_MSG_NEWKEYS
        // Server: Send SSH_MSG_EXT_INFO
        server.handle_key_exchange().unwrap();

        assert!(client.is_connected());
        assert!(server.is_connected());

        // Client receive SSH_MSG_EXT_INFO
        client.userauth_password(None, "test").unwrap();

        // Server: Receive service request?
        let mut message = server.get_message().unwrap();

        // Server: Send auth request?
        message.reply_default().unwrap();

        // Client: Receive auth request
        client.userauth_password(None, "test").unwrap();

        // Server: Receive Auth data (pw)
        let mut message = server.get_message().unwrap();

        /*printf("type: %d\n", ssh_message_type(message));
        printf("User %s wants to auth with pass %s\n",
               ssh_message_auth_user(message),
               ssh_message_auth_password(message));*/

        println!(
            "User {:?} wants to auth with pass {:?}",
            message.auth_user(),
            message.auth_password()
        );

        // Server: Send auth success
        message.auth_reply_success(0).unwrap();

        // Client: Receive auth success

        client.userauth_password(None, "test").unwrap();

        // Send close?
        client.disconnect();
        server.disconnect();
    }
}
