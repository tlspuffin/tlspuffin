use std::{
    ffi::{c_char, c_void, CStr, CString},
    os::{raw::c_int, unix::io::RawFd},
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

    /// `ssh_options_set`
    pub fn set_options_str(&mut self, typ: SessionOption, value: &str) -> Result<(), String> {
        unsafe {
            let value = CString::new(value).map_err(|err| err.to_string())?;
            cvt_n(
                libssh_sys::ssh_options_set(
                    self.as_ptr(),
                    typ as ssh_options_e,
                    value.as_ptr() as *const c_void,
                ),
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

pub enum SessionOption {
    HOST = libssh_sys::ssh_options_e_SSH_OPTIONS_HOST as isize,
    PORT = libssh_sys::ssh_options_e_SSH_OPTIONS_PORT as isize,
    PORT_STR = libssh_sys::ssh_options_e_SSH_OPTIONS_PORT_STR as isize,
    FD = libssh_sys::ssh_options_e_SSH_OPTIONS_FD as isize,
    USER = libssh_sys::ssh_options_e_SSH_OPTIONS_USER as isize,
    SSH_DIR = libssh_sys::ssh_options_e_SSH_OPTIONS_SSH_DIR as isize,
    IDENTITY = libssh_sys::ssh_options_e_SSH_OPTIONS_IDENTITY as isize,
    ADD_IDENTITY = libssh_sys::ssh_options_e_SSH_OPTIONS_ADD_IDENTITY as isize,
    KNOWNHOSTS = libssh_sys::ssh_options_e_SSH_OPTIONS_KNOWNHOSTS as isize,
    TIMEOUT = libssh_sys::ssh_options_e_SSH_OPTIONS_TIMEOUT as isize,
    TIMEOUT_USEC = libssh_sys::ssh_options_e_SSH_OPTIONS_TIMEOUT_USEC as isize,
    SSH1 = libssh_sys::ssh_options_e_SSH_OPTIONS_SSH1 as isize,
    SSH2 = libssh_sys::ssh_options_e_SSH_OPTIONS_SSH2 as isize,
    LOG_VERBOSITY = libssh_sys::ssh_options_e_SSH_OPTIONS_LOG_VERBOSITY as isize,
    LOG_VERBOSITY_STR = libssh_sys::ssh_options_e_SSH_OPTIONS_LOG_VERBOSITY_STR as isize,
    CIPHERS_C_S = libssh_sys::ssh_options_e_SSH_OPTIONS_CIPHERS_C_S as isize,
    CIPHERS_S_C = libssh_sys::ssh_options_e_SSH_OPTIONS_CIPHERS_S_C as isize,
    COMPRESSION_C_S = libssh_sys::ssh_options_e_SSH_OPTIONS_COMPRESSION_C_S as isize,
    COMPRESSION_S_C = libssh_sys::ssh_options_e_SSH_OPTIONS_COMPRESSION_S_C as isize,
    PROXYCOMMAND = libssh_sys::ssh_options_e_SSH_OPTIONS_PROXYCOMMAND as isize,
    BINDADDR = libssh_sys::ssh_options_e_SSH_OPTIONS_BINDADDR as isize,
    STRICTHOSTKEYCHECK = libssh_sys::ssh_options_e_SSH_OPTIONS_STRICTHOSTKEYCHECK as isize,
    COMPRESSION = libssh_sys::ssh_options_e_SSH_OPTIONS_COMPRESSION as isize,
    COMPRESSION_LEVEL = libssh_sys::ssh_options_e_SSH_OPTIONS_COMPRESSION_LEVEL as isize,
    KEY_EXCHANGE = libssh_sys::ssh_options_e_SSH_OPTIONS_KEY_EXCHANGE as isize,
    HOSTKEYS = libssh_sys::ssh_options_e_SSH_OPTIONS_HOSTKEYS as isize,
    GSSAPI_SERVER_IDENTITY = libssh_sys::ssh_options_e_SSH_OPTIONS_GSSAPI_SERVER_IDENTITY as isize,
    GSSAPI_CLIENT_IDENTITY = libssh_sys::ssh_options_e_SSH_OPTIONS_GSSAPI_CLIENT_IDENTITY as isize,
    GSSAPI_DELEGATE_CREDENTIALS =
        libssh_sys::ssh_options_e_SSH_OPTIONS_GSSAPI_DELEGATE_CREDENTIALS as isize,
    HMAC_C_S = libssh_sys::ssh_options_e_SSH_OPTIONS_HMAC_C_S as isize,
    HMAC_S_C = libssh_sys::ssh_options_e_SSH_OPTIONS_HMAC_S_C as isize,
    PASSWORD_AUTH = libssh_sys::ssh_options_e_SSH_OPTIONS_PASSWORD_AUTH as isize,
    PUBKEY_AUTH = libssh_sys::ssh_options_e_SSH_OPTIONS_PUBKEY_AUTH as isize,
    KBDINT_AUTH = libssh_sys::ssh_options_e_SSH_OPTIONS_KBDINT_AUTH as isize,
    GSSAPI_AUTH = libssh_sys::ssh_options_e_SSH_OPTIONS_GSSAPI_AUTH as isize,
    GLOBAL_KNOWNHOSTS = libssh_sys::ssh_options_e_SSH_OPTIONS_GLOBAL_KNOWNHOSTS as isize,
    NODELAY = libssh_sys::ssh_options_e_SSH_OPTIONS_NODELAY as isize,
    PUBLICKEY_ACCEPTED_TYPES =
        libssh_sys::ssh_options_e_SSH_OPTIONS_PUBLICKEY_ACCEPTED_TYPES as isize,
    PROCESS_CONFIG = libssh_sys::ssh_options_e_SSH_OPTIONS_PROCESS_CONFIG as isize,
    REKEY_DATA = libssh_sys::ssh_options_e_SSH_OPTIONS_REKEY_DATA as isize,
    REKEY_TIME = libssh_sys::ssh_options_e_SSH_OPTIONS_REKEY_TIME as isize,
    RSA_MIN_SIZE = libssh_sys::ssh_options_e_SSH_OPTIONS_RSA_MIN_SIZE as isize,
    IDENTITY_AGENT = libssh_sys::ssh_options_e_SSH_OPTIONS_IDENTITY_AGENT as isize,
}

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
                    typ as ssh_options_e,
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
                libssh_sys::ssh_bind_options_set(
                    self.as_ptr(),
                    typ as ssh_options_e,
                    value as *const c_void,
                ),
                self,
            )
            .map(|_| ())
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

pub enum SshRequest {
    REQUEST_AUTH = libssh_sys::ssh_requests_e_SSH_REQUEST_AUTH as isize,
    REQUEST_CHANNEL_OPEN = libssh_sys::ssh_requests_e_SSH_REQUEST_CHANNEL_OPEN as isize,
    REQUEST_CHANNEL = libssh_sys::ssh_requests_e_SSH_REQUEST_CHANNEL as isize,
    REQUEST_SERVICE = libssh_sys::ssh_requests_e_SSH_REQUEST_SERVICE as isize,
    REQUEST_GLOBAL = libssh_sys::ssh_requests_e_SSH_REQUEST_GLOBAL as isize,
}

impl SshRequest {
    fn from_raw(value: u32) -> Option<Self> {
        match value {
            libssh_sys::ssh_requests_e_SSH_REQUEST_AUTH => Some(SshRequest::REQUEST_AUTH),
            libssh_sys::ssh_requests_e_SSH_REQUEST_CHANNEL_OPEN => {
                Some(SshRequest::REQUEST_CHANNEL_OPEN)
            }
            libssh_sys::ssh_requests_e_SSH_REQUEST_CHANNEL => Some(SshRequest::REQUEST_CHANNEL),
            libssh_sys::ssh_requests_e_SSH_REQUEST_SERVICE => Some(SshRequest::REQUEST_SERVICE),
            libssh_sys::ssh_requests_e_SSH_REQUEST_GLOBAL => Some(SshRequest::REQUEST_GLOBAL),
            _ => None,
        }
    }
}

pub enum SshBindOption {
    BINDADDR = libssh_sys::ssh_bind_options_e_SSH_BIND_OPTIONS_BINDADDR as isize,
    BINDPORT = libssh_sys::ssh_bind_options_e_SSH_BIND_OPTIONS_BINDPORT as isize,
    BINDPORT_STR = libssh_sys::ssh_bind_options_e_SSH_BIND_OPTIONS_BINDPORT_STR as isize,
    HOSTKEY = libssh_sys::ssh_bind_options_e_SSH_BIND_OPTIONS_HOSTKEY as isize,
    DSAKEY = libssh_sys::ssh_bind_options_e_SSH_BIND_OPTIONS_DSAKEY as isize,
    RSAKEY = libssh_sys::ssh_bind_options_e_SSH_BIND_OPTIONS_RSAKEY as isize,
    BANNER = libssh_sys::ssh_bind_options_e_SSH_BIND_OPTIONS_BANNER as isize,
    LOG_VERBOSITY = libssh_sys::ssh_bind_options_e_SSH_BIND_OPTIONS_LOG_VERBOSITY as isize,
    LOG_VERBOSITY_STR = libssh_sys::ssh_bind_options_e_SSH_BIND_OPTIONS_LOG_VERBOSITY_STR as isize,
    ECDSAKEY = libssh_sys::ssh_bind_options_e_SSH_BIND_OPTIONS_ECDSAKEY as isize,
    IMPORT_KEY = libssh_sys::ssh_bind_options_e_SSH_BIND_OPTIONS_IMPORT_KEY as isize,
    KEY_EXCHANGE = libssh_sys::ssh_bind_options_e_SSH_BIND_OPTIONS_KEY_EXCHANGE as isize,
    CIPHERS_C_S = libssh_sys::ssh_bind_options_e_SSH_BIND_OPTIONS_CIPHERS_C_S as isize,
    CIPHERS_S_C = libssh_sys::ssh_bind_options_e_SSH_BIND_OPTIONS_CIPHERS_S_C as isize,
    HMAC_C_S = libssh_sys::ssh_bind_options_e_SSH_BIND_OPTIONS_HMAC_C_S as isize,
    HMAC_S_C = libssh_sys::ssh_bind_options_e_SSH_BIND_OPTIONS_HMAC_S_C as isize,
    CONFIG_DIR = libssh_sys::ssh_bind_options_e_SSH_BIND_OPTIONS_CONFIG_DIR as isize,
    PUBKEY_ACCEPTED_KEY_TYPES =
        libssh_sys::ssh_bind_options_e_SSH_BIND_OPTIONS_PUBKEY_ACCEPTED_KEY_TYPES as isize,
    HOSTKEY_ALGORITHMS =
        libssh_sys::ssh_bind_options_e_SSH_BIND_OPTIONS_HOSTKEY_ALGORITHMS as isize,
    PROCESS_CONFIG = libssh_sys::ssh_bind_options_e_SSH_BIND_OPTIONS_PROCESS_CONFIG as isize,
    MODULI = libssh_sys::ssh_bind_options_e_SSH_BIND_OPTIONS_MODULI as isize,
    RSA_MIN_SIZE = libssh_sys::ssh_bind_options_e_SSH_BIND_OPTIONS_RSA_MIN_SIZE as isize,
}

foreign_type! {
    pub unsafe type SshMessage: Sync + Send {
        type CType = libssh_sys::ssh_message_struct;
        fn drop = libssh_sys::ssh_message_free;
    }
}

impl SshMessage {}
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
            Ok(SshRequest::from_raw(
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
    use std::os::unix::{
        io::IntoRawFd,
        net::{SocketAddr, UnixListener, UnixStream},
    };

    use crate::libssh::ssh::{set_log_level, SessionOption, SshBind, SshBindOption, SshSession};

    #[test]
    fn test_only_server() {
        set_log_level(100);

        let addr = SocketAddr::from_abstract_namespace(b"\0socket").unwrap();
        let listener = UnixListener::bind_addr(&addr).unwrap();
        listener.set_nonblocking(true).unwrap();

        let mut client_stream = UnixStream::connect_addr(&addr).unwrap();
        client_stream.set_nonblocking(true).unwrap();
        let server_stream = listener.incoming().next().unwrap().unwrap();

        // ---- Initialize client session

        let mut client = SshSession::new().unwrap();
        client.set_blocking(false);
        client
            .set_options_str(SessionOption::HOST, "dummy")
            .unwrap();
        client
            .set_options_int(SessionOption::FD, client_stream.into_raw_fd())
            .unwrap();
        client
            .set_options_int(SessionOption::PROCESS_CONFIG, 0)
            .unwrap();

        // Initialize
        client.connect().unwrap();
        //server.handle_key_exchange().unwrap();

        assert!(client.is_connected());

        // Starting handshake

        // Server: Send SSH_MSG_KEXINIT
        //server.handle_key_exchange().unwrap();
    }

    #[test]
    fn test() {
        set_log_level(100);

        let addr = SocketAddr::from_abstract_namespace(b"\0socket").unwrap();
        let listener = UnixListener::bind_addr(&addr).unwrap();
        listener.set_nonblocking(true).unwrap();

        let mut client_stream = UnixStream::connect_addr(&addr).unwrap();
        client_stream.set_nonblocking(true).unwrap();
        let server_stream = listener.incoming().next().unwrap().unwrap();

        let mut server = SshSession::new().unwrap();
        server.set_blocking(false);
        server
            .set_options_int(SessionOption::PROCESS_CONFIG, 0)
            .unwrap();

        let mut bind = SshBind::new().unwrap();

        bind.set_options_str(
            SshBindOption::RSAKEY,
            "/home/max/projects/tlspuffin/ssh_host_rsa_key",
        )
        .unwrap();
        bind.set_blocking(false);

        bind.accept_fd(&server, server_stream.into_raw_fd())
            .unwrap();

        // ---- Initialize client session

        let mut client = SshSession::new().unwrap();
        client.set_blocking(false);
        client
            .set_options_str(SessionOption::HOST, "dummy")
            .unwrap();
        client
            .set_options_int(SessionOption::FD, client_stream.into_raw_fd())
            .unwrap();
        client
            .set_options_int(SessionOption::PROCESS_CONFIG, 0)
            .unwrap();

        // ------

        assert!(!client.is_connected());
        assert!(!server.is_connected());

        // Initialize
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
