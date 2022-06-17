use libc::{c_int, c_long, c_void};
use once_cell::sync::Lazy;
use std::any::TypeId;
use std::collections::HashMap;
use std::marker::PhantomData;
use std::ptr;
use std::sync::{Mutex, Once};
use wolfssl_sys as wolf;

/// A slot in a type's "extra data" structure.
///
/// It is parameterized over the type containing the extra data as well as the
/// type of the data in the slot.
pub struct Index<T, U>(c_int, PhantomData<(T, U)>);

impl<T, U> Copy for Index<T, U> {}

impl<T, U> Clone for Index<T, U> {
    fn clone(&self) -> Index<T, U> {
        *self
    }
}

impl<T, U> Index<T, U> {
    /// Creates an `Index` from a raw integer index.
    ///
    /// # Safety
    ///
    /// The caller must ensure that the index correctly maps to a `U` value stored in a `T`.
    pub unsafe fn from_raw(idx: c_int) -> Index<T, U> {
        Index(idx, PhantomData)
    }

    #[allow(clippy::trivially_copy_pass_by_ref)]
    pub fn as_raw(&self) -> c_int {
        self.0
    }
}

pub unsafe fn get_new_ssl_idx(f: wolf::WOLFSSL_CRYPTO_EX_free) -> c_int {
    // hack around https://rt.openssl.org/Ticket/Display.html?id=3710&user=guest&pass=guest
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        wolf::wolfSSL_get_ex_new_index(0, ptr::null_mut(), None, None, None);
    });

    wolf::wolfSSL_get_ex_new_index(0, ptr::null_mut(), None, None, f)
}

pub static SSL_INDEXES: Lazy<Mutex<HashMap<TypeId, c_int>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

pub unsafe extern "C" fn free_data_box<T>(
    _parent: *mut c_void,
    ptr: *mut c_void,
    _ad: *mut wolf::WOLFSSL_CRYPTO_EX_DATA,
    _idx: c_int,
    _argl: c_long,
    _argp: *mut c_void,
) {
    if !ptr.is_null() {
        Box::<T>::from_raw(ptr as *mut T);
    }
}
