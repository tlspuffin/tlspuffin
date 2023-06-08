use std::{
    any::{Any, TypeId},
    cell::{Ref, RefCell, RefMut},
    collections::HashMap,
    ffi::c_void,
    ops::Deref,
};

use foreign_types::ForeignTypeRef;
use libc::{c_int, c_ulong};
use wolfssl_sys as wolf;

use crate::ssl::{SslContextRef, SslRef};

///
/// We need to manually use this because the `wolfSSL_CRYPTO_get_ex_new_index` funcationality does
/// not support freeing data
pub struct ExtraUserDataRegistry {
    user_data: RefCell<HashMap<TypeId, UserData>>,
}

impl ExtraUserDataRegistry {
    pub fn new() -> Self {
        Self {
            user_data: Default::default(),
        }
    }

    pub fn get_mut<T: 'static>(&self) -> Option<RefMut<'_, T>> {
        let user_data = self.user_data.borrow_mut();
        let key = TypeId::of::<T>();

        if !user_data.contains_key(&key) {
            return None;
        }

        // TODO use filter_map
        Some(RefMut::map(
            user_data,
            |user_data: &mut HashMap<TypeId, UserData>| {
                let option = user_data
                    .get_mut(&key)
                    .and_then(|data| data.data.downcast_mut::<T>())
                    .unwrap();
                option
            },
        ))
    }

    pub fn get<T: 'static>(&self) -> Option<Ref<'_, T>> {
        let user_data = self.user_data.borrow();
        let key = TypeId::of::<T>();

        if !user_data.contains_key(&key) {
            return None;
        }

        // TODO use filter_map
        Some(Ref::map(
            user_data,
            |user_data: &HashMap<TypeId, UserData>| {
                let option = user_data
                    .get(&key)
                    .and_then(|data| data.data.downcast_ref::<T>())
                    .unwrap();
                option
            },
        ))
    }

    pub fn set<T: 'static>(&self, value: T) {
        self.user_data.borrow_mut().insert(
            TypeId::of::<T>(),
            UserData {
                data: Box::new(value),
            },
        );
    }
}

pub struct UserData {
    data: Box<dyn Any>,
}

pub unsafe extern "C" fn ctx_msg_callback<F>(
    write_p: c_int,
    _version: c_int,
    content_type: c_int,
    buf: *const c_void,
    len: c_ulong,
    ssl: *mut wolf::WOLFSSL,
    _arg: *mut c_void,
) where
    F: Fn(&mut SslRef, i32, u8, bool) + 'static,
{
    let ctx = SslContextRef::from_ptr_mut(wolf::wolfSSL_get_SSL_CTX(ssl));

    let callback = {
        let callback = ctx
            .get_user_data::<F>()
            .expect("BUG: missing ssl_msg_callback");

        callback.deref() as *const F
    };

    let ssl = SslRef::from_ptr_mut(ssl);

    (*callback)(
        ssl,
        content_type,
        if len > 0 { *(buf as *mut u8) } else { 0 },
        write_p == 1,
    );
}

pub unsafe extern "C" fn ssl_msg_callback<F>(
    write_p: c_int,
    _version: c_int,
    content_type: c_int,
    buf: *const c_void,
    len: c_ulong,
    ssl: *mut wolf::WOLFSSL,
    _arg: *mut c_void,
) where
    F: Fn(&mut SslRef, i32, u8, bool) + 'static,
{
    let ssl = SslRef::from_ptr_mut(ssl);

    let callback = {
        let callback = ssl
            .get_user_data::<F>()
            .expect("BUG: missing ssl_msg_callback");

        callback.deref() as *const F
    };

    (*callback)(
        ssl,
        content_type,
        if len > 0 { *(buf as *mut u8) } else { 0 },
        write_p == 1,
    );
}
