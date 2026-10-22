use ::jni::objects::JString;
use ::jni::{Env, JValue};
use sppuffin::swisspost::jni::get_jvm;

#[test]
fn test_jni_connection() {
    let jvm = get_jvm().unwrap();
    jvm.attach_current_thread(|env: &mut Env| -> ::jni::errors::Result<()> {
        // Call a method with signature: String concat(String str)
        let hello = env.new_string("Hello ")?;
        let arg = env.new_string("world!")?;
        let result = env.call_method(
            hello,
            jni_macros::jni_str!("concat"),
            jni_macros::jni_sig!((str: JString) -> JString),
            &[JValue::Object(&arg)],
        )?;
        assert_eq!(
            "Hello world!",
            JString::cast_local(env, result.l()?)?.try_to_string(env)?
        );
        Ok(())
    })
    .unwrap();
}
