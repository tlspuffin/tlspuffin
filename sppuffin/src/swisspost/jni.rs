use once_cell::sync::Lazy;
use std::env;
use std::path::Path;
use std::sync::Mutex;

use jni::{JNIVersion, JavaVM};
use puffin::algebra::error::FnError;

const DEFAULT_CLASSPATH_ENTRIES: &[&str] = &[
    "/home/binj/Documents/stageM2/e-voting/control-component/target/control-component-1.5.3.2.jar",
    "/home/binj/Documents/stageM2/crypto-primitives/target/crypto-primitives-1.5.2.1.jar",
    "/home/binj/.m2/repository/com/google/guava/guava/32.0.1-jre/guava-32.0.1-jre.jar",
    "/home/binj/.m2/repository/com/fasterxml/jackson/core/jackson-databind/2.20.0/jackson-databind-2.20.0.jar",
    "/home/binj/.m2/repository/com/fasterxml/jackson/core/jackson-core/2.20.0/jackson-core-2.20.0.jar",
    "/home/binj/.m2/repository/com/fasterxml/jackson/core/jackson-annotations/2.20/jackson-annotations-2.20.jar",
];

fn java_classpath() -> String {
    env::var("SPP_JAVA_CLASSPATH").unwrap_or_else(|_| DEFAULT_CLASSPATH_ENTRIES.join(":"))
}

// Concrete Global handle type for Java objects
static JVM: Lazy<Mutex<Result<JavaVM, String>>> = Lazy::new(|| {
    let classpath = java_classpath();
    for entry in classpath.split(':').filter(|entry| !entry.is_empty()) {
        if !Path::new(entry).exists() {
            log::warn!("Java classpath entry does not exist: {}", entry);
        }
    }

    let jvm_args = jni::InitArgsBuilder::new()
        .version(JNIVersion::V1_8)
        .option(format!("-Djava.class.path={classpath}"))
        .option("-Xcheck:jni")
        .build();
    Mutex::new(
        jvm_args
            .map_err(|e| format!("failed to build JVM init args: {e}"))
            .and_then(|args| JavaVM::new(args).map_err(|e| format!("failed to create JVM: {e}"))),
    )
});

/// The get_jvm() function gives the jni::JavaVM. The JVM is lazylly initialized on the first call,
/// so the first call can be subtsantially longer.
/// It is thread safe.
/// For now the jvm parameters are hardcoded TODO: change that
///
/// #Examples
/// ```
/// use sppuffin::swisspost::jni::get_jvm;
/// let jvm = get_jvm().unwrap();
/// jvm.attach_current_thread(|env: &mut jni::Env| -> jni::errors::Result<()> {
/// // Call a method with signature: String concat(String str)
///     let hello = env.new_string("Hello")?;
///     let arg = env.new_string("world")?;
///     let result = env.call_method(
///         hello,
///         jni_macros::jni_str!("concat"),
///         jni_macros::jni_sig!((str: JString) -> JString),
///         &[jni::JValue::Object(&arg)],
///     )?;
///     Ok(())
/// });
/// ```
pub fn get_jvm() -> Result<JavaVM, FnError> {
    let guard = JVM.lock().unwrap();
    guard.as_ref().cloned().map_err(|e| {
        FnError::Malformed(format!(
            "JVM not initialized: {e}. Set SPP_JAVA_CLASSPATH to override the Java classpath."
        ))
    })
}
