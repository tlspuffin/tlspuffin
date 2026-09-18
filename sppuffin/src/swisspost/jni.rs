use once_cell::sync::Lazy;
use std::sync::Mutex;

use jni::{JNIVersion, JavaVM};
use puffin::algebra::error::FnError;

// Concrete Global handle type for Java objects
static JVM: Lazy<Mutex<Option<JavaVM>>> = Lazy::new(|| {
    let jvm_args = jni::InitArgsBuilder::new()
        .version(JNIVersion::V1_8)
        .option(format!(
            "-Djava.class.path={}:{}:{}:{}:{}:{}:{}:{}:{}",
            "/home/binj/Documents/stageM2/e-voting/control-component/target/control-component-1.5.3.2.jar",
            "/home/binj/Documents/stageM2/crypto-primitives/target/crypto-primitives-1.5.2.1.jar",
            "/home/binj/.m2/repository/com/google/guava/guava/32.0.1-jre/guava-32.0.1-jre.jar",
            "/home/binj/.m2/repository/com/fasterxml/jackson/core/jackson-databind/2.20.0/jackson-databind-2.20.0.jar",
            "/home/binj/.m2/repository/com/fasterxml/jackson/core/jackson-databind/2.20.0/",
            "/home/binj/.m2/repository/com/fasterxml/jackson/core/jackson-core/2.20.0/",
            "/home/binj/.m2/repository/com/fasterxml/jackson/core/jackson-annotations/2.20.0/",
            "/home/binj/Documents/stageM2/tlspuffin/sppuffHin/jackson-databind-2.20.0.jar",
            "/home/binj/Documents/stageM2/tlspuffin/sppuffin/jackson-core-2.20.0.jar",
        ))
        .option("-Xcheck:jni")
        .build();
    match jvm_args {
        Ok(args) => match JavaVM::new(args) {
            Ok(jvm) => Mutex::new(Some(jvm)),
            Err(_) => Mutex::new(None),
        },
        Err(_) => Mutex::new(None),
    }
});

/// #Examples
/// ```
/// use sppuffin::swisspost::jni::get_jvm;
/// let jvm = get_jvm().unwrap();
/// ```
pub fn get_jvm() -> Result<JavaVM, FnError> {
    let guard = JVM.lock().unwrap();
    guard.as_ref().cloned().ok_or_else(|| {
        FnError::Malformed("JVM not initialized; set SPP_JAVA_CLASSPATH".to_string())
    })
}
