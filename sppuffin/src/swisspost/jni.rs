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
    "/home/binj/.m2/repository/org/apache/activemq/artemis-jakarta-client/2.44.0/artemis-jakarta-client-2.44.0.jar",
    "/home/binj/.m2/repository/org/apache/activemq/artemis-core-client/2.44.0/artemis-core-client-2.44.0.jar",
    "/home/binj/.m2/repository/org/apache/activemq/artemis-commons/2.44.0/artemis-commons-2.44.0.jar",
    "/home/binj/.m2/repository/org/apache/activemq/artemis-selector/2.44.0/artemis-selector-2.44.0.jar",
    "/home/binj/.m2/repository/commons-beanutils/commons-beanutils/1.11.0/commons-beanutils-1.11.0.jar",
    "/home/binj/.m2/repository/commons-collections/commons-collections/3.2.2/commons-collections-3.2.2.jar",
    "/home/binj/.m2/repository/commons-logging/commons-logging/1.3.6/commons-logging-1.3.6.jar",
    "/home/binj/.m2/repository/jakarta/jms/jakarta.jms-api/3.1.0/jakarta.jms-api-3.1.0.jar",
    "/home/binj/.m2/repository/io/netty/netty-common/4.1.127.Final/netty-common-4.1.127.Final.jar",
    "/home/binj/.m2/repository/io/netty/netty-buffer/4.1.127.Final/netty-buffer-4.1.127.Final.jar",
    "/home/binj/.m2/repository/io/netty/netty-codec-http/4.1.127.Final/netty-codec-http-4.1.127.Final.jar",
    "/home/binj/.m2/repository/io/netty/netty-codec-socks/4.1.127.Final/netty-codec-socks-4.1.127.Final.jar",
    "/home/binj/.m2/repository/io/netty/netty-transport/4.1.127.Final/netty-transport-4.1.127.Final.jar",
    "/home/binj/.m2/repository/io/netty/netty-resolver/4.1.127.Final/netty-resolver-4.1.127.Final.jar",
    "/home/binj/.m2/repository/io/netty/netty-codec/4.1.127.Final/netty-codec-4.1.127.Final.jar",
    "/home/binj/.m2/repository/io/netty/netty-handler/4.1.127.Final/netty-handler-4.1.127.Final.jar",
    "/home/binj/.m2/repository/io/netty/netty-handler-proxy/4.1.127.Final/netty-handler-proxy-4.1.127.Final.jar",
    "/home/binj/.m2/repository/io/netty/netty-transport-native-unix-common/4.1.127.Final/netty-transport-native-unix-common-4.1.127.Final.jar",
    "/home/binj/.m2/repository/org/jgroups/jgroups/5.3.13.Final/jgroups-5.3.13.Final.jar",
    "/home/binj/.m2/repository/org/slf4j/slf4j-api/2.0.17/slf4j-api-2.0.17.jar",
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
