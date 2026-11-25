use std::env;

use jni::errors::Result as JniResult;
use jni::objects::{Global, JByteArray, JObject, JObjectArray, JString, JValue};
use jni::signature::RuntimeMethodSignature;
use jni_macros::jni_str;
use puffin::algebra::error::FnError;

use crate::swisspost::jni::get_jvm;

type JavaGlobal = Global<JObject<'static>>;

const DEFAULT_JMX_URL: &str = "service:jmx:rmi:///jndi/rmi://127.0.0.1:9010/jmxrmi";
const JACOCO_RUNTIME_MBEAN: &str = "org.jacoco:type=Runtime";

pub struct JacocoCoverageClient {
    connector: JavaGlobal,
    connection: JavaGlobal,
    runtime_mbean: JavaGlobal,
}

impl JacocoCoverageClient {
    pub fn from_env() -> Result<Self, FnError> {
        let url = env::var("SPP_JACOCO_JMX_URL").unwrap_or_else(|_| DEFAULT_JMX_URL.to_string());
        Self::connect(&url)
    }

    fn connect(url: &str) -> Result<Self, FnError> {
        let vm = get_jvm()?;
        let (connector, connection, runtime_mbean) = vm
            .attach_current_thread(|env| -> JniResult<(JavaGlobal, JavaGlobal, JavaGlobal)> {
                let url_class = env.find_class(jni_str!("javax/management/remote/JMXServiceURL"))?;
                let url_string = env.new_string(url)?;
                let url_object = JObject::from(url_string);
                let service_url = env.new_object(
                    url_class,
                    RuntimeMethodSignature::from_str("(Ljava/lang/String;)V")?
                        .method_signature(),
                    &[JValue::Object(&url_object)],
                )?;

                let factory_class =
                    env.find_class(jni_str!("javax/management/remote/JMXConnectorFactory"))?;
                let null_environment = JObject::null();
                let connector = env
                    .call_static_method(
                        factory_class,
                        jni_str!("connect"),
                        RuntimeMethodSignature::from_str(
                            "(Ljavax/management/remote/JMXServiceURL;Ljava/util/Map;)Ljavax/management/remote/JMXConnector;",
                        )?
                        .method_signature(),
                        &[
                            JValue::Object(&service_url),
                            JValue::Object(&null_environment),
                        ],
                    )?
                    .l()?;

                let connection = env
                    .call_method(
                        &connector,
                        jni_str!("getMBeanServerConnection"),
                        RuntimeMethodSignature::from_str(
                            "()Ljavax/management/MBeanServerConnection;",
                        )?
                        .method_signature(),
                        &[],
                    )?
                    .l()?;

                let object_name_class = env.find_class(jni_str!("javax/management/ObjectName"))?;
                let object_name_string = env.new_string(JACOCO_RUNTIME_MBEAN)?;
                let object_name_object = JObject::from(object_name_string);
                let runtime_mbean = env.new_object(
                    object_name_class,
                    RuntimeMethodSignature::from_str("(Ljava/lang/String;)V")?
                        .method_signature(),
                    &[JValue::Object(&object_name_object)],
                )?;

                Ok((
                    env.new_global_ref(connector)?,
                    env.new_global_ref(connection)?,
                    env.new_global_ref(runtime_mbean)?,
                ))
            })
            .map_err(|error| {
                FnError::Unknown(format!("failed to connect to JaCoCo JMX at {url}: {error}"))
            })?;

        Ok(Self {
            connector,
            connection,
            runtime_mbean,
        })
    }

    pub fn get_execution_data(&self, reset: bool) -> Result<Vec<u8>, FnError> {
        let vm = get_jvm()?;
        vm.attach_current_thread(|env| -> JniResult<Vec<u8>> {
            let boolean_class = env.find_class(jni_str!("java/lang/Boolean"))?;
            let reset_argument = env.new_object(
                boolean_class,
                RuntimeMethodSignature::from_str("(Z)V")?.method_signature(),
                &[JValue::Bool(reset)],
            )?;
            let arguments = JObjectArray::<JObject>::new(env, 1, &reset_argument)?;

            let boolean_type = env.new_string("boolean")?;
            let signature = JObjectArray::<JString>::new(env, 1, &boolean_type)?;

            let arguments_object = JObject::from(arguments);
            let signature_object = JObject::from(signature);
            let operation_name = env.new_string("getExecutionData")?;
            let operation_name_object = JObject::from(operation_name);
            let execution_data = env
                .call_method(
                    self.connection.as_obj(),
                    jni_str!("invoke"),
                    RuntimeMethodSignature::from_str(
                        "(Ljavax/management/ObjectName;Ljava/lang/String;[Ljava/lang/Object;[Ljava/lang/String;)Ljava/lang/Object;",
                    )?
                    .method_signature(),
                    &[
                        JValue::Object(self.runtime_mbean.as_obj()),
                        JValue::Object(&operation_name_object),
                        JValue::Object(&arguments_object),
                        JValue::Object(&signature_object),
                    ],
                )?
                .l()?;
            let byte_array = JByteArray::cast_local(env, execution_data)?;
            env.convert_byte_array(byte_array)
        })
        .map_err(|error| FnError::Unknown(format!("failed to retrieve JaCoCo execution data: {error}")))
    }

    pub fn close(&self) {
        if let Ok(vm) = get_jvm() {
            if let Err(error) = vm.attach_current_thread(|env| -> JniResult<()> {
                env.call_method(
                    self.connector.as_obj(),
                    jni_str!("close"),
                    RuntimeMethodSignature::from_str("()V")?.method_signature(),
                    &[],
                )?;
                Ok(())
            }) {
                log::warn!("Failed to close JaCoCo JMX connection: {error}");
            }
        }
    }
}
