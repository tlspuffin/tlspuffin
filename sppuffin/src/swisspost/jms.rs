use std::env;
use std::time::{SystemTime, UNIX_EPOCH};

use jni::errors::Result as JniResult;
use jni::objects::{Global, JObject, JValue};
use jni::signature::RuntimeMethodSignature;
use jni_macros::{jni_sig, jni_str};
use puffin::algebra::error::FnError;

use crate::swisspost::jni::get_jvm;

type JavaGlobal = Global<JObject<'static>>;

#[derive(Clone, Debug)]
pub struct JmsConfig {
    pub broker_url: String,
    pub destination: String,
    pub username: String,
    pub password: String,
    pub message_type: String,
    pub tenant_id: String,
    pub correlation_id: String,
    pub node_id: Option<String>,
    pub duplicate_detection_header: String,
    pub pub_sub_domain: bool,
}

impl JmsConfig {
    pub fn from_env() -> Self {
        Self {
            broker_url: env::var("SPP_JMS_BROKER_URL")
                .unwrap_or_else(|_| "tcp://127.0.0.1:61616".to_string()),
            destination: env::var("SPP_JMS_DESTINATION")
                .unwrap_or_else(|_| "control-components::control-component-1".to_string()),
            username: env::var("SPP_JMS_USERNAME").unwrap_or_else(|_| "artemis".to_string()),
            password: env::var("SPP_JMS_PASSWORD").unwrap_or_else(|_| "artemis".to_string()),
            message_type: env::var("SPP_JMS_MESSAGE_TYPE")
                .unwrap_or_else(|_| "ch.post.it.evoting.sppuffin.FuzzedPayload".to_string()),
            tenant_id: env::var("SPP_JMS_TENANT_ID").unwrap_or_else(|_| "test".to_string()),
            correlation_id: env::var("SPP_JMS_CORRELATION_ID")
                .unwrap_or_else(|_| "sppuffin".to_string()),
            node_id: env::var("SPP_JMS_NODE_ID").ok(),
            duplicate_detection_header: env::var("SPP_JMS_DUPLICATE_DETECTION_HEADER")
                .unwrap_or_else(|_| "_AMQ_DUPL_ID".to_string()),
            pub_sub_domain: env::var("SPP_JMS_PUB_SUB_DOMAIN")
                .map(|value| matches!(value.as_str(), "1" | "true" | "TRUE" | "yes" | "YES"))
                .unwrap_or(false),
        }
    }
}

pub struct JmsProducer {
    connection: JavaGlobal,
    session: JavaGlobal,
    producer: JavaGlobal,
    config: JmsConfig,
    send_count: u64,
}

impl JmsProducer {
    pub fn connect(config: JmsConfig) -> Result<Self, FnError> {
        let vm = get_jvm()?;
        let (connection, session, producer) = vm
            .attach_current_thread(|env| -> JniResult<(JavaGlobal, JavaGlobal, JavaGlobal)> {
                let factory_class = env.find_class(jni_str!(
                    "org/apache/activemq/artemis/jms/client/ActiveMQConnectionFactory"
                ))?;

                let broker_url = env.new_string(&config.broker_url)?;
                let broker_url_obj = JObject::from(broker_url);
                let factory_constructor_sig =
                    RuntimeMethodSignature::from_str("(Ljava/lang/String;)V")?;
                let factory = env.new_object(
                    factory_class,
                    factory_constructor_sig.method_signature(),
                    &[JValue::Object(&broker_url_obj)],
                )?;

                let username = env.new_string(&config.username)?;
                let password = env.new_string(&config.password)?;
                let username_obj = JObject::from(username);
                let password_obj = JObject::from(password);
                let create_connection_sig = RuntimeMethodSignature::from_str(
                    "(Ljava/lang/String;Ljava/lang/String;)Ljakarta/jms/Connection;",
                )?;
                let connection = env
                    .call_method(
                        &factory,
                        jni_str!("createConnection"),
                        create_connection_sig.method_signature(),
                        &[JValue::Object(&username_obj), JValue::Object(&password_obj)],
                    )?
                    .l()?;

                let create_session_sig =
                    RuntimeMethodSignature::from_str("(ZI)Ljakarta/jms/Session;")?;
                let session = env
                    .call_method(
                        &connection,
                        jni_str!("createSession"),
                        create_session_sig.method_signature(),
                        &[JValue::Bool(false), JValue::Int(1)],
                    )?
                    .l()?;

                let destination_name = env.new_string(&config.destination)?;
                let destination_name_obj = JObject::from(destination_name);
                let destination_method = if config.pub_sub_domain {
                    jni_str!("createTopic")
                } else {
                    jni_str!("createQueue")
                };
                let destination_sig = RuntimeMethodSignature::from_str(if config.pub_sub_domain {
                    "(Ljava/lang/String;)Ljakarta/jms/Topic;"
                } else {
                    "(Ljava/lang/String;)Ljakarta/jms/Queue;"
                })?;
                let destination = env
                    .call_method(
                        &session,
                        destination_method,
                        destination_sig.method_signature(),
                        &[JValue::Object(&destination_name_obj)],
                    )?
                    .l()?;

                let create_producer_sig = RuntimeMethodSignature::from_str(
                    "(Ljakarta/jms/Destination;)Ljakarta/jms/MessageProducer;",
                )?;
                let producer = env
                    .call_method(
                        &session,
                        jni_str!("createProducer"),
                        create_producer_sig.method_signature(),
                        &[JValue::Object(&destination)],
                    )?
                    .l()?;

                env.call_method(&connection, jni_str!("start"), jni_sig!(()), &[])?;

                Ok((
                    env.new_global_ref(connection)?,
                    env.new_global_ref(session)?,
                    env.new_global_ref(producer)?,
                ))
            })
            .map_err(|e| FnError::Unknown(format!("failed to connect to JMS broker: {e}")))?;

        Ok(Self {
            connection,
            session,
            producer,
            config,
            send_count: 0,
        })
    }

    pub fn send_bytes(&mut self, payload: &[u8]) -> Result<(), FnError> {
        let duplicate_id = self.next_duplicate_detection_id();
        let vm = get_jvm()?;
        vm.attach_current_thread(|env| -> JniResult<()> {
            let create_message_sig =
                RuntimeMethodSignature::from_str("()Ljakarta/jms/BytesMessage;")?;
            let message = env
                .call_method(
                    self.session.as_obj(),
                    jni_str!("createBytesMessage"),
                    create_message_sig.method_signature(),
                    &[],
                )?
                .l()?;

            let body = env.byte_array_from_slice(payload)?;
            let body_obj = JObject::from(body);
            let write_bytes_sig = RuntimeMethodSignature::from_str("([B)V")?;
            env.call_method(
                &message,
                jni_str!("writeBytes"),
                write_bytes_sig.method_signature(),
                &[JValue::Object(&body_obj)],
            )?;

            self.set_jms_correlation_id(env, &message)?;
            self.set_string_property(env, &message, "message_type", &self.config.message_type)?;
            self.set_string_property(env, &message, "tenantId", &self.config.tenant_id)?;
            self.set_string_property(
                env,
                &message,
                &self.config.duplicate_detection_header,
                &duplicate_id,
            )?;
            if let Some(node_id) = &self.config.node_id {
                self.set_string_property(env, &message, "nodeId", node_id)?;
            }

            env.call_method(
                self.producer.as_obj(),
                jni_str!("send"),
                RuntimeMethodSignature::from_str("(Ljakarta/jms/Message;)V")?.method_signature(),
                &[JValue::Object(&message)],
            )?;

            Ok(())
        })
        .map_err(|e| FnError::Unknown(format!("failed to send JMS message: {e}")))
    }

    pub fn close(&self) {
        if let Ok(vm) = get_jvm() {
            if let Err(e) = vm.attach_current_thread(|env| -> JniResult<()> {
                let _ =
                    env.call_method(self.producer.as_obj(), jni_str!("close"), jni_sig!(()), &[]);
                let _ =
                    env.call_method(self.session.as_obj(), jni_str!("close"), jni_sig!(()), &[]);
                let _ = env.call_method(
                    self.connection.as_obj(),
                    jni_str!("close"),
                    jni_sig!(()),
                    &[],
                );
                Ok(())
            }) {
                log::warn!("Failed to close JMS producer cleanly: {e}");
            }
        }
    }

    fn next_duplicate_detection_id(&mut self) -> String {
        self.send_count += 1;
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_nanos())
            .unwrap_or_default();
        format!("sppuffin-{nanos}-{}", self.send_count)
    }

    fn set_jms_correlation_id(&self, env: &mut jni::Env, message: &JObject) -> JniResult<()> {
        let correlation_id = env.new_string(&self.config.correlation_id)?;
        let correlation_id_obj = JObject::from(correlation_id);
        env.call_method(
            message,
            jni_str!("setJMSCorrelationID"),
            RuntimeMethodSignature::from_str("(Ljava/lang/String;)V")?.method_signature(),
            &[JValue::Object(&correlation_id_obj)],
        )?;
        Ok(())
    }

    fn set_string_property(
        &self,
        env: &mut jni::Env,
        message: &JObject,
        name: &str,
        value: &str,
    ) -> JniResult<()> {
        let name = env.new_string(name)?;
        let value = env.new_string(value)?;
        let name_obj = JObject::from(name);
        let value_obj = JObject::from(value);
        env.call_method(
            message,
            jni_str!("setStringProperty"),
            RuntimeMethodSignature::from_str("(Ljava/lang/String;Ljava/lang/String;)V")?
                .method_signature(),
            &[JValue::Object(&name_obj), JValue::Object(&value_obj)],
        )?;
        Ok(())
    }
}
