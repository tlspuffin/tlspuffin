use once_cell::sync::Lazy;
use std::sync::Mutex;

use jni::errors::Result as JniResult;
use jni::objects::{Global, JByteArray, JObject, JString, JValue};
use jni::{JNIVersion, JavaVM};
use jni_macros::{jni_sig, jni_str};
use puffin::algebra::error::FnError;

use crate::protocol::SppU64;

// Manual serde impls rely on JNI helpers in crate::fn_impl
use serde::de::Deserializer;
use serde::ser::Serializer;
use serde::{Deserialize, Serialize};
use puffin::codec::encode_vec_u16;
use puffin::error::Error as PuffinError;
use puffin::trace::Knowledge;
use puffin::trace::Source;
// Concrete Global handle type for Java objects
type JavaGlobal = jni::objects::Global<jni::objects::JObject<'static>>;

static JVM: Lazy<Mutex<Option<JavaVM>>> = Lazy::new(|| {
    let jvm_args = jni::InitArgsBuilder::new()
        .version(JNIVersion::V1_8)
        .option(format!(
            "-Djava.class.path={}:{}:{}:{}:{}:{}",
            "/home/binj/Documents/stageM2/e-voting/control-component/target/control-component-1.5.3.2.jar",
            "/home/binj/Documents/stageM2/crypto-primitives/target/crypto-primitives-1.5.2.1.jar",
            "/home/binj/.m2/repository/com/google/guava/guava/32.0.1-jre/guava-32.0.1-jre.jar",
            "/home/binj/.m2/repository/com/fasterxml/jackson/core/jackson-databind/2.20.0/jackson-databind-2.20.0.jar",
            "/home/binj/.m2/repository/com/fasterxml/jackson/core/jackson-core/2.20.0/jackson-core-2.20.0.jar",
            "/home/binj/.m2/repository/com/fasterxml/jackson/core/jackson-annotations/2.20.0/jackson-annotations-2.20.0.jar",
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

fn java_class() -> &'static str {
    "ch/post/it/evoting/cryptoprimitives/collection/ImmutableByteArray"
}

fn get_jvm() -> Result<JavaVM, FnError> {
    let guard = JVM.lock().unwrap();
    guard.as_ref().cloned().ok_or_else(|| {
        FnError::Malformed("JVM not initialized; set SPP_JAVA_CLASSPATH".to_string())
    })
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SwissProtocolTypes;

// A thin Rust handle for the Java ImmutableByteArray. The actual bytes live in Java; Rust
// only keeps a global reference to the Java object. Serialization/deserialization and
// byte access are implemented via the JNI helpers in crate::fn_impl.
#[derive(Debug)]
pub struct ImmutableByteArray(pub Global<JObject<'static>>);

impl Clone for ImmutableByteArray {
    fn clone(&self) -> Self {
        match crate::fn_impl::duplicate_global(&self.0) {
            Ok(g) => ImmutableByteArray(g),
            Err(e) => panic!("Failed to clone ImmutableByteArray JNI global ref: {}", e),
        }
    }
}
use std::result::Result;

impl puffin::codec::Codec for ImmutableByteArray {
    fn encode(&self, bytes: &mut Vec<u8>) {
        let vm = get_jvm().unwrap();

        if let Err(e) = vm.attach_current_thread(
            |env: &mut jni::Env| -> Result<(), Box<dyn std::error::Error>> {
                let mapper_class_opt =
                    env.find_class(jni_str!("com/fasterxml/jackson/databind/ObjectMapper"));

                let mapper_class = match mapper_class_opt {
                    Ok(class) => class,
                    Err(e) => {
                        if env.exception_check() {
                            env.exception_describe();
                            env.exception_clear();
                        }
                        return Err(Box::new(e));

                    }
                };

                let mapper = env.new_object(mapper_class, jni_sig!(()), &[])?;

                let java_serialized = env.call_method(
                    &mapper,
                    jni_str!("writeValueAsString"),
                    jni_sig!((obj: JObject) -> JString),
                    &[JValue::Object(self.0.as_obj())],
                )?;

                let jstr_obj = java_serialized.l()?;
                let jstr = JString::cast_local(env, jstr_obj)?;

                let rust_str: String = jstr.to_string();

                bytes.extend_from_slice(rust_str.as_bytes());
                bytes.extend_from_slice(b"Agauog");

                Ok(())
            },
        ) {
            log::error!(
                "Failed to encode ImmutableByteArray with Jackson ObjectMapper: {}",
                e
            );
        }

        // bytes.extend("uaeitnrasetnr".bytes());
        // if let Ok(v) = crate::fn_impl::global_elements(&self.0) {
        // <Vec<u8> as puffin::codec::Codec>::encode(&v, bytes);
        // }
    }

    fn read(r: &mut puffin::codec::Reader) -> Option<Self> {
        let v = <Vec<u8> as puffin::codec::Codec>::read(r)?;
        match crate::fn_impl::create_global_from_bytes(&v) {
            Ok(g) => Some(ImmutableByteArray(g)),
            Err(_) => None,
        }
    }
}

impl puffin::protocol::Extractable<SwissProtocolTypes> for ImmutableByteArray {
    fn extract_knowledge<'a>(
        &'a self,
        knowledges: &mut Vec<Knowledge<'a, SwissProtocolTypes>>,
        _matcher: Option<<SwissProtocolTypes as ProtocolTypes>::Matcher>,
        source: &'a Source,
    ) -> Result<(), PuffinError> {
        knowledges.push(Knowledge {
            source,
            matcher: None,
            data: self,
        });
        Ok(())
    }
}

use puffin::protocol::{EvaluatedTerm, ProtocolTypes};

// Implement CompareKnowledge manually by comparing Java-side elements
impl puffin::protocol::CompareKnowledge<SwissProtocolTypes> for ImmutableByteArray {
    fn find_differences(
        &self,
        other: &dyn puffin::protocol::EvaluatedTerm<SwissProtocolTypes>,
        diffs: &mut Vec<puffin::differential::TraceDifference>,
        knowledge_num: usize,
        self_source: &Source,
        other_source: &Source,
    ) {
        if let Some(other_cast) = other.as_any().downcast_ref::<ImmutableByteArray>() {
            match (
                crate::fn_impl::global_elements(&self.0),
                crate::fn_impl::global_elements(&other_cast.0),
            ) {
                (Ok(a), Ok(b)) => {
                    if a != b {
                        diffs.push(puffin::differential::TraceDifference::Knowledges(
                            puffin::differential::KnowledgeDiff::InnerDifference {
                                index: knowledge_num,
                                type_name: other.type_name().into(),
                                diff: format!("{:?} != {:?}", a, b),
                                source: self_source.to_owned(),
                            },
                        ));
                    }
                }
                _ => {
                    diffs.push(puffin::differential::TraceDifference::Knowledges(
                        puffin::differential::KnowledgeDiff::DifferentTypes {
                            index: knowledge_num,
                            first_type: self.type_name().into(),
                            second_type: other.type_name().into(),
                            first_source: self_source.to_owned(),
                            second_source: other_source.to_owned(),
                        },
                    ));
                }
            }
        } else {
            diffs.push(puffin::differential::TraceDifference::Knowledges(
                puffin::differential::KnowledgeDiff::DifferentTypes {
                    index: knowledge_num,
                    first_type: std::any::type_name::<Self>().into(),
                    second_type: other.type_name().into(),
                    first_source: self_source.to_owned(),
                    second_source: other_source.to_owned(),
                },
            ));
        }
    }
}

pub fn create_global_from_bytes(bytes: &[u8]) -> Result<JavaGlobal, FnError> {
    let vm = get_jvm()?;
    vm.attach_current_thread(|env| -> JniResult<JavaGlobal> {
        // find the class and call ctor(byte[])
        let class_name = jni::strings::JNIString::new(java_class());
        let class = env.find_class(class_name)?;

        // constructor signature as RuntimeMethodSignature
        let ctor_binding = jni::signature::RuntimeMethodSignature::from_str("([B)V")?;
        let ctor_sig = ctor_binding.method_signature();
        let jarr = env.byte_array_from_slice(bytes)?;
        // pass the byte[] as an Object argument (borrowed JObject reference)
        let jarr_obj = JObject::from(jarr);
        let local = env.new_object(class, ctor_sig, &[JValue::Object(&jarr_obj)])?;
        let global_ref = env.new_global_ref(local)?;
        Ok(global_ref)
    })
    .map_err(|e| FnError::Unknown(e.to_string()))
}

pub fn global_elements(gref: &JavaGlobal) -> Result<Vec<u8>, FnError> {
    let vm = get_jvm()?;
    vm.attach_current_thread(|env| -> JniResult<Vec<u8>> {
        let name = jni::strings::JNIString::new("elements");
        let sig_binding = jni::signature::RuntimeMethodSignature::from_str("()[B")?;
        let sig = sig_binding.method_signature();
        let v = env.call_method(gref.as_obj(), name, sig, &[])?;
        let jarr_obj = v.l()?;
        // Wrap raw into a JByteArray
        let raw = jarr_obj.into_raw() as jni::sys::jarray;
        let ba = unsafe { JByteArray::from_raw(env, raw) };
        env.convert_byte_array(ba)
    })
    .map_err(|e| FnError::Unknown(e.to_string()))
}

pub fn global_length(gref: &JavaGlobal) -> Result<i32, FnError> {
    let vm = get_jvm()?;
    vm.attach_current_thread(|env| -> JniResult<i32> {
        let name = jni::strings::JNIString::new("length");
        let sig_binding = jni::signature::RuntimeMethodSignature::from_str("()I")?;
        let sig = sig_binding.method_signature();
        let v = env.call_method(gref.as_obj(), name, sig, &[])?;
        Ok(v.i()?)
    })
    .map_err(|e| FnError::Unknown(e.to_string()))
}

pub fn global_to_string(gref: &JavaGlobal) -> Result<String, FnError> {
    let vm = get_jvm()?;
    vm.attach_current_thread(|env| -> JniResult<String> {
        let name = jni::strings::JNIString::new("toString");
        let sig_binding = jni::signature::RuntimeMethodSignature::from_str("()Ljava/lang/String;")?;
        let sig = sig_binding.method_signature();
        let v = env.call_method(gref.as_obj(), name, sig, &[])?;
        let jstr_obj = v.l()?;
        let raw = jstr_obj.into_raw() as jni::sys::jstring;
        let jstr = unsafe { jni::objects::JString::from_raw(env, raw) };
        let s = jstr.try_to_string(env)?;
        Ok(s)
    })
    .map_err(|e| FnError::Unknown(e.to_string()))
}

// Serde helpers used by protocol::ImmutableByteArray

pub fn serialize_immutable_byte_array<S>(
    _imba: &crate::fn_impl::ImmutableByteArray,
    _serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    // Not used anymore; protocol implements Serialize directly
    unreachable!("serde helper not used")
}

pub fn deserialize_immutable_byte_array<'de, D>(
    _deserializer: D,
) -> Result<crate::fn_impl::ImmutableByteArray, D::Error>
where
    D: Deserializer<'de>,
{
    unreachable!("serde helper not used")
}

// Duplicate a global reference (helper used for Clone semantics)
pub fn duplicate_global(g: &JavaGlobal) -> Result<JavaGlobal, FnError> {
    let vm = get_jvm()?;
    vm.attach_current_thread(|env| -> JniResult<JavaGlobal> {
        // new_global_ref accepts a local object or existing global as JObject
        let local = g.as_obj();
        let newg = env.new_global_ref(local)?;
        Ok(newg)
    })
    .map_err(|e| FnError::Unknown(e.to_string()))
}

// Exposed functions used in the signature
pub fn fn_new_immutable_byte_array() -> Result<ImmutableByteArray, FnError> {
    println!("NEW");
    let a = [
        1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
        1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
        1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
        1, 1, 1, 1, 1, 1, 1,
    ];
    let array = create_global_from_bytes(&a).map(ImmutableByteArray);
    println!("NEWFINI");
    array
}

pub fn fn_immutable_byte_array_length(a: &ImmutableByteArray) -> Result<SppU64, FnError> {
    println!("LENGTH");
    global_length(&a.0).map(|l| SppU64(l as u64))
}
