use jni::errors::Result as JniResult;
use jni::objects::{Global, JByteArray, JObject, JObjectArray, JString, JValue};
use jni_macros::{jni_sig, jni_str};
use puffin::algebra::error::FnError;

use crate::protocol::SppU64;

// Manual serde impls rely on JNI helpers in crate::swisspost
use puffin::error::Error as PuffinError;
use puffin::trace::Knowledge;
use puffin::trace::Source;
use serde::de::Deserializer;
use serde::ser::Serializer;
use serde::{Deserialize, Serialize};
// Concrete Global handle type for Java objects
type JavaGlobal = jni::objects::Global<jni::objects::JObject<'static>>;

use crate::swisspost::jni::get_jvm;

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SwissProtocolTypes;

// A thin Rust handle for the Java ImmutableByteArray. The actual bytes live in Java; Rust
// only keeps a global reference to the Java object. Serialization/deserialization and
// byte access are implemented via the JNI helpers in crate::swisspost.
#[derive(Debug)]
pub struct ImmutableByteArray(pub Global<JObject<'static>>);

impl ImmutableByteArray {
    const JAVA_CLASS: &str = "ch/post/it/evoting/cryptoprimitives/collection/ImmutableByteArray";
    fn new(bytes: &[u8]) -> Result<ImmutableByteArray, FnError> {
        let vm = get_jvm()?;
        vm.attach_current_thread(|env| -> JniResult<JavaGlobal> {
            // find the class and call ctor(byte[])
            let class_name = jni::strings::JNIString::new(Self::JAVA_CLASS);
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
        .map(ImmutableByteArray)
    }
    fn length(&self) -> Result<i32, FnError> {
        let vm = get_jvm()?;
        vm.attach_current_thread(|env| -> JniResult<i32> {
            let name = jni::strings::JNIString::new("length");
            let sig_binding = jni::signature::RuntimeMethodSignature::from_str("()I")?;
            let sig = sig_binding.method_signature();
            let v = env.call_method(self.0.as_obj(), name, sig, &[])?;
            v.i()
        })
        .map_err(|e| FnError::Unknown(e.to_string()))
    }
    fn concat(&self, array: &Self) -> Result<Self, FnError> {
        let vm = get_jvm()?;
        vm.attach_current_thread(|env| -> JniResult<JavaGlobal> {
            let class_name = jni::strings::JNIString::new(Self::JAVA_CLASS);
            let class = env.find_class(class_name)?;
            let arrays = JObjectArray::<JObject>::new(env, 2, JObject::null())?;
            arrays.set_element(env, 0, self.0.as_obj())?;
            arrays.set_element(env, 1, array.0.as_obj())?;

            let sig_binding = jni::signature::RuntimeMethodSignature::from_str("([Lch/post/it/evoting/cryptoprimitives/collection/ImmutableByteArray;)Lch/post/it/evoting/cryptoprimitives/collection/ImmutableByteArray;")?;
            let sig = sig_binding.method_signature();
            let arrays_obj = JObject::from(arrays);
            let r = env.call_static_method(
                class,
                jni_str!("concat"),
                sig,
                &[JValue::Object(&arrays_obj)],
            )?;
            env.new_global_ref(r.l()?)
        })
        .map_err(|e| FnError::Unknown(e.to_string()))
        .map(ImmutableByteArray)
    }
}

impl Clone for ImmutableByteArray {
    fn clone(&self) -> Self {
        match crate::swisspost::duplicate_global(&self.0) {
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

                let rust_str = jstr.try_to_string(env)?;

                bytes.extend_from_slice(rust_str.as_bytes());
                // bytes.extend_from_slice(b"Agauog");

                Ok(())
            },
        ) {
            log::error!(
                "Failed to encode ImmutableByteArray with Jackson ObjectMapper: {}",
                e
            );
        }

        // bytes.extend("uaeitnrasetnr".bytes());
        // if let Ok(v) = crate::swisspost::global_elements(&self.0) {
        // <Vec<u8> as puffin::codec::Codec>::encode(&v, bytes);
        // }
    }

    fn read(r: &mut puffin::codec::Reader) -> Option<Self> {
        let v = <Vec<u8> as puffin::codec::Codec>::read(r)?;
        Self::new(&v).ok()
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
                crate::swisspost::global_elements(&self.0),
                crate::swisspost::global_elements(&other_cast.0),
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
    _imba: &crate::swisspost::ImmutableByteArray,
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
) -> Result<crate::swisspost::ImmutableByteArray, D::Error>
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
pub fn fn_new_immutable_byte_array(length: &SppU64) -> Result<ImmutableByteArray, FnError> {
    log::debug!("Creation of a new Byte Array");
    let mut a = Vec::new();
    for _ in 0..length.0 {
        a.push(2);
    }
    // let array = create_global_from_bytes(&a).map(ImmutableByteArray);
    ImmutableByteArray::new(&a)
}

pub fn fn_immutable_byte_array_length(a: &ImmutableByteArray) -> Result<SppU64, FnError> {
    log::debug!("Execution of fn_immutable_byte_array_length");
    Ok(SppU64(a.length()?.try_into().unwrap()))
}

pub fn fn_immutable_byte_array_concat(
    a: &ImmutableByteArray,
    b: &ImmutableByteArray,
) -> Result<ImmutableByteArray, FnError> {
    log::debug!("Execution of fn_immutable_byte_array_concat");
    a.concat(b)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_immutable_byte_array() {
        let size1 = rand::random::<i32>() % 100 + 100;
        let size2 = rand::random::<i32>() % 100 + 100;
        let mut array1 = Vec::new();
        for _ in 0..size1 {
            array1.push(rand::random());
        }
        let mut array2 = Vec::new();
        for _ in 0..size2 {
            array2.push(rand::random());
        }

        let immarr1 = ImmutableByteArray::new(&array1).unwrap();
        let immarr2 = ImmutableByteArray::new(&array2).unwrap();
        assert_eq!(
            size1 + size2,
            immarr1.concat(&immarr2).unwrap().length().unwrap()
        )
    }
}
