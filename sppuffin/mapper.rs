use jni::errors;
use jni::objects::{JByteArray, JClass, JValue, JString, GlobalRef};
use jni::signature::JavaType;
use jni::sys::jint;
use jni::{JNIEnv, JavaVM, JNIVersion};

// Keep utilities module if needed (currently unused)
mod utils;

/// Minimal wrapper around the Java class
/// ch.post.it.evoting.cryptoprimitives.collection.ImmutableByteArray
pub struct ImmutableByteArray {
    obj: GlobalRef,
}

impl ImmutableByteArray {
    /// Construct a new ImmutableByteArray from a Rust byte slice
    pub fn new(env: &JNIEnv, bytes: &[u8]) -> errors::Result<Self> {
        // Find the class
        let class = env.find_class("ch/post/it/evoting/cryptoprimitives/collection/ImmutableByteArray")?;

        // Convert Rust bytes to Java byte[]
        let jarr: JByteArray = env.byte_array_from_slice(bytes)?;

        // Call constructor that takes a byte[]: signature ([B)V
        let local = env.new_object(class, "([B)V", &[JValue::from(jarr)])?;

        // Promote to global ref so it lives beyond the current frame
        let global = env.new_global_ref(local)?;
        Ok(Self { obj: global })
    }

    /// Call length():int
    pub fn length(&self, env: &JNIEnv) -> errors::Result<jint> {
        let v = env.call_method(self.obj.as_obj(), "length", "()I", &[])?;
        v.i()
    }

    /// Call elements(): byte[] and return as Vec<u8>
    pub fn elements(&self, env: &JNIEnv) -> errors::Result<Vec<u8>> {
        let v = env.call_method(self.obj.as_obj(), "elements", "()[B", &[])?;
        let jarr = v.l()?;
        let byte_array: JByteArray = JByteArray::from(jarr);
        let out = env.convert_byte_array(byte_array)?;
        Ok(out)
    }

    /// Call get(int):byte
    pub fn get(&self, env: &JNIEnv, idx: jint) -> errors::Result<i8> {
        let v = env.call_method(self.obj.as_obj(), "get", "(I)B", &[JValue::from(idx)])?;
        Ok(v.b()?)
    }

    /// Call toString()
    pub fn to_string(&self, env: &JNIEnv) -> errors::Result<String> {
        let v = env.call_method(self.obj.as_obj(), "toString", "()Ljava/lang/String;", &[])?;
        let jstr = JString::from(v.l()?);
        let rust_str = env.get_string(jstr)?;
        Ok(rust_str.into())
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let jvm_args = jni::InitArgsBuilder::new()
        .version(JNIVersion::V1_8)
        .option(format!("-Djava.class.path=/home/binj/Documents/stageM2/e-voting/control-component/target/control-component-1.5.3.2.jar:/home/binj/Documents/stageM2/crypto-primitives/target/crypto-primitives-1.5.2.1.jar:/home/binj/.m2/repository/com/google/guava/guava/32.0.1-jre/guava-32.0.1-jre.jar"))
        .option("-Xcheck:jni")
        .build()?;

    let jvm = JavaVM::new(jvm_args)?;

    let bytes = [1_u8, 2, 3, 4];

    jvm.attach_current_thread(|env: JNIEnv| -> errors::Result<()> {
        // Try to create the Java ImmutableByteArray
        let imm = ImmutableByteArray::new(&env, &bytes)?;
        println!("Created ImmutableByteArray of length: {}", imm.length(&env)?);

        let elems = imm.elements(&env)?;
        println!("Elements from Java: {:?}", elems);

        let s = imm.to_string(&env)?;
        println!("toString -> {}", s);

        Ok(())
    })?;

    Ok(())
}
