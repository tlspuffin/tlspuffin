//! Definition of the VariableData trait. A VariableData can contain any data which has a `'static`
//! type.

use std::any::{Any, TypeId};
use std::fmt::Debug;

use crate::protocol::{EvaluatedTerm, ProtocolTypes};

pub trait VariableData<PT: ProtocolTypes>: Debug + EvaluatedTerm<PT> {
    fn boxed(&self) -> Box<dyn VariableData<PT>>;
    fn boxed_any(&self) -> Box<dyn Any>;
    fn boxed_extractable(&self) -> Box<dyn EvaluatedTerm<PT>>;
    fn type_id(&self) -> TypeId;
    fn type_name(&self) -> &'static str;
}

/// A VariableData is cloneable and has a `'static` type. This data type is used throughout
/// tlspuffin to handle data of dynamic size.
impl<T: 'static, PT: ProtocolTypes> VariableData<PT> for T
where
    T: Clone + Debug + EvaluatedTerm<PT>,
{
    fn boxed(&self) -> Box<dyn VariableData<PT>> {
        Box::new(self.clone())
    }

    fn boxed_any(&self) -> Box<dyn Any> {
        Box::new(self.clone())
    }

    fn boxed_extractable(&self) -> Box<dyn EvaluatedTerm<PT>> {
        Box::new(self.clone())
    }

    fn type_id(&self) -> TypeId {
        Any::type_id(self)
    }

    fn type_name(&self) -> &'static str {
        std::any::type_name::<T>()
    }
}
