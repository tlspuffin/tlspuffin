
pub trait Dependant {
    fn get_dependencies() -> Vec<Variable>;
}

pub enum VariableType {
    BINARY,
    I8,
    I16,
    I32,
    I64,
    I128,
    STRING,
}

pub struct Variable {
    pub name: &'static str,
    pub typ: VariableType,
}

impl Dependant for Variable {
    fn get_dependencies() -> Vec<Variable> {
        todo!()
    }
}
