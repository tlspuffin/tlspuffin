use itertools::Itertools;

use super::{Operator, Term};

pub trait Pretty: Sized {
    fn as_application(&self) -> Option<(Operator, &[Self])>;
    fn display(&self) -> String;

    fn pretty(&self) -> String {
        if let Some((op, args)) = self.as_application() {
            let op_str = op.display();
            // the following match `return`s applicable special cases
            match (op_str.as_str(), args.len()) {
                // TODO Special cases for pretty printing
                // (".", 2) => return pretty_binary_application(args, spaces_allowed),
                //("NIL", 0) => return "[]".to_string(),
                (_, 0) => return op_str,
                _ => (),
            }
            let args_str = args.iter().map(|arg| arg.pretty()).join(", ");
            format!("{}({})", op_str, args_str)
        } else {
            self.display()
        }
    }
}

impl Pretty for Term {
    fn as_application(&self) -> Option<(Operator, &[Term])> {
        match *self {
           Term::Application { ref op, ref args } => Some((op.clone(), &args)),
            _ => None,
        }
    }
    fn display(&self) -> String {
        self.display()
    }
}
