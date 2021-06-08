#[macro_export]
macro_rules! app_const {
    ($op:ident) => {
        Term::Application(Signature::new_function(&$op), vec![])
    };
}

#[macro_export]
macro_rules! app {
    ($op:ident, $($args:expr),*$(,)?) => {
        Term::Application(Signature::new_function(&$op),vec![$($args,)*])
    };
}

#[macro_export]
macro_rules! var {
    ($typ:ty, $id:expr) => {
        Term::Variable(Signature::new_var::<$typ>($id))
    };
}

// todo we could improve performance by not recreating these
#[macro_export]
macro_rules! term {
    // Variables
    (($step:expr, $msg:expr) / $typ:ty) => {{
        let var = crate::term::Signature::new_var::<$typ>( ($step, $msg));
        crate::term::Term::Variable(var)
    }};

    // Constants
    ($func:ident) => {{
        let func = crate::term::Signature::new_function(&$func);
        crate::term::Term::Application(func, vec![])
    }};

    // Function Applications
    ($func:ident ($($args:tt),*)) => {{
        let (shape, dynamic_fn) = crate::term::make_dynamic(&$func);
        let func = crate::term::Signature::new_function(&$func);
        crate::term::Term::Application(func, vec![$(crate::term_arg!($args)),*])
    }};
}

#[macro_export]
macro_rules! term_arg {
    // Somehow the following rules is very important
    ( ( $($e:tt)* ) ) => (term!($($e)*));
    // not sure why I should need this
    // ( ( $e:tt ) ) => (ast!($e));
    ($e:tt) => (term!($e));
}
