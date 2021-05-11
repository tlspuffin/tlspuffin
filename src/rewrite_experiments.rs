use term_rewriting::{parse, Signature, Strategy};

fn main() {
    let mut sig = Signature::default();

    let v1 = sig.new_var(None);
    let v2 = sig.new_var(Some("blah".to_string()));

    println!("{}", v1.display());
    println!("{}", v2.display());

    let input = "
 #-- rules:
     PLUS(SUCC(x_) y_) = PLUS(x_ SUCC(y_));
     PLUS(ZERO y_) = y_;

 #-- terms:
     PLUS(SUCC(SUCC(SUCC(ZERO))) SUCC(ZERO));
 ";

    let mut sig = Signature::default();

    let (trs, terms) = parse(&mut sig, &input).expect("parse TRS + terms");
    let l_term = &terms[0];

    let terms = trs.rewrite(&l_term, Strategy::All).unwrap();

    println!("{}", trs.is_deterministic());

    for term in terms {
        println!("{}", term.display());

        let terms = trs.rewrite(&term, Strategy::All).unwrap();

        for term in terms {
            println!("{}", term.display());

            let terms = trs.rewrite(&term, Strategy::All).unwrap();

            for term in terms {
                println!("{}", term.display());

                let terms = trs.rewrite(&term, Strategy::All).unwrap();

                for term in terms {
                    println!("{}", term.display());
                }
            }
        }
    }
}
