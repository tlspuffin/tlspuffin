use std::io;
use std::io::{BufWriter, ErrorKind, Write};
use std::process::{Command, Stdio};

pub fn write_graphviz(output: &str, format: &str, dot_script: &str) -> Result<(), io::Error> {
    let mut child = Command::new("dot")
        .args(&["-o", output, "-T", format])
        .stdin(Stdio::piped())
        .spawn()
        .expect("failed to spawn dot");

    let mut dot_stdin = child
        .stdin
        .take()
        .ok_or(io::Error::new(ErrorKind::Other, "Failed to open stdin"))?;
    let mut writer = BufWriter::new(&mut dot_stdin);
    writer.write(dot_script.as_bytes().as_ref())?;
    //child.kill().unwrap();
    //child.wait().expect("failed to execute dot");
    Ok(())
}
