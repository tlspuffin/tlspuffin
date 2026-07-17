/// Very small prototype message type for swisspost (sppuffin)
#[derive(Debug, Clone)]
pub enum SwissMessage {
    /// Single simple message that will be printed to stdout
    Simple(String),
}

impl SwissMessage {
    /// Send the message by printing to stdout (prototype behaviour)
    pub fn send(&self) {
        match self {
            SwissMessage::Simple(s) => println!("[sppuffin] {}", s),
        }
    }
}
