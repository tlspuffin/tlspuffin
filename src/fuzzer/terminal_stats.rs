use core::{time, time::Duration};
use std::io;
use std::io::Stdout;

use libafl::bolts::current_time;
use libafl::stats::{ClientStats, Stats};
use termion::raw::{IntoRawMode, RawTerminal};
use tui::backend::TermionBackend;
use tui::layout::Alignment;
use tui::style::{Color, Style};
use tui::widgets::{Block, Borders, Paragraph, Wrap};
use tui::Terminal;

pub struct TerminalStats {
    terminal: Terminal<TermionBackend<RawTerminal<Stdout>>>,
    start_time: Duration,
    corpus_size: usize,
    client_stats: Vec<ClientStats>,
}

impl Clone for TerminalStats {
    fn clone(&self) -> Self {
        let stdout = io::stdout().into_raw_mode().unwrap();
        let backend = TermionBackend::new(stdout);
        Self {
            terminal: Terminal::new(backend).unwrap(),
            start_time: self.start_time,
            corpus_size: self.corpus_size,
            client_stats: self.client_stats.clone(),
        }
    }
}

impl Stats for TerminalStats {
    /// the client stats, mutable
    fn client_stats_mut(&mut self) -> &mut Vec<ClientStats> {
        &mut self.client_stats
    }

    /// the client stats
    fn client_stats(&self) -> &[ClientStats] {
        &self.client_stats
    }

    /// Time this fuzzing run stated
    fn start_time(&mut self) -> time::Duration {
        self.start_time
    }

    fn display(&mut self, event_msg: String, sender_id: u32) {
        let sender = format!("#{}", sender_id);
        let pad = if event_msg.len() + sender.len() < 13 {
            " ".repeat(13 - event_msg.len() - sender.len())
        } else {
            String::new()
        };
        let head = format!("{}{} {}", event_msg, pad, sender);
        let global_fmt = format!(
            "[{}]  (GLOBAL) clients: {}, corpus: {}, objectives: {}, executions: {}, exec/sec: {}",
            head,
            self.client_stats().len(),
            self.corpus_size(),
            self.objective_size(),
            self.total_execs(),
            self.execs_per_sec()
        );

        self.terminal
            .draw(|f| {
                let size = f.size();
                /*                let block = Block::default().title("Block").borders(Borders::ALL);
                */
                let p = Paragraph::new(global_fmt)
                    .block(Block::default().title("Paragraph").borders(Borders::ALL))
                    .style(Style::default().fg(Color::White).bg(Color::Black))
                    .alignment(Alignment::Center)
                    .wrap(Wrap { trim: true });

                f.render_widget(p, size);
            })
            .unwrap();

        /*let client = self.client_stats_mut_for(sender_id);
        let cur_time = current_time();
        let exec_sec = client.execs_per_sec(cur_time);

        let pad = " ".repeat(head.len());
        let mut fmt = format!(
            " {}   (CLIENT) corpus: {}, objectives: {}, executions: {}, exec/sec: {}",
            pad, client.corpus_size, client.objective_size, client.executions, exec_sec
        );
        for (key, val) in &client.user_stats {
            fmt += &format!(", {}: {}", key, val);
        }
        (self.print_fn)(fmt);*/
    }
}

impl TerminalStats {
    /// Creates the stats, using the `current_time` as `start_time`.
    pub fn new() -> Self {
        let stdout = io::stdout().into_raw_mode().unwrap();
        let backend = TermionBackend::new(stdout);
        Self {
            terminal: Terminal::new(backend).unwrap(),
            start_time: current_time(),
            corpus_size: 0,
            client_stats: vec![],
        }
    }
}
