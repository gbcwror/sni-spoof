use std::sync::Arc;
use std::time::Instant;
use tokio::sync::Notify;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ConnectionId {
    pub src_ip:   [u8; 4],
    pub src_port: u16,
    pub dst_ip:   [u8; 4],
    pub dst_port: u16,
}

impl std::fmt::Display for ConnectionId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}.{}.{}.{}:{} -> {}.{}.{}.{}:{}",
            self.src_ip[0], self.src_ip[1], self.src_ip[2], self.src_ip[3],
            self.src_port,
            self.dst_ip[0], self.dst_ip[1], self.dst_ip[2], self.dst_ip[3],
            self.dst_port,
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum TcpPhase {
    WaitingSyn,
    SynSent,
    SynAckReceived,
    AckSent,
    FakeInjected,
    Completed,
    Failed,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum CompletionResult {
    Success,
    Failure,
}

pub struct ConnectionState {
    pub phase:      TcpPhase,
    pub syn_seq:    Option<u32>,
    pub syn_ack_seq: Option<u32>,
    pub fake_data:  Vec<u8>,
    pub completion: Arc<Notify>,
    pub result:     Option<CompletionResult>,
    pub active:     bool,
    pub created_at: Instant,
}

pub const CONNECTION_TTL_SECS: u64 = 60;

impl ConnectionState {
    pub fn new(fake_data: Vec<u8>) -> Self {
        Self {
            phase:       TcpPhase::WaitingSyn,
            syn_seq:     None,
            syn_ack_seq: None,
            fake_data,
            completion:  Arc::new(Notify::new()),
            result:      None,
            active:      true,
            created_at:  Instant::now(),
        }
    }

    pub fn signal_complete(&mut self, result: CompletionResult) {
        self.result = Some(result);
        self.active = false;
        self.completion.notify_one();
    }
}