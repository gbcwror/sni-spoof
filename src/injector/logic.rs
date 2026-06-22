use tracing::{debug, trace, warn};

use crate::config::BypassMethod;
use crate::connection::{CompletionResult, ConnectionId, TcpPhase};
use crate::ConnectionMap;

use super::{FakePacketAction, TcpFlags};

pub struct InjectorLogic;

impl InjectorLogic {
    /// Process an outbound packet for a tracked connection.
    /// Returns (should_forward_packet, optional_fake_action).
    pub fn process_outbound(
        connections: &ConnectionMap,
        conn_id: &ConnectionId,
        tcp_flags: TcpFlags,
        seq_num: u32,
        ack_num: u32,
        payload_len: usize,
        bypass_method: &BypassMethod,
    ) -> (bool, Option<FakePacketAction>) {
        let mut conns = connections.lock().unwrap_or_else(|e| e.into_inner());
        let state = match conns.get_mut(conn_id) {
            Some(s) if s.active => s,
            _ => return (true, None),
        };

        // RST is always terminal.
        if tcp_flags.rst {
            debug!("{} Outbound RST, failing connection", conn_id);
            state.signal_complete(CompletionResult::Failure);
            return (true, None);
        }

        match state.phase {
            TcpPhase::WaitingSyn | TcpPhase::SynSent => {
                // We only care about pure SYN packets (no payload, no ACK).
                if tcp_flags.syn
                    && !tcp_flags.ack
                    && !tcp_flags.fin
                    && payload_len == 0
                {
                    // A valid SYN should have ack_num == 0.
                    // Some stacks may set it; treat non-zero as suspicious
                    // only on the first SYN.
                    if state.syn_seq.is_none() && ack_num != 0 {
                        warn!("{} SYN with non-zero ACK={}, failing", conn_id, ack_num);
                        state.signal_complete(CompletionResult::Failure);
                        return (true, None);
                    }

                    // Retransmit: must have the same seq. Different seq means
                    // the OS recycled the port — this connection is broken.
                    if let Some(prev_seq) = state.syn_seq {
                        if prev_seq != seq_num {
                            warn!("{} SYN retransmit with different seq ({} vs {}), failing",
                                  conn_id, seq_num, prev_seq);
                            state.signal_complete(CompletionResult::Failure);
                            return (true, None);
                        }
                        // Same seq — harmless retransmit, let it through.
                        trace!("{} SYN retransmit (seq={}), forwarding", conn_id, seq_num);
                        return (true, None);
                    }

                    state.syn_seq = Some(seq_num);
                    state.phase   = TcpPhase::SynSent;
                    debug!("{} SYN captured, seq={}", conn_id, seq_num);
                    return (true, None);
                }

                // Anything else during handshake setup: ignore and forward.
                // The TCP stack may send window probes, keep-alives, or
                // other segments that are irrelevant to our state machine.
                trace!("{} Ignoring non-SYN packet in {:?} phase", conn_id, state.phase);
                (true, None)
            }

            TcpPhase::SynAckReceived => {
                // We expect the handshake ACK: pure ACK, no payload.
                if tcp_flags.ack
                    && !tcp_flags.syn
                    && !tcp_flags.fin
                    && payload_len == 0
                {
                    let expected_seq = state.syn_seq
                        .expect("syn_seq set in SynAckReceived")
                        .wrapping_add(1);
                    let expected_ack = state.syn_ack_seq
                        .expect("syn_ack_seq set in SynAckReceived")
                        .wrapping_add(1);

                    if seq_num != expected_seq || ack_num != expected_ack {
                        // Stale or duplicate ACK — not the handshake ACK.
                        // Let TCP handle it; don't fail the connection.
                        trace!(
                            "{} ACK seq/ack mismatch (got {}/{}, want {}/{}), ignoring",
                            conn_id, seq_num, ack_num, expected_seq, expected_ack
                        );
                        return (true, None);
                    }

                    state.phase = TcpPhase::AckSent;
                    debug!("{} Handshake ACK captured, injecting fake", conn_id);

                    let fake_payload = state.fake_data.clone();
                    let fake_action = match bypass_method {
                        BypassMethod::WrongSeq => {
                            let fake_seq =
                                expected_seq.wrapping_sub(fake_payload.len() as u32);
                            state.phase = TcpPhase::FakeInjected;
                            FakePacketAction {
                                seq_num: fake_seq,
                                ack_num: expected_ack,
                                payload: fake_payload,
                            }
                        }
                    };

                    return (true, Some(fake_action));
                }

                // Non-ACK packet in this phase (e.g. SYN retransmit because
                // the ACK was lost): forward and let TCP retry.
                trace!("{} Ignoring non-ACK packet in SynAckReceived phase", conn_id);
                (true, None)
            }

            TcpPhase::AckSent | TcpPhase::FakeInjected => {
                // After injection, we expect the server's ACK (inbound).
                // Any outbound traffic here is application data or TCP
                // control — forward it and don't interfere.
                trace!("{} Forwarding outbound in {:?} phase", conn_id, state.phase);
                (true, None)
            }

            TcpPhase::Completed | TcpPhase::Failed => (true, None),
        }
    }

    /// Process an inbound packet for a tracked connection.
    /// Returns whether the packet should be forwarded.
    pub fn process_inbound(
        connections: &ConnectionMap,
        conn_id: &ConnectionId,
        tcp_flags: TcpFlags,
        seq_num: u32,
        ack_num: u32,
        payload_len: usize,
    ) -> bool {
        let mut conns = connections.lock().unwrap_or_else(|e| e.into_inner());
        let state = match conns.get_mut(conn_id) {
            Some(s) if s.active => s,
            _ => return true,
        };

        // RST is always terminal.
        if tcp_flags.rst {
            debug!("{} Inbound RST, failing connection", conn_id);
            state.signal_complete(CompletionResult::Failure);
            return true;
        }

        match state.phase {
            TcpPhase::SynSent => {
                // We expect SYN-ACK.
                if tcp_flags.syn
                    && tcp_flags.ack
                    && !tcp_flags.fin
                    && payload_len == 0
                {
                    let expected_ack = state.syn_seq
                        .expect("syn_seq set in SynSent")
                        .wrapping_add(1);

                    if ack_num != expected_ack {
                        // SYN-ACK for a different connection or stale segment.
                        trace!(
                            "{} SYN-ACK ack mismatch (got {}, want {}), ignoring",
                            conn_id, ack_num, expected_ack
                        );
                        return true;
                    }

                    // Retransmitted SYN-ACK: must have the same seq.
                    if let Some(prev) = state.syn_ack_seq {
                        if prev != seq_num {
                            warn!("{} SYN-ACK seq changed ({} vs {}), failing",
                                  conn_id, seq_num, prev);
                            state.signal_complete(CompletionResult::Failure);
                            return true;
                        }
                        // Same seq — harmless retransmit.
                        trace!("{} SYN-ACK retransmit (seq={}), forwarding", conn_id, seq_num);
                        return true;
                    }

                    state.syn_ack_seq = Some(seq_num);
                    state.phase       = TcpPhase::SynAckReceived;
                    debug!(
                        "{} SYN-ACK captured, seq={} ack={}",
                        conn_id, seq_num, ack_num
                    );
                    return true;
                }

                // Not a SYN-ACK — ignore (could be a stale segment from
                // a previous connection on the same port).
                trace!("{} Ignoring non-SYN-ACK in SynSent phase", conn_id);
                true
            }

            TcpPhase::FakeInjected => {
                // After injecting the fake, the server should ACK the
                // handshake. The fake packet has a wrong seq so the server
                // ignores it — the ACK we get back acknowledges only the
                // real handshake.
                if tcp_flags.ack
                    && !tcp_flags.syn
                    && !tcp_flags.fin
                    && payload_len == 0
                {
                    let expected_seq = state.syn_ack_seq
                        .expect("syn_ack_seq set in FakeInjected")
                        .wrapping_add(1);
                    let expected_ack = state.syn_seq
                        .expect("syn_seq set in FakeInjected")
                        .wrapping_add(1);

                    if seq_num != expected_seq || ack_num != expected_ack {
                        // Duplicate or out-of-order ACK — not the one we want.
                        trace!(
                            "{} Post-fake ACK mismatch (got {}/{}, want {}/{}), ignoring",
                            conn_id, seq_num, ack_num, expected_seq, expected_ack
                        );
                        return true;
                    }

                    debug!("{} Injection confirmed successful", conn_id);
                    state.phase = TcpPhase::Completed;
                    state.signal_complete(CompletionResult::Success);
                    return true;
                }

                // Non-ACK inbound (e.g. retransmitted SYN-ACK): forward.
                trace!("{} Ignoring non-ACK in FakeInjected phase", conn_id);
                true
            }

            TcpPhase::WaitingSyn => {
                // Inbound traffic before we've even sent a SYN — stale
                // segment from a previous connection. Ignore.
                trace!("{} Ignoring inbound in WaitingSyn phase", conn_id);
                true
            }

            _ => true,
        }
    }
}