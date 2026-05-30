//! Bidirectional pipe forwarding (SPEC §8.3).

use tokio_tungstenite::tungstenite::Message;

use crate::state::{ActivePipe, SharedState};

/// Forward a message from one side of a pipe to the other.
///
/// Returns `false` if the other side's channel is closed.
#[allow(dead_code)]
pub fn forward(pipe: &ActivePipe, from_a: bool, msg: Message) -> bool {
    let target = if from_a {
        &pipe.sender_b
    } else {
        &pipe.sender_a
    };
    target.send(msg).is_ok()
}

/// Close both sides of a pipe and remove it from state.
pub fn close_pipe(state: &SharedState, pipe_id: u64) {
    if let Some((_, pipe)) = state.active_pipes.remove(&pipe_id) {
        let _ = pipe.sender_a.send(Message::Close(None));
        let _ = pipe.sender_b.send(Message::Close(None));
        state.pipe_assignments.remove(&pipe.conn_id_a);
        state.pipe_assignments.remove(&pipe.conn_id_b);
    }
}
