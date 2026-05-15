//! Length-prefixed envelope framing on a QUIC bidirectional stream.
//!
//! Each on-the-wire envelope is preceded by a 4-byte big-endian length.
//! Max envelope size is 64 KiB per spec §3.6.

use quinn::{RecvStream, SendStream};
use sidevers_core::Envelope;

use crate::error::{Error, Result};

/// Maximum allowed envelope length on the wire (§3.6).
pub const MAX_ENVELOPE_LEN: u32 = 64 * 1024;

pub async fn send_envelope(send: &mut SendStream, env: &Envelope) -> Result<()> {
    let bytes = env.to_wire_bytes();
    if bytes.len() > MAX_ENVELOPE_LEN as usize {
        return Err(Error::EnvelopeTooLarge {
            got: bytes.len() as u32,
            max: MAX_ENVELOPE_LEN,
        });
    }
    let len_be = (bytes.len() as u32).to_be_bytes();
    send.write_all(&len_be).await?;
    send.write_all(&bytes).await?;
    Ok(())
}

pub async fn recv_envelope(recv: &mut RecvStream) -> Result<Envelope> {
    let mut len_buf = [0u8; 4];
    recv.read_exact(&mut len_buf).await?;
    let len = u32::from_be_bytes(len_buf);
    if len == 0 || len > MAX_ENVELOPE_LEN {
        return Err(Error::EnvelopeTooLarge {
            got: len,
            max: MAX_ENVELOPE_LEN,
        });
    }
    let mut buf = vec![0u8; len as usize];
    recv.read_exact(&mut buf).await?;
    Envelope::from_wire_bytes(&buf).map_err(Error::Core)
}
