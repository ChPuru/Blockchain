//! Length-prefixed Borsh framing for `/ferrum/sync/1.0.0`.
//!
//! Every frame is `u32` little-endian length followed by exactly that many
//! bytes of Borsh. The length prefix is the point: libp2p's own CBOR and JSON
//! codecs call `read_to_end` and rely on the remote half-closing the stream,
//! which means the only bound on an inbound message is the `take()` limit and a
//! peer can stall a stream forever by never closing it. Reading a declared
//! length lets us reject an oversized frame *before* allocating for it, and
//! lets a stream carry more than one exchange.
//!
//! Request and response frames have separate caps because they have wildly
//! different legitimate sizes: a request is a locator, a response can be 64
//! blocks.

use std::io;

use async_trait::async_trait;
use futures::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use libp2p::StreamProtocol;
use libp2p::request_response::Codec;

use crate::error::P2pError;
use crate::limits;
use crate::message::{SyncRequest, SyncResponse};

/// The Borsh codec for the Ferrum sync protocol.
#[derive(Debug, Clone, Copy)]
pub struct SyncCodec {
    max_request_bytes: usize,
    max_response_bytes: usize,
}

impl Default for SyncCodec {
    fn default() -> Self {
        SyncCodec {
            max_request_bytes: limits::MAX_REQUEST_FRAME_BYTES,
            max_response_bytes: limits::MAX_RESPONSE_FRAME_BYTES,
        }
    }
}

impl SyncCodec {
    /// A codec with the contract's frame caps.
    pub fn new() -> Self {
        Self::default()
    }

    /// Override the request frame cap. Tests use this to drive the
    /// oversized-frame path without allocating a megabyte.
    pub fn with_max_request_bytes(mut self, max: usize) -> Self {
        self.max_request_bytes = max;
        self
    }

    /// Override the response frame cap.
    pub fn with_max_response_bytes(mut self, max: usize) -> Self {
        self.max_response_bytes = max;
        self
    }

    /// The request frame cap in force.
    pub fn max_request_bytes(&self) -> usize {
        self.max_request_bytes
    }

    /// The response frame cap in force.
    pub fn max_response_bytes(&self) -> usize {
        self.max_response_bytes
    }
}

/// Read one length-prefixed frame, refusing anything above `max`.
///
/// The length is checked before the body is read, so a peer claiming a 4 GiB
/// frame costs us four bytes and a disconnect rather than 4 GiB of `Vec`.
pub async fn read_frame<T>(io: &mut T, max: usize) -> Result<Vec<u8>, P2pError>
where
    T: AsyncRead + Unpin + Send,
{
    let mut len_bytes = [0u8; limits::FRAME_LENGTH_PREFIX_BYTES];
    io.read_exact(&mut len_bytes).await?;
    let len = u32::from_le_bytes(len_bytes) as usize;
    if len > max {
        return Err(P2pError::FrameTooLarge { size: len, max });
    }
    let mut body = vec![0u8; len];
    io.read_exact(&mut body).await?;
    Ok(body)
}

/// Write one length-prefixed frame, refusing anything above `max`.
///
/// The check is on our own side too: a bug that tries to send an over-cap frame
/// should fail locally and loudly rather than be dropped by the peer.
pub async fn write_frame<T>(io: &mut T, body: &[u8], max: usize) -> Result<(), P2pError>
where
    T: AsyncWrite + Unpin + Send,
{
    if body.len() > max {
        return Err(P2pError::FrameTooLarge { size: body.len(), max });
    }
    let len =
        u32::try_from(body.len()).map_err(|_| P2pError::FrameTooLarge { size: body.len(), max })?;
    io.write_all(&len.to_le_bytes()).await?;
    io.write_all(body).await?;
    io.flush().await?;
    Ok(())
}

#[async_trait]
impl Codec for SyncCodec {
    type Protocol = StreamProtocol;
    type Request = SyncRequest;
    type Response = SyncResponse;

    async fn read_request<T>(&mut self, _: &Self::Protocol, io: &mut T) -> io::Result<Self::Request>
    where
        T: AsyncRead + Unpin + Send,
    {
        let body = read_frame(io, self.max_request_bytes).await?;
        // Clamp on ingress: the locator length bounds server-side work, which
        // the response cap alone does not.
        Ok(SyncRequest::decode(&body).map_err(io::Error::from)?.clamped())
    }

    async fn read_response<T>(
        &mut self,
        _: &Self::Protocol,
        io: &mut T,
    ) -> io::Result<Self::Response>
    where
        T: AsyncRead + Unpin + Send,
    {
        let body = read_frame(io, self.max_response_bytes).await?;
        // Cap on ingress too: a peer that ignores the caps cannot make us hold
        // more than the contract allows.
        Ok(SyncResponse::decode(&body).map_err(io::Error::from)?.capped())
    }

    async fn write_request<T>(
        &mut self,
        _: &Self::Protocol,
        io: &mut T,
        req: Self::Request,
    ) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        let body = req.encode().map_err(io::Error::from)?;
        write_frame(io, &body, self.max_request_bytes).await.map_err(io::Error::from)
    }

    async fn write_response<T>(
        &mut self,
        _: &Self::Protocol,
        io: &mut T,
        res: Self::Response,
    ) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        // Belt and braces: the service caps every response before handing it
        // over, and the codec caps it again on the way out.
        let body = res.capped().encode().map_err(io::Error::from)?;
        write_frame(io, &body, self.max_response_bytes).await.map_err(io::Error::from)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ferrum_types::{BlockHash, BlockHeader, CompactTarget, Hash32};
    use futures::io::Cursor;

    const PROTO: StreamProtocol = StreamProtocol::new(crate::message::SYNC_PROTOCOL);

    fn header(nonce: u64) -> BlockHeader {
        BlockHeader {
            version: 1,
            prev_hash: BlockHash::from_bytes([1u8; 32]),
            merkle_root: Hash32::from_bytes([2u8; 32]),
            timestamp_ms: 42,
            bits: CompactTarget(0x1d00_ffff),
            nonce,
        }
    }

    fn request() -> SyncRequest {
        SyncRequest::GetHeaders {
            locator: vec![BlockHash::from_bytes([3u8; 32])],
            stop: None,
            max: 10,
        }
    }

    #[tokio::test]
    async fn a_frame_round_trips_through_the_length_prefix() {
        let mut buf = Vec::new();
        write_frame(&mut Cursor::new(&mut buf), b"hello ferrum", 1024).await.expect("write");
        assert_eq!(buf.len(), 4 + 12);
        assert_eq!(u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]), 12);

        let read = read_frame(&mut Cursor::new(buf), 1024).await.expect("read");
        assert_eq!(read, b"hello ferrum");
    }

    #[tokio::test]
    async fn an_empty_frame_round_trips() {
        let mut buf = Vec::new();
        write_frame(&mut Cursor::new(&mut buf), b"", 16).await.expect("write");
        assert_eq!(buf, vec![0, 0, 0, 0]);
        assert!(read_frame(&mut Cursor::new(buf), 16).await.expect("read").is_empty());
    }

    #[tokio::test]
    async fn writing_an_oversized_frame_is_refused_locally() {
        let mut buf = Vec::new();
        let err = write_frame(&mut Cursor::new(&mut buf), &[0u8; 64], 16)
            .await
            .expect_err("an over-cap frame must be refused");
        assert!(matches!(err, P2pError::FrameTooLarge { size: 64, max: 16 }));
        assert!(buf.is_empty(), "nothing may be written once the cap is exceeded");
    }

    #[tokio::test]
    async fn reading_an_oversized_frame_is_refused_before_allocating() {
        // Declare 4 GiB, supply no body at all.
        let mut wire = 0xffff_ffffu32.to_le_bytes().to_vec();
        wire.extend_from_slice(b"x");
        let err = read_frame(&mut Cursor::new(wire), 1024)
            .await
            .expect_err("an over-cap length prefix must be refused");
        match err {
            P2pError::FrameTooLarge { size, max } => {
                assert_eq!(size, 0xffff_ffff);
                assert_eq!(max, 1024);
            }
            other => panic!("wrong error: {other}"),
        }
    }

    #[tokio::test]
    async fn a_truncated_frame_is_an_unexpected_eof() {
        let mut wire = 32u32.to_le_bytes().to_vec();
        wire.extend_from_slice(b"only four");
        let err = read_frame(&mut Cursor::new(wire), 1024)
            .await
            .expect_err("a truncated body must be refused");
        assert!(matches!(err, P2pError::Io(_)), "got {err}");
    }

    #[tokio::test]
    async fn a_truncated_length_prefix_is_an_unexpected_eof() {
        let err = read_frame(&mut Cursor::new(vec![1u8, 2]), 1024)
            .await
            .expect_err("a truncated prefix must be refused");
        assert!(matches!(err, P2pError::Io(_)), "got {err}");
    }

    #[tokio::test]
    async fn the_codec_round_trips_a_request() {
        let mut codec = SyncCodec::new();
        let mut buf = Vec::new();
        codec.write_request(&PROTO, &mut Cursor::new(&mut buf), request()).await.expect("write");
        let got = codec.read_request(&PROTO, &mut Cursor::new(buf)).await.expect("read");
        assert_eq!(got, request());
    }

    #[tokio::test]
    async fn the_codec_round_trips_a_response() {
        let mut codec = SyncCodec::new();
        let resp = SyncResponse::Headers(vec![header(1), header(2)]);
        let mut buf = Vec::new();
        codec
            .write_response(&PROTO, &mut Cursor::new(&mut buf), resp.clone())
            .await
            .expect("write");
        let got = codec.read_response(&PROTO, &mut Cursor::new(buf)).await.expect("read");
        assert_eq!(got, resp);
    }

    #[tokio::test]
    async fn the_codec_round_trips_a_tip_response() {
        let mut codec = SyncCodec::new();
        let resp = SyncResponse::Tip {
            hash: BlockHash::from_bytes([6u8; 32]),
            height: 12,
            work: [1u8; 32],
        };
        let mut buf = Vec::new();
        codec
            .write_response(&PROTO, &mut Cursor::new(&mut buf), resp.clone())
            .await
            .expect("write");
        assert_eq!(codec.read_response(&PROTO, &mut Cursor::new(buf)).await.expect("read"), resp);
    }

    #[tokio::test]
    async fn the_codec_caps_a_response_it_writes() {
        let mut codec = SyncCodec::new();
        let over = limits::MAX_HEADERS_PER_RESPONSE + 10;
        let resp = SyncResponse::Headers((0..over as u64).map(header).collect());
        let mut buf = Vec::new();
        codec.write_response(&PROTO, &mut Cursor::new(&mut buf), resp).await.expect("write");
        match codec.read_response(&PROTO, &mut Cursor::new(buf)).await.expect("read") {
            SyncResponse::Headers(h) => assert_eq!(h.len(), limits::MAX_HEADERS_PER_RESPONSE),
            other => panic!("wrong variant: {}", other.kind()),
        }
    }

    #[tokio::test]
    async fn the_codec_clamps_a_hostile_request_on_read() {
        let mut codec = SyncCodec::new();
        let hostile = SyncRequest::GetBlocks {
            hashes: vec![BlockHash::ZERO; limits::MAX_REQUESTED_BLOCK_HASHES + 40],
        };
        // Bypass write_request so the wire really carries the hostile frame.
        let body = hostile.encode().expect("encode");
        let mut buf = Vec::new();
        write_frame(&mut Cursor::new(&mut buf), &body, limits::MAX_REQUEST_FRAME_BYTES)
            .await
            .expect("write");
        match codec.read_request(&PROTO, &mut Cursor::new(buf)).await.expect("read") {
            SyncRequest::GetBlocks { hashes } => {
                assert_eq!(hashes.len(), limits::MAX_REQUESTED_BLOCK_HASHES);
            }
            other => panic!("wrong variant: {}", other.kind()),
        }
    }

    #[tokio::test]
    async fn the_codec_rejects_a_response_frame_above_its_cap() {
        let mut codec = SyncCodec::new().with_max_response_bytes(8);
        let err = codec
            .write_response(
                &PROTO,
                &mut Cursor::new(Vec::new()),
                SyncResponse::Headers(vec![header(1)]),
            )
            .await
            .expect_err("an over-cap response must be refused");
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[tokio::test]
    async fn the_codec_rejects_garbage_bytes() {
        let mut codec = SyncCodec::new();
        let mut buf = Vec::new();
        write_frame(&mut Cursor::new(&mut buf), &[0xfe, 0xfe, 0xfe], 1024).await.expect("write");
        let err = codec
            .read_request(&PROTO, &mut Cursor::new(buf))
            .await
            .expect_err("garbage must not decode");
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn the_default_caps_come_from_limits() {
        let codec = SyncCodec::default();
        assert_eq!(codec.max_request_bytes(), limits::MAX_REQUEST_FRAME_BYTES);
        assert_eq!(codec.max_response_bytes(), limits::MAX_RESPONSE_FRAME_BYTES);
    }
}
