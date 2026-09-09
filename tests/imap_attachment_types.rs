use mailctl::imap::{AttachmentChunk, AttachmentProgress, AttachmentRequest};

const _: fn(AttachmentChunk) = |chunk| {
    let _: Vec<u8> = chunk.bytes;
    let _: u64 = chunk.decoded_offset;
    match chunk.progress {
        AttachmentProgress::Continue(transfer) => {
            let _: AttachmentRequest = AttachmentRequest::resume(transfer);
        }
        AttachmentProgress::Complete(integrity) => {
            let _: u64 = integrity.total_decoded_bytes;
            let _: [u8; 32] = integrity.sha256;
        }
    }
};
