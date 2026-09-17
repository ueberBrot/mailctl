use mailctl::imap::AttachmentData;

const _: fn(AttachmentData) = |chunk| {
    let _: Vec<u8> = chunk.bytes;
    let _: u64 = chunk.decoded_offset;
    if let Some(integrity) = chunk.integrity {
        let _: u64 = integrity.total_decoded_bytes;
        let _: [u8; 32] = integrity.sha256;
    }
};
