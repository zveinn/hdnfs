use crate::error::{Error, Result};
use crate::pathutil::validate_component;

pub const MAGIC: &[u8; 8] = b"HDNFS2\0\0";
pub const VERSION: u16 = 1;
pub const SUPER_SIZE: usize = 4096;
pub const HEADER_LEN: usize = 256;
pub const BODY_PLAIN_LEN: usize = 128;
pub const BODY_SEALED_LEN: usize = BODY_PLAIN_LEN + 16;
pub const BLOCK_SIZE: u64 = 1024 * 1024;
pub const NONCE_LEN: usize = 24;
pub const TAG_LEN: usize = 16;
pub const PAYLOAD: usize = BLOCK_SIZE as usize - NONCE_LEN - TAG_LEN;
pub const MIN_DATA_BLOCKS: u64 = 8;
pub const MAX_PATH_BYTES: usize = 4096;
pub const MAX_NAME_BYTES: usize = 255;
pub const MAX_DIR_BYTES: u64 = 32 * 1024 * 1024;
pub const CHAIN_END: u64 = u64::MAX;

pub const PURPOSE_FILE: u8 = 1;
pub const PURPOSE_DIR: u8 = 2;
pub const PURPOSE_INODE: u8 = 3;
pub const PURPOSE_BITMAP: u8 = 4;
pub const PURPOSE_PARITY: u8 = 5;

pub const SUPER_COPIES: usize = 3;
pub const HEADER_BYTES: u64 = SUPER_SIZE as u64 * SUPER_COPIES as u64;
pub const DATA_STRIPE: u64 = 8;
pub const PARITY_COUNT: u64 = 3;
/// Best-effort gap between stripe members, in blocks (64 MiB).
pub const STRIPE_GAP: u64 = 64;

pub const KIND_DIR: u8 = 1;
pub const KIND_FILE: u8 = 2;

pub fn div_ceil(n: u64, d: u64) -> u64 {
    if n == 0 {
        0
    } else {
        (n - 1) / d + 1
    }
}

pub fn minimum_volume_bytes() -> u64 {
    // One bitmap block plus its 3 parity blocks, twice, plus 8 data blocks.
    HEADER_BYTES + (MIN_DATA_BLOCKS + 2 * slot_span(1)) * BLOCK_SIZE
}

pub fn block_offset(physical: u64) -> u64 {
    HEADER_BYTES + physical * BLOCK_SIZE
}

pub fn content_parity_len(data_blocks: u64) -> u64 {
    if data_blocks == 0 {
        0
    } else {
        div_ceil(data_blocks, DATA_STRIPE) * PARITY_COUNT
    }
}

pub fn chain_parity_len(chain_blocks: u64) -> u64 {
    div_ceil(chain_blocks.max(1), DATA_STRIPE) * PARITY_COUNT
}

pub fn bitmap_parity_blocks(blocks_per_slot: u64) -> u64 {
    div_ceil(blocks_per_slot, DATA_STRIPE) * PARITY_COUNT
}

/// Bitmap blocks plus the parity that follows them, for one bitmap slot.
pub fn slot_span(blocks_per_slot: u64) -> u64 {
    blocks_per_slot + bitmap_parity_blocks(blocks_per_slot)
}

/// Returns `(bitmap blocks per slot, allocatable start, data block count)`.
pub fn geometry(total_physical: u64) -> Result<(u32, u64, u64)> {
    let too_small = Error::Message(format!(
        "volume must be at least {} bytes",
        minimum_volume_bytes()
    ));
    if total_physical < 4 {
        return Err(too_small);
    }
    let mut blocks_per_slot = 1u64;
    loop {
        let span = slot_span(blocks_per_slot);
        if blocks_per_slot > 100_000 || 2 * span >= total_physical {
            return Err(too_small);
        }
        let data = total_physical - 2 * span;
        let bitmap_bytes = (data + 7) / 8;
        let need = div_ceil(bitmap_bytes, PAYLOAD as u64);
        if blocks_per_slot >= need {
            if data < MIN_DATA_BLOCKS {
                return Err(too_small);
            }
            return Ok((blocks_per_slot as u32, 2 * span, data));
        }
        blocks_per_slot += 1;
    }
}

pub fn bitmap_len(data_blocks: u64) -> usize {
    ((data_blocks + 7) / 8) as usize
}

pub fn mask_bitmap(bitmap: &mut [u8], data_blocks: u64) {
    let bits = data_blocks as usize;
    let bytes = (bits + 7) / 8;
    if bytes == 0 {
        return;
    }
    if bits % 8 != 0 && bytes <= bitmap.len() {
        let keep = (1u8 << (bits % 8)) - 1;
        bitmap[bytes - 1] &= keep;
    }
    if bytes < bitmap.len() {
        for byte in &mut bitmap[bytes..] {
            *byte = 0;
        }
    }
}

pub fn block_aad(
    volume_id: &[u8; 16],
    purpose: u8,
    inode_id: u64,
    logical: u64,
    physical: u64,
    extra: u32,
) -> [u8; 48] {
    let mut aad = [0u8; 48];
    aad[0..16].copy_from_slice(volume_id);
    aad[16] = purpose;
    aad[20..28].copy_from_slice(&inode_id.to_le_bytes());
    aad[28..36].copy_from_slice(&logical.to_le_bytes());
    aad[36..44].copy_from_slice(&physical.to_le_bytes());
    aad[44..48].copy_from_slice(&extra.to_le_bytes());
    aad
}

pub fn dek_aad(volume_id: &[u8; 16]) -> [u8; 22] {
    let mut aad = [0u8; 22];
    aad[..16].copy_from_slice(volume_id);
    aad[16..].copy_from_slice(b"dek-v1");
    aad
}

pub fn sb_aad(volume_id: &[u8; 16]) -> [u8; 26] {
    let mut aad = [0u8; 26];
    aad[..16].copy_from_slice(volume_id);
    aad[16..].copy_from_slice(b"sb-body-v1");
    aad
}

pub fn file_key_aad(volume_id: &[u8; 16], inode_id: u64) -> [u8; 35] {
    let mut aad = [0u8; 35];
    aad[..16].copy_from_slice(volume_id);
    aad[16..24].copy_from_slice(&inode_id.to_le_bytes());
    aad[24..].copy_from_slice(b"file-key-v1");
    aad
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SuperHeader {
    pub kdf_memory_kib: u32,
    pub kdf_iterations: u32,
    pub kdf_parallelism: u32,
    pub salt: [u8; 32],
    pub volume_id: [u8; 16],
    pub dek_nonce: [u8; 24],
    pub wrapped_dek: [u8; 48],
    pub body_nonce: [u8; 24],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SuperBody {
    pub generation: u64,
    pub total_physical: u64,
    pub allocatable_start: u64,
    pub data_block_count: u64,
    pub used_blocks: u64,
    pub next_inode_id: u64,
    pub root_inode_id: u64,
    pub root_inode_block: u64,
    pub created_unix: i64,
    pub bitmap_slot: u32,
    pub bitmap_blocks_per_slot: u32,
    pub flags: u64,
    pub root_parity: [u64; 3],
}

pub fn encode_body(body: &SuperBody) -> [u8; BODY_PLAIN_LEN] {
    let mut out = [0u8; BODY_PLAIN_LEN];
    out[0..8].copy_from_slice(&body.generation.to_le_bytes());
    out[8..16].copy_from_slice(&body.total_physical.to_le_bytes());
    out[16..24].copy_from_slice(&body.allocatable_start.to_le_bytes());
    out[24..32].copy_from_slice(&body.data_block_count.to_le_bytes());
    out[32..40].copy_from_slice(&body.used_blocks.to_le_bytes());
    out[40..48].copy_from_slice(&body.next_inode_id.to_le_bytes());
    out[48..56].copy_from_slice(&body.root_inode_id.to_le_bytes());
    out[56..64].copy_from_slice(&body.root_inode_block.to_le_bytes());
    out[64..72].copy_from_slice(&body.created_unix.to_le_bytes());
    out[72..76].copy_from_slice(&body.bitmap_slot.to_le_bytes());
    out[76..80].copy_from_slice(&body.bitmap_blocks_per_slot.to_le_bytes());
    out[80..88].copy_from_slice(&body.flags.to_le_bytes());
    out[88..96].copy_from_slice(&body.root_parity[0].to_le_bytes());
    out[96..104].copy_from_slice(&body.root_parity[1].to_le_bytes());
    out[104..112].copy_from_slice(&body.root_parity[2].to_le_bytes());
    out
}

pub fn decode_body(plain: &[u8]) -> Result<SuperBody> {
    if plain.len() != BODY_PLAIN_LEN {
        return Err(Error::Corrupt("superblock body length".into()));
    }
    if plain[112..].iter().any(|b| *b != 0) {
        return Err(Error::Corrupt("superblock body reserved bytes".into()));
    }
    let mut root_parity = [0u64; 3];
    root_parity[0] = u64::from_le_bytes(plain[88..96].try_into().unwrap());
    root_parity[1] = u64::from_le_bytes(plain[96..104].try_into().unwrap());
    root_parity[2] = u64::from_le_bytes(plain[104..112].try_into().unwrap());
    let body = SuperBody {
        generation: u64::from_le_bytes(plain[0..8].try_into().unwrap()),
        total_physical: u64::from_le_bytes(plain[8..16].try_into().unwrap()),
        allocatable_start: u64::from_le_bytes(plain[16..24].try_into().unwrap()),
        data_block_count: u64::from_le_bytes(plain[24..32].try_into().unwrap()),
        used_blocks: u64::from_le_bytes(plain[32..40].try_into().unwrap()),
        next_inode_id: u64::from_le_bytes(plain[40..48].try_into().unwrap()),
        root_inode_id: u64::from_le_bytes(plain[48..56].try_into().unwrap()),
        root_inode_block: u64::from_le_bytes(plain[56..64].try_into().unwrap()),
        created_unix: i64::from_le_bytes(plain[64..72].try_into().unwrap()),
        bitmap_slot: u32::from_le_bytes(plain[72..76].try_into().unwrap()),
        bitmap_blocks_per_slot: u32::from_le_bytes(plain[76..80].try_into().unwrap()),
        flags: u64::from_le_bytes(plain[80..88].try_into().unwrap()),
        root_parity,
    };
    validate_body(&body)?;
    Ok(body)
}

pub fn validate_body(body: &SuperBody) -> Result<()> {
    if body.flags != 0 {
        return Err(Error::Corrupt("unsupported superblock flags".into()));
    }
    if body.generation == 0 {
        return Err(Error::Corrupt("superblock generation is zero".into()));
    }
    if body.bitmap_slot > 1 {
        return Err(Error::Corrupt("bitmap slot".into()));
    }
    if body.root_inode_id != 1 {
        return Err(Error::Corrupt("root inode id".into()));
    }
    if body.next_inode_id < 2 {
        return Err(Error::Corrupt("next inode id".into()));
    }
    if body.bitmap_blocks_per_slot == 0 {
        return Err(Error::Corrupt("bitmap size".into()));
    }
    if body.allocatable_start != slot_span(u64::from(body.bitmap_blocks_per_slot)) * 2 {
        return Err(Error::Corrupt("allocatable start".into()));
    }
    if body.allocatable_start.checked_add(body.data_block_count) != Some(body.total_physical) {
        return Err(Error::Corrupt("block counts".into()));
    }
    if body.used_blocks > body.data_block_count {
        return Err(Error::Corrupt("used blocks".into()));
    }
    if body.root_inode_block < body.allocatable_start
        || body.root_inode_block >= body.allocatable_start + body.data_block_count
    {
        return Err(Error::Corrupt("root block".into()));
    }
    let mut seen = vec![body.root_inode_block];
    for block in body.root_parity {
        if block < body.allocatable_start
            || block >= body.allocatable_start + body.data_block_count
            || seen.contains(&block)
        {
            return Err(Error::Corrupt("root parity".into()));
        }
        seen.push(block);
    }
    let (blocks, start, data) = geometry(body.total_physical)?;
    if blocks != body.bitmap_blocks_per_slot
        || start != body.allocatable_start
        || data != body.data_block_count
    {
        return Err(Error::Corrupt("geometry mismatch".into()));
    }
    Ok(())
}

pub fn encode_superblock(header: &SuperHeader, body_sealed: &[u8]) -> Result<[u8; SUPER_SIZE]> {
    if body_sealed.len() != BODY_SEALED_LEN {
        return Err(Error::Corrupt("sealed superblock length".into()));
    }
    let mut out = [0u8; SUPER_SIZE];
    out[0..8].copy_from_slice(MAGIC);
    out[8..10].copy_from_slice(&VERSION.to_le_bytes());
    out[10..12].copy_from_slice(&(HEADER_LEN as u16).to_le_bytes());
    out[12..16].copy_from_slice(&header.kdf_memory_kib.to_le_bytes());
    out[16..20].copy_from_slice(&header.kdf_iterations.to_le_bytes());
    out[20..24].copy_from_slice(&header.kdf_parallelism.to_le_bytes());
    out[24..56].copy_from_slice(&header.salt);
    out[56..72].copy_from_slice(&header.volume_id);
    out[72..96].copy_from_slice(&header.dek_nonce);
    out[96..144].copy_from_slice(&header.wrapped_dek);
    out[144..168].copy_from_slice(&header.body_nonce);
    out[168..170].copy_from_slice(&(BODY_SEALED_LEN as u16).to_le_bytes());
    out[256..256 + BODY_SEALED_LEN].copy_from_slice(body_sealed);
    Ok(out)
}

pub fn decode_superblock_header(raw: &[u8]) -> Result<SuperHeader> {
    if raw.len() != SUPER_SIZE {
        return Err(Error::Corrupt("superblock size".into()));
    }
    if &raw[0..8] != MAGIC {
        return Err(Error::NotAVolume);
    }
    let version = u16::from_le_bytes(raw[8..10].try_into().unwrap());
    if version != VERSION {
        return Err(Error::Corrupt(format!("unsupported version {version}")));
    }
    let header_len = u16::from_le_bytes(raw[10..12].try_into().unwrap()) as usize;
    if header_len != HEADER_LEN {
        return Err(Error::Corrupt("header length".into()));
    }
    let body_len = u16::from_le_bytes(raw[168..170].try_into().unwrap()) as usize;
    if body_len != BODY_SEALED_LEN {
        return Err(Error::Corrupt("body length".into()));
    }
    if raw[170..HEADER_LEN].iter().any(|b| *b != 0) {
        return Err(Error::Corrupt("header reserved bytes".into()));
    }
    if raw[HEADER_LEN + BODY_SEALED_LEN..].iter().any(|b| *b != 0) {
        return Err(Error::Corrupt("superblock tail".into()));
    }
    let mut salt = [0u8; 32];
    salt.copy_from_slice(&raw[24..56]);
    let mut volume_id = [0u8; 16];
    volume_id.copy_from_slice(&raw[56..72]);
    let mut dek_nonce = [0u8; 24];
    dek_nonce.copy_from_slice(&raw[72..96]);
    let mut wrapped_dek = [0u8; 48];
    wrapped_dek.copy_from_slice(&raw[96..144]);
    let mut body_nonce = [0u8; 24];
    body_nonce.copy_from_slice(&raw[144..168]);
    Ok(SuperHeader {
        kdf_memory_kib: u32::from_le_bytes(raw[12..16].try_into().unwrap()),
        kdf_iterations: u32::from_le_bytes(raw[16..20].try_into().unwrap()),
        kdf_parallelism: u32::from_le_bytes(raw[20..24].try_into().unwrap()),
        salt,
        volume_id,
        dek_nonce,
        wrapped_dek,
        body_nonce,
    })
}

pub fn sealed_body<'a>(raw: &'a [u8]) -> Result<&'a [u8]> {
    if raw.len() != SUPER_SIZE {
        return Err(Error::Corrupt("superblock size".into()));
    }
    Ok(&raw[HEADER_LEN..HEADER_LEN + BODY_SEALED_LEN])
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InodeRecord {
    pub kind: u8,
    pub inode_id: u64,
    pub created: i64,
    pub modified: i64,
    pub size: u64,
    pub key_nonce: [u8; 24],
    pub wrapped_key: [u8; 48],
    pub blocks: Vec<u64>,
    pub parity: Vec<u64>,
}

pub fn encode_inode_record(record: &InodeRecord) -> Vec<u8> {
    let mut out = Vec::with_capacity(120 + record.blocks.len() * 8 + record.parity.len() * 8);
    out.extend_from_slice(b"INOD");
    out.extend_from_slice(&2u16.to_le_bytes());
    out.push(record.kind);
    out.push(0);
    out.extend_from_slice(&record.inode_id.to_le_bytes());
    out.extend_from_slice(&record.created.to_le_bytes());
    out.extend_from_slice(&record.modified.to_le_bytes());
    out.extend_from_slice(&record.size.to_le_bytes());
    out.extend_from_slice(&record.key_nonce);
    out.extend_from_slice(&record.wrapped_key);
    out.extend_from_slice(&(record.blocks.len() as u32).to_le_bytes());
    for block in &record.blocks {
        out.extend_from_slice(&block.to_le_bytes());
    }
    out.extend_from_slice(&(record.parity.len() as u32).to_le_bytes());
    for block in &record.parity {
        out.extend_from_slice(&block.to_le_bytes());
    }
    out
}

pub fn decode_inode_record(bytes: &[u8]) -> Result<InodeRecord> {
    if bytes.len() < 120 || &bytes[0..4] != b"INOD" {
        return Err(Error::Corrupt("inode magic".into()));
    }
    let version = u16::from_le_bytes(bytes[4..6].try_into().unwrap());
    if version != 2 || bytes[7] != 0 {
        return Err(Error::Corrupt("inode version".into()));
    }
    let kind = bytes[6];
    if kind != KIND_DIR && kind != KIND_FILE {
        return Err(Error::Corrupt("inode kind".into()));
    }
    let n = u32::from_le_bytes(bytes[112..116].try_into().unwrap()) as usize;
    if n > 10_000_000 || bytes.len() < 120 + n * 8 {
        return Err(Error::Corrupt("inode block list".into()));
    }
    let mut blocks = Vec::with_capacity(n);
    for i in 0..n {
        let start = 116 + i * 8;
        blocks.push(u64::from_le_bytes(
            bytes[start..start + 8].try_into().unwrap(),
        ));
    }
    let parity_at = 116 + n * 8;
    let p = u32::from_le_bytes(bytes[parity_at..parity_at + 4].try_into().unwrap()) as usize;
    if p > 10_000_000 || bytes.len() != parity_at + 4 + p * 8 {
        return Err(Error::Corrupt("inode record length".into()));
    }
    let mut parity = Vec::with_capacity(p);
    for i in 0..p {
        let start = parity_at + 4 + i * 8;
        parity.push(u64::from_le_bytes(
            bytes[start..start + 8].try_into().unwrap(),
        ));
    }
    let mut key_nonce = [0u8; 24];
    key_nonce.copy_from_slice(&bytes[40..64]);
    let mut wrapped_key = [0u8; 48];
    wrapped_key.copy_from_slice(&bytes[64..112]);
    Ok(InodeRecord {
        kind,
        inode_id: u64::from_le_bytes(bytes[8..16].try_into().unwrap()),
        created: i64::from_le_bytes(bytes[16..24].try_into().unwrap()),
        modified: i64::from_le_bytes(bytes[24..32].try_into().unwrap()),
        size: u64::from_le_bytes(bytes[32..40].try_into().unwrap()),
        key_nonce,
        wrapped_key,
        blocks,
        parity,
    })
}

pub fn inode_chain_blocks(content_blocks: u64) -> u64 {
    let parity = content_parity_len(content_blocks);
    let record = 120u64
        .saturating_add(content_blocks.saturating_mul(8))
        .saturating_add(parity.saturating_mul(8));
    div_ceil(record.max(1), (PAYLOAD - 12) as u64).max(1)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RawEntry {
    pub name: String,
    pub inode_id: u64,
    pub kind: u8,
    pub inode_block: u64,
    pub size: u64,
    /// Parity blocks for this inode's chain, three per stripe of chain blocks.
    pub chain_parity: Vec<u64>,
}

pub fn encode_entries(entries: &[RawEntry]) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    let mut previous: Option<&str> = None;
    for entry in entries {
        validate_component(&entry.name)?;
        if entry.kind != KIND_DIR && entry.kind != KIND_FILE {
            return Err(Error::Corrupt("directory entry kind".into()));
        }
        if let Some(prev) = previous {
            if prev.as_bytes() >= entry.name.as_bytes() {
                return Err(Error::Corrupt("directory entries are not sorted".into()));
            }
        }
        previous = Some(&entry.name);
        let bytes = entry.name.as_bytes();
        out.extend_from_slice(&(bytes.len() as u16).to_le_bytes());
        out.extend_from_slice(bytes);
        out.extend_from_slice(&entry.inode_id.to_le_bytes());
        out.push(entry.kind);
        out.extend_from_slice(&entry.inode_block.to_le_bytes());
        out.extend_from_slice(&entry.size.to_le_bytes());
        if entry.chain_parity.is_empty()
            || entry.chain_parity.len() > 4096
            || entry.chain_parity.len() % PARITY_COUNT as usize != 0
        {
            return Err(Error::Corrupt("directory entry parity".into()));
        }
        out.extend_from_slice(&(entry.chain_parity.len() as u16).to_le_bytes());
        for block in &entry.chain_parity {
            out.extend_from_slice(&block.to_le_bytes());
        }
    }
    Ok(out)
}

pub fn decode_entries(bytes: &[u8]) -> Result<Vec<RawEntry>> {
    let mut entries = Vec::new();
    let mut offset = 0;
    while offset < bytes.len() {
        if bytes.len() - offset < 2 {
            return Err(Error::Corrupt("truncated directory entry".into()));
        }
        let name_len = u16::from_le_bytes(bytes[offset..offset + 2].try_into().unwrap()) as usize;
        offset += 2;
        if name_len == 0
            || name_len > MAX_NAME_BYTES
            || bytes.len() - offset < name_len + 8 + 1 + 8 + 8
        {
            return Err(Error::Corrupt("bad directory entry".into()));
        }
        let name_bytes = &bytes[offset..offset + name_len];
        offset += name_len;
        let name = std::str::from_utf8(name_bytes)
            .map_err(|_| Error::Corrupt("directory name is not utf-8".into()))?
            .to_string();
        validate_component(&name)?;
        let inode_id = u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap());
        offset += 8;
        let kind = bytes[offset];
        offset += 1;
        if kind != KIND_DIR && kind != KIND_FILE {
            return Err(Error::Corrupt("directory entry kind".into()));
        }
        let inode_block = u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap());
        offset += 8;
        let size = u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap());
        offset += 8;
        if bytes.len() - offset < 2 {
            return Err(Error::Corrupt("truncated directory entry".into()));
        }
        let parity_count =
            u16::from_le_bytes(bytes[offset..offset + 2].try_into().unwrap()) as usize;
        offset += 2;
        if parity_count == 0
            || parity_count > 4096
            || parity_count % PARITY_COUNT as usize != 0
            || bytes.len() - offset < parity_count * 8
        {
            return Err(Error::Corrupt("directory entry parity".into()));
        }
        let mut chain_parity = Vec::with_capacity(parity_count);
        for _ in 0..parity_count {
            chain_parity.push(u64::from_le_bytes(
                bytes[offset..offset + 8].try_into().unwrap(),
            ));
            offset += 8;
        }
        if inode_id == 0 {
            return Err(Error::Corrupt("directory entry inode".into()));
        }
        entries.push(RawEntry {
            name,
            inode_id,
            kind,
            inode_block,
            size,
            chain_parity,
        });
    }
    for pair in entries.windows(2) {
        if pair[0].name.as_bytes() >= pair[1].name.as_bytes() {
            return Err(Error::Corrupt("directory entries are not sorted".into()));
        }
    }
    Ok(entries)
}

/// Which superblock copy wins. The highest generation wins. Ties prefer the lower index.
pub fn prefer_index(generations: &[Option<u64>]) -> Result<usize> {
    let mut best: Option<(u64, usize)> = None;
    for (index, generation) in generations.iter().enumerate() {
        if let Some(generation) = generation {
            match best {
                Some((winner, _)) if *generation <= winner => {}
                _ => best = Some((*generation, index)),
            }
        }
    }
    best.map(|(_, index)| index)
        .ok_or_else(|| Error::Corrupt("no readable superblock".into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn geometry_matches_the_documented_minimum() {
        let (blocks, start, data) = geometry(16).unwrap();
        assert_eq!((blocks, start, data), (1, 8, 8));
        assert!(geometry(15).is_err());
        assert_eq!(minimum_volume_bytes(), HEADER_BYTES + 16 * BLOCK_SIZE);
        let total = 16 + 10_000_000;
        let (blocks, start, data) = geometry(total).unwrap();
        assert_eq!(start + data, total);
        assert_eq!(start, slot_span(u64::from(blocks)) * 2);
        let bytes = (data + 7) / 8;
        let need = div_ceil(bytes, PAYLOAD as u64);
        assert!(u64::from(blocks) >= need);
        assert!(blocks > 1);
    }

    #[test]
    fn superblock_body_roundtrip() {
        let body = SuperBody {
            generation: 4,
            total_physical: 16,
            allocatable_start: 8,
            data_block_count: 8,
            used_blocks: 4,
            next_inode_id: 2,
            root_inode_id: 1,
            root_inode_block: 8,
            created_unix: 1_700_000_000,
            bitmap_slot: 1,
            bitmap_blocks_per_slot: 1,
            flags: 0,
            root_parity: [9, 10, 11],
        };
        let encoded = encode_body(&body);
        assert_eq!(decode_body(&encoded).unwrap(), body);
    }

    #[test]
    fn directory_entries_roundtrip_and_reject_order() {
        let entries = vec![
            RawEntry {
                name: "a".into(),
                inode_id: 2,
                kind: KIND_FILE,
                inode_block: 3,
                size: 4,
                chain_parity: vec![5, 6, 7],
            },
            RawEntry {
                name: "b".into(),
                inode_id: 3,
                kind: KIND_DIR,
                inode_block: 4,
                size: 0,
                chain_parity: vec![8, 9, 10],
            },
        ];
        let bytes = encode_entries(&entries).unwrap();
        assert_eq!(decode_entries(&bytes).unwrap(), entries);
        let mut reversed = entries.clone();
        reversed.reverse();
        assert!(encode_entries(&reversed).is_err());
    }

    #[test]
    fn generation_preference() {
        assert_eq!(prefer_index(&[Some(1), Some(1), Some(1)]).unwrap(), 0);
        assert_eq!(prefer_index(&[Some(1), Some(2), Some(2)]).unwrap(), 1);
        assert_eq!(prefer_index(&[Some(3), None, None]).unwrap(), 0);
        assert_eq!(prefer_index(&[None, None, Some(4)]).unwrap(), 2);
        assert!(prefer_index(&[None, None, None]).is_err());
    }
}
