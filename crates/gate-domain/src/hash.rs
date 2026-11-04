//! SHA-256 (FIPS 180-4), hex and base64url encoding, and a constant-time comparison.
//!
//! The digest is implemented here instead of pulled from a crate so that the workspace keeps a
//! single third-party dependency (see ADR 4). It is checked against the NIST test vectors and
//! against the system `sha256sum` in the end-to-end tests.

const K: [u32; 64] = [
    0x428a_2f98,
    0x7137_4491,
    0xb5c0_fbcf,
    0xe9b5_dba5,
    0x3956_c25b,
    0x59f1_11f1,
    0x923f_82a4,
    0xab1c_5ed5,
    0xd807_aa98,
    0x1283_5b01,
    0x2431_85be,
    0x550c_7dc3,
    0x72be_5d74,
    0x80de_b1fe,
    0x9bdc_06a7,
    0xc19b_f174,
    0xe49b_69c1,
    0xefbe_4786,
    0x0fc1_9dc6,
    0x240c_a1cc,
    0x2de9_2c6f,
    0x4a74_84aa,
    0x5cb0_a9dc,
    0x76f9_88da,
    0x983e_5152,
    0xa831_c66d,
    0xb003_27c8,
    0xbf59_7fc7,
    0xc6e0_0bf3,
    0xd5a7_9147,
    0x06ca_6351,
    0x1429_2967,
    0x27b7_0a85,
    0x2e1b_2138,
    0x4d2c_6dfc,
    0x5338_0d13,
    0x650a_7354,
    0x766a_0abb,
    0x81c2_c92e,
    0x9272_2c85,
    0xa2bf_e8a1,
    0xa81a_664b,
    0xc24b_8b70,
    0xc76c_51a3,
    0xd192_e819,
    0xd699_0624,
    0xf40e_3585,
    0x106a_a070,
    0x19a4_c116,
    0x1e37_6c08,
    0x2748_774c,
    0x34b0_bcb5,
    0x391c_0cb3,
    0x4ed8_aa4a,
    0x5b9c_ca4f,
    0x682e_6ff3,
    0x748f_82ee,
    0x78a5_636f,
    0x84c8_7814,
    0x8cc7_0208,
    0x90be_fffa,
    0xa450_6ceb,
    0xbef9_a3f7,
    0xc671_78f2,
];

const INITIAL: [u32; 8] = [
    0x6a09_e667,
    0xbb67_ae85,
    0x3c6e_f372,
    0xa54f_f53a,
    0x510e_527f,
    0x9b05_688c,
    0x1f83_d9ab,
    0x5be0_cd19,
];

/// Incremental SHA-256.
#[derive(Clone)]
pub struct Sha256 {
    state: [u32; 8],
    buf: [u8; 64],
    buf_len: usize,
    total_len: u64,
}

impl Default for Sha256 {
    fn default() -> Self {
        Self::new()
    }
}

impl Sha256 {
    pub fn new() -> Self {
        Sha256 {
            state: INITIAL,
            buf: [0; 64],
            buf_len: 0,
            total_len: 0,
        }
    }

    pub fn update(&mut self, mut data: &[u8]) {
        self.total_len = self.total_len.wrapping_add(data.len() as u64);
        if self.buf_len > 0 {
            let take = (64 - self.buf_len).min(data.len());
            let (head, rest) = data.split_at(take);
            if let Some(dst) = self.buf.get_mut(self.buf_len..self.buf_len + take) {
                dst.copy_from_slice(head);
            }
            self.buf_len += take;
            data = rest;
            if self.buf_len < 64 {
                return;
            }
            let block = self.buf;
            compress(&mut self.state, &block);
            self.buf_len = 0;
        }
        let mut blocks = data.chunks_exact(64);
        for block in &mut blocks {
            if let Ok(block) = <&[u8; 64]>::try_from(block) {
                compress(&mut self.state, block);
            }
        }
        let rest = blocks.remainder();
        if let Some(dst) = self.buf.get_mut(..rest.len()) {
            dst.copy_from_slice(rest);
        }
        self.buf_len = rest.len();
    }

    pub fn finalize(mut self) -> [u8; 32] {
        let bit_len = self.total_len.wrapping_mul(8);
        let pad_len = if self.buf_len < 56 {
            56 - self.buf_len
        } else {
            120 - self.buf_len
        };
        let mut pad = [0u8; 72];
        if let Some(first) = pad.first_mut() {
            *first = 0x80;
        }
        if let Some(pad) = pad.get(..pad_len) {
            self.update_without_count(pad);
        }
        self.update_without_count(&bit_len.to_be_bytes());
        let mut out = [0u8; 32];
        for (chunk, word) in out.chunks_exact_mut(4).zip(self.state.iter()) {
            chunk.copy_from_slice(&word.to_be_bytes());
        }
        out
    }

    fn update_without_count(&mut self, data: &[u8]) {
        let before = self.total_len;
        self.update(data);
        self.total_len = before;
    }
}

// The message schedule and the 64 rounds index fixed-size arrays with loop bounds that are
// compile-time constants; an iterator formulation would be harder to check against the standard.
#[allow(clippy::indexing_slicing)]
fn compress(state: &mut [u32; 8], block: &[u8; 64]) {
    let mut w = [0u32; 64];
    for (slot, chunk) in w.iter_mut().zip(block.chunks_exact(4)) {
        *slot = u32::from_be_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
    }
    for i in 16..64 {
        let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
        let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16]
            .wrapping_add(s0)
            .wrapping_add(w[i - 7])
            .wrapping_add(s1);
    }
    let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = *state;
    for i in 0..64 {
        let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
        let ch = (e & f) ^ (!e & g);
        let t1 = h
            .wrapping_add(s1)
            .wrapping_add(ch)
            .wrapping_add(K[i])
            .wrapping_add(w[i]);
        let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
        let maj = (a & b) ^ (a & c) ^ (b & c);
        let t2 = s0.wrapping_add(maj);
        h = g;
        g = f;
        f = e;
        e = d.wrapping_add(t1);
        d = c;
        c = b;
        b = a;
        a = t1.wrapping_add(t2);
    }
    for (s, v) in state.iter_mut().zip([a, b, c, d, e, f, g, h]) {
        *s = s.wrapping_add(v);
    }
}

/// SHA-256 of `data` in one call.
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(data);
    h.finalize()
}

/// Looks a digit up in an encoding table; the callers pass indexes below the table length.
fn table_char(table: &[u8], index: usize) -> char {
    table.get(index).copied().map_or('?', char::from)
}

const HEX: &[u8; 16] = b"0123456789abcdef";

/// Lowercase hexadecimal.
pub fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(table_char(HEX, usize::from(b >> 4)));
        s.push(table_char(HEX, usize::from(b & 0x0f)));
    }
    s
}

/// Decodes exactly `N` bytes from `2 * N` hexadecimal digits (either case).
pub fn hex_decode_array<const N: usize>(text: &str) -> Option<[u8; N]> {
    if text.len() != N * 2 || !text.is_ascii() {
        return None;
    }
    let mut out = [0u8; N];
    for (slot, pair) in out.iter_mut().zip(text.as_bytes().chunks_exact(2)) {
        let hi = hex_value(*pair.first()?)?;
        let lo = hex_value(*pair.get(1)?)?;
        *slot = hi << 4 | lo;
    }
    Some(out)
}

fn hex_value(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

const B64URL: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// Base64url without padding (RFC 4648 section 5).
pub fn base64url_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b0 = u32::from(chunk.first().copied().unwrap_or(0));
        let b1 = u32::from(chunk.get(1).copied().unwrap_or(0));
        let b2 = u32::from(chunk.get(2).copied().unwrap_or(0));
        let n = b0 << 16 | b1 << 8 | b2;
        let chars = chunk.len() + 1;
        for i in 0..chars {
            let idx = usize::try_from((n >> (18 - 6 * i)) & 0x3f).unwrap_or(0);
            s.push(table_char(B64URL, idx));
        }
    }
    s
}

/// Compares two byte strings without stopping at the first difference. The time depends on the
/// length of the inputs, never on where they differ. Different lengths compare unequal (the
/// lengths of digests are public).
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    std::hint::black_box(diff) == 0
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
    use super::*;

    fn hex(data: &[u8]) -> String {
        hex_encode(&sha256(data))
    }

    #[test]
    fn nist_vectors() {
        assert_eq!(
            hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            hex(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"),
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
        );
        assert_eq!(
            hex(b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu"),
            "cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1"
        );
    }

    #[test]
    fn million_a() {
        let mut h = Sha256::new();
        let chunk = [b'a'; 1000];
        for _ in 0..1000 {
            h.update(&chunk);
        }
        assert_eq!(
            hex_encode(&h.finalize()),
            "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"
        );
    }

    #[test]
    fn split_updates_match_one_shot_at_every_boundary() {
        let data: Vec<u8> = (0..300u32).map(|i| (i * 7 % 251) as u8).collect();
        let whole = sha256(&data);
        for split in 0..data.len() {
            let mut h = Sha256::new();
            h.update(&data[..split]);
            h.update(&data[split..]);
            assert_eq!(h.finalize(), whole, "split at {split}");
        }
    }

    #[test]
    fn padding_boundaries() {
        // lengths around the 55/56/64 byte padding edges agree with incremental feeding byte by byte
        for len in [0usize, 1, 54, 55, 56, 57, 63, 64, 65, 119, 120, 127, 128] {
            let data = vec![0x61u8; len];
            let mut h = Sha256::new();
            for b in &data {
                h.update(std::slice::from_ref(b));
            }
            assert_eq!(h.finalize(), sha256(&data), "len {len}");
        }
    }

    #[test]
    fn hex_roundtrip_and_rejects() {
        let digest = sha256(b"x");
        let text = hex_encode(&digest);
        assert_eq!(hex_decode_array::<32>(&text), Some(digest));
        assert_eq!(hex_decode_array::<32>(&text.to_uppercase()), Some(digest));
        assert_eq!(hex_decode_array::<32>(&text[..63]), None);
        assert_eq!(hex_decode_array::<32>(&format!("{}g", &text[..63])), None);
        assert_eq!(hex_decode_array::<2>("é1"), None);
    }

    #[test]
    fn base64url_vectors() {
        assert_eq!(base64url_encode(b""), "");
        assert_eq!(base64url_encode(b"f"), "Zg");
        assert_eq!(base64url_encode(b"fo"), "Zm8");
        assert_eq!(base64url_encode(b"foo"), "Zm9v");
        assert_eq!(base64url_encode(b"foob"), "Zm9vYg");
        assert_eq!(base64url_encode(&[0xfb, 0xff, 0xbf]), "-_-_");
        assert_eq!(base64url_encode(&[0u8; 32]).len(), 43);
    }

    #[test]
    fn ct_eq_agrees_with_eq() {
        let cases: [(&[u8], &[u8]); 6] = [
            (b"", b""),
            (b"a", b"a"),
            (b"a", b"b"),
            (b"ab", b"a"),
            (b"abc", b"abd"),
            (b"xbc", b"abc"),
        ];
        for (a, b) in cases {
            assert_eq!(ct_eq(a, b), a == b);
        }
    }

    #[test]
    fn ct_eq_property_over_pseudo_random_inputs() {
        // a tiny xorshift generator keeps the test deterministic without a dependency
        let mut x = 0x2545_f491_4f6c_dd1du64;
        let mut next = move || {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x
        };
        for _ in 0..2000 {
            let len = (next() % 40) as usize;
            let a: Vec<u8> = (0..len).map(|_| next() as u8).collect();
            let mut b = a.clone();
            assert!(ct_eq(&a, &b));
            if len > 0 {
                let i = (next() as usize) % len;
                b[i] ^= 1 << (next() % 8);
                assert!(
                    !ct_eq(&a, &b),
                    "a single flipped bit at {i} must be detected"
                );
            }
            let other: Vec<u8> = (0..(next() % 40) as usize).map(|_| next() as u8).collect();
            assert_eq!(ct_eq(&a, &other), a == other);
        }
    }
}
