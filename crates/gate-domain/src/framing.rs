//! Splitting the output of the upstream server into lines.
//!
//! MCP over stdio is newline-delimited JSON. The server's output is untrusted: a line can be
//! enormous or the stream can lack newlines altogether. The splitter bounds its memory by the
//! configured maximum, reports an oversized line once (with its beginning, so that the caller can
//! try to find out whose answer it was) and carries on with the next line.

/// How much of an oversized line is kept for the caller.
pub const HEAD_BYTES: usize = 256;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Line {
    /// A complete line without its terminator; never empty.
    Complete(Vec<u8>),
    /// A line longer than the maximum: its first bytes and its full length.
    Oversize { head: Vec<u8>, len: usize },
}

#[derive(Debug)]
pub struct LineSplitter {
    max_len: usize,
    buf: Vec<u8>,
    /// Total length of the current line once it passed the maximum, `None` before.
    oversize: Option<usize>,
}

impl LineSplitter {
    pub fn new(max_len: usize) -> LineSplitter {
        LineSplitter {
            max_len: max_len.max(1),
            buf: Vec::new(),
            oversize: None,
        }
    }

    /// Feeds a chunk read from the child and appends the lines it completes to `out`.
    pub fn push(&mut self, mut chunk: &[u8], out: &mut Vec<Line>) {
        while !chunk.is_empty() {
            let newline = chunk.iter().position(|&b| b == b'\n');
            let (segment, rest) = match newline {
                Some(at) => (
                    chunk.get(..at).unwrap_or_default(),
                    chunk.get(at + 1..).unwrap_or_default(),
                ),
                None => (chunk, &[][..]),
            };
            self.take_segment(segment);
            if newline.is_some() {
                self.end_line(out);
            }
            chunk = rest;
        }
    }

    fn take_segment(&mut self, segment: &[u8]) {
        match &mut self.oversize {
            Some(total) => *total = total.saturating_add(segment.len()),
            None => {
                if self.buf.len() + segment.len() > self.max_len {
                    let total = self.buf.len() + segment.len();
                    let keep = HEAD_BYTES.saturating_sub(self.buf.len()).min(segment.len());
                    self.buf
                        .extend_from_slice(segment.get(..keep).unwrap_or_default());
                    self.buf.truncate(HEAD_BYTES);
                    self.oversize = Some(total);
                } else {
                    self.buf.extend_from_slice(segment);
                }
            }
        }
    }

    fn end_line(&mut self, out: &mut Vec<Line>) {
        let mut line = std::mem::take(&mut self.buf);
        if let Some(len) = self.oversize.take() {
            out.push(Line::Oversize { head: line, len });
            return;
        }
        if line.last() == Some(&b'\r') {
            line.pop();
        }
        if !line.is_empty() {
            out.push(Line::Complete(line));
        }
    }

    /// Bytes of an unfinished line that are held back.
    pub fn pending_len(&self) -> usize {
        self.oversize.unwrap_or(self.buf.len())
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::indexing_slicing,
        clippy::panic
    )]
    use super::*;

    fn feed(max: usize, chunks: &[&[u8]]) -> (Vec<Line>, LineSplitter) {
        let mut s = LineSplitter::new(max);
        let mut out = Vec::new();
        for c in chunks {
            s.push(c, &mut out);
        }
        (out, s)
    }

    fn complete(s: &str) -> Line {
        Line::Complete(s.as_bytes().to_vec())
    }

    #[test]
    fn splits_lines_across_chunks() {
        let (out, s) = feed(
            100,
            &[b"{\"a\":1}\n{\"b\"", b":2}\n\n\r\n{\"c\":3}\r\npart"],
        );
        assert_eq!(
            out,
            vec![
                complete("{\"a\":1}"),
                complete("{\"b\":2}"),
                complete("{\"c\":3}")
            ]
        );
        assert_eq!(s.pending_len(), 4);
    }

    #[test]
    fn any_chunking_gives_the_same_lines() {
        let data = b"one\ntwo two\n\nthree\r\nfour";
        let (whole, _) = feed(100, &[data]);
        for cut in 0..data.len() {
            let (a, b) = data.split_at(cut);
            let (parts, _) = feed(100, &[a, b]);
            assert_eq!(parts, whole, "cut at {cut}");
        }
        let singles: Vec<&[u8]> = data.chunks(1).collect();
        assert_eq!(feed(100, &singles).0, whole);
    }

    #[test]
    fn a_line_of_exactly_the_maximum_passes() {
        let line = "x".repeat(10);
        let (out, _) = feed(10, &[line.as_bytes(), b"\n"]);
        assert_eq!(out, vec![complete(&line)]);
    }

    #[test]
    fn an_oversized_line_is_reported_once_and_skipped() {
        let big = "y".repeat(1000);
        let (out, s) = feed(10, &[b"ok\n", big.as_bytes(), big.as_bytes(), b"\nafter\n"]);
        assert_eq!(out.len(), 3);
        assert_eq!(out[0], complete("ok"));
        match &out[1] {
            Line::Oversize { head, len } => {
                assert_eq!(*len, 2000);
                assert_eq!(head.len(), HEAD_BYTES);
                assert!(head.iter().all(|&b| b == b'y'));
            }
            other => panic!("{other:?}"),
        }
        assert_eq!(out[2], complete("after"));
        assert_eq!(s.pending_len(), 0);
    }

    #[test]
    fn the_head_of_an_oversized_line_begins_with_the_line() {
        let line = format!(
            "{{\"jsonrpc\":\"2.0\",\"id\":42,\"result\":\"{}\"}}\n",
            "z".repeat(500)
        );
        let (out, _) = feed(50, &[line.as_bytes()]);
        match &out[0] {
            Line::Oversize { head, .. } => {
                assert!(head.starts_with(b"{\"jsonrpc\":\"2.0\",\"id\":42,"))
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn memory_stays_bounded_without_newlines() {
        let mut s = LineSplitter::new(1024);
        let mut out = Vec::new();
        let chunk = vec![b'a'; 65_536];
        for _ in 0..200 {
            s.push(&chunk, &mut out);
            assert!(s.buf.len() <= HEAD_BYTES.max(1024));
        }
        assert!(out.is_empty());
        assert_eq!(s.pending_len(), 200 * 65_536);
        s.push(b"\n", &mut out);
        assert_eq!(out.len(), 1);
    }

    #[test]
    fn binary_noise_does_not_panic() {
        let mut s = LineSplitter::new(8);
        let mut out = Vec::new();
        let noise: Vec<u8> = (0..5000u32)
            .map(|i| (i.wrapping_mul(2_654_435_761) >> 13) as u8)
            .collect();
        for c in noise.chunks(7) {
            s.push(c, &mut out);
        }
    }
}
