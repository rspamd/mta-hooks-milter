//! Milter framing and constants, following Rspamd's milter{,_internal}.h.
//! A frame is a big-endian u32 length (including command byte), then payload.
use bytes::Bytes;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub const VERSION: u32 = 6;
pub const BODY_CHUNK: usize = 65_536;
pub const ADD_HEADERS: u32 = 1;
pub const CHANGE_BODY: u32 = 1 << 1;
pub const ADD_RECIPIENT: u32 = 1 << 2;
pub const DELETE_RECIPIENT: u32 = 1 << 3;
pub const CHANGE_HEADERS: u32 = 1 << 4;
pub const QUARANTINE: u32 = 1 << 5;
pub const CHANGE_FROM: u32 = 1 << 6;
pub const ADD_RECIPIENT_PAR: u32 = 1 << 7;
pub const SUPPORTED_ACTIONS: u32 = ADD_HEADERS
    | CHANGE_BODY
    | ADD_RECIPIENT
    | DELETE_RECIPIENT
    | CHANGE_HEADERS
    | QUARANTINE
    | CHANGE_FROM
    | ADD_RECIPIENT_PAR;
pub const NR_HEADER: u32 = 1 << 7;
pub const NR_CONNECT: u32 = 1 << 12;
pub const NR_HELO: u32 = 1 << 13;
pub const NR_MAIL: u32 = 1 << 14;
pub const NR_RCPT: u32 = 1 << 15;
pub const NR_DATA: u32 = 1 << 16;
pub const NR_UNKNOWN: u32 = 1 << 17;
pub const NR_EOH: u32 = 1 << 18;
pub const NR_BODY: u32 = 1 << 19;
pub const HEADER_LEADING_SPACE: u32 = 1 << 20;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("I/O: {0}")]
    Io(#[from] std::io::Error),
    #[error("invalid milter input: {0}")]
    Invalid(&'static str),
    #[error("milter limit exceeded: {0}")]
    Limit(&'static str),
    #[error("command {command:#x} is invalid in state {state}")]
    Sequence { command: u8, state: &'static str },
    #[error("operation was not negotiated")]
    NotNegotiated,
    #[error("operation timed out")]
    Timeout,
    #[error("policy failed: {0}")]
    Policy(String),
    #[error("HTTP transport failure ({0})")]
    HttpTransport(HttpErrorKind),
    #[error("unexpected HTTP status {0}")]
    HttpStatus(u16),
}

/// Sanitized transport categories: never retain URLs or upstream error text.
#[derive(Clone, Copy, Debug, thiserror::Error)]
pub enum HttpErrorKind {
    #[error("timeout")]
    Timeout,
    #[error("connect")]
    Connect,
    #[error("request")]
    Request,
    #[error("body")]
    Body,
    #[error("decode")]
    Decode,
    #[error("transport")]
    Other,
}

impl Error {
    /// Fixed, low-cardinality label, safe for logs and metrics.
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Timeout | Self::HttpTransport(HttpErrorKind::Timeout) => "timeout",
            Self::HttpTransport(HttpErrorKind::Connect) => "connect",
            Self::HttpTransport(HttpErrorKind::Request) => "request",
            Self::HttpTransport(HttpErrorKind::Body) => "body",
            Self::HttpTransport(HttpErrorKind::Decode) => "decode",
            Self::HttpTransport(HttpErrorKind::Other) => "transport",
            Self::HttpStatus(_) => "http_status",
            Self::Io(_) => "io",
            Self::Invalid(_) => "invalid",
            Self::Limit(_) => "limit",
            Self::Sequence { .. } => "protocol",
            Self::NotNegotiated => "capability",
            Self::Policy(_) => "upstream",
        }
    }
}
pub type Result<T> = std::result::Result<T, Error>;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Frame {
    pub command: u8,
    pub payload: Bytes,
}
impl Frame {
    pub fn new(command: u8, payload: impl Into<Bytes>) -> Self {
        Self {
            command,
            payload: payload.into(),
        }
    }
    pub fn empty(command: u8) -> Self {
        Self::new(command, Bytes::new())
    }
    pub fn encode(&self) -> Result<Vec<u8>> {
        let size = self
            .payload
            .len()
            .checked_add(1)
            .and_then(|n| u32::try_from(n).ok())
            .ok_or(Error::Limit("frame"))?;
        let mut out = Vec::with_capacity(size as usize + 4);
        out.extend_from_slice(&size.to_be_bytes());
        out.push(self.command);
        out.extend_from_slice(&self.payload);
        Ok(out)
    }
}

/// EOF at a frame boundary is normal; EOF inside a frame is an error.
/// Callers must discard the stream if this future is cancelled midway.
pub async fn read_frame<R: AsyncRead + Unpin>(r: &mut R, max: usize) -> Result<Option<Frame>> {
    let mut first = [0; 1];
    if r.read(&mut first).await? == 0 {
        return Ok(None);
    }
    read_frame_after_start(r, first[0], max).await.map(Some)
}

/// Complete a frame after its first length byte has already been consumed.
/// This lets the driver apply a separate deadline to idle and partial reads.
pub(crate) async fn read_frame_after_start<R: AsyncRead + Unpin>(
    r: &mut R,
    first: u8,
    max: usize,
) -> Result<Frame> {
    let mut length = [first, 0, 0, 0];
    r.read_exact(&mut length[1..]).await?;
    let length = u32::from_be_bytes(length) as usize;
    if length == 0 {
        return Err(Error::Invalid("zero frame length"));
    }
    if length > max {
        return Err(Error::Limit("frame"));
    }
    let mut data = vec![0; length];
    r.read_exact(&mut data).await?;
    let data = Bytes::from(data);
    Ok(Frame::new(data[0], data.slice(1..)))
}
pub async fn write_frame<W: AsyncWrite + Unpin>(w: &mut W, frame: &Frame) -> Result<()> {
    w.write_all(&frame.encode()?).await?;
    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Options {
    pub version: u32,
    pub actions: u32,
    pub protocol: u32,
}
impl Options {
    pub fn frame(&self) -> Frame {
        let mut p = Vec::with_capacity(12);
        for n in [self.version, self.actions, self.protocol] {
            p.extend_from_slice(&n.to_be_bytes());
        }
        Frame::new(b'O', p)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Connection {
    pub hostname: Bytes,
    pub family: u8,
    pub port: Option<u16>,
    pub address: Option<Bytes>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Command {
    Negotiate(Options),
    Connect(Connection),
    Macro {
        stage: u8,
        values: Vec<(Bytes, Bytes)>,
    },
    Helo(Bytes),
    Mail(Vec<Bytes>),
    Recipient(Vec<Bytes>),
    Data,
    Header {
        name: Bytes,
        value: Bytes,
    },
    EndHeaders,
    Body(Bytes),
    EndMessage,
    Abort,
    Quit,
    QuitNewConnection,
    Unknown(Bytes),
}
impl Command {
    pub fn decode(f: Frame) -> Result<Self> {
        let p = f.payload;
        Ok(match f.command {
            b'O' => {
                if p.len() != 12 {
                    return Err(Error::Invalid("negotiation length"));
                }
                let n = |i| u32::from_be_bytes(p[i..i + 4].try_into().expect("checked length"));
                Self::Negotiate(Options {
                    version: n(0),
                    actions: n(4),
                    protocol: n(8),
                })
            }
            b'C' => {
                let end = p
                    .iter()
                    .position(|c| *c == 0)
                    .ok_or(Error::Invalid("connect hostname"))?;
                let hostname = p.slice(..end);
                let family = *p.get(end + 1).ok_or(Error::Invalid("connect family"))?;
                let tail = p.slice(end + 2..);
                let (port, address) = match family {
                    b'U' if tail.is_empty() => (None, None),
                    b'4' | b'6' | b'L' => {
                        if tail.len() < 3 {
                            return Err(Error::Invalid("connect address"));
                        }
                        let fields = strings(tail.slice(2..))?;
                        if fields.len() != 1 {
                            return Err(Error::Invalid("connect address count"));
                        }
                        let address = fields[0].clone();
                        if family != b'L' {
                            let text = std::str::from_utf8(&address)
                                .map_err(|_| Error::Invalid("IP encoding"))?;
                            let text = text.strip_prefix("IPv6:").unwrap_or(text);
                            let text = text
                                .strip_prefix('[')
                                .and_then(|s| s.strip_suffix(']'))
                                .unwrap_or(text);
                            let ip: std::net::IpAddr =
                                text.parse().map_err(|_| Error::Invalid("IP address"))?;
                            if (family == b'4') != ip.is_ipv4() {
                                return Err(Error::Invalid("IP family"));
                            }
                        }
                        (Some(u16::from_be_bytes([tail[0], tail[1]])), Some(address))
                    }
                    _ => return Err(Error::Invalid("connect family or trailing bytes")),
                };
                Self::Connect(Connection {
                    hostname,
                    family,
                    port,
                    address,
                })
            }
            b'D' => {
                let stage = *p.first().ok_or(Error::Invalid("macro stage"))?;
                if !b"CHMRTUNELB".contains(&stage) {
                    return Err(Error::Invalid("macro stage"));
                }
                let fields = strings(p.slice(1..))?;
                if fields.len() % 2 != 0 {
                    return Err(Error::Invalid("macro pair"));
                }
                let mut values = Vec::new();
                for pair in fields.chunks_exact(2) {
                    if pair[0].is_empty() {
                        return Err(Error::Invalid("empty macro name"));
                    }
                    values.push((pair[0].clone(), pair[1].clone()));
                }
                Self::Macro { stage, values }
            }
            b'H' | b'U' => {
                let mut fields = strings(p)?;
                if fields.len() != 1 {
                    return Err(Error::Invalid("string count"));
                }
                let s = fields.remove(0);
                if f.command == b'H' {
                    Self::Helo(s)
                } else {
                    Self::Unknown(s)
                }
            }
            b'M' | b'R' => {
                let fields = strings(p)?;
                if fields.first().is_none_or(Bytes::is_empty) {
                    return Err(Error::Invalid("empty envelope"));
                }
                if f.command == b'M' {
                    Self::Mail(fields)
                } else {
                    Self::Recipient(fields)
                }
            }
            b'L' => {
                let fields = strings(p)?;
                if fields.len() != 2 || fields[0].is_empty() {
                    return Err(Error::Invalid("header fields"));
                }
                Self::Header {
                    name: fields[0].clone(),
                    value: fields[1].clone(),
                }
            }
            b'B' => Self::Body(p),
            b'T' | b'N' | b'E' | b'A' | b'Q' | b'K' => {
                if !p.is_empty() {
                    return Err(Error::Invalid("unexpected payload"));
                }
                match f.command {
                    b'T' => Self::Data,
                    b'N' => Self::EndHeaders,
                    b'E' => Self::EndMessage,
                    b'A' => Self::Abort,
                    b'Q' => Self::Quit,
                    _ => Self::QuitNewConnection,
                }
            }
            _ => return Err(Error::Invalid("unknown opcode")),
        })
    }
}

fn strings(p: Bytes) -> Result<Vec<Bytes>> {
    if p.is_empty() {
        return Ok(Vec::new());
    }
    if p.last() != Some(&0) {
        return Err(Error::Invalid("unterminated string"));
    }
    let mut result = Vec::new();
    let mut start = 0;
    for (i, b) in p.iter().enumerate() {
        if *b == 0 {
            result.push(p.slice(start..i));
            start = i + 1;
        }
    }
    Ok(result)
}

pub fn string_frame(command: u8, values: &[&[u8]]) -> Result<Frame> {
    let mut p = Vec::new();
    for value in values {
        if value.contains(&0) {
            return Err(Error::Invalid("NUL in response"));
        }
        p.extend_from_slice(value);
        p.push(0);
    }
    Ok(Frame::new(command, p))
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Modification {
    AddHeader {
        name: String,
        value: String,
    },
    /// Absolute, zero-based insertion index (SMFIR_INSHEADER).
    InsertHeader {
        index: u32,
        name: String,
        value: String,
    },
    /// One-based occurrence among headers with this name. Empty value deletes.
    ChangeHeader {
        occurrence: u32,
        name: String,
        value: String,
    },
    ReplaceBody(Bytes),
    ChangeFrom {
        address: String,
        parameters: Option<String>,
    },
    AddRecipient {
        address: String,
        parameters: Option<String>,
    },
    DeleteRecipient(String),
    Quarantine(String),
}
impl Modification {
    pub fn capability(&self) -> u32 {
        match self {
            Self::AddHeader { .. } | Self::InsertHeader { .. } => ADD_HEADERS,
            Self::ChangeHeader { .. } => CHANGE_HEADERS,
            Self::ReplaceBody(_) => CHANGE_BODY,
            Self::ChangeFrom { .. } => CHANGE_FROM,
            Self::AddRecipient {
                parameters: Some(_),
                ..
            } => ADD_RECIPIENT_PAR,
            Self::AddRecipient { .. } => ADD_RECIPIENT,
            Self::DeleteRecipient(_) => DELETE_RECIPIENT,
            Self::Quarantine(_) => QUARANTINE,
        }
    }
    /// Wire payload allocation size, checked before serializing a decision.
    pub fn payload_bytes(&self, leading_space: bool) -> Result<usize> {
        let parts = match self {
            Self::ReplaceBody(body) => [body.len(), 0, 0, 0],
            Self::AddHeader { name, value }
            | Self::InsertHeader { name, value, .. }
            | Self::ChangeHeader { name, value, .. } => [
                name.len(),
                value.len(),
                2 + usize::from(leading_space && !value.is_empty()),
                if matches!(self, Self::AddHeader { .. }) {
                    0
                } else {
                    4
                },
            ],
            Self::ChangeFrom {
                address,
                parameters,
            }
            | Self::AddRecipient {
                address,
                parameters,
            } => [
                address.len(),
                parameters.as_ref().map_or(0, String::len),
                1 + usize::from(parameters.is_some()),
                0,
            ],
            Self::DeleteRecipient(value) | Self::Quarantine(value) => [value.len(), 1, 0, 0],
        };
        parts.into_iter().try_fold(0usize, |n, part| {
            n.checked_add(part).ok_or(Error::Limit("output"))
        })
    }
    pub fn frames(&self, leading_space: bool) -> Result<Vec<Frame>> {
        match self {
            Self::ReplaceBody(body) => {
                if body.is_empty() {
                    return Ok(vec![Frame::empty(b'b')]);
                }
                Ok(body
                    .chunks(BODY_CHUNK)
                    .map(|chunk| Frame::new(b'b', Bytes::copy_from_slice(chunk)))
                    .collect())
            }
            Self::AddHeader { name, value }
            | Self::InsertHeader { name, value, .. }
            | Self::ChangeHeader { name, value, .. } => {
                if name.is_empty() || !name.bytes().all(|c| (33..=126).contains(&c) && c != b':') {
                    return Err(Error::Invalid("header name"));
                }
                // Unfolded output values only; raw input headers retain their bytes.
                clean(value)?;
                let value = if leading_space && !value.is_empty() {
                    format!(" {value}")
                } else {
                    value.clone()
                };
                let (cmd, idx) = match self {
                    Self::AddHeader { .. } => (b'h', None),
                    Self::InsertHeader { index, .. } => (b'i', Some(*index)),
                    Self::ChangeHeader { occurrence, .. } if *occurrence > 0 => {
                        (b'm', Some(*occurrence))
                    }
                    _ => return Err(Error::Invalid("header occurrence is one-based")),
                };
                let f = string_frame(cmd, &[name.as_bytes(), value.as_bytes()])?;
                if let Some(idx) = idx {
                    let mut p = idx.to_be_bytes().to_vec();
                    p.extend_from_slice(&f.payload);
                    Ok(vec![Frame::new(cmd, p)])
                } else {
                    Ok(vec![f])
                }
            }
            Self::ChangeFrom {
                address,
                parameters,
            }
            | Self::AddRecipient {
                address,
                parameters,
            } => {
                clean(address)?;
                if address.is_empty() {
                    return Err(Error::Invalid("empty address"));
                }
                let cmd = if matches!(self, Self::ChangeFrom { .. }) {
                    b'e'
                } else if parameters.is_some() {
                    b'2'
                } else {
                    b'+'
                };
                let mut values = vec![address.as_bytes()];
                if let Some(p) = parameters {
                    clean(p)?;
                    values.push(p.as_bytes());
                }
                Ok(vec![string_frame(cmd, &values)?])
            }
            Self::DeleteRecipient(s) | Self::Quarantine(s) => {
                clean(s)?;
                Ok(vec![string_frame(
                    if matches!(self, Self::Quarantine(_)) {
                        b'q'
                    } else {
                        b'-'
                    },
                    &[s.as_bytes()],
                )?])
            }
        }
    }
}
pub fn clean(value: &str) -> Result<()> {
    if value.bytes().any(|c| matches!(c, 0 | b'\r' | b'\n')) {
        return Err(Error::Invalid("control character in response"));
    }
    Ok(())
}
