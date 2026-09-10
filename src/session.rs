use crate::protocol::{
    self as wire, Command, Connection, Error, Frame, MacroLists, Modification, Options, Result,
};
use bytes::Bytes;
use std::collections::BTreeMap;

#[derive(Clone, Debug)]
pub struct Limits {
    pub frame_bytes: usize,
    pub message_bytes: usize,
    pub envelope_bytes: usize,
    pub headers: usize,
    pub recipients: usize,
    pub macro_bytes: usize,
    pub modifications: usize,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            frame_bytes: 131_073,
            message_bytes: 25 * 1024 * 1024,
            envelope_bytes: 1024 * 1024,
            headers: 10_000,
            recipients: 1_000,
            macro_bytes: 65_536,
            modifications: 1_000,
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Stage {
    Connect,
    Helo,
    Mail,
    Recipient,
    EndMessage,
}
impl Stage {
    pub const ALL: [Self; 5] = [
        Self::Connect,
        Self::Helo,
        Self::Mail,
        Self::Recipient,
        Self::EndMessage,
    ];
    pub fn hook_name(self) -> &'static str {
        match self {
            Self::Connect => "connect",
            Self::Helo => "ehlo",
            Self::Mail => "mail",
            Self::Recipient => "rcpt",
            Self::EndMessage => "data",
        }
    }
    /// Parse an MTA Hooks inbound stage name.
    pub fn from_hook_name(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|s| s.hook_name() == name)
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    Initial,
    Negotiated,
    Ready,
    Mail,
    Recipients,
    Data,
    Headers,
    Body,
    Stopped,
    Closed,
}
impl State {
    fn name(self) -> &'static str {
        match self {
            Self::Initial => "initial",
            Self::Negotiated => "negotiated",
            Self::Ready => "ready",
            Self::Mail => "mail",
            Self::Recipients => "recipients",
            Self::Data => "data",
            Self::Headers => "headers",
            Self::Body => "body",
            Self::Stopped => "stopped",
            Self::Closed => "closed",
        }
    }
}
#[derive(Clone, Debug, Default)]
pub struct EnvelopeAddress {
    pub address: Bytes,
    pub parameters: Vec<Bytes>,
}
impl From<Vec<Bytes>> for EnvelopeAddress {
    fn from(mut fields: Vec<Bytes>) -> Self {
        let address = fields.remove(0);
        Self {
            address,
            parameters: fields,
        }
    }
}
#[derive(Clone, Debug, Default)]
pub struct Message {
    pub sender: Option<EnvelopeAddress>,
    pub recipients: Vec<EnvelopeAddress>,
    /// Names and values as received, including folding and negotiated leading space.
    pub headers: Vec<(Bytes, Bytes)>,
    pub body: Vec<u8>,
    bytes: usize,
    envelope_bytes: usize,
}
type Macros = BTreeMap<Bytes, Bytes>;

pub struct Session {
    pub state: State,
    pub options: Option<Options>,
    pub connection: Option<Connection>,
    pub helo: Option<Bytes>,
    pub message: Message,
    pub limits: Limits,
    macros: BTreeMap<u8, Macros>,
    pending_macros: BTreeMap<u8, Macros>,
    pending: Option<Stage>,
    stages: Vec<Stage>,
    wanted_actions: u32,
    macro_lists: MacroLists,
}
pub struct Step {
    pub frames: Vec<Frame>,
    pub event: Option<Stage>,
    pub close: bool,
}
impl Step {
    fn empty() -> Self {
        Self {
            frames: vec![],
            event: None,
            close: false,
        }
    }
}

#[derive(Clone, Debug, Default)]
pub enum Verdict {
    #[default]
    Continue,
    /// Finish filtering this message. Use Continue to retain later callbacks.
    Accept,
    Reject,
    Tempfail,
    Discard,
    Reply {
        code: u16,
        enhanced: Option<String>,
        message: String,
    },
    /// Ask the MTA to reply 421 and close the SMTP connection (SMFIR_SHUTDOWN).
    Shutdown,
}
#[derive(Clone, Debug, Default)]
pub struct Decision {
    pub verdict: Verdict,
    pub modifications: Vec<Modification>,
}

impl Session {
    pub fn new(limits: Limits, stages: Vec<Stage>, wanted_actions: u32) -> Self {
        Self {
            state: State::Initial,
            options: None,
            connection: None,
            helo: None,
            message: Message::default(),
            macros: BTreeMap::new(),
            pending_macros: BTreeMap::new(),
            pending: None,
            stages,
            wanted_actions: wanted_actions & wire::SUPPORTED_ACTIONS,
            limits,
            macro_lists: MacroLists::default(),
        }
    }
    /// Override the MTA's macro lists in the negotiation reply. Must be set
    /// before negotiation; an empty request keeps the MTA's configured lists.
    pub fn request_macros(&mut self, macro_lists: MacroLists) {
        self.macro_lists = macro_lists;
    }
    fn require(&self, cmd: u8, states: &[State]) -> Result<()> {
        if states.contains(&self.state) {
            Ok(())
        } else {
            Err(Error::Sequence {
                command: cmd,
                state: self.state.name(),
            })
        }
    }
    fn reset_message(&mut self) {
        self.message = Message::default();
        self.macros.retain(|s, _| matches!(s, b'C' | b'H'));
        self.pending_macros.retain(|s, _| matches!(s, b'C' | b'H'));
        self.pending = None;
    }
    fn activate_macros(&mut self, cmd: u8) {
        if let Some(values) = self.pending_macros.remove(&cmd) {
            self.macros.insert(cmd, values);
        } else {
            self.macros.remove(&cmd);
        }
    }
    pub fn macro_value(&self, name: &str) -> Option<&[u8]> {
        // Later protocol stages shadow earlier values; empty batches replace old batches.
        for stage in b"EBNLTURMHC" {
            if let Some(m) = self.macros.get(stage) {
                if let Some(v) = m.get(name.as_bytes()) {
                    return Some(v);
                }
                if let Some(v) = m.get(format!("{{{name}}}").as_bytes()) {
                    return Some(v);
                }
            }
        }
        None
    }
    fn account(&mut self, bytes: usize) -> Result<()> {
        self.message.bytes = self
            .message
            .bytes
            .checked_add(bytes)
            .ok_or(Error::Limit("message"))?;
        if self.message.bytes > self.limits.message_bytes {
            return Err(Error::Limit("message"));
        }
        Ok(())
    }
    pub fn leading_space(&self) -> bool {
        self.options
            .as_ref()
            .is_some_and(|o| o.protocol & wire::HEADER_LEADING_SPACE != 0)
    }
    /// The milter-visible RFC5322 view, not necessarily the entire Postfix queue file.
    pub fn raw_message(&self) -> Vec<u8> {
        let mut raw = Vec::with_capacity(self.message.bytes);
        for (name, value) in &self.message.headers {
            raw.extend_from_slice(name);
            raw.push(b':');
            if !self.leading_space() && !matches!(value.first(), Some(b'\r' | b'\n')) {
                raw.push(b' ');
            }
            raw.extend_from_slice(value);
            raw.extend_from_slice(b"\r\n");
        }
        raw.extend_from_slice(b"\r\n");
        raw.extend_from_slice(&self.message.body);
        raw
    }
    pub fn receive(&mut self, frame: Frame) -> Result<Step> {
        if self.pending.is_some() {
            return Err(Error::Invalid("callback has no decision yet"));
        }
        let opcode = frame.command;
        let command = Command::decode(frame)?;
        let mut step = Step::empty();
        if self.state == State::Closed {
            return Err(Error::Invalid("closed session"));
        }
        if let Command::Negotiate(offered) = command {
            self.require(opcode, &[State::Initial])?;
            if offered.version < wire::VERSION {
                return Err(Error::Invalid("milter v6 required"));
            }
            let mut protocol = wire::NR_HEADER
                | wire::NR_DATA
                | wire::NR_UNKNOWN
                | wire::NR_EOH
                | wire::NR_BODY
                | wire::HEADER_LEADING_SPACE;
            for (stage, flag) in [
                (Stage::Connect, wire::NR_CONNECT),
                (Stage::Helo, wire::NR_HELO),
                (Stage::Mail, wire::NR_MAIL),
                (Stage::Recipient, wire::NR_RCPT),
            ] {
                if !self.stages.contains(&stage) {
                    protocol |= flag;
                }
            }
            let options = Options {
                version: wire::VERSION,
                actions: offered.actions & self.wanted_actions,
                protocol: offered.protocol & protocol,
            };
            step.frames
                .push(options.frame_with_macros(&self.macro_lists)?);
            self.options = Some(options);
            self.state = State::Negotiated;
            return Ok(step);
        }
        if self.state == State::Initial {
            return Err(Error::Invalid("negotiate first"));
        }
        if let Command::Macro { stage, values } = command {
            let values: Macros = values.into_iter().collect();
            self.pending_macros.insert(stage, values);
            let total: usize = self
                .macros
                .values()
                .chain(self.pending_macros.values())
                .flat_map(|m| m.iter())
                .map(|(k, v)| k.len() + v.len())
                .sum();
            if total > self.limits.macro_bytes {
                return Err(Error::Limit("macros"));
            }
            return Ok(step);
        }
        // MAIL may have received its macro batch before the transaction reset.
        let mail_macros = if matches!(command, Command::Mail(_)) {
            self.pending_macros.remove(&b'M')
        } else {
            None
        };
        if matches!(command, Command::Mail(_)) {
            self.require(opcode, &[State::Ready])?;
            self.reset_message();
            if let Some(values) = mail_macros {
                self.pending_macros.insert(b'M', values);
            }
        }
        self.activate_macros(opcode);
        let mut reply_bit = None;
        match command {
            Command::Connect(info) => {
                self.require(opcode, &[State::Negotiated])?;
                self.connection = Some(info);
                self.state = State::Ready;
                step.event = Some(Stage::Connect);
                reply_bit = Some(wire::NR_CONNECT);
            }
            Command::Helo(helo) => {
                self.require(opcode, &[State::Ready])?;
                self.helo = Some(helo);
                step.event = Some(Stage::Helo);
                reply_bit = Some(wire::NR_HELO);
            }
            Command::Mail(fields) => {
                self.account_envelope(&fields)?;
                self.message.sender = Some(fields.into());
                self.state = State::Mail;
                step.event = Some(Stage::Mail);
                reply_bit = Some(wire::NR_MAIL);
            }
            Command::Recipient(fields) => {
                self.require(opcode, &[State::Mail, State::Recipients])?;
                self.account_envelope(&fields)?;
                if self.message.recipients.len() >= self.limits.recipients {
                    return Err(Error::Limit("recipients"));
                }
                self.message.recipients.push(fields.into());
                self.state = State::Recipients;
                step.event = Some(Stage::Recipient);
                reply_bit = Some(wire::NR_RCPT);
            }
            Command::Data => {
                self.require(opcode, &[State::Recipients])?;
                self.state = State::Data;
                reply_bit = Some(wire::NR_DATA);
            }
            Command::Header { name, value } => {
                self.require(opcode, &[State::Data, State::Headers])?;
                if self.message.headers.len() >= self.limits.headers {
                    return Err(Error::Limit("headers"));
                }
                self.account(name.len() + value.len() + 4)?;
                self.message.headers.push((name, value));
                self.state = State::Headers;
                reply_bit = Some(wire::NR_HEADER);
            }
            Command::EndHeaders => {
                self.require(opcode, &[State::Data, State::Headers])?;
                self.account(2)?;
                self.state = State::Body;
                reply_bit = Some(wire::NR_EOH);
            }
            Command::Body(body) => {
                self.require(opcode, &[State::Body])?;
                self.account(body.len())?;
                self.message.body.extend_from_slice(&body);
                reply_bit = Some(wire::NR_BODY);
            }
            Command::EndMessage => {
                self.require(opcode, &[State::Body])?;
                // EOM always has a final response, even with no subscribed policy.
                step.event = Some(Stage::EndMessage);
            }
            Command::Abort => {
                self.reset_message();
                if self.connection.is_some() && self.state != State::Stopped {
                    self.state = State::Ready;
                }
            }
            Command::QuitNewConnection => {
                self.reset_message();
                self.connection = None;
                self.helo = None;
                self.macros.clear();
                self.pending_macros.clear();
                self.state = State::Negotiated;
            }
            Command::Quit => {
                self.reset_message();
                self.state = State::Closed;
                step.close = true;
            }
            Command::Unknown(_) => {
                reply_bit = Some(wire::NR_UNKNOWN);
            }
            Command::Negotiate(_) | Command::Macro { .. } => unreachable!(),
        }
        if step
            .event
            .is_some_and(|s| s != Stage::EndMessage && !self.stages.contains(&s))
        {
            step.event = None;
        }
        if let Some(stage) = step.event {
            self.pending = Some(stage);
        } else if reply_bit
            .is_some_and(|b| self.options.as_ref().expect("negotiated").protocol & b == 0)
        {
            step.frames.push(Frame::empty(b'c'));
        }
        Ok(step)
    }
    fn account_envelope(&mut self, fields: &[Bytes]) -> Result<()> {
        // Count attempted recipients too: repeated rejected RCPT commands cannot
        // keep an unbounded transaction alive under a fixed envelope budget.
        for field in fields {
            self.message.envelope_bytes = self
                .message
                .envelope_bytes
                .checked_add(field.len() + 1)
                .ok_or(Error::Limit("envelope"))?;
        }
        if self.message.envelope_bytes > self.limits.envelope_bytes {
            return Err(Error::Limit("envelope"));
        }
        Ok(())
    }
    /// Validate the entire decision before exposing any modification bytes to the MTA.
    pub fn complete(&mut self, decision: Decision) -> Result<Vec<Frame>> {
        let stage = self.pending.ok_or(Error::Invalid("no pending callback"))?;
        let options = self.options.as_ref().expect("negotiated");
        if !decision.modifications.is_empty() && stage != Stage::EndMessage {
            return Err(Error::Invalid("modifications require EOM"));
        }
        if decision.modifications.len() > self.limits.modifications {
            return Err(Error::Limit("modifications"));
        }
        let mut frames = Vec::new();
        let mut output_bytes = 0usize;
        for m in &decision.modifications {
            if options.actions & m.capability() == 0 {
                return Err(Error::NotNegotiated);
            }
            let next_bytes = output_bytes
                .checked_add(m.payload_bytes(self.leading_space())?)
                .ok_or(Error::Limit("output"))?;
            if next_bytes > self.limits.message_bytes {
                return Err(Error::Limit("output"));
            }
            for f in m.frames(self.leading_space())? {
                if f.payload.len() + 1 > self.limits.frame_bytes {
                    return Err(Error::Limit("output frame"));
                }
                output_bytes = output_bytes
                    .checked_add(f.payload.len())
                    .ok_or(Error::Limit("output"))?;
                if output_bytes > self.limits.message_bytes {
                    return Err(Error::Limit("output"));
                }
                frames.push(f);
            }
        }
        let mut rejected = false;
        let mut finished = false;
        let mut disconnect = false;
        let final_frame = match &decision.verdict {
            Verdict::Continue => Frame::empty(b'c'),
            Verdict::Accept => {
                finished = true;
                Frame::empty(b'a')
            }
            Verdict::Reject => {
                rejected = true;
                Frame::empty(b'r')
            }
            Verdict::Tempfail => {
                rejected = true;
                Frame::empty(b't')
            }
            Verdict::Discard => {
                finished = true;
                Frame::empty(b'd')
            }
            Verdict::Reply {
                code,
                enhanced,
                message,
            } => {
                if !(400..600).contains(code) {
                    return Err(Error::Invalid("SMTP error code must be 4xx or 5xx"));
                }
                wire::clean(message)?;
                let mut text = code.to_string();
                if let Some(enhanced) = enhanced {
                    let parts: Vec<_> = enhanced.split('.').collect();
                    if parts.len() != 3
                        || parts[0] != (*code / 100).to_string()
                        || parts[1..].iter().any(|p| {
                            p.is_empty() || p.len() > 3 || !p.bytes().all(|c| c.is_ascii_digit())
                        })
                    {
                        return Err(Error::Invalid("enhanced SMTP code"));
                    }
                    text.push(' ');
                    text.push_str(enhanced);
                }
                text.push(' ');
                text.push_str(message);
                rejected = true;
                wire::string_frame(b'y', &[text.as_bytes()])?
            }
            Verdict::Shutdown => {
                rejected = true;
                disconnect = true;
                Frame::empty(wire::SHUTDOWN)
            }
        };
        if final_frame.payload.len() + 1 > self.limits.frame_bytes {
            return Err(Error::Limit("SMTP reply"));
        }
        // Reject/discard decisions need no content edits; never mutate an unaccepted message.
        if rejected || matches!(decision.verdict, Verdict::Discard) {
            frames.clear();
        }
        frames.push(final_frame);
        self.pending = None;
        if disconnect {
            // The MTA closes the SMTP session; only ABORT/QUIT should follow.
            self.reset_message();
            self.state = State::Stopped;
        } else if rejected && stage == Stage::Recipient {
            self.message.recipients.pop();
            self.state = if self.message.recipients.is_empty() {
                State::Mail
            } else {
                State::Recipients
            };
        } else if rejected && matches!(stage, Stage::Connect | Stage::Helo) {
            self.state = State::Stopped;
        } else if stage == Stage::EndMessage || rejected || finished {
            self.reset_message();
            self.state = State::Ready;
        }
        Ok(frames)
    }
}
