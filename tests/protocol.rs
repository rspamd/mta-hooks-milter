use bytes::Bytes;
use mta_hooks_milter::{protocol::*, session::*};
use tokio::io::{AsyncWriteExt, duplex};

fn options(protocol: u32, actions: u32) -> Frame {
    Options {
        version: 6,
        actions,
        protocol,
    }
    .frame()
}
fn f(cmd: u8, p: &[u8]) -> Frame {
    Frame::new(cmd, Bytes::copy_from_slice(p))
}
fn session(protocol: u32) -> Session {
    let mut s = Session::new(Limits::default(), Stage::ALL.to_vec(), SUPPORTED_ACTIONS);
    s.receive(options(protocol, SUPPORTED_ACTIONS)).unwrap();
    s.receive(f(b'C', b"mx.example\0\x34\x00\x19\x31\x39\x32.0.2.1\0"))
        .unwrap();
    s.complete(Decision::default()).unwrap();
    s
}
fn callback(s: &mut Session, cmd: u8, p: &[u8]) {
    let step = s.receive(f(cmd, p)).unwrap();
    if step.event.is_some() {
        s.complete(Decision::default()).unwrap();
    }
}
fn envelope(s: &mut Session) {
    callback(s, b'M', b"<alice@example.com>\0SIZE=5\0");
    callback(s, b'R', b"<bob@example.com>\0NOTIFY=SUCCESS\0");
}
fn eom(s: &mut Session) {
    s.receive(Frame::empty(b'T')).unwrap();
    s.receive(Frame::empty(b'N')).unwrap();
    s.receive(Frame::empty(b'E')).unwrap();
}

#[tokio::test]
async fn split_frames_and_coalesced_frames_roundtrip() {
    let frames = vec![
        options(0, 0),
        f(b'L', b"X-Test\0a\0"),
        f(b'B', b"\xff\0\r\n"),
        Frame::empty(b'E'),
    ];
    let expected = frames.clone();
    let (mut w, mut r) = duplex(8);
    let writer = tokio::spawn(async move {
        for frame in frames {
            for byte in frame.encode().unwrap() {
                w.write_all(&[byte]).await.unwrap();
            }
        }
    });
    for frame in expected {
        assert_eq!(read_frame(&mut r, 131073).await.unwrap(), Some(frame));
    }
    assert_eq!(read_frame(&mut r, 131073).await.unwrap(), None);
    writer.await.unwrap();
    let data = [
        Frame::empty(b'A').encode().unwrap(),
        Frame::empty(b'Q').encode().unwrap(),
    ]
    .concat();
    let mut r = data.as_slice();
    assert_eq!(
        read_frame(&mut r, 100).await.unwrap(),
        Some(Frame::empty(b'A'))
    );
    assert_eq!(
        read_frame(&mut r, 100).await.unwrap(),
        Some(Frame::empty(b'Q'))
    );
}
#[tokio::test]
async fn truncated_zero_and_oversized_frames_fail_before_allocation() {
    for input in [
        &b"\0\0"[..],
        &b"\0\0\0\x02B"[..],
        &b"\0\0\0\0"[..],
        &b"\xff\xff\xff\xff"[..],
    ] {
        assert!(read_frame(&mut &input[..], 1024).await.is_err());
    }
}
#[test]
fn malformed_fields_are_rejected() {
    for frame in [
        f(b'O', b"short"),
        f(b'M', b"unterminated"),
        f(b'D', b"Mkey\0"),
        f(b'D', b""),
        f(b'L', b"key\0value\0extra\0"),
        f(b'C', b"mx\0\x34\0"),
        f(b'H', b"a\0b\0"),
        f(b'A', b"garbage"),
        Frame::empty(0),
    ] {
        assert!(Command::decode(frame).is_err());
    }
}
#[test]
fn all_small_payloads_are_panic_free() {
    for cmd in 0..=255 {
        for len in 0..32 {
            for byte in [0, 1, b'\r', b'\n', 255] {
                let _ = Command::decode(Frame::new(cmd, vec![byte; len]));
            }
        }
    }
}
#[test]
fn connect_supports_ipv6_unix_unknown() {
    for frame in [
        f(b'C', b"mx\0\x36\x00\x19IPv6:[::1]\0"),
        f(b'C', b"local\0L\0\0/run/smtp.sock\0"),
        f(b'C', b"unknown\0U"),
    ] {
        assert!(matches!(
            Command::decode(frame).unwrap(),
            Command::Connect(_)
        ));
    }
    assert!(Command::decode(f(b'C', b"mx\0\x34\0\x19::1\0")).is_err());
}
#[test]
fn negotiation_intersects_capabilities_and_falls_back_to_replies() {
    let mut s = Session::new(
        Limits::default(),
        vec![Stage::EndMessage],
        SUPPORTED_ACTIONS,
    );
    let step = s.receive(options(0, ADD_HEADERS)).unwrap();
    assert_eq!(
        step.frames,
        [Options {
            version: 6,
            actions: ADD_HEADERS,
            protocol: 0
        }
        .frame()]
    );
    let step = s.receive(f(b'C', b"unknown\0U")).unwrap();
    assert_eq!(step.frames, [Frame::empty(b'c')]);
    let mut old = Session::new(Limits::default(), vec![], 0);
    assert!(
        old.receive(
            Options {
                version: 5,
                actions: 0,
                protocol: 0
            }
            .frame()
        )
        .is_err()
    );
}
#[test]
fn hooked_stages_never_negotiate_no_reply() {
    let s = session(u32::MAX);
    let p = s.options.unwrap().protocol;
    assert_eq!(p & (NR_CONNECT | NR_HELO | NR_MAIL | NR_RCPT), 0);
    assert_ne!(p & NR_BODY, 0);
    assert_ne!(p & HEADER_LEADING_SPACE, 0);
}
#[test]
fn two_messages_null_sender_and_abort_reset() {
    let mut s = session(0);
    callback(&mut s, b'H', b"client.example\0");
    envelope(&mut s);
    eom(&mut s);
    assert_eq!(
        s.complete(Decision::default()).unwrap(),
        [Frame::empty(b'c')]
    );
    assert_eq!(s.state, State::Ready);
    assert!(s.message.sender.is_none());
    assert!(s.message.recipients.is_empty());
    callback(&mut s, b'M', b"<>\0");
    assert_eq!(s.message.sender.as_ref().unwrap().address, b"<>"[..]);
    s.receive(Frame::empty(b'A')).unwrap();
    assert!(s.message.sender.is_none());
    assert_eq!(s.helo.as_deref(), Some(&b"client.example"[..]));
    envelope(&mut s);
    eom(&mut s);
    s.complete(Decision::default()).unwrap();
    s.receive(Frame::empty(b'K')).unwrap();
    assert_eq!(s.state, State::Negotiated);
    assert!(s.helo.is_none());
    assert!(s.connection.is_none());
    s.receive(f(b'C', b"unknown\0U")).unwrap();
    s.complete(Decision::default()).unwrap();
    assert!(s.receive(Frame::empty(b'Q')).unwrap().close);
}
#[test]
fn recipient_rejection_only_removes_current_recipient() {
    let mut s = session(0);
    envelope(&mut s);
    s.receive(f(b'R', b"<bad@example.com>\0")).unwrap();
    s.complete(Decision {
        verdict: Verdict::Reject,
        ..Default::default()
    })
    .unwrap();
    assert_eq!(s.message.recipients.len(), 1);
    assert_eq!(s.state, State::Recipients);
    eom(&mut s);
    s.complete(Decision::default()).unwrap();
    callback(&mut s, b'M', b"<>\0");
    s.receive(f(b'R', b"<bad@example.com>\0")).unwrap();
    s.complete(Decision {
        verdict: Verdict::Tempfail,
        ..Default::default()
    })
    .unwrap();
    assert_eq!(s.state, State::Mail);
    assert!(s.receive(Frame::empty(b'T')).is_err());
}
#[test]
fn wrong_sequence_and_reentrant_callback_fail() {
    let mut s = session(0);
    assert!(s.receive(Frame::empty(b'E')).is_err());
    assert!(s.receive(f(b'B', b"body")).is_err());
    s.receive(f(b'M', b"<>\0")).unwrap();
    assert!(s.receive(f(b'R', b"<a@b>\0")).is_err());
    s.complete(Decision::default()).unwrap();
    assert!(s.receive(options(0, 0)).is_err());
}
#[test]
fn macros_are_stage_scoped_and_transaction_values_do_not_leak() {
    let mut s = session(0);
    s.receive(f(b'D', b"H{tls_version}\0TLSv1.3\0")).unwrap();
    callback(&mut s, b'H', b"mx\0");
    s.receive(f(b'D', b"M{auth_authen}\0alice\0")).unwrap();
    envelope(&mut s);
    s.receive(f(b'D', b"Ei\0FIRST\0")).unwrap();
    assert_eq!(s.macro_value("i"), None);
    eom(&mut s);
    assert_eq!(s.macro_value("i"), Some(&b"FIRST"[..]));
    s.complete(Decision::default()).unwrap();
    assert_eq!(s.macro_value("i"), None);
    assert_eq!(s.macro_value("auth_authen"), None);
    assert_eq!(s.macro_value("tls_version"), Some(&b"TLSv1.3"[..]));
    s.receive(f(b'D', b"H")).unwrap();
    callback(&mut s, b'H', b"again\0");
    assert_eq!(s.macro_value("tls_version"), None);
}
#[test]
fn raw_headers_preserve_leading_space_folding_and_binary_body() {
    for (opts, val, expected) in [
        (
            HEADER_LEADING_SPACE,
            &b"nospace"[..],
            &b"X-Test:nospace\r\n\r\n\xff\0"[..],
        ),
        (0, &b"normal"[..], &b"X-Test: normal\r\n\r\n\xff\0"[..]),
        (
            0,
            &b"\r\n folded"[..],
            &b"X-Test:\r\n folded\r\n\r\n\xff\0"[..],
        ),
    ] {
        let mut s = session(opts);
        envelope(&mut s);
        s.receive(Frame::empty(b'T')).unwrap();
        s.receive(string_frame(b'L', &[b"X-Test", val]).unwrap())
            .unwrap();
        s.receive(Frame::empty(b'N')).unwrap();
        s.receive(f(b'B', b"\xff\0")).unwrap();
        assert_eq!(s.raw_message(), expected);
    }
}
#[test]
fn message_recipient_header_and_macro_limits() {
    let mut s = session(0);
    s.limits.envelope_bytes = 3;
    assert!(matches!(
        s.receive(f(b'M', b"<a@b>\0")),
        Err(Error::Limit("envelope"))
    ));
    let mut s = session(0);
    s.limits.recipients = 1;
    envelope(&mut s);
    assert!(s.receive(f(b'R', b"<b@c>\0")).is_err());
    let mut s = session(0);
    s.limits.message_bytes = 3;
    envelope(&mut s);
    s.receive(Frame::empty(b'T')).unwrap();
    s.receive(Frame::empty(b'N')).unwrap();
    assert!(s.receive(f(b'B', b"xx")).is_err());
    let mut s = session(0);
    s.limits.headers = 0;
    envelope(&mut s);
    s.receive(Frame::empty(b'T')).unwrap();
    assert!(s.receive(f(b'L', b"X\0v\0")).is_err());
    let mut s = session(0);
    s.limits.macro_bytes = 2;
    assert!(s.receive(f(b'D', b"Mkey\0value\0")).is_err());
}

#[test]
fn output_budget_is_checked_before_body_frame_allocation() {
    let mut s = session(0);
    envelope(&mut s);
    eom(&mut s);
    s.limits.message_bytes = 1024;
    assert!(matches!(
        s.complete(Decision {
            modifications: vec![Modification::ReplaceBody(Bytes::from(vec![
                0;
                BODY_CHUNK * 2
            ]))],
            ..Default::default()
        }),
        Err(Error::Limit("output"))
    ));
    assert_eq!(
        s.complete(Decision::default()).unwrap(),
        [Frame::empty(b'c')]
    );
}

#[test]
fn modification_size_estimates_match_encoded_payloads() {
    let edits = [
        Modification::AddHeader {
            name: "X".into(),
            value: "a".into(),
        },
        Modification::InsertHeader {
            index: 0,
            name: "X".into(),
            value: "".into(),
        },
        Modification::ChangeHeader {
            occurrence: 1,
            name: "X".into(),
            value: "b".into(),
        },
        Modification::ReplaceBody(Bytes::from(vec![1; BODY_CHUNK + 1])),
        Modification::ChangeFrom {
            address: "<>".into(),
            parameters: None,
        },
        Modification::AddRecipient {
            address: "a@b".into(),
            parameters: Some("NOTIFY=NEVER".into()),
        },
        Modification::DeleteRecipient("a@b".into()),
        Modification::Quarantine("hold".into()),
    ];
    for leading in [false, true] {
        for edit in &edits {
            let actual: usize = edit
                .frames(leading)
                .unwrap()
                .iter()
                .map(|f| f.payload.len())
                .sum();
            assert_eq!(edit.payload_bytes(leading).unwrap(), actual);
        }
    }
}
#[test]
fn output_modifications_are_validated_before_any_frame_is_returned() {
    let mut s = session(0);
    envelope(&mut s);
    eom(&mut s);
    assert!(
        s.complete(Decision {
            modifications: vec![
                Modification::AddHeader {
                    name: "X-Good".into(),
                    value: "ok".into()
                },
                Modification::AddHeader {
                    name: "X-Bad".into(),
                    value: "a\r\nInjected: b".into()
                }
            ],
            ..Default::default()
        })
        .is_err()
    );
    assert_eq!(
        s.complete(Decision {
            verdict: Verdict::Tempfail,
            ..Default::default()
        })
        .unwrap(),
        [Frame::empty(b't')]
    );
}
#[test]
fn quarantine_requires_negotiated_capability_and_final_reply() {
    let mut s = session(0);
    envelope(&mut s);
    eom(&mut s);
    let frames = s
        .complete(Decision {
            modifications: vec![Modification::Quarantine("hold".into())],
            ..Default::default()
        })
        .unwrap();
    assert_eq!(frames, [f(b'q', b"hold\0"), Frame::empty(b'c')]);
    let mut s = session(0);
    s.options.as_mut().unwrap().actions = 0;
    envelope(&mut s);
    eom(&mut s);
    assert!(matches!(
        s.complete(Decision {
            modifications: vec![Modification::Quarantine("hold".into())],
            ..Default::default()
        }),
        Err(Error::NotNegotiated)
    ));
}
#[test]
fn modification_wire_indexes_and_empty_body() {
    let change = Modification::ChangeHeader {
        occurrence: 2,
        name: "Subject".into(),
        value: "".into(),
    }
    .frames(true)
    .unwrap();
    assert_eq!(change, [f(b'm', b"\0\0\0\x02Subject\0\0")]);
    let insert = Modification::InsertHeader {
        index: 0,
        name: "X-Test".into(),
        value: "hi".into(),
    }
    .frames(true)
    .unwrap();
    assert_eq!(insert, [f(b'i', b"\0\0\0\0X-Test\0 hi\0")]);
    assert_eq!(
        Modification::ReplaceBody(Bytes::new())
            .frames(false)
            .unwrap(),
        [Frame::empty(b'b')]
    );
    let frames = Modification::ReplaceBody(Bytes::from(vec![42; BODY_CHUNK + 1]))
        .frames(false)
        .unwrap();
    assert_eq!(frames.len(), 2);
    assert_eq!(frames[0].payload.len(), BODY_CHUNK);
    assert_eq!(frames[1].payload.len(), 1);
    assert_eq!(
        Modification::ChangeFrom {
            address: "<>".into(),
            parameters: Some("RET=HDRS".into())
        }
        .frames(false)
        .unwrap(),
        [f(b'e', b"<>\0RET=HDRS\0")]
    );
    assert_eq!(
        Modification::AddRecipient {
            address: "<a@b>".into(),
            parameters: Some("NOTIFY=SUCCESS".into())
        }
        .frames(false)
        .unwrap(),
        [f(b'2', b"<a@b>\0NOTIFY=SUCCESS\0")]
    );
}
#[test]
fn modifications_require_eom_and_smtp_reply_codes_are_validated() {
    let mut s = session(0);
    s.receive(f(b'M', b"<>\0")).unwrap();
    assert!(
        s.complete(Decision {
            modifications: vec![Modification::Quarantine("hold".into())],
            ..Default::default()
        })
        .is_err()
    );
    assert!(
        s.complete(Decision {
            verdict: Verdict::Reply {
                code: 250,
                enhanced: None,
                message: "OK".into()
            },
            ..Default::default()
        })
        .is_err()
    );
    assert!(
        s.complete(Decision {
            verdict: Verdict::Reply {
                code: 451,
                enhanced: Some("5.7.1".into()),
                message: "no".into()
            },
            ..Default::default()
        })
        .is_err()
    );
    assert_eq!(
        s.complete(Decision {
            verdict: Verdict::Reply {
                code: 451,
                enhanced: Some("4.7.1".into()),
                message: "later".into()
            },
            ..Default::default()
        })
        .unwrap(),
        [f(b'y', b"451 4.7.1 later\0")]
    );
}
