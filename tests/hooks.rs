use base64::{Engine, engine::general_purpose::STANDARD};
use bytes::Bytes;
use mta_hooks_milter::{hooks::translate, protocol::*, session::*};
use serde_json::json;

#[test]
fn raw_replacement_preserves_original_fields_and_replaces_binary_or_empty_body() {
    for body in [b"new\0binary\r\n".as_slice(), b"".as_slice()] {
        let mut s = at_eom_with_headers();
        s.message.body = b"old\r\n".to_vec();
        let mut raw = s.raw_message();
        raw.truncate(raw.len() - s.message.body.len());
        raw.extend_from_slice(body);
        let d = translate(
            json!({"set":[{"path":"/rawMessage","value":STANDARD.encode(raw)}],
            "add":[{"path":"/message/headers","value":{"name":"Ignored","value":"yes"}}]}),
            &s,
            Stage::EndMessage,
        )
        .unwrap();
        assert_eq!(
            d.modifications,
            vec![Modification::ReplaceBody(Bytes::copy_from_slice(body))]
        );
        let frames = s.complete(d).unwrap();
        assert_eq!(frames[0].command, b'b');
        assert_eq!(frames[0].payload.as_ref(), body);
    }
}

#[test]
fn raw_replacement_header_edits_and_invalid_inputs_are_atomic() {
    let s = at_eom_with_headers();
    let raw = b"Subject: replaced\r\nDKIM-Signature: v=1;\r\n\tb=signature\r\n\r\nnew\r\n";
    let d = translate(
        json!({"set":[{"path":"/rawMessage","value":STANDARD.encode(raw)}]}),
        &s,
        Stage::EndMessage,
    )
    .unwrap();
    assert!(d.modifications.iter().any(
        |m| matches!(m, Modification::InsertRawHeader {name, ..} if name == "DKIM-Signature")
    ));
    for m in &d.modifications {
        m.frames(false).unwrap();
    }
    for raw in [
        b"orphan\r\n\r\nx".as_slice(),
        b" folded\r\n\r\nx",
        b"X: bad\rvalue\r\n\r\nx",
    ] {
        assert!(
            translate(
                json!({"set":[{"path":"/rawMessage","value":STANDARD.encode(raw)}]}),
                &s,
                Stage::EndMessage
            )
            .is_err()
        );
    }
    let mut small = at_eom_with_headers();
    small.limits.message_bytes = 2;
    assert!(
        translate(
            json!({"set":[{"path":"/rawMessage","value":STANDARD.encode(raw)}]}),
            &small,
            Stage::EndMessage
        )
        .is_err()
    );
    assert!(
        translate(
            json!({"set":[{"path":"/rawMessage","value":STANDARD.encode(raw)}]}),
            &s,
            Stage::Connect
        )
        .is_err()
    );
}

fn at_eom(actions: u32) -> Session {
    let mut session = Session::new(Limits::default(), vec![Stage::EndMessage], actions);
    session
        .receive(
            Options {
                version: 6,
                actions,
                protocol: 0,
            }
            .frame(),
        )
        .unwrap();
    for (command, payload) in [
        (b'C', &b"unknown\0U"[..]),
        (b'M', &b"<>\0"[..]),
        (b'R', &b"a@b\0"[..]),
        (b'T', &b""[..]),
        (b'N', &b""[..]),
        (b'E', &b""[..]),
    ] {
        session
            .receive(Frame::new(command, Bytes::copy_from_slice(payload)))
            .unwrap();
    }
    session
}

#[test]
fn hook_actions_map_to_final_milter_verdicts() {
    for (action, expected) in [
        ("accept", vec![Frame::empty(b'c')]),
        ("discard", vec![Frame::empty(b'd')]),
        (
            "reject",
            vec![string_frame(b'y', &[b"550 Rejected by policy"]).unwrap()],
        ),
        (
            "quarantine",
            vec![
                string_frame(b'q', &[b"MTA Hooks policy"]).unwrap(),
                Frame::empty(b'c'),
            ],
        ),
    ] {
        let mut s = at_eom(SUPPORTED_ACTIONS);
        let d = translate(
            json!({"set":[{"path":"/action","value":action}]}),
            &s,
            Stage::EndMessage,
        )
        .unwrap();
        assert_eq!(s.complete(d).unwrap(), expected);
    }
    let mut s = at_eom(SUPPORTED_ACTIONS);
    let d = translate(
        json!({"set":[
            {"path":"/action","value":"reject"},
            {"path":"/response","value":{"code":451,"enhancedCode":"4.7.1","message":"Retry later"}}
        ]}),
        &s,
        Stage::EndMessage,
    )
    .unwrap();
    assert_eq!(
        s.complete(d).unwrap(),
        [string_frame(b'y', &[b"451 4.7.1 Retry later"]).unwrap()]
    );
}

#[test]
fn unsupported_and_malformed_hook_edits_fail_atomically() {
    let s = at_eom(SUPPORTED_ACTIONS);
    for value in [
        json!({"set":[{"path":"/action","value":"disconnect"},{"path":"/response","value":{"code":421}}]}),
        json!({"set":[{"path":"/rawMessage","value":""}]}),
        json!({"set":[{"path":"/message/headers/0","value":{"name":"Renamed","value":"x"}}]}),
        json!({"set":[{"path":"/message/headers/9","value":{"name":"Subject","value":"x"}}]}),
        json!({"delete":[{"path":"/message/headers/7"}]}),
        json!({"delete":[{"path":"/envelope/to/1"}]}),
        json!({"add":[{"path":"/envelope/to","value":{"address":null}}]}),
        json!({"add":[{"path":"/envelope/to","value":{"address":"c@d","parameters":{"NOTIFY":"a b"}}}]}),
        json!({"set":[{"path":"/envelope/from","value":{"address":"a\r\nb"}}]}),
        json!({"delete":[{"path":"/message/headers","index":0}]}),
        json!({"add":[{"path":"/message/headers","value":{"name":"X","value":"a\r\nX-Evil: b"}}]}),
        json!({"add":[{"path":"/message/headers","index":1,"value":{"name":"X","value":"b"}}]}),
        json!({"set":[{"path":"/action","value":0}]}),
        json!({"unknown":true}),
    ] {
        assert!(translate(value, &s, Stage::EndMessage).is_err());
    }
    // Edits and message-level actions are meaningless before the data stage.
    for value in [
        json!({"add":[{"path":"/message/headers","value":{"name":"X","value":"a"}}]}),
        json!({"set":[{"path":"/envelope/from","value":{"address":"a@b"}}]}),
        json!({"set":[{"path":"/action","value":"quarantine"}]}),
        json!({"set":[{"path":"/action","value":"discard"}]}),
    ] {
        assert!(translate(value, &s, Stage::Connect).is_err());
    }
    assert!(
        translate(
            json!({"set":[{"path":"/action","value":"discard"}]}),
            &s,
            Stage::Mail
        )
        .is_ok()
    );
    let mut s = at_eom(0);
    let d = translate(
        json!({"set":[{"path":"/action","value":"quarantine"}]}),
        &s,
        Stage::EndMessage,
    )
    .unwrap();
    assert!(matches!(s.complete(d), Err(Error::NotNegotiated)));
    assert_eq!(
        s.complete(Decision::default()).unwrap(),
        [Frame::empty(b'c')]
    );
}

fn at_eom_with_headers() -> Session {
    let mut session = Session::new(
        Limits::default(),
        vec![Stage::EndMessage],
        SUPPORTED_ACTIONS,
    );
    session
        .receive(
            Options {
                version: 6,
                actions: SUPPORTED_ACTIONS,
                protocol: 0,
            }
            .frame(),
        )
        .unwrap();
    for (command, payload) in [
        (b'C', &b"unknown\0U"[..]),
        (b'M', &b"<s@example.com>\0"[..]),
        (b'R', &b"<a@example.com>\0NOTIFY=NEVER\0"[..]),
        (b'R', &b"<b@example.com>\0"[..]),
        (b'T', &b""[..]),
        (b'L', &b"Received\0one\0"[..]),
        (b'L', &b"Subject\0test\0"[..]),
        (b'L', &b"Received\0two\0"[..]),
        (b'L', &b"X-Old\0drop\0"[..]),
        (b'N', &b""[..]),
        (b'E', &b""[..]),
    ] {
        session
            .receive(Frame::new(command, Bytes::copy_from_slice(payload)))
            .unwrap();
    }
    session
}

#[test]
fn header_and_envelope_edits_translate_to_ordered_milter_frames() {
    let mut s = at_eom_with_headers();
    let d = translate(
        json!({
            "set":[
                {"path":"/message/headers/1/value","value":"changed"},
                {"path":"/envelope/from","value":{"address":"new@example.com","parameters":{"SIZE":"10"}}}
            ],
            "add":[
                {"path":"/message/headers","value":{"name":"X-First","value":"1"},"index":0},
                {"path":"/message/headers","value":{"name":"X-Last","value":"2"}},
                {"path":"/message/headers","value":{"name":"X-Gone","value":"3"}},
                {"path":"/envelope/to","value":{"address":"c@example.com","parameters":{"NOTIFY":"SUCCESS"}}},
                {"path":"/envelope/to","value":{"address":"<d@example.com>","parameters":{}}},
                {"path":"/envelope/to","value":{"address":"e@example.com"}}
            ],
            "delete":[
                {"path":"/message/headers/6"},
                {"path":"/message/headers/3"},
                {"path":"/message/headers/1"},
                {"path":"/envelope/to/4"},
                {"path":"/envelope/to/0"}
            ]
        }),
        &s,
        Stage::EndMessage,
    )
    .unwrap();
    // Working list after adds: X-First, Received(one), Subject, Received(two), X-Old, X-Last, X-Gone.
    // Deletes: X-Gone (added), Received(two) (original 2), Received(one) (original 0).
    assert_eq!(
        d.modifications,
        vec![
            Modification::ChangeHeader {
                occurrence: 2,
                name: "Received".into(),
                value: String::new()
            },
            Modification::ChangeHeader {
                occurrence: 1,
                name: "Subject".into(),
                value: "changed".into()
            },
            Modification::ChangeHeader {
                occurrence: 1,
                name: "Received".into(),
                value: String::new()
            },
            Modification::InsertHeader {
                index: 0,
                name: "X-First".into(),
                value: "1".into()
            },
            Modification::AddHeader {
                name: "X-Last".into(),
                value: "2".into()
            },
            Modification::ChangeFrom {
                address: "<new@example.com>".into(),
                parameters: Some("SIZE=10".into())
            },
            Modification::DeleteRecipient("<a@example.com>".into()),
            Modification::AddRecipient {
                address: "<c@example.com>".into(),
                parameters: Some("NOTIFY=SUCCESS".into())
            },
            Modification::AddRecipient {
                address: "<d@example.com>".into(),
                parameters: None
            },
        ]
    );
    let frames = s.complete(d).unwrap();
    assert_eq!(frames.len(), 10);
    assert_eq!(frames[0].command, b'm');
    assert_eq!(frames[5].command, b'e');
    assert_eq!(frames[7].command, b'2');
    assert_eq!(frames[8].command, b'+');
    assert_eq!(frames[9], Frame::empty(b'c'));
    // A conflicting set+delete on the same original header is refused as a whole.
    let s = at_eom_with_headers();
    assert!(
        translate(
            json!({"set":[{"path":"/message/headers/1/value","value":"x"}],"delete":[{"path":"/message/headers/1"}]}),
            &s,
            Stage::EndMessage
        )
        .is_err()
    );
    // Null sender is representable; disconnect maps to SMFIR_SHUTDOWN and stops the connection.
    let mut s = at_eom_with_headers();
    let d = translate(
        json!({"set":[{"path":"/envelope/from","value":{"address":null}}]}),
        &s,
        Stage::EndMessage,
    )
    .unwrap();
    assert_eq!(
        d.modifications,
        vec![Modification::ChangeFrom {
            address: "<>".into(),
            parameters: None
        }]
    );
    let d = translate(
        json!({"set":[{"path":"/action","value":"disconnect"}]}),
        &s,
        Stage::EndMessage,
    )
    .unwrap();
    assert_eq!(s.complete(d).unwrap(), [Frame::empty(SHUTDOWN)]);
    assert_eq!(s.state, State::Stopped);
    assert!(matches!(
        s.receive(Frame::new(b'M', Bytes::from_static(b"<x>\0"))),
        Err(Error::Sequence { .. })
    ));
}
