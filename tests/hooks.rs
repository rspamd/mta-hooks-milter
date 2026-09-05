use bytes::Bytes;
use mta_hooks_milter::{hooks::translate, protocol::*, session::*};
use serde_json::json;

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
        let d = translate(json!({"set":[{"path":"/action","value":action}]}), &s).unwrap();
        assert_eq!(s.complete(d).unwrap(), expected);
    }
    let mut s = at_eom(SUPPORTED_ACTIONS);
    let d = translate(
        json!({"set":[
            {"path":"/action","value":"reject"},
            {"path":"/response","value":{"code":451,"enhancedCode":"4.7.1","message":"Retry later"}}
        ]}),
        &s,
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
        json!({"set":[{"path":"/action","value":"disconnect"}]}),
        json!({"set":[{"path":"/rawMessage","value":""}]}),
        json!({"delete":[{"path":"/message/headers","index":0}]}),
        json!({"add":[{"path":"/message/headers","value":{"name":"X","value":"a\r\nX-Evil: b"}}]}),
        json!({"add":[{"path":"/message/headers","index":1,"value":{"name":"X","value":"b"}}]}),
        json!({"set":[{"path":"/action","value":0}]}),
        json!({"unknown":true}),
    ] {
        assert!(translate(value, &s).is_err());
    }
    let mut s = at_eom(0);
    let d = translate(json!({"set":[{"path":"/action","value":"quarantine"}]}), &s).unwrap();
    assert!(matches!(s.complete(d), Err(Error::NotNegotiated)));
    assert_eq!(
        s.complete(Decision::default()).unwrap(),
        [Frame::empty(b'c')]
    );
}
