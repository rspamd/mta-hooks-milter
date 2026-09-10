"""Isolated Postfix interoperability, using a controlled draft-01 HTTP fixture.

Run only inside interop/Dockerfile with --network none. No host config is touched.
This fixture is not an independent scanner implementation.
"""
import base64
import concurrent.futures
import email
import grp
import http.server
import json
import os
import re
import smtplib
import socket
import ssl
import subprocess
import threading
import time
import urllib.request


TOKEN = "container-test-only"
ALL_STAGES = ["connect", "ehlo", "mail", "rcpt", "data"]
STAGES = ALL_STAGES if os.environ.get("HOOK_STAGES") == "all" else ["data"]
REQUESTS = []
# Every hook request in arrival order: (stage, request, request id).
STAGE_EVENTS = []
DEREGISTRATIONS = []
LOCK = threading.Lock()
RESULTS = []


class Scanner(http.server.BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def reply(self, status, value=None):
        data = json.dumps(value).encode() if value is not None else b""
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        try:
            self.wfile.write(data)
        except BrokenPipeError:
            pass

    def do_DELETE(self):
        if self.headers.get("Authorization") != "Bearer " + TOKEN:
            return self.reply(401)
        assert self.path == "/register/postfix-interop", self.path
        assert self.headers["X-MTA-Hooks-Registration"] == "postfix-interop"
        with LOCK:
            DEREGISTRATIONS.append(self.path)
        return self.reply(200, {"registrationId": "postfix-interop", "status": "deregistered"})

    def do_POST(self):
        if self.headers.get("Authorization") != "Bearer " + TOKEN:
            return self.reply(401)
        request = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        if self.path == "/register":
            assert request["inbound"]["stages"] == STAGES, request["inbound"]
            return self.reply(201, {
                "registrationId": "postfix-interop", "status": "active",
                "createdAt": "2026-09-05T00:00:00Z", "expiresAt": None,
                "hookEndpoint": "/hook",
                "endpoints": {"deregistration": "/register/postfix-interop"},
                "negotiated": {"serialization": "json", "inbound": request["inbound"]},
            })
        assert self.path == "/hook"
        assert self.headers["X-MTA-Hooks-Registration"] == "postfix-interop"
        assert self.headers["X-MTA-Hooks-Request-Id"]
        stage = request["stage"]
        assert stage in STAGES, stage
        with LOCK:
            STAGE_EVENTS.append((stage, request, self.headers["X-MTA-Hooks-Request-Id"]))
        if stage != "data":
            return self.early_stage(stage, request)
        raw = base64.b64decode(request["rawMessage"], validate=True)
        message = email.message_from_bytes(raw)
        case = message["X-Interop-Case"]
        with LOCK:
            REQUESTS.append((case, request, raw, self.headers["X-MTA-Hooks-Request-Id"]))
        if case == "timeout":
            time.sleep(2)
            return self.reply(204)
        if case == "unavailable":
            return self.reply(503)
        if case == "unchanged":
            return self.reply(204)
        if case == "invalid":
            return self.reply(200, {"add": [{"path": "/message/headers", "value": {
                "name": "X-Must-Not-Leak", "value": "bad\r\nInjected: yes"}}]})
        if case in ("reject", "tempfail"):
            code = 550 if case == "reject" else 451
            return self.reply(200, {"set": [
                {"path": "/action", "value": "reject"},
                {"path": "/response", "value": {"code": code,
                 "enhancedCode": f"{code // 100}.7.1", "message": "Interop policy"}},
            ]})
        if case in ("discard", "quarantine"):
            return self.reply(200, {"set": [{"path": "/action", "value": case}]})
        if case == "edits":
            # Indexes refer to the milter-visible header list, i.e. the rawMessage headers.
            names = [name for name, _ in message.items()]
            subject = names.index("Subject")
            duplicate = len(names) - 1 - names[::-1].index("X-Duplicate")
            return self.reply(200, {
                "set": [
                    {"path": f"/message/headers/{subject}/value", "value": "[scanned] edits"},
                    {"path": "/envelope/from", "value": {"address": "rewritten@example.test"}},
                ],
                "add": [
                    {"path": "/message/headers", "value": {"name": "X-Interop-Scanned", "value": case}},
                    {"path": "/envelope/to", "value": {"address": "carol@localhost", "parameters": {}}},
                ],
                "delete": [{"path": f"/message/headers/{duplicate}"}, {"path": "/envelope/to/0"}],
            })
        return self.reply(200, {"add": [{"path": "/message/headers", "value": {
            "name": "X-Interop-Scanned", "value": case}}]})

    def early_stage(self, stage, request):
        assert request["rawMessage"] is None and request["action"] == "accept"
        assert request["client"]["ip"] == "127.0.0.1"
        if stage == "connect":
            assert request["envelope"] is None and request["tls"] is None
            return self.reply(204)
        if stage == "ehlo":
            if request["client"]["ehlo"] == "disconnect.example.test":
                return self.reply(200, {"set": [{"path": "/action", "value": "disconnect"}]})
            return self.reply(200, {})
        sender = request["envelope"]["from"]["address"]
        if stage == "mail":
            assert request["envelope"]["to"] == []
            if sender == "denied@example.test":
                return self.reply(200, {"set": [
                    {"path": "/action", "value": "reject"},
                    {"path": "/response", "value": {"code": 550, "enhancedCode": "5.7.1",
                                                    "message": "Sender denied at MAIL"}}]})
            if sender == "discard@example.test":
                return self.reply(200, {"set": [{"path": "/action", "value": "discard"}]})
            return self.reply(204)
        assert stage == "rcpt"
        recipient = request["envelope"]["to"][-1]["address"]
        if recipient == "blocked@localhost":
            return self.reply(200, {"set": [
                {"path": "/action", "value": "reject"},
                {"path": "/response", "value": {"code": 550, "enhancedCode": "5.1.1",
                                                "message": "Recipient blocked at RCPT"}}]})
        if recipient == "later@localhost":
            return self.reply(200, {"set": [
                {"path": "/action", "value": "reject"},
                {"path": "/response/code", "value": 451},
                {"path": "/response/message", "value": "Recipient deferred at RCPT"}]})
        return self.reply(204)


def run(*args):
    return subprocess.check_output(args, text=True, stderr=subprocess.STDOUT)


def wait_port(port, process=None):
    until = time.monotonic() + 20
    while time.monotonic() < until:
        if process is not None and process.poll() is not None:
            raise RuntimeError(f"process exited: {process.returncode}")
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=.2):
                return
        except OSError:
            time.sleep(.1)
    raise TimeoutError(f"port {port} not ready")


def connect():
    smtp = smtplib.SMTP("127.0.0.1", 2525, timeout=10)
    assert smtp.ehlo("client.example.test")[0] == 250
    return smtp


def submit(smtp, case, sender="alice@example.test", body=b"hello\r\n", expected=250,
           extra_rcpts=()):
    assert smtp.mail(sender)[0] == 250
    for address, rcpt_code in extra_rcpts:
        assert smtp.rcpt(address)[0] == rcpt_code, (case, address)
    assert smtp.rcpt("bob@localhost")[0] == 250
    raw = (f"From: alice@example.test\r\nTo: bob@localhost\r\n"
           f"Subject: {case}\r\nX-Interop-Case: {case}\r\n"
           "X-Duplicate: one\r\nX-Duplicate: two\r\nX-Folded: first\r\n\tsecond\r\n"
           "\r\n").encode() + body
    code, response = smtp.data(raw)
    assert code == expected, (case, code, response)
    queue_id = None
    if expected == 250 and case != "discard":
        match = re.search(rb"queued as ([A-Za-z0-9]+)", response)
        assert match, response
        queue_id = match[1].decode()
        queued = run("postcat", "-qbh", queue_id)
        if case not in ("quarantine", "unchanged"):
            assert f"X-Interop-Scanned: {case}" in queued, (case, queued)
        assert "X-Must-Not-Leak" not in queued
        if case == "edits":
            envelope = run("postcat", "-qe", queue_id)
            assert "Subject: [scanned] edits" in queued, queued
            assert queued.count("X-Duplicate:") == 1 and "X-Duplicate: one" in queued, queued
            assert "sender: rewritten@example.test" in envelope, envelope
            assert re.search(r"^recipient: carol@localhost$", envelope, re.M), envelope
            assert not re.search(r"^recipient: bob@localhost$", envelope, re.M), envelope
    with LOCK:
        matches = [(req, data, rid) for name, req, data, rid in REQUESTS if name == case]
    # A 503 is retried twice with the same request identifier (draft 7.5.3).
    assert len(matches) == (3 if case == "unavailable" else 1), (case, len(matches))
    assert len({rid for _, _, rid in matches}) == 1, case
    request, observed, _ = matches[0]
    assert request["envelope"]["from"]["address"] == (sender or None)
    # Recipients rejected at the rcpt stage never reach the data-stage envelope.
    assert [r["address"] for r in request["envelope"]["to"]] == ["bob@localhost"]
    assert request["client"]["ehlo"] == "client.example.test"
    assert request["client"]["ip"] == "127.0.0.1"
    assert observed.endswith(body), (case, len(observed), len(body))
    assert observed.count(b"X-Duplicate:") == 2
    parsed = email.message_from_bytes(observed)
    assert re.sub(r"\s+", " ", parsed["X-Folded"]) == "first second"
    if queue_id:
        assert request["queue"]["id"] == queue_id, (request["queue"], queue_id)
    with LOCK:
        RESULTS.append({"case": case, "smtp_code": code, "queue_id": queue_id})
        print("PASS", case, code, queue_id or "no queued message", flush=True)
    return queue_id


def multi_stage_cases(smtp):
    """Decisions taken before DATA, plus data-stage envelope/header edits."""
    code, response = smtp.mail("denied@example.test")
    assert code == 550 and b"Sender denied at MAIL" in response, (code, response)
    assert smtp.rset()[0] == 250
    submit(smtp, "after-mail-reject")
    # DISCARD at MAIL: Postfix accepts the whole transaction, sends no further
    # events for it and queues nothing.
    assert smtp.mail("discard@example.test")[0] == 250
    assert smtp.rcpt("bob@localhost")[0] == 250
    code, response = smtp.data(b"Subject: mail-discard\r\nX-Interop-Case: mail-discard\r\n\r\nx\r\n")
    # Postfix still reports a queue ID here; the final queue listing proves it is gone.
    assert code == 250, (code, response)
    with LOCK:
        assert not any(name == "mail-discard" for name, *_ in REQUESTS)
        RESULTS.append({"case": "mail-discard", "smtp_code": code, "queue_id": None})
    print("PASS mail-discard 250 no queued message", flush=True)
    submit(smtp, "rcpt-blocked", extra_rcpts=[("blocked@localhost", 550)])
    submit(smtp, "rcpt-deferred", extra_rcpts=[("later@localhost", 451)])
    submit(smtp, "edits")


def disconnect_session():
    """The ehlo-stage disconnect action closes the SMTP session with 421."""
    smtp = smtplib.SMTP("127.0.0.1", 2525, timeout=10)
    try:
        code, response = smtp.ehlo("disconnect.example.test")
        assert code == 421, (code, response)
        try:
            code = smtp.mail("alice@example.test")[0]
            assert code != 250, code
        except smtplib.SMTPServerDisconnected:
            pass
    except smtplib.SMTPServerDisconnected:
        pass
    finally:
        smtp.close()
    print("PASS ehlo-disconnect 421", flush=True)
    return 1


def check_stage_events(sessions):
    with LOCK:
        events = list(STAGE_EVENTS)
    by_stage = {stage: [r for s, r, _ in events if s == stage] for stage in ALL_STAGES}
    # The port-readiness probe is a bare TCP connection that Postfix also reports.
    assert len(by_stage["connect"]) >= sessions, (len(by_stage["connect"]), sessions)
    for request in by_stage["connect"]:
        assert request["server"]["name"] == "postfix.interop.test", request["server"]
        assert request["queue"] is None and request["auth"] is None
    # EHLO is sent again after STARTTLS; that request carries the TLS macros.
    ehlos = by_stage["ehlo"]
    assert len(ehlos) == sessions + 1, len(ehlos)
    secured = [r for r in ehlos if r["tls"] is not None]
    assert len(secured) == 1 and secured[0]["tls"]["version"].startswith("TLSv"), secured
    assert secured[0]["tls"]["cipherBits"] >= 128, secured[0]["tls"]
    assert sum(r["client"]["ehlo"] == "disconnect.example.test" for r in ehlos) == 1
    mails = by_stage["mail"]
    assert any(r["envelope"]["from"]["address"] is None for r in mails)
    assert any(r["envelope"]["from"]["address"] == "denied@example.test" for r in mails)
    rcpts = by_stage["rcpt"]
    last = [r["envelope"]["to"][-1]["address"] for r in rcpts]
    assert last.count("blocked@localhost") == 1 and last.count("later@localhost") == 1, last
    # A rejected recipient is gone from the next RCPT request of the same message.
    index = last.index("blocked@localhost")
    assert [r["address"] for r in rcpts[index + 1]["envelope"]["to"]] == ["bob@localhost"]
    queued_at_mail = sum(r["queue"] is not None for r in mails)
    print("STAGES", {stage: len(reqs) for stage, reqs in by_stage.items()},
          "queue-id-known-at-mail", queued_at_mail, flush=True)
    print("PASS multi-stage-events", flush=True)


def main():
    if not os.path.exists("/.dockerenv"):
        raise RuntimeError("This harness must run in its disposable Docker container, not on the host")
    transport = os.environ.get("MILTER_TRANSPORT", "tcp")
    assert transport in ("tcp", "unix")
    unix_path = "/var/spool/postfix/mta-hooks.sock"
    endpoint = "inet:127.0.0.1:11332" if transport == "tcp" else "unix:" + unix_path
    # Keep all synthetic mail in this disposable queue; never attempt delivery.
    for setting in [
        "myhostname=postfix.interop.test", "mydestination=localhost",
        "inet_interfaces=127.0.0.1", "inet_protocols=ipv4", "local_recipient_maps=",
        "mynetworks=127.0.0.0/8", "smtpd_relay_restrictions=permit_mynetworks,reject",
        "smtpd_milters=" + endpoint, "milter_protocol=6",
        "milter_default_action=tempfail", "milter_command_timeout=10s",
        "milter_content_timeout=10s", "defer_transports=smtp,local,relay",
        "maillog_file=/dev/stdout", "smtpd_delay_reject=no",
        "smtpd_tls_security_level=may",
        "smtpd_tls_cert_file=/etc/ssl/certs/ssl-cert-snakeoil.pem",
        "smtpd_tls_key_file=/etc/ssl/private/ssl-cert-snakeoil.key",
    ]:
        run("postconf", "-e", setting)
    run("postconf", "-M", "smtp/inet=smtp inet n - n - - smtpd")
    run("postconf", "-M", "2525/inet=2525 inet n - n - - smtpd")
    run("postconf", "-e", "milter_end_of_data_macros=i")
    run("postfix", "check")
    print("POSTFIX", run("postconf", "mail_version").strip(), "transport=" + transport)
    scanner = http.server.ThreadingHTTPServer(("127.0.0.1", 18080), Scanner)
    threading.Thread(target=scanner.serve_forever, daemon=True).start()
    env = dict(os.environ, MTA_HOOKS_TOKEN=TOKEN, RUST_LOG="mta_hooks_milter=debug", NO_COLOR="1")
    bridge = subprocess.Popen([
        "/usr/local/bin/mta-hooks-milter", "--scanner", "http://127.0.0.1:18080/register",
        "--insecure-loopback", "--policy-timeout-ms", "1500",
        "--milter-progress-interval-ms", "1000", "--scanner-stages", ",".join(STAGES),
    ] + (["--milter-unix", unix_path] if transport == "unix" else []), env=env)
    postfix = None
    try:
        wait_port(8080, bridge)
        if transport == "unix":
            os.chown(unix_path, -1, grp.getgrnam("postfix").gr_gid)
            os.chmod(unix_path, 0o660)
        postfix = subprocess.Popen(["postfix", "start-fg"])
        wait_port(2525, postfix)
        with connect() as smtp:
            submit(smtp, "accept-first")
            # Postfix retains this milter socket for the SMTP session. A legal
            # pause beyond the former 60-second frame/idle deadline must not
            # lose filtering or fall back to milter_default_action.
            print("WAIT 65 seconds on the existing SMTP session", flush=True)
            time.sleep(65)
            submit(smtp, "after-idle")
            submit(smtp, "null-sender", sender="")
            assert smtp.mail("aborted@example.test")[0] == 250
            assert smtp.rcpt("bob@localhost")[0] == 250
            assert smtp.rset()[0] == 250
            submit(smtp, "after-rset")
            submit(smtp, "reject", expected=550)
            submit(smtp, "after-reject")
            submit(smtp, "tempfail", expected=451)
            submit(smtp, "after-tempfail")
            submit(smtp, "discard")
            hold = submit(smtp, "quarantine")
            submit(smtp, "unchanged")
            submit(smtp, "large-body", body=(b"A" * 998 + b"\r\n") * 180)
            submit(smtp, "invalid", expected=451)
            submit(smtp, "unavailable", expected=451)
            submit(smtp, "timeout", expected=451)
            submit(smtp, "after-errors")
            if STAGES == ALL_STAGES:
                multi_stage_cases(smtp)
        with connect() as smtp:
            # The snake-oil certificate is confined to this network-isolated fixture.
            smtp.starttls(context=ssl._create_unverified_context())
            assert smtp.ehlo("client.example.test")[0] == 250
            submit(smtp, "after-starttls")
            submit(smtp, "empty-body", body=b"")
            submit(smtp, "dot-and-eight-bit", body=b".leading dot\r\n..two dots\r\ncaf\xc3\xa9\r\n")
        def concurrent_message(n):
            with connect() as smtp:
                return submit(smtp, f"concurrent-{n}")
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
            list(pool.map(concurrent_message, range(4)))
        sessions = 6
        if STAGES == ALL_STAGES:
            sessions += disconnect_session()
            check_stage_events(sessions)
        queue = [json.loads(line) for line in run("postqueue", "-j").splitlines()]
        assert any(m["queue_id"] == hold and m["queue_name"] == "hold" for m in queue)
        print("PASS quarantine-is-in-hold-queue")
        expected_ids = {r["queue_id"] for r in RESULTS if r["queue_id"]}
        assert {m["queue_id"] for m in queue} == expected_ids, queue
        metrics = urllib.request.urlopen("http://127.0.0.1:8080/metrics").read().decode()
        assert "milter_protocol_errors_total 0\n" in metrics
        with LOCK:
            # A MAIL-stage discard ends the transaction before end-of-message.
            messages = len({rid for stage, _, rid in STAGE_EVENTS if stage == "data"})
        assert f"milter_messages_total {messages}\n" in metrics
        assert "milter_policy_errors_total 3\n" in metrics
        assert "milter_hook_retries_total 2\n" in metrics
        # The scanner-timeout case outlives one progress interval; Postfix accepted the keepalive.
        assert "milter_progress_total 1\n" in metrics
        for operation in ("policy", "registration", "hook", "registration_wait"):
            assert f'milter_operations_active{{operation="{operation}"}} 0\n' in metrics
        with LOCK:
            evaluations = len({rid for _, _, rid in STAGE_EVENTS})
            hooks = len(STAGE_EVENTS)
        assert evaluations >= len(RESULTS) and hooks == evaluations + 2
        assert f'milter_operation_duration_seconds_count{{operation="policy"}} {evaluations}\n' in metrics
        assert f'milter_operation_duration_seconds_count{{operation="hook"}} {hooks}\n' in metrics
        for outcome in ("invalid", "http_status", "timeout"):
            assert f'milter_operations_total{{operation="policy",outcome="{outcome}"}} 1\n' in metrics
        assert f'milter_listener_up{{transport="{transport}"}} 1\n' in metrics
        print(metrics)
        bridge.terminate()
        bridge.wait(timeout=10)
        with LOCK:
            assert DEREGISTRATIONS == ["/register/postfix-interop"], DEREGISTRATIONS
        print("PASS deregistration-on-shutdown")
        # Negative control: fail closed when the bridge itself is absent. With a
        # connect-stage subscription Postfix may already answer EHLO temporarily.
        with smtplib.SMTP("127.0.0.1", 2525, timeout=10) as smtp:
            code = smtp.ehlo("client.example.test")[0]
            if code == 250:
                code, _ = smtp.mail("alice@example.test")
            assert 400 <= code < 500, code
        print("PASS missing-bridge temporary failure")
        # Top-level checks beyond the message cases: hold queue, deregistration,
        # missing bridge, plus the disconnect session and stage-event audit.
        extra = 5 if STAGES == ALL_STAGES else 3
        print(json.dumps({"passed": len(RESULTS) + extra, "transport": transport,
                          "stages": STAGES, "cases": RESULTS,
                          "scanner": "controlled Python draft-01 fixture, not independent"}))
    finally:
        if bridge.poll() is None:
            bridge.terminate()
            bridge.wait(timeout=10)
        if postfix is not None and postfix.poll() is None:
            run("postfix", "stop")
            postfix.wait(timeout=10)
        scanner.shutdown()


if __name__ == "__main__":
    main()
