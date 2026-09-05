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
REQUESTS = []
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

    def do_POST(self):
        if self.headers.get("Authorization") != "Bearer " + TOKEN:
            return self.reply(401)
        request = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        if self.path == "/register":
            assert request["inbound"]["stages"] == ["data"]
            return self.reply(201, {
                "registrationId": "postfix-interop", "status": "active",
                "createdAt": "2026-09-05T00:00:00Z", "expiresAt": None,
                "hookEndpoint": "/hook",
                "negotiated": {"serialization": "json", "inbound": request["inbound"]},
            })
        assert self.path == "/hook"
        assert self.headers["X-MTA-Hooks-Registration"] == "postfix-interop"
        assert self.headers["X-MTA-Hooks-Request-Id"]
        assert request["stage"] == "data"
        raw = base64.b64decode(request["rawMessage"], validate=True)
        message = email.message_from_bytes(raw)
        case = message["X-Interop-Case"]
        with LOCK:
            REQUESTS.append((case, request, raw))
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
        return self.reply(200, {"add": [{"path": "/message/headers", "value": {
            "name": "X-Interop-Scanned", "value": case}}]})


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


def submit(smtp, case, sender="alice@example.test", body=b"hello\r\n", expected=250):
    assert smtp.mail(sender)[0] == 250
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
    with LOCK:
        matches = [(req, data) for name, req, data in REQUESTS if name == case]
    assert len(matches) == 1, (case, len(matches))
    request, observed = matches[0]
    assert request["envelope"]["from"]["address"] == (sender or None)
    assert request["envelope"]["to"][0]["address"] == "bob@localhost"
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
        "--insecure-loopback", "--policy-timeout-ms", "500",
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
        queue = [json.loads(line) for line in run("postqueue", "-j").splitlines()]
        assert any(m["queue_id"] == hold and m["queue_name"] == "hold" for m in queue)
        print("PASS quarantine-is-in-hold-queue")
        expected_ids = {r["queue_id"] for r in RESULTS if r["queue_id"]}
        assert {m["queue_id"] for m in queue} == expected_ids, queue
        metrics = urllib.request.urlopen("http://127.0.0.1:8080/metrics").read().decode()
        assert "milter_protocol_errors_total 0\n" in metrics
        assert f"milter_messages_total {len(RESULTS)}\n" in metrics
        assert "milter_policy_errors_total 3\n" in metrics
        print(metrics)
        bridge.terminate()
        bridge.wait(timeout=10)
        # Negative control: fail closed when the bridge itself is absent.
        with connect() as smtp:
            code, _ = smtp.mail("alice@example.test")
            assert 400 <= code < 500, code
        print("PASS missing-bridge temporary failure")
        print(json.dumps({"passed": len(RESULTS) + 2, "transport": transport, "cases": RESULTS,
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
