FROM rust:1.90-bookworm AS builder
WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo build --locked

FROM debian:bookworm-slim
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    postfix python3 ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=builder /build/target/debug/mta-hooks-milter /usr/local/bin/mta-hooks-milter
COPY interop/postfix_test.py /opt/interop/postfix_test.py
ENTRYPOINT ["python3", "-u", "/opt/interop/postfix_test.py"]
