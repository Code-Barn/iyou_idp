# Stage 1: Native Compilations
FROM python:3.12-slim AS builder

ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    PYTHONUNBUFFERED=1

WORKDIR /app

# Install system compilation toolchains and database headers
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    curl \
    gcc \
    libpq-dev \
    git \
    && rm -rf /var/lib/apt/lists/*

# Install the standard Rust compiler toolchain natively
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
ENV PATH="/root/.cargo/bin:${PATH}"

# Inject the modern uv packager tool layer
COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /bin/

# Copy dependencies manifest and sync the complete virtual environment
COPY pyproject.toml uv.lock ./
RUN uv sync --no-dev

# Copy project files and compile the interior Rust DID crypto module bindings
COPY . .
    WORKDIR /app/crates/did_rust

    RUN cargo build --release 2>&1

    # Copy libdid_rust.so out of the builder so the app image can use it
    COPY --from=builder /app/crates/did_rust/target/release/libdid_rust.so /app/crates/did_rust/
COPY --from=builder /app/staticfiles /app/staticfiles

ENV PATH="/app/.venv/bin:$PATH" \
    PYTHONUNBUFFERED=1

# Configure execution entrypoints
COPY docker-entrypoint.sh /
RUN chmod +x /docker-entrypoint.sh
ENTRYPOINT ["/docker-entrypoint.sh"]
