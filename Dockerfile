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
WORKDIR /app/crates/rust-did
RUN cargo build --release

# Re-align back to the primary execution context framework
WORKDIR /app
RUN uv run python manage.py collectstatic --noinput

# Stage 2: Hardened Runtime Environment
FROM python:3.12-slim

WORKDIR /app

# Install only the slim production client library for Postgres runtime execution
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpq5 \
    && rm -rf /var/lib/apt/lists/*

# Extract only the compiled virtualenv and app binaries from the builder stage
COPY --from=builder /app/.venv /app/.venv
COPY . .
COPY --from=builder /app/crates/rust-did/target/release/libdid_rust.so /app/crates/rust-did/
COPY --from=builder /app/staticfiles /app/staticfiles

ENV PATH="/app/.venv/bin:$PATH" \
    PYTHONUNBUFFERED=1

# Configure execution entrypoints
COPY docker-entrypoint.sh /
RUN chmod +x /docker-entrypoint.sh
ENTRYPOINT ["/docker-entrypoint.sh"]
