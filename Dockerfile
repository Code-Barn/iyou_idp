# Stage 1: Builder — compile native Rust crypto + Python dependencies
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

# Install the standard Rust compiler toolchain
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
ENV PATH="/root/.cargo/bin:${PATH}"

# Inject the modern uv packager tool layer
COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /bin/

# Copy dependency manifests and sync production virtual environment
COPY pyproject.toml uv.lock Cargo.toml Cargo.lock ./
COPY crates/ ./crates/
RUN uv sync --no-dev

# Install maturin for native Rust-to-Python bridge compilation
RUN uv pip install 'maturin>=1.0,<2.0'

# Copy the remaining project source
COPY . .

# Compile the _crypto.abi3.so PyO3 extension via maturin
RUN maturin build --release --out /app/dist && \
    uv pip install /app/dist/*.whl && \
    uv pip uninstall maturin -y

# Harvest all static assets at build time
RUN DJANGO_SETTINGS_MODULE=config.settings uv run python manage.py collectstatic --noinput

# Stage 2: Slim runtime — production image
FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PATH="/app/.venv/bin:${PATH}"

# Install runtime-only database adapter library
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpq5 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy the fully-resolved virtual environment from builder
COPY --from=builder /app/.venv /app/.venv

# Copy harvested static assets
COPY --from=builder /app/staticfiles /app/staticfiles

# Copy application source (needed for Django app discovery)
COPY --from=builder /app/config /app/config
COPY --from=builder /app/auth_bridge /app/auth_bridge
COPY --from=builder /app/manage.py /app/manage.py
COPY --from=builder /app/pyproject.toml /app/pyproject.toml

# Copy the compiled _crypto.abi3.so from site-packages into the app source tree
# so the sys.path fallback in settings.py picks it up
COPY --from=builder /app/.venv/lib/python3.12/site-packages/iyou_idp/_crypto*.so /app/src/iyou_idp/
COPY --from=builder /app/src/iyou_idp/__init__.py /app/src/iyou_idp/__init__.py

# Copy and secure the entrypoint
COPY docker-entrypoint.sh /docker-entrypoint.sh
RUN chmod 755 /docker-entrypoint.sh

# Enforce non-root user for security hardening
RUN addgroup --system --gid 1001 app && \
    adduser --system --uid 1001 --ingroup app --no-create-home app
USER app

# Standard cluster container health check against the auth endpoint
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/auth/challenge/')" || exit 1

ENTRYPOINT ["/docker-entrypoint.sh"]
