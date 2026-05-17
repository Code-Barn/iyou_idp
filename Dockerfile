# =============================================================================
# Stage 1: Builder — compile the Rust _crypto extension with Maturin
# =============================================================================
FROM python:3.13-slim AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    gcc \
    libc6-dev \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Install latest stable Rust via rustup (apt rustc 1.85 is too old for reqwest deps)
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
ENV PATH="/root/.cargo/bin:${PATH}"

RUN pip install --no-cache-dir "maturin>=1.0,<2.0"

# Cache Rust crate dependencies before copying full source
WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY crates/rust-did/Cargo.toml crates/rust-did/
RUN mkdir -p src crates/rust-did/src && \
    touch src/lib.rs crates/rust-did/src/lib.rs && \
    cargo fetch

# Now copy the actual Rust and Python source
COPY src/ ./src/
COPY crates/rust-did/src/ ./crates/rust-did/src/
COPY pyproject.toml ./

# Build the _crypto extension module
RUN maturin build --release


# =============================================================================
# Stage 2: Runner — Django application
# =============================================================================
FROM python:3.13-slim AS runner

# Runtime library for PostgreSQL (psycopg2)
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpq5 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy pyproject.toml first to install Python dependencies
COPY pyproject.toml ./

# Install all Python dependencies from pyproject.toml using tomllib (stdlib in 3.12)
RUN pip install --no-cache-dir \
    $(python -c "import tomllib; d=tomllib.load(open('pyproject.toml','rb')); print(' '.join(d['project']['dependencies']))")

# Copy the compiled wheel from the builder and install it
# This places _crypto.abi3.so into site-packages/iyou_idp/
COPY --from=builder /build/target/wheels/*.whl /tmp/
RUN pip install --no-cache-dir /tmp/*.whl && rm -rf /tmp/*.whl

# Copy the rest of the Django project code
COPY . .

EXPOSE 8000

CMD ["python", "manage.py", "runserver", "0.0.0.0:8000"]
