# Stage 1: Builder
FROM rust:1.76-slim-bookworm as builder
WORKDIR /app
COPY Cargo.toml Cargo.lock ./
# Add a dummy main.rs if needed for dependency caching
# This step ensures dependencies are built and cached efficiently
RUN mkdir src && echo "fn main() {}" > src/main.rs
RUN cargo build --release -j $(nproc) # Build dependencies
RUN rm -rf src # Remove dummy main.rs

COPY . .
RUN cargo build --release -j $(nproc) --bin your_app_name # Adjust --bin if your binary name differs

# Stage 2: Runtime
FROM debian:bookworm-slim
WORKDIR /app
COPY --from=builder /app/target/release/your_app_name /usr/local/bin/your_app_name

# If your Axum app needs certificates, you might need to install ca-certificates
# RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*

# Set appropriate user for security (non-root)
# USER nobody

EXPOSE 8000
CMD ["/usr/local/bin/your_app_name"]
