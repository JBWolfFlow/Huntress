# Huntress Attack Machine — Docker Sandbox Image
#
# Multi-stage build providing a hardened Kali-based attack container with:
# - Pre-installed security tools (nmap, nuclei, ffuf, sqlmap, etc.)
# - Scope-enforcing Squid proxy (HUNTRESS_ALLOWED_DOMAINS -> ACL)
# - Custom X-Huntress-Agent request header
# - Non-root execution as 'hunter' user
#
# Build: docker build -t huntress-attack-machine:latest -f Dockerfile .
# Run: managed by SandboxManager (never run directly)

# ──────────────────────────────────────────────────────────────────────────────
# Stage 1: Install tools
# ──────────────────────────────────────────────────────────────────────────────
FROM kalilinux/kali-rolling AS builder

ENV DEBIAN_FRONTEND=noninteractive

# Install base packages and security tools
RUN apt-get update && apt-get install -y --no-install-recommends \
    # Core utilities
    ca-certificates curl wget git jq python3 python3-pip \
    # Network scanning
    nmap masscan \
    # Web tools
    httpx-toolkit dnsx \
    # Fuzzing
    ffuf \
    # SQL injection
    sqlmap \
    # XSS
    dalfox \
    # Parameter discovery
    arjun \
    # Subdomain enumeration
    subfinder amass \
    # Fingerprinting
    whatweb wafw00f \
    # Proxy for scope enforcement
    squid \
    # Misc
    dnsutils netcat-openbsd iputils-ping \
    && rm -rf /var/lib/apt/lists/*

# Install Go-based tools that aren't in Kali repos
RUN curl -fsSL https://go.dev/dl/go1.22.5.linux-amd64.tar.gz | tar -C /usr/local -xzf - \
    && export PATH=$PATH:/usr/local/go/bin:/root/go/bin \
    # Nuclei — vulnerability scanner
    && go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest \
    # Interactsh client — OOB interaction detection
    && go install -v github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest \
    && cp /root/go/bin/nuclei /usr/local/bin/ \
    && cp /root/go/bin/interactsh-client /usr/local/bin/ \
    && rm -rf /usr/local/go /root/go

# ──────────────────────────────────────────────────────────────────────────────
# Stage 2: Slim runtime image
# ──────────────────────────────────────────────────────────────────────────────
FROM kalilinux/kali-rolling

ENV DEBIAN_FRONTEND=noninteractive

# Install only runtime dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates curl wget jq python3 \
    nmap masscan squid \
    dnsutils netcat-openbsd iputils-ping \
    && rm -rf /var/lib/apt/lists/*

# Copy tools from builder stage
COPY --from=builder /usr/bin/httpx /usr/bin/httpx
COPY --from=builder /usr/bin/dnsx /usr/bin/dnsx
COPY --from=builder /usr/bin/ffuf /usr/bin/ffuf
COPY --from=builder /usr/bin/sqlmap /usr/bin/sqlmap
COPY --from=builder /usr/bin/dalfox /usr/bin/dalfox
COPY --from=builder /usr/bin/arjun /usr/bin/arjun
COPY --from=builder /usr/bin/subfinder /usr/bin/subfinder
COPY --from=builder /usr/bin/amass /usr/bin/amass
COPY --from=builder /usr/bin/whatweb /usr/bin/whatweb
COPY --from=builder /usr/bin/wafw00f /usr/bin/wafw00f
COPY --from=builder /usr/local/bin/nuclei /usr/local/bin/nuclei
COPY --from=builder /usr/local/bin/interactsh-client /usr/local/bin/interactsh-client

# Create non-root user
RUN groupadd -r hunter && useradd -r -g hunter -d /home/hunter -s /bin/bash hunter

# Squid configuration template (populated at runtime by entrypoint)
RUN mkdir -p /etc/squid/conf.d

# Copy entrypoint script
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

# Set default environment
ENV http_proxy=http://127.0.0.1:3128
ENV https_proxy=http://127.0.0.1:3128
ENV HTTP_PROXY=http://127.0.0.1:3128
ENV HTTPS_PROXY=http://127.0.0.1:3128

WORKDIR /home/hunter

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
CMD ["sleep", "infinity"]
