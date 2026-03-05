# Prompt Sentinel Framework

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Rust](https://img.shields.io/badge/Rust-1.70%2B-blue)](https://www.rust-lang.org/)

A comprehensive framework for safe, compliant, and ethical AI interactions with provider-agnostic LLM backends (Mistral default).

## Features

- **Prompt Firewall**: Protects against prompt injection attacks
- **Bias Detection**: Analyzes prompts for potential biases
- **EU AI Act Compliance**: Ensures compliance with EU regulations
- **Audit Logging**: Comprehensive audit trail for all operations
- **Provider-Agnostic LLM Layer**: OpenAI-compatible and Anthropic-compatible backend support
- **Production Hardening**: Health probes, circuit breaker, secure headers, and configurable CORS allowlist
- **Auth + RBAC Bootstrap**: API key authentication, role permissions, and per-key rate limiting

## Quick Start

```bash
# Clone the repository
git clone https://github.com/Inferenco/prompt_sentinel.git
cd prompt_sentinel

# Build the project
cargo build --release

# Set environment variables
export LLM_API_KEY="your-api-key"
export LLM_BACKEND="openai_compat"
export RUST_LOG="info"

# Run the server
cargo run --release
```

## Installation

### Prerequisites

- Rust 1.85 or higher
- Cargo package manager
- LLM provider API key (for full functionality)

### Build from Source

```bash
# Install Rust (if not already installed)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source $HOME/.cargo/env

# Clone and build
git clone https://github.com/Inferenco/prompt_sentinel.git
cd prompt_sentinel
cargo build --release
```

### Docker Installation

```bash
# Build Docker image
docker build -t prompt-sentinel .

# Run container
docker run -d \
  -p 3000:3000 \
  -e LLM_API_KEY="your-api-key" \
  -e LLM_BACKEND="openai_compat" \
  -e RUST_LOG="info" \
  --name prompt-sentinel \
  prompt-sentinel
```

## Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `LLM_BACKEND` | `openai_compat`, `anthropic_compat`, `ollama`, `vllm` | `openai_compat` |
| `LLM_API_KEY` | API key for remote providers | None |
| `LLM_BASE_URL` | Override provider base URL | Backend-specific |
| `LLM_GENERATION_MODEL` | Generation model id | Backend-specific |
| `LLM_MODERATION_MODEL` | Moderation model id | Backend-specific |
| `LLM_EMBEDDING_MODEL` | Embedding model id | Backend-specific |
| `CORS_ALLOW_ORIGINS` | Comma-separated CORS allowlist | `http://localhost:5175,http://127.0.0.1:5175` |
| `LLM_REQUEST_TIMEOUT_SECS` | Upstream request timeout | `120` |
| `LLM_CONNECT_TIMEOUT_SECS` | Upstream connect timeout | `10` |
| `LLM_POOL_MAX_IDLE_PER_HOST` | Upstream HTTP pool tuning | `20` |
| `LLM_POOL_IDLE_TIMEOUT_SECS` | Upstream idle connection timeout | `90` |
| `LLM_CIRCUIT_BREAKER_FAILURE_THRESHOLD` | Consecutive failures before open | `5` |
| `LLM_CIRCUIT_BREAKER_OPEN_DURATION_SECS` | Circuit open window | `30` |
| `AUTH_ENABLED` | Enable API key auth + RBAC middleware | `false` |
| `AUTH_API_KEYS` | Comma-separated `token:role[:scope1\|scope2]` values | None |
| `AUTH_SERVICE_TOKENS` | Comma-separated service tokens in same format | None |
| `AUTH_RATE_LIMIT_PER_MINUTE` | Per-key request limit per 60s | `300` |
| `AUTH_KEY_STORE_PATH` | Persistent auth key store path | `prompt_sentinel_data/auth_keys.json` |
| `AUTH_DEFAULT_KEY_EXPIRY_SECS` | Default TTL (seconds) for generated keys | None |
| `OIDC_ENABLED` | Enable OIDC bearer-token verification path | `false` |
| `OIDC_PROVIDER` | `generic`, `auth0`, `okta`, `azure_ad`, `keycloak` | `generic` |
| `OIDC_ISSUER_URL` | Expected JWT issuer (`iss`) | None |
| `OIDC_AUDIENCE` | Expected audience (`aud`) | None |
| `OIDC_CLIENT_ID` | Expected client id audience match | None |
| `OIDC_ROLES_CLAIM` | JWT claim containing role list | `roles` |
| `OIDC_SCOPES_CLAIM` | JWT claim containing scopes | `scope` |
| `OIDC_JWKS_URL` | OIDC JWKS endpoint for JWT signature verification | None |
| `OIDC_JWKS_REFRESH_INTERVAL_SECS` | JWKS cache refresh interval | `300` |
| `OIDC_CLOCK_SKEW_SECS` | JWT clock skew tolerance | `60` |
| `OIDC_ALLOW_INSECURE_JWT_PARSE` | Dev-only claim parsing without signature verification | `false` |
| `RUST_LOG` | Logging level | `info` |
| `SERVER_PORT` | Server port | `3000` |
| `SLED_DB_PATH` | Database path | `prompt_sentinel_data` |

### Configuration Files

Edit configuration files in the `config/` directory:

- `firewall_rules.json`: Prompt firewall rules
- `eu_risk_keywords.json`: EU AI Act compliance keywords

See [CONFIGURATION_GUIDE.md](CONFIGURATION_GUIDE.md) for detailed configuration options.

## Usage

### Basic Usage

```rust
use prompt_sentinel::FrameworkConfig;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize tracing
    tracing_subscriber::fmt::init();

    // Use default configuration
    let config = FrameworkConfig::default();

    // Initialize the framework
    let server = config.initialize().await?;

    // Start the server
    server.start().await?;

    Ok(())
}
```

### Custom Configuration

```rust
use prompt_sentinel::FrameworkConfig;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();

    let config = FrameworkConfig {
        server_port: 8080,
        sled_db_path: "/custom/path/to/db".to_string(),
        mistral_api_key: Some("your-api-key".to_string()),
    };

    let server = config.initialize().await?;
    server.start().await?;

    Ok(())
}
```

## API Endpoints

### POST /api/compliance/check

Check a prompt for compliance with all framework rules.

**Request:**
```json
{
  "correlation_id": "optional-uuid",
  "prompt": "Your prompt text here"
}
```

**Response:**
```json
{
  "correlation_id": "generated-or-provided-uuid",
  "status": "Completed|BlockedByFirewall|BlockedByInputModeration|BlockedByOutputModeration",
  "firewall": {
    "action": "Allow|Block",
    "reasons": ["reason1", "reason2"],
    "sanitized_prompt": "cleaned prompt text"
  },
  "bias": {
    "score": 0.25,
    "level": "Low|Medium|High",
    "categories": ["gender", "race"]
  },
  "input_moderation": {
    "flagged": false,
    "categories": []
  },
  "output_moderation": {
    "flagged": false,
    "categories": []
  },
  "generated_text": "AI response text",
  "audit_proof": {
    "audit_id": "uuid",
    "timestamp": "iso8601",
    "signature": "base64"
  }
}
```

### GET /health

Readiness check endpoint.

### GET /health/live

Liveness probe endpoint.

### GET /health/ready

Readiness probe endpoint.

### GET /health/startup

Startup probe endpoint.

### GET /api/llm/health (alias: `/api/mistral/health`)

Check LLM provider integration health.

**Response:**
```json
{
  "status": "healthy|unhealthy",
  "message": "status message",
  "models": ["model1", "model2", "model3"]
}
```

### GET /api/auth/keys

List current auth credential metadata (token values are never returned).

### OIDC Bearer Auth (Bootstrap)

When `OIDC_ENABLED=true`, `Authorization: Bearer <jwt>` requests are evaluated through the OIDC verifier abstraction (`generic` / `auth0` / `okta` / `azure_ad` / `keycloak` provider configs).  
Secure mode validates JWT signatures against `OIDC_JWKS_URL` with an in-memory JWKS cache (`OIDC_JWKS_REFRESH_INTERVAL_SECS`) and clock-skew tolerance (`OIDC_CLOCK_SKEW_SECS`).  
`OIDC_ALLOW_INSECURE_JWT_PARSE=true` is development-only and bypasses signature checks.

### POST /api/auth/keys/generate

Generate a new API credential. The plaintext `token` is returned only once.

**Request:**
```json
{
  "role": "developer",
  "scopes": ["check:invoke", "audit:read"],
  "label": "ci-staging",
  "is_service_account": true,
  "expires_in_seconds": 3600
}
```

### Resource-Scoped Permissions (Scaffold)

Auth checks can now evaluate optional project/environment context from request headers:

- `x-project-id: <project>`
- `x-environment: <environment>`

Scope examples:

- `check:invoke:project:alpha:env:prod`
- `check:invoke:project:alpha`
- `check:invoke:env:staging`

Global scopes such as `check:invoke` remain valid and act as a fallback.

### POST /api/auth/keys/rotate

Rotate a credential without restarting the server.

**Request:**
```json
{
  "old_token": "old-api-token",
  "new_token": "new-api-token",
  "role": "developer",
  "scopes": ["check:invoke", "audit:read"],
  "expires_in_seconds": 86400
}
```

### POST /api/auth/keys/revoke

Revoke a credential by `key_id`.

**Request:**
```json
{
  "key_id": "key_123abc456def"
}
```

### POST /api/auth/keys/expire

Expire a credential immediately by `key_id`.

**Request:**
```json
{
  "key_id": "key_123abc456def"
}
```

### GET /api/auth/access-log

Fetch auth access events (allow/deny decisions).

## API Client Examples

### Python Example

```python
import requests
import json

# Check compliance endpoint
url = "http://localhost:3000/api/compliance/check"

payload = {
    "prompt": "Tell me about the best programming language"
}

headers = {
    "Content-Type": "application/json"
}

response = requests.post(url, data=json.dumps(payload), headers=headers)

if response.status_code == 200:
    result = response.json()
    print(f"Status: {result['status']}")
    print(f"Bias Score: {result['bias']['score']}")
    if result['status'] == 'Completed':
        print(f"Generated Text: {result['generated_text']}")
else:
    print(f"Error: {response.text}")
```

### JavaScript Example

```javascript
const axios = require('axios');

async function checkCompliance() {
    try {
        const response = await axios.post('http://localhost:3000/api/compliance/check', {
            prompt: "What are the benefits of Rust programming?"
        });
        
        console.log('Status:', response.data.status);
        console.log('Bias Score:', response.data.bias.score);
        if (response.data.status === 'Completed') {
            console.log('Generated Text:', response.data.generated_text);
        }
    } catch (error) {
        console.error('Error:', error.response?.data || error.message);
    }
}

checkCompliance();
```

### cURL Example

```bash
curl -X POST http://localhost:3000/api/compliance/check \
  -H "Content-Type: application/json" \
  -d '{"prompt": "Explain quantum computing"}' \
  | jq .
```

## Testing

### Run All Tests

```bash
cargo test
```

### Run Specific Tests

```bash
# Compliance flow tests
cargo test --test compliance_flow

# Security regression tests
cargo test --test security_regressions

# EU compliance tests
cargo test --test eu_compliance_rules

# Firewall benchmark
cargo bench
```

## Architecture

```
┌───────────────────────────────────────────────────────────────┐
│                     Prompt Sentinel Framework                  │
├───────────────────────────────────────────────────────────────┤
│                                                               │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────────┐    │
│  │ Prompt      │    │ Bias        │    │ EU Law          │    │
│  │ Firewall    │    │ Detection   │    │ Compliance      │    │
│  └─────────────┘    └─────────────┘    └─────────────────┘    │
│        │               │                     │                 │
│        ▼               ▼                     ▼                 │
│  ┌─────────────────────────────────────────────────────┐    │
│  │                 Compliance Engine                   │    │
│  └─────────────────────────────────────────────────────┘    │
│                        │                                  │
│                        ▼                                  │
│  ┌─────────────────────────────────────────────────────┐    │
│  │                 Mistral Service                    │    │
│  └─────────────────────────────────────────────────────┘    │
│                        │                                  │
│                        ▼                                  │
│  ┌─────────────────────────────────────────────────────┐    │
│  │                 Audit Logger                       │    │
│  └─────────────────────────────────────────────────────┘    │
│                                                               │
└───────────────────────────────────────────────────────────────┘
```

## Modules

### Prompt Firewall

- Detects and blocks prompt injection attempts
- Sanitizes potentially harmful content
- Configurable rules with fuzzy matching

### Bias Detection

- Analyzes prompts for potential biases
- Scoring system with configurable thresholds
- Categorization of bias types

### EU Law Compliance

- Ensures compliance with EU AI Act
- Risk classification system
- Audit trail for compliance decisions

### Mistral Service

- Integration with Mistral AI APIs
- Text generation and moderation
- Model validation and health checks

### Audit Logger

- Immutable audit trail
- Cryptographic proof generation
- Sled database storage

## Demo UI

The framework includes a React-based demo UI that provides an interactive interface for testing the compliance framework.

### Running the Demo

#### Prerequisites
- Node.js 20+
- npm or yarn

#### Installation

```bash
# Navigate to the demo-ui directory
cd demo-ui

# Install dependencies
npm install

# Start the development server
npm run dev
```

The demo UI will be available at `http://localhost:5175` (or the port specified in `FRONTEND_PORT`).

#### Configuration

The demo UI can be configured using environment variables:

| Variable | Description | Default |
|----------|-------------|---------|
| `FRONTEND_PORT` | Demo UI port | `5175` |
| `VITE_API_BASE_URL` | Backend API URL | `http://localhost:3000` |

Create a `.env` file in the `demo-ui` directory:

```env
# Demo UI configuration
FRONTEND_PORT=5175
VITE_API_BASE_URL=http://localhost:3000
```

#### Docker Deployment

To run the demo UI with Docker:

```bash
# Build and start both backend and frontend
docker compose up -d

# Access the demo UI
open http://localhost:5175
```

The `docker-compose.yml` file includes configuration for both services:

```yaml
services:
  prompt-sentinel:
    build: .
    ports:
      - "${SERVER_PORT}:${SERVER_PORT}"
    environment:
      - MISTRAL_API_KEY=${MISTRAL_API_KEY}
      - RUST_LOG=${RUST_LOG}
      - SERVER_PORT=${SERVER_PORT}
      - SLED_DB_PATH=${SLED_DB_PATH}
    volumes:
      - sled-data:/data
    restart: unless-stopped

  demo-ui:
    build:
      context: ./demo-ui
      dockerfile: Dockerfile
    ports:
      - "${FRONTEND_PORT}:${FRONTEND_PORT}"
    environment:
      - VITE_API_BASE_URL=${VITE_API_BASE_URL}
    depends_on:
      - prompt-sentinel
    restart: unless-stopped

volumes:
  sled-data:
```

### Demo Features

The demo UI provides:
- **Interactive prompt testing**: Test prompts and see real-time compliance results
- **Compliance visualization**: Visual representation of firewall, bias, and moderation results
- **Audit trail**: View compliance history and audit records
- **Configuration management**: Adjust framework settings through the UI

## Deployment

### Production Deployment

```bash
# Build for production
cargo build --release

# Create systemd service
sudo nano /etc/systemd/system/prompt-sentinel.service
```

```ini
[Unit]
Description=Prompt Sentinel Framework
After=network.target

[Service]
User=prompt-sentinel
WorkingDirectory=/opt/prompt-sentinel
Environment="MISTRAL_API_KEY=your-api-key"
Environment="RUST_LOG=info"
ExecStart=/opt/prompt-sentinel/target/release/prompt_sentinel
Restart=always

[Install]
WantedBy=multi-user.target
```

```bash
# Enable and start service
sudo systemctl enable prompt-sentinel
sudo systemctl start prompt-sentinel
```

### Kubernetes Deployment

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: prompt-sentinel
spec:
  replicas: 3
  selector:
    matchLabels:
      app: prompt-sentinel
  template:
    metadata:
      labels:
        app: prompt-sentinel
    spec:
      containers:
      - name: prompt-sentinel
        image: prompt-sentinel:latest
        ports:
        - containerPort: 3000
        env:
        - name: MISTRAL_API_KEY
          valueFrom:
            secretKeyRef:
              name: mistral-api-key
              key: api-key
        - name: RUST_LOG
          value: "info"
        resources:
          requests:
            cpu: "500m"
            memory: "512Mi"
          limits:
            cpu: "1"
            memory: "1Gi"
        volumeMounts:
        - name: sled-data
          mountPath: /data
      volumes:
      - name: sled-data
        persistentVolumeClaim:
          claimName: sled-pvc
```

## Monitoring

### Health Endpoints

- `GET /health`: Basic health check
- `GET /api/mistral/health`: Mistral API health check

### Logging

Configure logging level with `RUST_LOG` environment variable:

```bash
# Debug logging
export RUST_LOG="debug"

# Info logging (default)
export RUST_LOG="info"

# Trace logging (verbose)
export RUST_LOG="trace"
```

### Metrics

Integrate with Prometheus for monitoring:

```rust
// Add to your main.rs
use prometheus::Encoder;

async fn metrics() -> String {
    let encoder = prometheus::TextEncoder::new();
    let metric_families = prometheus::gather();
    let mut buffer = vec![];
    encoder.encode(&metric_families, &mut buffer).unwrap();
    String::from_utf8(buffer).unwrap()
}
```

## Security

### Best Practices

1. **API Keys**: Store Mistral API keys securely
2. **Network**: Use HTTPS in production
3. **Updates**: Keep dependencies updated
4. **Firewall**: Regularly update firewall rules
5. **Backups**: Backup the Sled database regularly

### Security Features

- Input validation and sanitization
- Rate limiting (recommended to add)
- Audit logging for all operations
- Secure configuration management

## Performance

### Optimization Tips

1. **Caching**: Implement response caching
2. **Batching**: Batch requests where possible
3. **Connection Pooling**: Use connection pooling for Mistral API
4. **Async**: Leverage async I/O throughout

### Benchmarking

```bash
# Run firewall benchmark
cargo bench

# Profile with flamegraph
cargo flamegraph --bench firewall_benchmark
```

## Troubleshooting

### Common Issues

**Server fails to start:**
- Check Mistral API key is valid
- Verify database path is writable
- Review error logs for details

**High latency:**
- Check network connectivity to Mistral API
- Review bias detection threshold
- Monitor system resources

**False positives:**
- Adjust firewall rules
- Review fuzzy matching settings
- Update configuration files

### Debugging

```bash
# Enable debug logging
export RUST_LOG="debug"

# Run with backtrace
RUST_BACKTRACE=1 cargo run

# Check logs
journalctl -u prompt-sentinel -f
```

## Contributing

Contributions are welcome! Please follow these guidelines:

1. Fork the repository
2. Create a feature branch
3. Add tests for new features
4. Submit a pull request
5. Follow the existing code style

### Development Setup

```bash
# Clone repository
git clone https://github.com/Inferenco/prompt_sentinel.git

# Install pre-commit hooks
cargo install cargo-husky
cargo husky install

# Run tests
cargo test
```

## Roadmap

- Enhanced bias detection algorithms
- Additional compliance frameworks
- Performance optimizations
- Extended API capabilities
- Improved documentation

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Support

For issues, questions, or feature requests:

1. Check the [documentation](DOCUMENTATION.md)
2. Review the [configuration guide](CONFIGURATION_GUIDE.md)
3. Open an issue on GitHub
4. Join our community discussions

## Acknowledgements

- Mistral AI for their powerful language models
- The Rust community for excellent tools and libraries
- All contributors who help improve this framework

## Contact

For more information, visit our [website](https://inferenco.com) or contact us at [info@inferenco.com](mailto:info@inferenco.com).
