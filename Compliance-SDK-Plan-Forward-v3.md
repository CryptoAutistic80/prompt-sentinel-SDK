# Prompt Sentinel: Commercial Development Plan v2

## Strategic Vision

**Mission**: Build the world's most trusted, developer-friendly EU AI Act compliance platform that enables organisations to deploy AI responsibly while achieving regulatory conformity.

**Positioning**: The only open-source, security-first, provider-agnostic AI compliance SDK with cryptographic audit trails, designed for developers who need to embed regulatory compliance directly into their AI pipelines — compatible with any OpenAI SDK-compatible or Anthropic SDK-compatible model provider out of the box.

**Competitive Moat**: While competitors like Credo AI, Holistic AI, and IBM watsonx.governance focus on governance dashboards for compliance officers, Prompt Sentinel is the compliance engine that developers actually integrate. Provider-agnostic by design — supporting any OpenAI SDK-compatible or Anthropic SDK-compatible model with Mistral as the default — we are to AI compliance what Stripe is to payments.

---

## Part 1: Strategic Foundation

### 1.1 Market Analysis Summary

| Metric | Value | Source |
|--------|-------|--------|
| Market Size (2026) | $492M | Gartner |
| Projected Size (2034) | $4.83B | Industry Research |
| CAGR | 35-45% | Multiple Sources |
| EU AI Act Enforcement | August 2, 2026 | European Commission |
| Enterprise AI Governance Adoption | 70%+ by 2026 | Gartner |
| Organisations with Advanced AI Security | 6% | Deloitte |

### 1.2 Competitive Positioning

| Competitor | Strengths | Weaknesses | Our Advantage |
|------------|-----------|------------|---------------|
| **Credo AI** | #1 ranked, comprehensive lifecycle | Enterprise-only, no SDK, opaque pricing | Developer SDK, open-source core, transparent |
| **Holistic AI** | Strong EU presence, 360-degree | Limited developer tools, closed source | API-first design, self-hosting option |
| **IBM watsonx.governance** | Enterprise trust, agent monitoring | Complex, expensive, IBM ecosystem bias | Lightweight, provider-agnostic (any OpenAI/Anthropic-compat API), Rust performance |
| **OneTrust** | Privacy expertise, assessments | Privacy-first (not AI-native), heavy | AI-native architecture, real-time enforcement |

### 1.3 Unique Value Proposition

1. **Developer-First**: SDK-native with REST API, language wrappers, and CLI tools
2. **Open-Source Core**: MIT-licensed foundation builds trust and enables customisation
3. **Cryptographic Auditability**: SHA-256 chained audit trail provides tamper-evident compliance evidence
4. **Security-Native**: Defence-in-depth with prompt firewall, semantic detection, and bias guards
5. **Self-Hosting Freedom**: No vendor lock-in; run anywhere from laptop to Kubernetes
6. **Provider-Agnostic**: Works with any OpenAI-compatible or Anthropic-compatible LLM API out of the box, with Mistral as the default; swap providers by changing a base URL
7. **Performance**: Rust-based engine delivers sub-100ms local checks at enterprise scale

---

## Part 2: Technical Architecture Vision

### 2.1 Target Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           PROMPT SENTINEL PLATFORM                          │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                        DEVELOPER SURFACE                             │   │
│  │  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐  │   │
│  │  │ Rust SDK │ │Python SDK│ │ Node SDK │ │  Go SDK  │ │   CLI    │  │   │
│  │  └────┬─────┘ └────┬─────┘ └────┬─────┘ └────┬─────┘ └────┬─────┘  │   │
│  │       │            │            │            │            │         │   │
│  │       └────────────┴────────────┴────────────┴────────────┘         │   │
│  │                              │                                       │   │
│  │                        ┌─────▼─────┐                                │   │
│  │                        │  REST API │                                │   │
│  │                        │  (v1/v2)  │                                │   │
│  │                        └─────┬─────┘                                │   │
│  └──────────────────────────────┼──────────────────────────────────────┘   │
│                                 │                                           │
│  ┌──────────────────────────────┼──────────────────────────────────────┐   │
│  │                     COMPLIANCE ENGINE                               │   │
│  │                              │                                      │   │
│  │    ┌─────────────────────────▼─────────────────────────────────┐   │   │
│  │    │                   REQUEST ROUTER                           │   │   │
│  │    │         (Rate Limiting, Auth, Tenant Isolation)           │   │   │
│  │    └─────────────────────────┬─────────────────────────────────┘   │   │
│  │                              │                                      │   │
│  │    ┌─────────────────────────▼─────────────────────────────────┐   │   │
│  │    │              DECISION PIPELINE (Configurable)              │   │   │
│  │    │  ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐         │   │   │
│  │    │  │Firewall │→│EU Risk  │→│  Bias   │→│Semantic │         │   │   │
│  │    │  │  Guard  │ │Classifier│ │Detector │ │ Threat  │         │   │   │
│  │    │  └─────────┘ └─────────┘ └─────────┘ └─────────┘         │   │   │
│  │    │       │           │           │           │               │   │   │
│  │    │       └───────────┴───────────┴───────────┘               │   │   │
│  │    │                          │                                 │   │   │
│  │    │  ┌───────────────────────▼───────────────────────────┐    │   │   │
│  │    │  │            MODERATION LAYER                        │    │   │   │
│  │    │  │  ┌──────────────┐        ┌──────────────┐         │    │   │   │
│  │    │  │  │Input Moderator│   →   │Output Moderator│        │    │   │   │
│  │    │  │  └──────────────┘        └──────────────┘         │    │   │   │
│  │    │  └───────────────────────┬───────────────────────────┘    │   │   │
│  │    │                          │                                 │   │   │
│  │    │  ┌───────────────────────▼───────────────────────────┐    │   │   │
│  │    │  │              LLM PROVIDER LAYER                    │    │   │   │
│  │    │  │  ┌──────────────────┐ ┌──────────────────┐         │    │   │   │
│  │    │  │  │ OpenAI-Compat    │ │ Anthropic-Compat │         │    │   │   │
│  │    │  │  │ (Mistral default,│ │ (Claude, Bedrock,│         │    │   │   │
│  │    │  │  │  OpenAI, Groq,  │ │  Vertex, etc.)   │         │    │   │   │
│  │    │  │  │  Together, etc.) │ │                  │         │    │   │   │
│  │    │  │  └──────────────────┘ └──────────────────┘         │    │   │   │
│  │    │  │  ┌──────────────────┐ ┌──────────────────┐         │    │   │   │
│  │    │  │  │ Ollama (Local)   │ │ vLLM (Local)     │         │    │   │   │
│  │    │  │  └──────────────────┘ └──────────────────┘         │    │   │   │
│  │    │  └───────────────────────────────────────────────────┘    │   │   │
│  │    └───────────────────────────────────────────────────────────┘   │   │
│  │                                                                     │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                      DATA & AUDIT LAYER                              │   │
│  │                                                                      │   │
│  │  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐              │   │
│  │  │ Audit Logger │  │  Evidence    │  │  Compliance  │              │   │
│  │  │ (Immutable)  │  │  Exporter    │  │  Reporter    │              │   │
│  │  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘              │   │
│  │         │                 │                 │                       │   │
│  │  ┌──────▼─────────────────▼─────────────────▼───────┐              │   │
│  │  │              STORAGE BACKENDS                     │              │   │
│  │  │  ┌────────┐ ┌────────┐ ┌────────┐ ┌────────┐    │              │   │
│  │  │  │ SledDB │ │PostgreSQL│ │  S3   │ │Blockchain│   │              │   │
│  │  │  │(Local) │ │(Cloud)  │ │(Archive)│ │(Anchor) │   │              │   │
│  │  │  └────────┘ └────────┘ └────────┘ └────────┘    │              │   │
│  │  └─────────────────────────────────────────────────┘              │   │
│  │                                                                      │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                    OBSERVABILITY LAYER                               │   │
│  │  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐           │   │
│  │  │Prometheus│  │  Jaeger  │  │ Grafana  │  │  Alerts  │           │   │
│  │  │ Metrics  │  │ Tracing  │  │Dashboards│  │ (PagerDuty)│          │   │
│  │  └──────────┘  └──────────┘  └──────────┘  └──────────┘           │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                    MANAGEMENT PLANE (SaaS)                           │   │
│  │  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐           │   │
│  │  │   Auth   │  │  Tenant  │  │ Billing  │  │   Admin  │           │   │
│  │  │(SSO/OIDC)│  │Management│  │ (Stripe) │  │Dashboard │           │   │
│  │  └──────────┘  └──────────┘  └──────────┘  └──────────┘           │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 2.2 Core Design Principles

1. **Defence in Depth**: Multiple independent compliance checks, any of which can block
2. **Fail Secure**: When uncertain, default to blocking; never fail open
3. **Audit Everything**: Every decision, every payload, cryptographically chained
4. **Pluggable Components**: Trait-based design for LLM providers (OpenAI-compat and Anthropic-compat backends), storage, and rules
5. **Configuration as Code**: All rules, thresholds, and policies in version-controlled JSON/YAML
6. **Zero Trust**: Assume all inputs are malicious; validate at every boundary
7. **Privacy by Design**: Data minimisation, encryption at rest, configurable retention

---

## Part 3: Phased Development Plan

### Phase 0: Foundation Hardening
**Objective**: Solidify the existing codebase for production deployment

#### 0.1 Security Hardening
- [ ] **CORS Policy Lockdown**: Replace `Allow-Origin: *` with configurable allowlist
- [ ] **TLS Termination Guide**: Document reverse proxy (nginx/Caddy) TLS setup
- [ ] **Secret Management Integration**:
  - HashiCorp Vault provider
  - AWS Secrets Manager provider
  - Kubernetes Secrets support
- [ ] **Input Validation Audit**: Fuzz testing with `cargo-fuzz` for all public APIs
- [ ] **Dependency Audit**: `cargo-audit` integration in CI, automated CVE scanning
- [ ] **Security Headers**: CSP, HSTS, X-Frame-Options middleware

#### 0.2 Reliability Improvements
- [ ] **Circuit Breaker Pattern**: Implement for all external API calls (LLM providers, etc.)
  - Open after 5 consecutive failures
  - Half-open probe after 30 seconds
  - Configurable thresholds
- [ ] **Health Check Enhancement**:
  - `/health/live` - Process is alive (Kubernetes liveness)
  - `/health/ready` - Dependencies available (Kubernetes readiness)
  - `/health/startup` - Initialisation complete (Kubernetes startup probe)
- [ ] **Graceful Shutdown**: Drain in-flight requests on SIGTERM
- [ ] **Connection Pooling**: HTTP client connection reuse with configurable pool size
- [ ] **Request Timeout Configuration**: Expose all timeouts via environment variables

#### 0.3 Observability Enhancement
- [ ] **OpenTelemetry Integration**: Replace custom telemetry with OTel SDK
  - Traces with W3C Trace Context propagation
  - Metrics with Prometheus export
  - Logs with structured JSON
- [ ] **Distributed Tracing**: Jaeger/Zipkin exporter support
- [ ] **Error Tracking**: Sentry integration for exception monitoring
- [ ] **SLI/SLO Dashboards**: Pre-built Grafana dashboards for:
  - Request latency (p50, p95, p99)
  - Error rates by type
  - Compliance check outcomes
  - LLM provider health

#### 0.4 Testing Infrastructure
- [ ] **Load Testing Suite**: Implement `firewall_benchmark` with k6 or Locust
  - Baseline: 1000 req/s sustained
  - Target: Sub-10ms p99 for firewall checks
- [ ] **Chaos Engineering**: Implement failure injection
  - Network partition simulation
  - LLM API timeout simulation
  - Storage failure simulation
- [ ] **Contract Testing**: OpenAPI spec with automated validation
- [ ] **Security Regression Suite**: Expand to 50+ injection patterns
- [ ] **Property-Based Testing**: Extend proptest coverage to all parsers

---

### Phase 1: Provider-Agnostic LLM Support
**Objective**: Ship a provider-agnostic LLM layer supporting any OpenAI SDK-compatible or Anthropic SDK-compatible model; Mistral as default, zero lock-in

#### 1.1 Provider Abstraction Layer
- [ ] **Define `LLMProvider` Trait**:
```rust
#[async_trait]
pub trait LLMProvider: Send + Sync {
    async fn generate(&self, request: GenerationRequest) -> Result<GenerationResponse>;
    async fn moderate(&self, content: &str) -> Result<ModerationResponse>;
    async fn embed(&self, texts: &[String]) -> Result<Vec<Embedding>>;
    fn capabilities(&self) -> ProviderCapabilities;
    fn health_check(&self) -> impl Future<Output = HealthStatus>;
}
```

- [ ] **Implement SDK-Compatible Provider Backends**:
  - `OpenAICompatProvider` — works with any provider exposing an OpenAI-compatible chat/completions API (Mistral, OpenAI, Azure OpenAI, Together AI, Groq, Fireworks, Deepseek, OpenRouter, any local server with OpenAI-compat endpoint, etc.) via configurable `base_url`
  - `AnthropicCompatProvider` — works with any provider exposing an Anthropic Messages API-compatible endpoint (Anthropic direct, AWS Bedrock Anthropic models, Google Vertex Anthropic models, etc.) via configurable `base_url`
  - `OllamaProvider` — local/self-hosted models (Ollama exposes an OpenAI-compatible API, but benefits from a dedicated provider for model management, GPU detection, and download workflows)
  - `VLLMProvider` — high-performance local inference (also OpenAI-compatible, dedicated provider for quantisation and performance tuning)

- [ ] **Default Configuration**: Mistral via `OpenAICompatProvider` with `base_url: https://api.mistral.ai/v1` — works out of the box, switchable to any other provider by changing `base_url` and `api_key`

#### 1.2 Base URL Override Pattern
- [ ] **Config-Driven Provider Switching**: Change provider by setting `base_url` + `api_key` + `model` — no code changes required
  ```yaml
  # Mistral (default)
  llm_provider:
    backend: openai_compat
    base_url: "https://api.mistral.ai/v1"
    api_key: "${MISTRAL_API_KEY}"
    model: "mistral-large-latest"

  # Switch to OpenAI — just change config
  llm_provider:
    backend: openai_compat
    base_url: "https://api.openai.com/v1"
    api_key: "${OPENAI_API_KEY}"
    model: "gpt-4o"

  # Switch to Anthropic
  llm_provider:
    backend: anthropic_compat
    base_url: "https://api.anthropic.com"
    api_key: "${ANTHROPIC_API_KEY}"
    model: "claude-sonnet-4-5-20250514"

  # Self-hosted via Ollama
  llm_provider:
    backend: openai_compat
    base_url: "http://localhost:11434/v1"
    model: "llama3"
  ```

#### 1.3 Provider Selection Logic
- [ ] **Capability-Based Routing**: Select provider based on required capabilities
- [ ] **Fallback Chains**: Configure primary → secondary → tertiary providers (can mix backends)
- [ ] **Cost Optimisation**: Route based on token costs when multiple providers qualify
- [ ] **Regional Compliance**: Prefer EU-hosted providers for GDPR compliance (Mistral default aligns here)
- [ ] **Model Versioning**: Pin to specific model versions for reproducibility

#### 1.4 Local Inference Support
- [ ] **Ollama Integration**: First-class support for local models
- [ ] **Model Download Manager**: CLI to download and verify models
- [ ] **GPU Detection**: Automatic CUDA/Metal acceleration detection
- [ ] **Quantisation Support**: Run quantised models for resource-constrained environments
- [ ] **Air-Gapped Mode**: Full functionality without internet connectivity

---

### Phase 2: Enterprise Authentication & Multi-Tenancy
**Objective**: Support enterprise deployment with isolation and access control

#### 2.1 Authentication Layer
- [ ] **API Key Authentication**:
  - Key generation with configurable expiry
  - Key rotation without downtime
  - Scoped permissions per key
  - Rate limits per key
- [ ] **OAuth 2.0 / OIDC Support**:
  - Auth0 integration
  - Okta integration
  - Azure AD integration
  - Keycloak integration
  - Generic OIDC provider support
- [ ] **mTLS Authentication**: Client certificate validation for zero-trust networks
- [ ] **Service Account Tokens**: Non-expiring tokens for CI/CD pipelines

#### 2.2 Authorisation Model
- [ ] **Role-Based Access Control (RBAC)**:
  ```yaml
  roles:
    - name: compliance_viewer
      permissions: [audit:read, reports:read, config:read]
    - name: compliance_admin
      permissions: [audit:*, reports:*, config:*, rules:*]
    - name: developer
      permissions: [check:invoke, audit:read]
  ```
- [ ] **Resource-Level Permissions**: Per-project, per-environment granularity
- [ ] **Audit Log for Access**: Track who accessed what, when

#### 2.3 Multi-Tenancy Architecture
- [ ] **Tenant Isolation Model**:
  - Logical isolation (shared infrastructure, database row-level security)
  - Physical isolation (dedicated databases, optional dedicated compute)
- [ ] **Tenant Configuration**:
  - Per-tenant firewall rules
  - Per-tenant bias thresholds
  - Per-tenant EU compliance keywords
  - Per-tenant LLM provider preferences
- [ ] **Tenant Quotas**:
  - Requests per minute/hour/day
  - Storage limits
  - Concurrent request limits
- [ ] **Data Residency**: Ensure tenant data stays in specified regions

#### 2.4 Workspace Model
- [ ] **Hierarchical Organisation**:
  ```
  Organisation (billing entity)
  └── Workspace (team/project)
      └── Environment (dev/staging/prod)
          └── API Keys (access credentials)
  ```
- [ ] **Cross-Workspace Policies**: Organisation-wide compliance baselines
- [ ] **Workspace Templates**: Pre-configured environments for common use cases

---

### Phase 3: Comprehensive EU AI Act Coverage
**Objective**: Full regulatory coverage for high-risk AI system compliance

#### 3.1 Risk Classification Engine
- [ ] **Automated Risk Tier Assessment**:
  - Questionnaire-based classification wizard
  - Automated scanning of AI system descriptions
  - Integration with existing risk management systems
- [ ] **Annex III Coverage**: Full mapping of high-risk categories
  - Biometric identification
  - Critical infrastructure management
  - Educational and vocational training
  - Employment and worker management
  - Access to essential services
  - Law enforcement
  - Migration and border control
  - Administration of justice
- [ ] **Dynamic Reclassification**: Detect when system usage changes risk tier
- [ ] **Classification Evidence**: Generate documentation for regulators

#### 3.2 Article-by-Article Compliance
- [ ] **Article 9 - Risk Management System**:
  - Risk register integration
  - Continuous risk monitoring
  - Mitigation tracking
  - Residual risk documentation
- [ ] **Article 10 - Data Governance**:
  - Training data lineage tracking
  - Data quality metrics
  - Bias detection in training data
  - Data provenance documentation
- [ ] **Article 11 - Technical Documentation**:
  - Auto-generated documentation templates
  - Version-controlled documentation
  - Documentation completeness checker
  - Export in regulator-friendly formats
- [ ] **Article 13 - Transparency**:
  - AI disclosure insertion
  - User notification APIs
  - Transparency report generation
- [ ] **Article 14 - Human Oversight**:
  - Human-in-the-loop enforcement
  - Override request workflows
  - Escalation rules engine
  - Decision audit with human reviewer ID
- [ ] **Article 15 - Accuracy, Robustness, Cybersecurity**:
  - Accuracy metric tracking
  - Adversarial robustness testing
  - Security posture scoring
- [ ] **Article 17 - Quality Management System**:
  - QMS documentation templates
  - Process compliance tracking
  - Non-conformity management
- [ ] **Article 50 - Transparency Obligations**:
  - Deepfake detection markers
  - AI-generated content labelling
  - Emotion recognition disclosure
- [ ] **Article 61 - Post-Market Monitoring**:
  - Incident reporting system
  - Performance degradation alerts
  - User feedback collection

#### 3.3 Conformity Assessment Support
- [ ] **Self-Assessment Module**:
  - Guided assessment workflows
  - Evidence collection automation
  - Gap analysis reporting
- [ ] **Notified Body Preparation**:
  - Document package generator
  - Evidence chain verification
  - Pre-assessment checklist
- [ ] **CE Marking Workflow**:
  - Declaration of conformity template
  - Technical file compilation
  - Registration database integration (future EU database)

#### 3.4 Prohibited Practices Detection (Article 5)
- [ ] **Enhanced Detection Engine**:
  - Social scoring detection
  - Manipulation technique detection
  - Vulnerability exploitation detection
  - Real-time biometric identification detection
  - Emotion inference detection (workplace/education)
  - Biometric categorisation detection
  - Facial recognition database scraping detection
- [ ] **Contextual Analysis**: Distinguish legitimate from prohibited uses
- [ ] **Hard Blocking**: Immediate rejection with detailed explanation
- [ ] **Incident Escalation**: Alert compliance officers on detection

---

### Phase 4: Audit Trail & Evidence Management
**Objective**: Tamper-proof, regulator-ready compliance evidence system

#### 4.1 Enhanced Audit Architecture
- [ ] **Immutable Append-Only Log**:
  - Write-once storage (S3 Object Lock, Azure Immutable Storage)
  - Cryptographic chaining (current SHA-256, upgrade path to SHA-3)
  - Merkle tree aggregation for efficient verification
- [ ] **Audit Event Schema v2**:
  ```rust
  struct AuditEvent {
      // Identity
      event_id: Uuid,
      correlation_id: String,
      tenant_id: String,
      workspace_id: String,

      // Timing
      timestamp: DateTime<Utc>,
      processing_duration_ms: u64,

      // Request
      prompt_hash: String,  // SHA-256 of prompt (not plaintext for privacy)
      prompt_length: usize,
      detected_language: String,

      // Decisions
      firewall_result: FirewallDecision,
      eu_compliance_result: EuComplianceDecision,
      bias_result: BiasDecision,
      semantic_result: SemanticDecision,
      input_moderation_result: ModerationDecision,
      output_moderation_result: ModerationDecision,
      final_decision: FinalDecision,

      // Evidence
      decision_reasons: Vec<DecisionReason>,
      human_override: Option<HumanOverride>,

      // Cryptographic Proof
      previous_hash: String,
      record_hash: String,

      // Metadata
      sdk_version: String,
      model_used: String,
      model_version: String,
  }
  ```

#### 4.2 Storage Backend Abstraction
- [ ] **Define `AuditStorage` Trait** (expand existing):
  ```rust
  #[async_trait]
  pub trait AuditStorage: Send + Sync {
      async fn append(&self, event: AuditEvent) -> Result<AuditProof>;
      async fn query(&self, filter: AuditFilter) -> Result<Vec<AuditEvent>>;
      async fn verify_chain(&self, start: &str, end: &str) -> Result<ChainVerification>;
      async fn export(&self, filter: AuditFilter, format: ExportFormat) -> Result<Vec<u8>>;
      async fn retention_policy(&self) -> RetentionPolicy;
  }
  ```
- [ ] **Storage Implementations**:
  - `SledStorage` (local, current)
  - `PostgresStorage` (cloud, row-level security)
  - `S3Storage` (archive, immutable)
  - `TimescaleStorage` (time-series optimised)
  - `BlockchainAnchor` (periodic anchoring for legal evidence)

#### 4.3 Evidence Export & Reporting
- [ ] **Export Formats**:
  - JSON Lines (streaming)
  - CSV (spreadsheet analysis)
  - PDF (human-readable reports)
  - SARIF (security findings)
  - Regulator-specific formats (TBD based on guidance)
- [ ] **Report Types**:
  - Compliance Summary Report
  - Incident Report
  - Human Oversight Report
  - Risk Assessment Report
  - Article 61 Six-Month Log Report
- [ ] **Scheduled Reports**: Automated daily/weekly/monthly report generation
- [ ] **Evidence Signing**: GPG/PKI signing for legal admissibility

#### 4.4 Retention & Lifecycle
- [ ] **Configurable Retention Policies**:
  - Minimum: 6 months (EU AI Act requirement)
  - Default: 1 year
  - Extended: 5+ years (enterprise)
- [ ] **Secure Deletion**: Cryptographic erasure for GDPR compliance
- [ ] **Tiered Storage**: Hot → Warm → Cold → Archive lifecycle
- [ ] **Legal Hold**: Prevent deletion during investigations

---

### Phase 5: Configuration & Rules Management
**Objective**: Runtime-configurable compliance rules without restarts

#### 5.1 Configuration Management System
- [ ] **Config Schema Definition**:
  ```yaml
  # prompt_sentinel_config.yaml
  version: "1.0"

  firewall:
    enabled: true
    rules_path: "./rules/firewall_rules.json"
    fuzzy_distance: 2
    block_action: reject  # reject | sanitize | flag

  bias_detection:
    enabled: true
    threshold: 0.35
    categories:
      - gender
      - religious
      - ethnic
      - political
    custom_patterns_path: "./rules/custom_bias.json"

  eu_compliance:
    enabled: true
    risk_tier: high  # minimal | limited | high | unacceptable
    keywords_path: "./rules/eu_keywords.json"
    article_5_strict: true

  semantic_detection:
    enabled: true
    templates_path: "./rules/attack_templates.json"
    medium_threshold: 0.70
    high_threshold: 0.80

  llm_provider:
    backend: openai_compat        # openai_compat | anthropic_compat
    base_url: "https://api.mistral.ai/v1"  # Mistral default; override for any compatible provider
    model: "mistral-large-latest"
    api_key: "${LLM_API_KEY}"
    fallback:
      - backend: anthropic_compat
        base_url: "https://api.anthropic.com"
        model: "claude-sonnet-4-5-20250514"
        api_key: "${ANTHROPIC_API_KEY}"
      - backend: openai_compat
        base_url: "http://localhost:11434/v1"  # Ollama local fallback
        model: "llama3"
    timeout_ms: 120000

  audit:
    storage: postgres
    retention_days: 365
    export_schedule: "0 0 * * 0"  # Weekly
  ```

#### 5.2 Hot Reload System
- [ ] **File Watcher**: Detect config file changes without restart
- [ ] **API-Based Updates**: `PUT /api/config` with validation
- [ ] **Staged Rollout**: Apply config to percentage of traffic first
- [ ] **Rollback Capability**: Instant revert to previous config
- [ ] **Config Versioning**: Git-like history of configuration changes
- [ ] **Config Diff**: Show what changed between versions

#### 5.3 Rules Management UI (SaaS)
- [ ] **Visual Rule Editor**:
  - Firewall rule builder (drag-and-drop)
  - Bias pattern editor
  - EU keyword manager
  - Semantic template editor
- [ ] **Rule Testing**: Test rules against sample prompts before deployment
- [ ] **Rule Analytics**: See which rules trigger most frequently
- [ ] **Rule Sharing**: Export/import rules between environments

#### 5.4 Policy as Code
- [ ] **OPA (Open Policy Agent) Integration**:
  - Write policies in Rego
  - Reuse existing enterprise policies
  - Policy testing framework
- [ ] **GitOps Workflow**:
  - Store configs in Git
  - PR-based review for config changes
  - Automated deployment on merge

---

### Phase 6: SDK & Developer Experience
**Objective**: Best-in-class developer experience across languages and platforms

#### 6.1 Rust SDK (Core)
- [ ] **Crate Structure**:
  ```
  prompt-sentinel/
  ├── prompt-sentinel-core    # Core engine, no network
  ├── prompt-sentinel-client  # HTTP client for remote service
  ├── prompt-sentinel-server  # HTTP server binary
  ├── prompt-sentinel-cli     # Command-line interface
  └── prompt-sentinel         # Meta-crate, re-exports all
  ```
- [ ] **Publish to crates.io**: Automated release workflow
- [ ] **Documentation**: Full rustdoc coverage, examples for every public API
- [ ] **Async-First**: Tokio-based async runtime, sync wrappers available
- [ ] **WebAssembly Support**: `prompt-sentinel-core` compiles to WASM

#### 6.2 Python SDK
- [ ] **PyO3 Bindings**: Native performance, Python ergonomics
- [ ] **Package Structure**:
  ```python
  from prompt_sentinel import ComplianceClient

  client = ComplianceClient(api_key="...")
  result = await client.check("User prompt here")

  if result.blocked:
      print(f"Blocked: {result.reason}")
  else:
      print(f"Generated: {result.text}")
  ```
- [ ] **Type Hints**: Full mypy/pyright compatibility
- [ ] **Async/Await**: `asyncio` support out of the box
- [ ] **Publish to PyPI**: `pip install prompt-sentinel`
- [ ] **Framework Integrations**:
  - LangChain callback/tool
  - LlamaIndex plugin
  - FastAPI middleware
  - Django integration

#### 6.3 Node.js SDK
- [ ] **napi-rs Bindings**: Native addon for performance
- [ ] **TypeScript First**: Full type definitions
- [ ] **Package Structure**:
  ```typescript
  import { ComplianceClient } from '@prompt-sentinel/client';

  const client = new ComplianceClient({ apiKey: '...' });
  const result = await client.check('User prompt here');

  if (result.blocked) {
    console.log(`Blocked: ${result.reason}`);
  }
  ```
- [ ] **Publish to npm**: `npm install @prompt-sentinel/client`
- [ ] **Framework Integrations**:
  - Express middleware
  - Next.js plugin
  - Vercel AI SDK hook

#### 6.4 Go SDK
- [ ] **Pure Go Client**: No CGO dependencies
- [ ] **Package Structure**:
  ```go
  import "github.com/inferenco/prompt-sentinel-go"

  client := promptsentinel.NewClient(apiKey)
  result, err := client.Check(ctx, "User prompt here")
  ```
- [ ] **Context Support**: Proper context.Context propagation
- [ ] **Error Handling**: Idiomatic Go error wrapping

#### 6.5 CLI Tool
- [ ] **Commands**:
  ```bash
  # Check a prompt
  sentinel check "Is this prompt safe?"

  # Batch check from file
  sentinel check --file prompts.txt --output results.json

  # Start local server
  sentinel serve --config config.yaml

  # Validate configuration
  sentinel config validate config.yaml

  # Run self-test
  sentinel doctor

  # Generate compliance report
  sentinel report --start 2026-01-01 --end 2026-03-31 --output report.pdf
  ```
- [ ] **Interactive Mode**: REPL for testing prompts
- [ ] **Shell Completion**: Bash, Zsh, Fish, PowerShell
- [ ] **Publish**: Homebrew, apt, yum, Chocolatey, Scoop

#### 6.6 IDE Extensions
- [ ] **VS Code Extension**:
  - Inline prompt checking
  - Configuration validation
  - Audit log viewer
  - Rule editor
- [ ] **JetBrains Plugin**: IntelliJ, PyCharm, WebStorm
- [ ] **Neovim Plugin**: Lua-based integration

---

### Phase 7: SaaS Platform & Management Console
**Objective**: Fully managed cloud service with enterprise-grade management UI

#### 7.1 Cloud Infrastructure
- [ ] **Multi-Region Deployment**:
  - EU (Frankfurt) - Primary for EU customers
  - EU (Ireland) - EU redundancy
  - US (Virginia) - US customers
  - Asia (Singapore) - APAC customers
- [ ] **Infrastructure as Code**: Terraform/Pulumi for all resources
- [ ] **Kubernetes Deployment**: Helm charts, ArgoCD GitOps
- [ ] **Auto-Scaling**: HPA based on request volume
- [ ] **Database Architecture**:
  - PostgreSQL with Citus for horizontal scaling
  - Read replicas per region
  - Automated backups with PITR

#### 7.2 Management Console
- [ ] **Dashboard Home**:
  - Request volume trends
  - Compliance score over time
  - Recent incidents
  - Quick actions
- [ ] **Compliance Explorer**:
  - Real-time request stream
  - Drill-down into any request
  - Decision explanation
  - Human override interface
- [ ] **Rules Management**:
  - Visual rule editor
  - Rule testing sandbox
  - Deployment workflow
- [ ] **Reports & Analytics**:
  - Pre-built report templates
  - Custom report builder
  - Scheduled report delivery
  - Export to PDF/Excel
- [ ] **Settings**:
  - Organisation settings
  - Workspace management
  - User management (RBAC)
  - API key management
  - Billing & usage
  - Integrations

#### 7.3 Billing System
- [ ] **Usage Tracking**:
  - Per-request metering
  - Storage usage
  - API call counts
- [ ] **Pricing Tiers**:
  ```
  Free:       1,000 checks/month, 7-day retention, community support
  Starter:    50,000 checks/month, 30-day retention, email support
  Pro:        500,000 checks/month, 6-month retention, priority support
  Enterprise: Unlimited, custom retention, dedicated support, SLA
  ```
- [ ] **Stripe Integration**: Subscriptions, usage-based billing, invoicing
- [ ] **Self-Service**: Upgrade/downgrade, payment methods, invoices

#### 7.4 Integrations Hub
- [ ] **Notification Integrations**:
  - Slack (compliance alerts)
  - Microsoft Teams
  - PagerDuty (incidents)
  - Email
  - Webhooks (generic)
- [ ] **SIEM Integrations**:
  - Splunk
  - Datadog
  - Elastic SIEM
  - Sumo Logic
- [ ] **GRC Integrations**:
  - ServiceNow
  - OneTrust (ironic but useful)
  - Archer
- [ ] **DevOps Integrations**:
  - GitHub Actions
  - GitLab CI
  - Jenkins
  - Terraform provider

---

### Phase 8: Agentic AI Governance
**Objective**: Support autonomous AI agents with compliance guardrails

#### 8.1 Agent Orchestration Compliance
- [ ] **Agent Identity Management**:
  - Register AI agents as first-class entities
  - Agent capability declarations
  - Agent trust levels
- [ ] **Agent-to-Agent Communication Monitoring**:
  - Intercept inter-agent messages
  - Apply compliance checks to all exchanges
  - Detect agent collusion patterns
- [ ] **Agent Lifecycle Tracking**:
  - Agent spawn events
  - Agent task assignments
  - Agent termination and cleanup

#### 8.2 Multi-Agent Workflow Compliance
- [ ] **Workflow Definition Language**:
  ```yaml
  workflow:
    name: customer_support_agent
    agents:
      - id: classifier
        role: intent_classification
        allowed_actions: [classify]
      - id: responder
        role: response_generation
        allowed_actions: [generate, retrieve]
      - id: escalator
        role: human_escalation
        allowed_actions: [escalate, notify]

    compliance_gates:
      - before: responder.generate
        check: [firewall, bias, eu_compliance]
      - after: responder.generate
        check: [output_moderation]
  ```
- [ ] **Gate Enforcement**: Block workflow progression on compliance failure
- [ ] **Cross-Agent Audit**: Unified audit trail across agent interactions

#### 8.3 Model Context Protocol (MCP) Support
- [ ] **MCP Server Implementation**: Expose compliance as MCP tool
- [ ] **MCP Client Integration**: Consume other MCP tools with compliance wrapping
- [ ] **Tool Use Governance**: Policy enforcement on tool invocations

---

### Phase 9: Certification & Standards Alignment
**Objective**: Achieve industry certifications to build enterprise trust

#### 9.1 ISO 27001 Certification
- [ ] **ISMS Documentation**:
  - Information security policy
  - Risk assessment methodology
  - Statement of applicability
  - Asset inventory
- [ ] **Control Implementation**:
  - Access control (A.9)
  - Cryptography (A.10)
  - Operations security (A.12)
  - Communications security (A.13)
  - Supplier relationships (A.15)
- [ ] **Internal Audit Program**: Quarterly internal audits
- [ ] **External Certification Audit**: Engage accredited CB
- [ ] **Continuous Compliance**: Automated evidence collection

#### 9.2 ISO 42001 Certification (AI Management)
- [ ] **AI Management System**:
  - AI policy and objectives
  - AI risk management
  - Data quality management
  - Model lifecycle management
  - Human oversight provisions
- [ ] **AI-Specific Controls**:
  - Bias and fairness controls
  - Explainability measures
  - Robustness testing
  - Continuous monitoring
- [ ] **Certification Path**: ISO 27001 first (40% faster to 42001)

#### 9.3 SOC 2 Type II
- [ ] **Trust Service Criteria**:
  - Security
  - Availability
  - Processing Integrity
  - Confidentiality
  - Privacy
- [ ] **Control Environment**: Policies, procedures, monitoring
- [ ] **Type I Audit**: Control design assessment
- [ ] **Type II Audit**: Operating effectiveness over 6+ months
- [ ] **Annual Recertification**: Continuous SOC 2 maintenance

#### 9.4 GDPR & Data Protection
- [ ] **Data Protection Impact Assessment (DPIA)**: Published DPIA for platform
- [ ] **Data Processing Agreements**: Standard DPA for all customers
- [ ] **Data Subject Rights Automation**:
  - Access requests (export user data)
  - Erasure requests (cryptographic deletion)
  - Rectification requests
  - Portability requests
- [ ] **EU Representative**: Appointed representative for non-EU entities
- [ ] **Records of Processing**: Maintained per Article 30

---

### Phase 10: Ecosystem & Partnerships
**Objective**: Build a thriving ecosystem around the platform

#### 10.1 Developer Ecosystem
- [ ] **Documentation Portal**:
  - Getting started guides
  - API reference (OpenAPI 3.1)
  - SDK documentation
  - Integration tutorials
  - Best practices guides
  - Troubleshooting guides
- [ ] **Developer Community**:
  - Discord server
  - GitHub Discussions
  - Stack Overflow tag
  - Regular office hours
- [ ] **Sample Applications**:
  - Chatbot with compliance (Python/FastAPI)
  - RAG pipeline with compliance (LangChain)
  - Customer support agent (multi-agent)
  - Content moderation service
- [ ] **Certification Program**: Prompt Sentinel Certified Developer

#### 10.2 Partner Ecosystem
- [ ] **Technology Partners**:
  - LLM providers — Mistral (default partner), plus OpenAI, Anthropic, Cohere, and any OpenAI/Anthropic SDK-compatible provider
  - Cloud providers (AWS, Azure, GCP)
  - Observability platforms (Datadog, Splunk)
- [ ] **Consulting Partners**:
  - Big 4 (Deloitte, PwC, EY, KPMG)
  - AI specialists
  - Compliance consultancies
- [ ] **Reseller Partners**:
  - Regional distributors
  - Value-added resellers
  - System integrators
- [ ] **Partner Program**:
  - Partner portal
  - Co-marketing opportunities
  - Revenue sharing
  - Technical enablement

#### 10.3 Community Contributions
- [ ] **Rule Marketplace**:
  - Community-contributed firewall rules
  - Industry-specific bias patterns
  - Regional EU compliance extensions
- [ ] **Plugin Architecture**:
  - Custom check plugins
  - Storage backend plugins
  - LLM provider plugins (implement `LLMProvider` trait, or use OpenAI/Anthropic-compat interface with custom base_url)
- [ ] **Bounty Program**:
  - Security bug bounties
  - Feature bounties
  - Documentation bounties

---

## Part 4: Quality Gates & Release Criteria

### 4.1 Definition of Done (Per Feature)

Every feature must satisfy:

- [ ] **Code Complete**: Implemented, reviewed, merged
- [ ] **Tests Complete**: Unit, integration, property-based as appropriate
- [ ] **Documentation**: API docs, usage examples, changelog entry
- [ ] **Security Review**: No new vulnerabilities introduced
- [ ] **Performance Baseline**: No regression beyond acceptable threshold
- [ ] **Accessibility**: UI meets WCAG 2.1 AA (if applicable)
- [ ] **Compliance Impact**: EU AI Act mapping updated if affected

### 4.2 Phase Completion Criteria

**Foundation Hardening (Phase 0)**:
- Zero critical/high CVEs in dependencies
- Health checks pass in Kubernetes deployment
- Circuit breaker protects against cascading failures
- Load test baseline established and documented

**Provider-Agnostic LLM Support (Phase 1)**:
- OpenAI-compatible and Anthropic-compatible backends implemented and tested
- Mistral working as default via OpenAI-compat backend
- At least 3 additional providers verified (e.g. OpenAI, Anthropic, Ollama) via base_url config
- Provider failover works without data loss across backend types
- Local inference with Ollama demonstrated
- Base URL override pattern documented with examples for all major providers

**Enterprise Auth (Phase 2)**:
- SSO working with at least 2 IdPs (Okta, Azure AD)
- Multi-tenant isolation verified with penetration test
- RBAC enforced consistently across all endpoints
- API key lifecycle management complete

**EU AI Act Coverage (Phase 3)**:
- All Article 5 prohibited practices detected
- All Annex III high-risk categories classifiable
- Technical documentation generator produces valid output
- Compliance officer demo validates completeness

**Audit & Evidence (Phase 4)**:
- Six-month retention verified
- Audit chain cryptographically verifiable
- Export formats accepted by sample regulators
- Legal counsel signs off on evidence admissibility

**Configuration Management (Phase 5)**:
- Hot reload works without request loss
- Config changes audited
- Rollback demonstrated
- GitOps workflow documented

**SDK & DevEx (Phase 6)**:
- SDKs published (crates.io, PyPI, npm)
- Getting started achievable in <15 minutes
- Framework integrations tested with sample apps
- CLI published via package managers

**SaaS Platform (Phase 7)**:
- Multi-region deployment operational
- 99.9% uptime achieved over 30-day window
- Billing system tested with real transactions
- Management console user-tested with 10+ beta users

**Agentic AI (Phase 8)**:
- Multi-agent workflow compliance demonstrated
- MCP integration working
- Agent audit trail complete
- Performance acceptable for real-time agent coordination

**Certifications (Phase 9)**:
- ISO 27001 certificate obtained
- SOC 2 Type II report available
- ISO 42001 readiness assessment passed
- GDPR compliance verified by external DPO

**Ecosystem (Phase 10)**:
- Documentation site live with full content
- 3+ technology partnerships announced
- 10+ community-contributed rules in marketplace
- Developer certification program launched

---

## Part 5: Risk Register

### 5.1 Technical Risks

| Risk | Probability | Impact | Mitigation |
|------|-------------|--------|------------|
| LLM provider API instability | Medium | High | Provider-agnostic architecture (base_url swap), circuit breakers, fallback chains across backends, local inference fallback |
| Semantic detection evasion techniques | High | Medium | Continuous template updates, ML model pipeline, bug bounty |
| Audit storage scalability limits | Low | High | Tiered storage, archival strategy, tested at 10x expected load |
| Security vulnerability in dependencies | Medium | High | Automated CVE scanning, rapid patching process, SBOM |
| Performance degradation at scale | Medium | Medium | Load testing, caching strategy, horizontal scaling |

### 5.2 Regulatory Risks

| Risk | Probability | Impact | Mitigation |
|------|-------------|--------|------------|
| EU AI Act interpretation changes | Medium | High | Legal counsel engagement, regulatory monitoring, modular architecture |
| Additional national requirements (France, Germany) | Medium | Medium | Country-specific rule modules, partnership with local law firms |
| GDPR enforcement action | Low | High | DPIA, DPO engagement, privacy by design |
| New prohibited practice categories | Low | Medium | Hot-reload architecture, rapid rule deployment |

### 5.3 Business Risks

| Risk | Probability | Impact | Mitigation |
|------|-------------|--------|------------|
| Competitor achieves market dominance | Medium | High | Speed to market, open-source community, developer focus |
| Enterprise sales cycle too long | Medium | Medium | Self-serve tier, partner channel, POC acceleration |
| Open-source sustainability | Low | Medium | Clear SaaS value proposition, contributor agreements |
| Key person dependency | Medium | Medium | Documentation culture, pair programming, knowledge sharing |

---

## Part 6: Success Metrics

### 6.1 Technical Metrics

| Metric | Target |
|--------|--------|
| API Latency (p99) | < 500ms for local checks, < 2s with LLM |
| Availability | 99.9% uptime (SaaS) |
| Security Vulnerabilities | Zero critical, < 5 high at any time |
| Test Coverage | > 80% line coverage |
| Documentation Coverage | 100% public API documented |
| Release Cadence | Monthly minor releases, patches as needed |

### 6.2 Adoption Metrics

| Metric | Target (12 months post-GA) |
|--------|---------------------------|
| GitHub Stars | 5,000+ |
| Monthly Active SDK Users | 10,000+ |
| SaaS Paying Customers | 100+ |
| Enterprise Customers | 10+ |
| Community Contributors | 50+ |
| Partner Integrations | 20+ |

### 6.3 Compliance Metrics

| Metric | Target |
|--------|--------|
| EU AI Act Article Coverage | 100% of applicable articles |
| False Positive Rate (Firewall) | < 0.1% |
| False Negative Rate (Prohibited Practices) | 0% (critical safety) |
| Audit Trail Completeness | 100% of requests logged |
| Evidence Export Acceptance | Accepted by 3+ regulatory bodies (via testing) |

---

## Appendices

### Appendix A: EU AI Act Article Reference

| Article | Title | Prompt Sentinel Coverage |
|---------|-------|-------------------------|
| 5 | Prohibited Practices | Firewall, EU Compliance Module |
| 9 | Risk Management | Risk Classification Engine |
| 10 | Data Governance | Data Lineage Tracking (planned) |
| 11 | Technical Documentation | Documentation Generator |
| 13 | Transparency | Transparency Notice API |
| 14 | Human Oversight | Override Workflow |
| 15 | Accuracy & Robustness | Performance Monitoring |
| 17 | Quality Management | QMS Templates |
| 50 | Transparency Obligations | Content Labelling |
| 61 | Post-Market Monitoring | Incident Reporting |

### Appendix B: Technology Stack

| Layer | Technology | Rationale |
|-------|------------|-----------|
| Language | Rust | Performance, safety, reliability |
| Web Framework | Axum | Modern, async-first, production-proven |
| Database (Local) | SledDB | Embedded, no dependencies |
| Database (Cloud) | PostgreSQL + Citus | Scalable, ACID, familiar |
| Cache | Redis | Fast, distributed, mature |
| Message Queue | NATS | Lightweight, fast, cloud-native |
| Container | Docker | Universal, well-supported |
| Orchestration | Kubernetes | Standard, scalable |
| IaC | Terraform | Multi-cloud, declarative |
| CI/CD | GitHub Actions | Integrated, fast, familiar |
| Observability | OpenTelemetry | Vendor-neutral, comprehensive |

### Appendix C: Competitive Feature Matrix

| Feature | Prompt Sentinel | Credo AI | Holistic AI | IBM watsonx |
|---------|-----------------|----------|-------------|-------------|
| Open Source Core | Yes | No | No | No |
| Developer SDK | Rust, Python, Node, Go | Limited | Limited | Java/Python |
| Self-Hosting | Yes | No | No | Partial |
| Cryptographic Audit | Yes | Unknown | Unknown | No |
| Real-Time Enforcement | Yes | Batch | Batch | Yes |
| Prompt-Level Security | Yes | No | Partial | Partial |
| Local Inference | Yes | No | No | Partial |
| Multi-LLM Support | Yes (any OpenAI/Anthropic-compat API) | N/A | N/A | Yes |
| Agentic AI Support | Planned | Emerging | Emerging | Yes |
| ISO 42001 Aligned | Planned | Yes | Yes | Yes |

---

## Version History

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0 | 2026-03-01 | Deep Research | Initial comprehensive analysis |
| 2.0 | 2026-03-03 | Claude | Complete rewrite: phased development plan, competitive positioning, technical architecture |
| 3.0 | 2026-03-05 | Claude | Provider-agnostic LLM strategy: Mistral default, OpenAI-compat and Anthropic-compat SDK interfaces, base_url override pattern |

---

*This document is a living plan. It should be reviewed and updated quarterly as the regulatory landscape evolves and as implementation progresses.*