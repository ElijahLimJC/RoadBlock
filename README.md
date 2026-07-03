# RoadBlock

Automated social honeypot pipeline that intercepts scammer communications, wastes their time using an AI-driven "confused elder" persona, and extracts validated Indicators of Compromise (IoCs) in real time.

## What It Does

1. **Engages scammers** with an LLM-powered persona that plays a confused elderly person, keeping them on the hook
2. **Extracts IoCs** from scammer messages: crypto wallet addresses, phishing domains, phone numbers, mule bank accounts
3. **Enriches IoCs** via VirusTotal MCP integration for threat intelligence context
4. **Blocks prompt injection** with a deterministic safety filter that prevents persona jailbreaks
5. **Displays everything** on a real-time SOC dashboard with session metrics, conversation log, and notification feed

## Quick Start

```bash
# Create and activate the virtual environment
python -m venv roadblock
roadblock\Scripts\activate  # Windows
# source roadblock/bin/activate  # Linux/Mac

# Install dependencies
pip install -r requirements.txt

# Set up environment variables
cp .env.example .env
# Edit .env with your API keys

# Run
streamlit run app.py
```

## Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `MISTRAL_API_KEY` | Yes | LLM API key for persona response generation |
| `VIRUSTOTAL_API_KEY` | No | VirusTotal API key for IoC enrichment |
| `IMAP_HOST` | No | IMAP server for email ingestion |
| `IMAP_PORT` | No | IMAP port (default: 993) |
| `IMAP_USERNAME` | No | IMAP login |
| `IMAP_PASSWORD` | No | IMAP password |
| `SMTP_HOST` | No | SMTP server for outbound replies |
| `SMTP_PORT` | No | SMTP port (default: 587) |
| `SMTP_USERNAME` | No | SMTP login |
| `SMTP_PASSWORD` | No | SMTP password |
| `SMTP_SENDER` | No | Outbound sender address |

## Project Structure

```
.
├── app.py                     # Streamlit entry point + SOC dashboard
├── pipeline.py                # Pipeline orchestration (safety -> persona -> parser -> VT)
├── components/
│   ├── safety_filter.py       # Prompt injection detection and sanitization
│   ├── persona_engine.py      # LLM-driven confused elder persona
│   ├── threat_parser.py       # IoC extraction (crypto, domains, phones, bank accounts)
│   ├── virustotal_mcp.py      # VirusTotal MCP client for IoC enrichment
│   ├── stalling_tracker.py    # Conversation engagement metrics
│   ├── notification_module.py # Mock AWS GuardDuty/WAF payload generation
│   ├── email_ingestion.py     # Email polling and auto-reply pipeline
│   ├── scam_classifier.py     # Two-stage scam classification (regex + LLM)
│   ├── imap_client.py         # IMAP connection management
│   └── smtp_client.py         # SMTP outbound delivery
├── models/
│   ├── ioc_models.py          # Pydantic IoC schemas (wallet, domain, phone, bank)
│   ├── chat_models.py         # ChatMessage, SessionMetrics, ScanResult
│   ├── aws_models.py          # Mock notification payloads
│   ├── email_models.py        # Email ingestion models
│   └── lookup_models.py       # VirusTotal lookup result models
├── dashboard/
│   ├── soc_dashboard.py       # Dashboard rendering (metrics, chat, IoCs, notifications)
│   └── styles.py              # Custom CSS theme
├── pages/
│   ├── 1_Manual_Chat.py       # Manual scammer message submission
│   └── 2_Email_Ingestion.py   # Email ingestion monitoring
└── tests/
    └── ...                    # Property-based tests (Hypothesis)
```

## Pipeline Flow

```
Scammer Message
    │
    ▼
┌─────────────────┐
│  Safety Filter   │  ← Blocks >=80% injection; sanitizes partial injection
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  Persona Engine  │  ← Generates confused elder response via LLM
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  Threat Parser   │  ← Extracts + validates IoCs (Pydantic models)
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  VirusTotal MCP  │  ← Enriches IoCs with threat intel (known/new)
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  Notifications   │  ← Generates alerts for NEW IoCs only
└─────────────────┘
```

## Features

### IoC Extraction
- Bitcoin addresses (Base58 + Bech32 with checksum validation)
- Ethereum addresses (EIP-55 checksum)
- Phishing domains (defanged notation support)
- Phone numbers (E.164 normalization via `phonenumbers`)
- Mule bank accounts (ABA routing number checksum validation)

### Safety Filter
- Deterministic pattern matching (no ML dependencies)
- Partial sanitization: strips injection tokens while preserving legitimate content
- Full block at >=80% injection ratio with default confused-elder response

### VirusTotal Integration
- Spawns `@burtthecoder/mcp-virustotal` MCP server via stdio
- Domain lookups via `get_domain_report`
- General corpus search for wallets/phones/accounts via `search_vt`
- Session-level caching to avoid duplicate API calls
- Graceful degradation on timeout/error

### Email Ingestion
- IMAP polling with configurable interval
- Two-stage scam classification (regex patterns + optional LLM)
- Auto-reply with persona-generated responses
- Thread tracking per sender

## Development

```bash
# Lint
ruff check .

# Type check
mypy .

# Run tests
pytest

# Run with property-based test stats
pytest --hypothesis-show-statistics
```

## Architecture Decisions

- **Single process, no database**: All state lives in `st.session_state`. Session lifetime = data lifetime.
- **Deterministic safety over ML**: Prompt injection detection uses pattern matching, not a classifier that could be fooled.
- **Graceful degradation**: Every parser and external call is wrapped in try/except. A missed IoC is acceptable; a crashed pipeline is not.
- **MCP over REST**: VirusTotal integration uses the Model Context Protocol SDK for tool-calling semantics rather than raw HTTP.
