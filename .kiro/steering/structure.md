# Project Structure

## Expected Layout

```
.
├── app.py                    # Streamlit entry point
├── .kiro/
│   ├── specs/                # Feature specifications
│   │   └── tarpit-honeypot-pipeline/
│   │       ├── requirements.md
│   │       ├── design.md
│   │       └── .config.kiro
│   └── steering/             # AI guidance files
├── components/
│   ├── safety_filter.py      # Prompt injection detection and sanitization
│   ├── persona_engine.py     # LLM-driven confused elder persona
│   ├── threat_parser.py      # Async IoC extraction (crypto, domains, phones, bank accounts)
│   ├── stalling_tracker.py   # Conversation engagement metrics
│   ├── notification_module.py # Mock AWS GuardDuty/WAF payload generation
│   └── ioc_lookup_mcp.py     # MCP client for threat intel lookups
├── models/
│   ├── ioc_models.py         # Pydantic IoC schemas (BaseIoC, CryptoWallet, Domain, Phone, MuleAccount)
│   ├── chat_models.py        # ChatMessage, SessionMetrics, ExtractionResult
│   ├── aws_models.py         # MockAWSPayload, WAFPayload, GuardDutyFinding
│   └── lookup_models.py      # IoCLookupResult, LookupStatus
├── dashboard/
│   └── soc_dashboard.py      # Streamlit UI rendering (conversation log, IoC panel, metrics, notifications)
├── tests/
│   ├── test_threat_parser.py # Property-based tests for IoC extraction
│   ├── test_safety_filter.py # Injection detection tests
│   ├── test_models.py        # Serialization round-trip properties
│   └── test_stalling.py      # Metrics invariant tests
├── requirements.txt          # Python dependencies
└── pyproject.toml            # Project configuration
```

## Conventions

- One component per module — each pipeline stage is a separate file
- Pydantic models are grouped by domain (IoC, chat, AWS, lookup)
- Tests mirror source structure and prioritize property-based testing
- Dashboard rendering is separated from business logic
- All state flows through `st.session_state` — no global mutable state outside Streamlit sessions
