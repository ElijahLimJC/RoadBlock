# Product: RoadBlock

RoadBlock is an automated social honeypot pipeline that intercepts scammer communications, wastes their time using an AI-driven "Tech-Illiterate Confused Elder" persona, and simultaneously extracts validated Threat Intelligence Indicators of Compromise (IoCs) in real time.

## Core Capabilities

- **Persona Engine**: LLM-powered conversational agent that maintains a confused elderly character to stall scammers
- **Threat Parser**: Pydantic-based extraction engine that identifies and validates IoCs (crypto wallets, phishing domains, phone numbers, mule bank accounts) from chat content
- **SOC Dashboard**: Real-time Streamlit UI showing extracted IoCs, conversation logs, stalling metrics, and mock AWS notifications
- **Safety Filter**: Input sanitization boundary that detects and neutralizes prompt injection attacks
- **Mock AWS Integration**: Simulates GuardDuty findings and WAF IP block rules for integration pattern validation

## Key Design Principles

- Single-process monolithic runtime — no external database dependencies
- All state lives in `st.session_state` (session lifetime = data lifetime)
- Async threat parsing runs concurrently with the synchronous Streamlit render cycle
- Jailbreak resistance is a first-class concern — the persona must never break character
