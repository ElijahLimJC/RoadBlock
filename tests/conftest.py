"""Shared test fixtures for RoadBlock test suite."""

import pytest

from components.threat_parser import ThreatParser


@pytest.fixture
def parser() -> ThreatParser:
    """Create a fresh ThreatParser instance."""
    return ThreatParser()
