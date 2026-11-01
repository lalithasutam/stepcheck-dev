"""Deterministic token accounting (GLOSSARY: Telemetry terms). Private module."""
import math


def count(text: str) -> int:
    """ceil(len/4) — deterministic, provider-free."""
    return math.ceil(len(text) / 4)
