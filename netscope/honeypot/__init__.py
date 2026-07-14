"""Honeypot: decoy listeners that alert on any connection attempt."""
from .listener import Honeypot, honeypot

__all__ = ["Honeypot", "honeypot"]
