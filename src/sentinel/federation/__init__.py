"""Threat-intelligence federation primitives for Sentinel.

Federation is an intelligence exchange layer. Imported intelligence is never a
case-management path and must be promoted through Detection -> AutoCase ->
Response by the caller after provenance and policy validation.
"""

from .anon import FederationAnonymizer
from .reputation import FederationReputation

__all__ = ["FederationAnonymizer", "FederationReputation"]
