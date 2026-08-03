"""Hozo exception hierarchy.

One base (``HozoError``) with two specific subclasses. Other failures raise
``HozoError`` directly — we don't add a class per failure mode.
"""


class HozoError(Exception):
    """Base for all Hozo errors."""


class ProfileError(HozoError):
    """A profile file is missing, malformed, or fails validation."""


class MergeConflictError(HozoError):
    """Two layers set incompatible values for the same bind or env key."""
