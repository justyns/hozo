class HozoError(Exception):
    pass


class ProfileError(HozoError):
    """A profile file is missing, malformed, or fails validation."""


class MergeConflictError(HozoError):
    """Two layers set incompatible values for the same bind or env key."""
