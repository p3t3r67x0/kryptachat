"""Reproducible property exploration, independent of developer example databases."""

from hypothesis import settings

settings.register_profile("identity_review", derandomize=True, database=None, deadline=None)
settings.load_profile("identity_review")
