"""Shared test configuration.

Hypothesis profiles are registered once here — individual test modules
must not register their own, or whichever module is collected last
silently overwrites the profile the others expect (e.g. the deep run's
10k examples being replaced by a smaller count).
"""

try:
    from datetime import timedelta

    from hypothesis import HealthCheck, settings

    settings.register_profile(
        "ci",
        max_examples=200,
        deadline=timedelta(seconds=2),
        suppress_health_check=[HealthCheck.too_slow],
    )
    settings.register_profile(
        "deep", max_examples=10_000, deadline=timedelta(seconds=2)
    )
except ImportError:  # hypothesis not installed (e.g. RPM %check)
    pass
