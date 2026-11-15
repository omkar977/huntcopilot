"""Skip integration tests unless HC_INTEGRATION=1. Owner: Lead."""
import os

import pytest


def pytest_collection_modifyitems(config, items):
    if os.getenv("HC_INTEGRATION") == "1":
        return
    skip = pytest.mark.skip(reason="set HC_INTEGRATION=1 to run integration tests")
    for item in items:
        if "integration" in item.keywords:
            item.add_marker(skip)
