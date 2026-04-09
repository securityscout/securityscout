from pathlib import Path

import pytest


@pytest.fixture
async def db_session(tmp_path: Path):
    """Fresh async SQLite session per test"""


@pytest.fixture
def mock_github_client(mocker):
    """Mocked PyGithub client"""


@pytest.fixture
def mock_slack_client(mocker):
    """Mocked Slack WebClient"""


@pytest.fixture
def sample_advisory():
    """Realistic GHSA advisory payload"""


@pytest.fixture
def sample_sarif():
    """Minimal valid SARIF 2.1.0 document"""
