# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

from unittest.mock import patch

from run_worker import main
from worker import WorkerSettings


def test_main_sets_event_loop_and_calls_arq_run_worker() -> None:
    with patch("run_worker.run_worker") as mock_arq_run:
        main()
    mock_arq_run.assert_called_once_with(WorkerSettings)
