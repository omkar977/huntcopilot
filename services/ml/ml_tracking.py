"""Optional MLflow logging to the local file store. Failures never break training or evaluation."""
from __future__ import annotations

from typing import Any

from hc_common.logging import get_logger

log = get_logger("ml.tracking")


def log_run(name: str, params: dict, metrics: dict, artifacts: dict[str, str]) -> bool:
    """Log a run. Returns False (and logs a warning) when MLflow is missing or fails."""
    try:
        import mlflow

        from hc_common.config import get_settings

        mlflow.set_tracking_uri(get_settings().hc_mlflow_uri)
        mlflow.set_experiment("huntcopilot-ml")
        with mlflow.start_run(run_name=name):
            mlflow.log_params({k: str(v) for k, v in params.items()})
            mlflow.log_metrics({k: float(v) for k, v in metrics.items() if _is_number(v)})
            for path in artifacts.values():
                mlflow.log_artifact(path)
        return True
    except Exception as exc:  # noqa: BLE001 - tracking is best effort
        log.warning("mlflow logging skipped", extra={"error": type(exc).__name__})
        return False


def _is_number(v: Any) -> bool:
    return isinstance(v, (int, float)) and not isinstance(v, bool)
