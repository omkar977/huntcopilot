"""Entry point: uvicorn main:app --host 0.0.0.0 --port 8000 (HC_API_KEY must be set)."""
from hc_api.app import create_app

app = create_app()
