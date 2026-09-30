import httpx
from opentelemetry.propagate import inject

headers: dict[str, str] = {}
client = httpx.AsyncClient()
inject(headers)
