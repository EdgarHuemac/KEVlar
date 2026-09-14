from __future__ import annotations

import time
from typing import Any

import requests


class HttpClient:
    def __init__(self, timeout: int = 20, retries: int = 3) -> None:
        self.timeout, self.retries = timeout, retries
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": "KEVlar/1.0 (+https://github.com/)"})

    def request(self, method: str, url: str, **kwargs: Any) -> requests.Response:
        last_error: Exception | None = None
        for attempt in range(self.retries):
            try:
                response = self.session.request(method, url, timeout=self.timeout, **kwargs)
                if response.status_code not in (429,) and response.status_code < 500:
                    response.raise_for_status()
                    return response
                last_error = requests.HTTPError(f"HTTP {response.status_code} for {url}", response=response)
            except requests.RequestException as exc:
                last_error = exc
            if attempt < self.retries - 1:
                time.sleep(2 ** attempt)
        raise last_error or RuntimeError("HTTP request failed")

    def get_json(self, url: str, **kwargs: Any) -> Any:
        return self.request("GET", url, **kwargs).json()

    def post_json(self, url: str, payload: dict[str, Any], **kwargs: Any) -> requests.Response:
        return self.request("POST", url, json=payload, **kwargs)
