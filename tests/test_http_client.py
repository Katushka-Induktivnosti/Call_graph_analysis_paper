from __future__ import annotations

import ssl
import unittest
import urllib.error
from unittest.mock import Mock, patch

from graph_analysis.dependencies.http_client import HttpClient


class HttpClientTests(unittest.TestCase):
    def test_request_uses_ssl_context(self) -> None:
        response = Mock()
        response.read.return_value = b'{"ok": true}'

        with patch("graph_analysis.dependencies.http_client.urllib.request.urlopen", return_value=response) as urlopen:
            payload = HttpClient(retries=0).request_json("https://example.test")

        self.assertEqual(payload, {"ok": True})
        self.assertIsInstance(urlopen.call_args.kwargs["context"], ssl.SSLContext)

    def test_certificate_error_is_actionable_and_not_retried(self) -> None:
        certificate_error = ssl.SSLCertVerificationError("certificate verify failed")
        url_error = urllib.error.URLError(certificate_error)

        with patch("graph_analysis.dependencies.http_client.urllib.request.urlopen", side_effect=url_error) as urlopen:
            with self.assertRaisesRegex(RuntimeError, "TLS certificate verification failed"):
                HttpClient(retries=3).request_json("https://example.test")

        self.assertEqual(urlopen.call_count, 1)


if __name__ == "__main__":
    unittest.main()
