import urllib.request
import urllib.error


def detect_http_service(host, port, timeout=5):
    """
    Detect whether an open TCP service is serving HTTP/HTTPS.

    Intended for authorized security assessments and local labs.
    """

    schemes = ["http", "https"]

    for scheme in schemes:
        url = f"{scheme}://{host}:{port}/"

        try:
            request = urllib.request.Request(
                url,
                method="GET",
                headers={
                    "User-Agent": "CyberShield/1.0"
                }
            )

            with urllib.request.urlopen(
                request,
                timeout=timeout
            ) as response:

                headers = {
                    key.lower(): value
                    for key, value in response.headers.items()
                }

                return {
                    "is_http": True,
                    "scheme": scheme,
                    "url": url,
                    "status_code": response.status,
                    "server": headers.get("server"),
                    "content_type": headers.get("content-type"),
                    "headers": headers,
                }

        except urllib.error.HTTPError as error:
            return {
                "is_http": True,
                "scheme": scheme,
                "url": url,
                "status_code": error.code,
                "server": error.headers.get("Server"),
                "content_type": error.headers.get("Content-Type"),
                "headers": {
                    key.lower(): value
                    for key, value in error.headers.items()
                },
            }

        except (
            urllib.error.URLError,
            TimeoutError,
            ConnectionError,
        ):
            continue

    return {
        "is_http": False,
        "scheme": None,
        "url": None,
        "status_code": None,
        "server": None,
        "content_type": None,
        "headers": {},
    }