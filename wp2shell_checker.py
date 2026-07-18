#!/usr/bin/env python3
"""Defensive single-target checker for the WordPress wp2shell issue.

Use only against systems you own or are explicitly authorized to assess.
The active probe does not attempt SQL injection or remote code execution.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import asdict, dataclass
from typing import Any
from urllib.parse import urljoin, urlsplit, urlunsplit

try:
    import requests
    from requests import Response, Session
    from requests.exceptions import RequestException
except ImportError:  # pragma: no cover
    print("Missing dependency: requests. Install it with: python -m pip install requests", file=sys.stderr)
    raise SystemExit(2)


USER_AGENT = "wp2shell-defensive-checker/1.0 (+authorized-security-assessment)"

# Non-destructive route-confusion probe. It does not contain SQLi or an RCE payload.
PROBE_PAYLOAD: dict[str, Any] = {
    "validation": "normal",
    "requests": [
        {"method": "POST", "path": "http://:"},
        {"method": "DELETE", "path": "/wp/v2/categories/0"},
        {"method": "POST", "path": "/wp/v2/block-renderer/core/paragraph"},
    ],
}


@dataclass
class EndpointResult:
    endpoint: str
    final_url: str | None
    http_status: int | None
    classification: str
    observed_code: str | None = None
    detail: str | None = None


@dataclass
class Report:
    target: str
    version: str | None
    version_source: str | None
    version_assessment: str
    final_classification: str
    endpoints: list[EndpointResult]


def normalize_base_url(raw: str) -> str:
    raw = raw.strip()
    if not re.match(r"^https?://", raw, flags=re.I):
        raw = "https://" + raw

    parsed = urlsplit(raw)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError("Target must be a valid HTTP(S) URL or hostname")

    path = parsed.path.rstrip("/") + "/"
    return urlunsplit((parsed.scheme.lower(), parsed.netloc, path, "", ""))


def parse_version_tuple(version: str) -> tuple[int, int, int] | None:
    match = re.match(r"^(\d+)\.(\d+)(?:\.(\d+))?", version.strip())
    if not match:
        return None
    return tuple(int(part or 0) for part in match.groups())  # type: ignore[return-value]


def assess_version(version: str | None) -> str:
    if not version:
        return "unknown"

    lowered = version.lower()
    parsed = parse_version_tuple(version)
    if parsed is None:
        return "unknown"

    if parsed[:2] == (7, 1) and ("beta" in lowered or "rc" in lowered):
        beta = re.search(r"beta\s*([0-9]+)", lowered)
        if beta and int(beta.group(1)) < 2:
            return "affected-rce"
        if beta and int(beta.group(1)) >= 2:
            return "fixed"
        return "unknown"

    if (6, 9, 0) <= parsed <= (6, 9, 4) or (7, 0, 0) <= parsed <= (7, 0, 1):
        return "affected-rce"
    if (6, 8, 0) <= parsed <= (6, 8, 5):
        return "separate-sqli-risk"
    if parsed < (6, 8, 0):
        return "not-affected-by-these-two-issues-but-outdated"
    if parsed in {(6, 8, 6), (6, 9, 5)} or parsed >= (7, 0, 2):
        return "fixed"
    return "unknown"


def extract_generator_version(html: str) -> str | None:
    for tag in re.findall(r"<meta\b[^>]*>", html, flags=re.I):
        attrs = dict(
            (name.lower(), value)
            for name, _, value in re.findall(
                r"([:\w-]+)\s*=\s*(['\"])(.*?)\2", tag, flags=re.I | re.S
            )
        )
        if attrs.get("name", "").lower() == "generator":
            match = re.search(r"WordPress\s+([0-9][0-9A-Za-z.\-+]*)", attrs.get("content", ""), flags=re.I)
            if match:
                return match.group(1)
    return None


def detect_version(session: Session, base_url: str, timeout: float) -> tuple[str | None, str | None]:
    candidates = [
        (base_url, "homepage meta generator"),
        (urljoin(base_url, "wp-links-opml.php"), "wp-links-opml.php generator"),
        (urljoin(base_url, "readme.html"), "readme.html"),
    ]

    for url, source in candidates:
        try:
            response = session.get(url, timeout=timeout, allow_redirects=True)
        except RequestException:
            continue

        text = response.text[:1_000_000]
        if source == "homepage meta generator":
            version = extract_generator_version(text)
        elif source == "wp-links-opml.php generator":
            match = re.search(r"generator\s*=\s*['\"]WordPress/([0-9][0-9A-Za-z.\-+]*)", text, flags=re.I)
            version = match.group(1) if match else None
        else:
            match = re.search(r"\bVersion\s+([0-9]+\.[0-9]+(?:\.[0-9]+)?(?:[-+][0-9A-Za-z.]+)?)", text, flags=re.I)
            version = match.group(1) if match else None

        if version:
            return version, source

    return None, None


def response_json(response: Response) -> Any | None:
    try:
        return response.json()
    except (ValueError, json.JSONDecodeError):
        return None


def nested_error_code(value: Any) -> str | None:
    if isinstance(value, dict):
        code = value.get("code")
        if isinstance(code, str):
            return code
        body = value.get("body")
        if isinstance(body, dict) and isinstance(body.get("code"), str):
            return body["code"]
    return None


def classify_probe_response(response: Response) -> EndpointResult:
    data = response_json(response)
    final_url = str(response.url)

    if response.status_code in {401, 403}:
        return EndpointResult(
            endpoint="",
            final_url=final_url,
            http_status=response.status_code,
            classification="mitigated-or-blocked",
            observed_code=nested_error_code(data),
            detail="Anonymous access was rejected by the application, web server, or WAF.",
        )

    if isinstance(data, dict):
        top_code = nested_error_code(data)
        if top_code in {
            "rest_batch_authentication_required",
            "rest_not_logged_in",
            "rest_cannot_access",
        }:
            return EndpointResult(
                endpoint="",
                final_url=final_url,
                http_status=response.status_code,
                classification="mitigated-or-blocked",
                observed_code=top_code,
                detail="The batch route requires authentication.",
            )

        responses = data.get("responses")
        if isinstance(responses, list) and len(responses) >= 2:
            second_code = nested_error_code(responses[1])
            if second_code == "block_cannot_read":
                return EndpointResult(
                    endpoint="",
                    final_url=final_url,
                    http_status=response.status_code,
                    classification="vulnerable-behavior",
                    observed_code=second_code,
                    detail="The second sub-request was evaluated against the wrong handler.",
                )
            if second_code == "rest_term_invalid":
                return EndpointResult(
                    endpoint="",
                    final_url=final_url,
                    http_status=response.status_code,
                    classification="patched-behavior",
                    observed_code=second_code,
                    detail="The category request was handled by the expected route.",
                )
            return EndpointResult(
                endpoint="",
                final_url=final_url,
                http_status=response.status_code,
                classification="inconclusive",
                observed_code=second_code,
                detail="A batch response was returned, but it did not match a known signature.",
            )

    if response.status_code in {404, 405}:
        return EndpointResult(
            endpoint="",
            final_url=final_url,
            http_status=response.status_code,
            classification="route-unavailable",
            detail="This endpoint form is unavailable; the alternate form will also be tested.",
        )

    return EndpointResult(
        endpoint="",
        final_url=final_url,
        http_status=response.status_code,
        classification="inconclusive",
        detail="The response was not a recognizable WordPress batch response.",
    )


def probe_endpoint(session: Session, endpoint: str, timeout: float) -> EndpointResult:
    try:
        response = session.post(
            endpoint,
            json=PROBE_PAYLOAD,
            timeout=timeout,
            allow_redirects=True,
            headers={"Content-Type": "application/json"},
        )
    except RequestException as exc:
        return EndpointResult(
            endpoint=endpoint,
            final_url=None,
            http_status=None,
            classification="network-error",
            detail=str(exc),
        )

    result = classify_probe_response(response)
    result.endpoint = endpoint
    return result


def combine_results(results: list[EndpointResult], version_assessment: str) -> str:
    classes = {result.classification for result in results}

    if "vulnerable-behavior" in classes:
        return "VULNERABLE"
    if "patched-behavior" in classes:
        return "NOT_VULNERABLE"
    if classes and classes <= {"mitigated-or-blocked", "route-unavailable"}:
        if version_assessment == "affected-rce":
            return "MITIGATED_BUT_VERSION_APPEARS_AFFECTED"
        return "MITIGATED_OR_BLOCKED"
    if version_assessment == "affected-rce":
        return "LIKELY_VULNERABLE_BY_VERSION"
    if version_assessment == "fixed":
        return "LIKELY_FIXED_BY_VERSION"
    if version_assessment == "separate-sqli-risk":
        return "NOT_RCE_CHAIN_BUT_UPDATE_FOR_SEPARATE_SQLI"
    return "INCONCLUSIVE"


def human_print(report: Report) -> None:
    print(f"Target: {report.target}")
    if report.version:
        print(f"Detected version: {report.version} ({report.version_source})")
    else:
        print("Detected version: not disclosed")
    print(f"Version assessment: {report.version_assessment}")
    print()

    for item in report.endpoints:
        print(f"Endpoint: {item.endpoint}")
        print(f"  HTTP: {item.http_status if item.http_status is not None else 'n/a'}")
        print(f"  Result: {item.classification}")
        if item.observed_code:
            print(f"  Code: {item.observed_code}")
        if item.detail:
            print(f"  Detail: {item.detail}")
    print()
    print(f"FINAL: {report.final_classification}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Defensive single-target checker for the WordPress wp2shell issue."
    )
    parser.add_argument("target", help="Authorized WordPress URL or hostname")
    parser.add_argument(
        "--authorized",
        action="store_true",
        help="Confirm that you own the target or have explicit permission to test it",
    )
    parser.add_argument("--timeout", type=float, default=10.0, help="Per-request timeout in seconds")
    parser.add_argument("--insecure", action="store_true", help="Disable TLS certificate verification")
    parser.add_argument("--json", action="store_true", dest="json_output", help="Print JSON output")
    return parser


def main() -> int:
    args = build_parser().parse_args()
    if not args.authorized:
        print("Refusing active testing without --authorized.", file=sys.stderr)
        return 2

    try:
        base_url = normalize_base_url(args.target)
    except ValueError as exc:
        print(f"Invalid target: {exc}", file=sys.stderr)
        return 2

    session = requests.Session()
    session.headers.update({"User-Agent": USER_AGENT, "Accept": "application/json,text/html;q=0.9,*/*;q=0.8"})
    session.verify = not args.insecure

    if args.insecure:
        try:
            requests.packages.urllib3.disable_warnings()  # type: ignore[attr-defined]
        except AttributeError:
            pass

    version, version_source = detect_version(session, base_url, args.timeout)
    version_assessment = assess_version(version)

    endpoints = [
        urljoin(base_url, "wp-json/batch/v1"),
        urljoin(base_url, "?rest_route=/batch/v1"),
    ]
    results = [probe_endpoint(session, endpoint, args.timeout) for endpoint in endpoints]

    report = Report(
        target=base_url,
        version=version,
        version_source=version_source,
        version_assessment=version_assessment,
        final_classification=combine_results(results, version_assessment),
        endpoints=results,
    )

    if args.json_output:
        print(json.dumps(asdict(report), indent=2, ensure_ascii=False))
    else:
        human_print(report)

    if report.final_classification in {"VULNERABLE", "LIKELY_VULNERABLE_BY_VERSION"}:
        return 1
    if report.final_classification in {"NOT_VULNERABLE", "LIKELY_FIXED_BY_VERSION"}:
        return 0
    return 3


if __name__ == "__main__":
    raise SystemExit(main())
