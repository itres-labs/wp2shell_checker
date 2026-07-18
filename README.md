# wp2shell checker

A small Python checker for the WordPress issue commonly referred to as **wp2shell**.

It checks the exposed WordPress version when available and probes the REST Batch endpoint to classify the target as vulnerable, patched, blocked, or inconclusive.

## Requirements

* Python 3.9+
* `requests`

```bash
python -m pip install requests
```

## Usage

```bash
python wp2shell_checker.py https://example.com --authorized
```

JSON output:

```bash
python wp2shell_checker.py https://example.com --authorized --json
```

Custom timeout:

```bash
python wp2shell_checker.py https://example.com --authorized --timeout 20
```

Ignore TLS certificate errors:

```bash
python wp2shell_checker.py https://example.com --authorized --insecure
```

## Arguments

```text
usage: wp2shell_checker.py [-h] [--authorized] [--timeout TIMEOUT]
                           [--insecure] [--json]
                           target
```

* `target`: WordPress URL or hostname.
* `--authorized`: Required confirmation that you are allowed to test the target.
* `--timeout`: Request timeout in seconds. Default: `10`.
* `--insecure`: Disable TLS certificate verification.
* `--json`: Print the full report as JSON.

## Results

Possible final classifications include:

* `VULNERABLE`
* `NOT_VULNERABLE`
* `MITIGATED_OR_BLOCKED`
* `LIKELY_VULNERABLE_BY_VERSION`
* `LIKELY_FIXED_BY_VERSION`
* `INCONCLUSIVE`

Exit codes:

* `0`: patched or likely fixed
* `1`: vulnerable or likely vulnerable
* `2`: invalid usage or missing dependency
* `3`: blocked or inconclusive

## Notes

Version detection is best effort. WordPress, a CDN, a WAF, or a security plugin may hide the version or alter the Batch endpoint response.

The checker does not run an SQL injection or command-execution payload.

Use it only on systems you own or are authorized to assess.

## License

MIT License.
