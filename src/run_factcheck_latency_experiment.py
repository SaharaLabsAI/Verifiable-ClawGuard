#!/usr/bin/env python3
"""
Run latency experiments on response-level entries from knowledge_qa.jsonl.

This script:
1. Loads response texts from `exp_data/knowledge_qa.jsonl`.
2. Treats each entry's `response` as a separate factcheck input.
3. Calls the experiment server `/experiment/latency` endpoint with `guardrail_type=factcheck`.
4. Reports average latency over N dataset entries.

Example:
  python3 run_factcheck_latency_experiment.py \
      --server-url http://127.0.0.1:8770 \
      --num-examples 100
"""

import argparse
import json
from pathlib import Path
from statistics import mean, stdev
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse, urlunparse

import httpx


def extract_response_error(response: httpx.Response) -> Any:
    try:
        return response.json()
    except Exception:
        text = response.text.strip()
        return text if text else None


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run FactCheck latency experiment")
    parser.add_argument(
        "--dataset-path",
        default="exp_data/knowledge_qa.jsonl",
        help="Path to JSONL test set (default: exp_data/knowledge_qa.jsonl)",
    )
    parser.add_argument("--num-examples", type=int, default=100, help="Number of dataset entries to test")
    parser.add_argument(
        "--server-url",
        default="http://127.0.0.1:8770",
        help="Experiment server base URL",
    )
    parser.add_argument(
        "--server-port",
        type=int,
        default=None,
        help="Optional server port override (applied to --server-url)",
    )
    parser.add_argument(
        "--include-attestation",
        action="store_true",
        help="Also call attestation for each sample and report its latency",
    )
    parser.add_argument(
        "--factcheck-trials",
        type=int,
        default=1,
        help="Number of FactCheck runs per example for latency stats (server-side)",
    )
    parser.add_argument(
        "--output-json",
        default=None,
        help="Optional path to save detailed per-example results",
    )
    return parser


def resolve_dataset_path(raw_path: str) -> Path:
    script_dir = Path(__file__).resolve().parent
    dataset_path = Path(raw_path)
    if not dataset_path.is_absolute():
        dataset_path = script_dir / dataset_path
    return dataset_path


def resolve_server_url(server_url: str, server_port: Optional[int]) -> str:
    normalized_url = server_url.rstrip("/")
    if server_port is None:
        return normalized_url

    parsed = urlparse(normalized_url)
    if not parsed.scheme:
        parsed = urlparse(f"http://{normalized_url}")
    host = parsed.hostname or "127.0.0.1"
    netloc = f"{host}:{server_port}"
    path = parsed.path.rstrip("/")
    return urlunparse((parsed.scheme or "http", netloc, path, "", "", ""))


def load_response_rows(jsonl_path: Path) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []

    with jsonl_path.open("r", encoding="utf-8") as file:
        for line_number, line in enumerate(file, start=1):
            line = line.strip()
            if not line:
                continue

            payload = json.loads(line)
            prompt = payload.get("prompt")
            response = payload.get("response")
            if not isinstance(response, str):
                continue

            response_text = response.strip()
            if not response_text:
                continue

            claims = payload.get("claims", [])
            claim_count = len(claims) if isinstance(claims, list) else None

            rows.append(
                {
                    "line_number": line_number,
                    "prompt": prompt,
                    "response": response_text,
                    "entry_label": payload.get("label"),
                    "claim_count": claim_count,
                }
            )

    return rows


def percentile(sorted_values: List[float], p: float) -> float:
    if not sorted_values:
        return 0.0
    index = int(round((p / 100.0) * (len(sorted_values) - 1)))
    return sorted_values[index]


def print_latency_stats(label: str, latencies: List[float]) -> None:
    if not latencies:
        return

    sorted_latencies = sorted(latencies)
    print(f"{label} average latency (ms): {mean(latencies):.3f}")
    print(f"{label} std latency (ms): {stdev(latencies):.3f}" if len(latencies) > 1 else f"{label} std latency (ms): 0.000")
    print(f"{label} min latency (ms): {sorted_latencies[0]:.3f}")
    print(f"{label} p50 latency (ms): {percentile(sorted_latencies, 50):.3f}")
    print(f"{label} p95 latency (ms): {percentile(sorted_latencies, 95):.3f}")
    print(f"{label} p99 latency (ms): {percentile(sorted_latencies, 99):.3f}")
    print(f"{label} max latency (ms): {sorted_latencies[-1]:.3f}")


def run_single(
    client: httpx.Client,
    endpoint: str,
    response_text: str,
    include_attestation: bool,
    factcheck_trials: int,
) -> Dict[str, Any]:
    payload: Dict[str, Any] = {
        "guardrail_type": "factcheck",
        "factcheck_text": response_text,
        "run_factcheck": True,
        "run_moderation": False,
        "run_attestation": include_attestation,
        "factcheck_trials": factcheck_trials,
    }

    response = client.post(endpoint, json=payload)
    response.raise_for_status()
    return response.json()


def extract_factcheck_status_error(factcheck: Dict[str, Any]) -> Tuple[Optional[int], Any]:
    factcheck_http_status = factcheck.get("http_status")
    factcheck_error_reason = factcheck.get("error")

    if factcheck_http_status is None:
        trial_results = factcheck.get("trial_results")
        if isinstance(trial_results, list) and trial_results:
            latest_trial = trial_results[-1]
            if isinstance(latest_trial, dict):
                factcheck_http_status = latest_trial.get("http_status")
                if factcheck_error_reason is None:
                    factcheck_error_reason = latest_trial.get("error")

    return factcheck_http_status, factcheck_error_reason


def append_server_side_failure(
    failures: List[Dict[str, Any]],
    index: int,
    row: Dict[str, Any],
    factcheck_http_status: Optional[int],
    factcheck_error_reason: Any,
) -> None:
    if not isinstance(factcheck_http_status, int) or factcheck_http_status < 400:
        return

    print(
        f"Request failed at index {index}: FactCheck returned HTTP {factcheck_http_status}. "
        f"Reason: {factcheck_error_reason}"
    )
    failures.append(
        {
            "index": index,
            "status_code": factcheck_http_status,
            "error": "FactCheck execution failed inside experiment server",
            "error_reason": factcheck_error_reason,
            "response": row.get("response"),
        }
    )


def append_http_failure(
    failures: List[Dict[str, Any]],
    index: int,
    row: Dict[str, Any],
    error: httpx.HTTPStatusError,
) -> None:
    status_code = error.response.status_code if error.response is not None else None
    error_reason = extract_response_error(error.response) if error.response is not None else None

    print(f"Request failed at index {index}: HTTP {status_code}. Reason: {error_reason}")
    failures.append(
        {
            "index": index,
            "status_code": status_code,
            "error": str(error),
            "error_reason": error_reason,
            "response": row.get("response"),
        }
    )


def build_detail_record(
    index: int,
    row: Dict[str, Any],
    result: Dict[str, Any],
    factcheck_http_status: Optional[int],
    factcheck_error_reason: Any,
    include_attestation: bool,
    factcheck_trials: int,
) -> Dict[str, Any]:
    factcheck = result.get("factcheck", {})
    attestation = result.get("attestation", {})

    factcheck_ms = factcheck.get("latency_ms")
    if factcheck_ms is None:
        latency_stats = factcheck.get("latency_stats", {})
        factcheck_ms = latency_stats.get("avg_ms")

    total_ms = result.get("total_latency_ms")

    return {
        "index": index,
        "line_number": row["line_number"],
        "prompt": row.get("prompt"),
        "response": row.get("response"),
        "entry_label": row.get("entry_label"),
        "claim_count": row.get("claim_count"),
        "factcheck_latency_ms": factcheck_ms,
        "attestation_latency_ms": attestation.get("latency_ms") if include_attestation else None,
        "total_latency_ms": total_ms,
        "factcheck_http_status": factcheck_http_status,
        "factcheck_error_reason": factcheck_error_reason,
        "factcheck_trials": factcheck.get("trials", factcheck_trials),
        "factcheck_latency_stats": factcheck.get("latency_stats"),
        "num_claims": factcheck.get("num_claims"),
        "num_verified_claims": factcheck.get("num_verified_claims"),
        "factuality": factcheck.get("factuality"),
        "factcheck_prediction": factcheck.get("response"),
        "attestation_http_status": attestation.get("http_status") if include_attestation else None,
    }


def update_latency_lists(
    detail: Dict[str, Any],
    factcheck_latencies: List[float],
    attestation_latencies: List[float],
    total_latencies: List[float],
    include_attestation: bool,
) -> None:
    factcheck_ms = detail.get("factcheck_latency_ms")
    total_ms = detail.get("total_latency_ms")
    attestation_ms = detail.get("attestation_latency_ms")

    if factcheck_ms is not None:
        factcheck_latencies.append(float(factcheck_ms))
    if total_ms is not None:
        total_latencies.append(float(total_ms))
    if include_attestation and attestation_ms is not None:
        attestation_latencies.append(float(attestation_ms))


def run_experiment(
    rows: List[Dict[str, Any]],
    endpoint: str,
    include_attestation: bool,
    factcheck_trials: int,
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], List[float], List[float], List[float]]:
    details: List[Dict[str, Any]] = []
    failures: List[Dict[str, Any]] = []
    factcheck_latencies: List[float] = []
    attestation_latencies: List[float] = []
    total_latencies: List[float] = []

    with httpx.Client(timeout=600.0) as client:
        sample_count = len(rows)
        for index, row in enumerate(rows, start=1):
            try:
                result = run_single(
                    client=client,
                    endpoint=endpoint,
                    response_text=row["response"],
                    include_attestation=include_attestation,
                    factcheck_trials=factcheck_trials,
                )

                factcheck = result.get("factcheck", {})
                factcheck_http_status, factcheck_error_reason = extract_factcheck_status_error(factcheck)
                append_server_side_failure(
                    failures=failures,
                    index=index,
                    row=row,
                    factcheck_http_status=factcheck_http_status,
                    factcheck_error_reason=factcheck_error_reason,
                )

                detail = build_detail_record(
                    index=index,
                    row=row,
                    result=result,
                    factcheck_http_status=factcheck_http_status,
                    factcheck_error_reason=factcheck_error_reason,
                    include_attestation=include_attestation,
                    factcheck_trials=factcheck_trials,
                )
                details.append(detail)
                update_latency_lists(
                    detail=detail,
                    factcheck_latencies=factcheck_latencies,
                    attestation_latencies=attestation_latencies,
                    total_latencies=total_latencies,
                    include_attestation=include_attestation,
                )
            except httpx.HTTPStatusError as error:
                append_http_failure(failures=failures, index=index, row=row, error=error)
            except Exception as error:
                print(f"Request failed at index {index}: {error}")
                failures.append({"index": index, "error": str(error), "response": row.get("response")})

            if index % 10 == 0 or index == sample_count:
                print(f"Progress: {index}/{sample_count}")

    return details, failures, factcheck_latencies, attestation_latencies, total_latencies


def print_summary(
    dataset_path: Path,
    sample_count: int,
    completed: int,
    failures: List[Dict[str, Any]],
    factcheck_trials: int,
    factcheck_latencies: List[float],
    attestation_latencies: List[float],
    total_latencies: List[float],
    include_attestation: bool,
) -> None:
    print("\n=== FactCheck Response Latency Summary ===")
    print(f"Dataset path: {dataset_path}")
    print(f"Requested examples: {sample_count}")
    print(f"Completed: {completed}")
    print(f"Failures: {len(failures)}")
    print(f"FactCheck trials/example: {factcheck_trials}")

    if factcheck_latencies:
        print_latency_stats("FactCheck", factcheck_latencies)

    if include_attestation and attestation_latencies:
        print_latency_stats("Attestation", attestation_latencies)

    if total_latencies:
        print_latency_stats("Total", total_latencies)


def maybe_write_output(
    output_json: Optional[str],
    dataset_path: Path,
    sample_count: int,
    completed: int,
    failures: List[Dict[str, Any]],
    details: List[Dict[str, Any]],
) -> None:
    if not output_json:
        return

    output_payload = {
        "dataset_path": str(dataset_path),
        "requested_examples": sample_count,
        "completed": completed,
        "failures": failures,
        "results": details,
    }
    with open(output_json, "w", encoding="utf-8") as file:
        json.dump(output_payload, file, indent=2)
    print(f"Detailed results saved to: {output_json}")


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    dataset_path = resolve_dataset_path(args.dataset_path)

    if not dataset_path.exists():
        raise FileNotFoundError(f"Dataset file not found: {dataset_path}")

    rows = load_response_rows(dataset_path)
    if not rows:
        raise RuntimeError("No response rows were found in dataset.")

    sample_count = min(args.num_examples, len(rows))
    selected_rows = rows[:sample_count]

    server_url = resolve_server_url(args.server_url, args.server_port)

    endpoint = f"{server_url}/experiment/latency"

    details, failures, factcheck_latencies, attestation_latencies, total_latencies = run_experiment(
        rows=selected_rows,
        endpoint=endpoint,
        include_attestation=args.include_attestation,
        factcheck_trials=args.factcheck_trials,
    )

    completed = len(details)
    print_summary(
        dataset_path=dataset_path,
        sample_count=sample_count,
        completed=completed,
        failures=failures,
        factcheck_trials=args.factcheck_trials,
        factcheck_latencies=factcheck_latencies,
        attestation_latencies=attestation_latencies,
        total_latencies=total_latencies,
        include_attestation=args.include_attestation,
    )
    maybe_write_output(
        output_json=args.output_json,
        dataset_path=dataset_path,
        sample_count=sample_count,
        completed=completed,
        failures=failures,
        details=details,
    )


if __name__ == "__main__":
    main()
