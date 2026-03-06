#!/usr/bin/env python3
"""
Run latency experiments on ToxicChat test split.

This script:
1. Loads `lmsys/toxic-chat` test split from Hugging Face.
2. Uses `user_input` + `model_output` as moderation messages.
3. Calls the enclave experiment server `/experiment/latency` endpoint.
4. Reports average latency over N examples (default: 100).

Example:
  python3 run_toxicchat_latency_experiment.py \
      --server-url http://127.0.0.1:8770 \
      --num-examples 100
"""

import argparse
import json
from statistics import mean, stdev
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse, urlunparse

import httpx
from datasets import get_dataset_config_names, load_dataset


def pick_config(dataset_name: str) -> Optional[str]:
    try:
        config_names = get_dataset_config_names(dataset_name)
    except Exception:
        return None

    if not config_names:
        return None

    preferred = ["toxicchat0124", "default"]
    for candidate in preferred:
        if candidate in config_names:
            return candidate

    return config_names[0]


def load_test_rows(dataset_name: str, split: str) -> List[Dict[str, Any]]:
    config_name = pick_config(dataset_name)
    if config_name:
        dataset = load_dataset(dataset_name, config_name, split=split)
    else:
        dataset = load_dataset(dataset_name, split=split)

    rows = [row for row in dataset if row.get("user_input") and row.get("model_output")]
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
    user_input: str,
    model_output: str,
    role: str,
    unsafe_categories: Optional[str],
    include_attestation: bool,
    moderation_provider: str,
    moderation_trials: int,
    openrouter_api_key: Optional[str],
    openai_api_key: Optional[str],
    openai_model: str,
) -> Dict[str, Any]:
    payload: Dict[str, Any] = {
        "user_input": user_input,
        "model_output": model_output,
        "role": role,
        "run_moderation": True,
        "run_attestation": include_attestation,
        "moderation_provider": moderation_provider,
        "moderation_trials": moderation_trials,
        "openai_model": openai_model,
    }

    if unsafe_categories:
        payload["unsafe_categories"] = unsafe_categories

    if openrouter_api_key:
        payload["openrouter_api_key"] = openrouter_api_key

    if openai_api_key:
        payload["openai_api_key"] = openai_api_key

    response = client.post(endpoint, json=payload)
    response.raise_for_status()
    return response.json()


def main() -> None:
    parser = argparse.ArgumentParser(description="Run ToxicChat latency experiment")
    parser.add_argument("--dataset", default="lmsys/toxic-chat", help="Hugging Face dataset name")
    parser.add_argument("--split", default="test", help="Dataset split (default: test)")
    parser.add_argument("--num-examples", type=int, default=100, help="Number of examples to test")
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
        "--openrouter-api-key",
        default=None,
        help="Optional API key (if omitted, server must have OPENROUTER_API_KEY set)",
    )
    parser.add_argument(
        "--moderation-provider",
        default="openrouter",
        choices=["openrouter", "openai"],
        help="Moderation provider to use on server",
    )
    parser.add_argument(
        "--moderation-trials",
        type=int,
        default=1,
        help="Number of moderation calls per example for latency stats (server-side)",
    )
    parser.add_argument(
        "--openai-api-key",
        default=None,
        help="Optional OpenAI API key (if omitted, server must have OPENAI_API_KEY set)",
    )
    parser.add_argument(
        "--openai-model",
        default="gpt-5.1",
        help="OpenAI model for moderation when --moderation-provider openai",
    )
    parser.add_argument(
        "--role",
        default="Agent",
        choices=["User", "Agent"],
        help="Which role to assess in the Llama Guard prompt",
    )
    parser.add_argument(
        "--unsafe-categories-file",
        default=None,
        help="Optional file path containing unsafe categories block",
    )
    parser.add_argument(
        "--output-json",
        default=None,
        help="Optional path to save detailed per-example results",
    )
    args = parser.parse_args()

    rows = load_test_rows(args.dataset, args.split)
    if not rows:
        raise RuntimeError("No rows with both user_input and model_output were found.")

    sample_count = min(args.num_examples, len(rows))
    selected_rows = rows[:sample_count]

    server_url = args.server_url.rstrip('/')
    if args.server_port is not None:
        parsed = urlparse(server_url)
        if not parsed.scheme:
            parsed = urlparse(f"http://{server_url}")
        host = parsed.hostname or "127.0.0.1"
        netloc = f"{host}:{args.server_port}"
        path = parsed.path.rstrip("/")
        server_url = urlunparse((parsed.scheme or "http", netloc, path, "", "", ""))

    endpoint = f"{server_url}/experiment/latency"
    unsafe_categories: Optional[str] = None
    if args.unsafe_categories_file:
        with open(args.unsafe_categories_file, "r", encoding="utf-8") as file:
            unsafe_categories = file.read().strip()

    moderation_latencies: List[float] = []
    attestation_latencies: List[float] = []
    total_latencies: List[float] = []
    safe_count = 0
    unsafe_count = 0
    failures: List[Dict[str, Any]] = []
    details: List[Dict[str, Any]] = []

    with httpx.Client(timeout=120.0) as client:
        for index, row in enumerate(selected_rows, start=1):
            try:
                result = run_single(
                    client=client,
                    endpoint=endpoint,
                    user_input=row["user_input"],
                    model_output=row["model_output"],
                    role=args.role,
                    unsafe_categories=unsafe_categories,
                    include_attestation=args.include_attestation,
                    moderation_provider=args.moderation_provider,
                    moderation_trials=args.moderation_trials,
                    openrouter_api_key=args.openrouter_api_key,
                    openai_api_key=args.openai_api_key,
                    openai_model=args.openai_model,
                )

                moderation = result.get("moderation", {})
                attestation = result.get("attestation", {})

                moderation_ms = moderation.get("latency_ms")
                if moderation_ms is None:
                    latency_stats = moderation.get("latency_stats", {})
                    moderation_ms = latency_stats.get("avg_ms")
                total_ms = result.get("total_latency_ms")
                moderation_verdict = moderation.get("verdict")
                moderation_http_status = moderation.get("http_status")
                if moderation_http_status is None:
                    trial_results = moderation.get("trial_results")
                    if isinstance(trial_results, list) and trial_results:
                        moderation_http_status = trial_results[-1].get("http_status")

                if moderation_verdict == "safe":
                    safe_count += 1
                elif moderation_verdict == "unsafe":
                    unsafe_count += 1

                if moderation_ms is not None:
                    moderation_latencies.append(float(moderation_ms))
                if total_ms is not None:
                    total_latencies.append(float(total_ms))
                if args.include_attestation and attestation.get("latency_ms") is not None:
                    attestation_latencies.append(float(attestation["latency_ms"]))

                details.append(
                    {
                        "index": index,
                        "moderation_latency_ms": moderation_ms,
                        "attestation_latency_ms": attestation.get("latency_ms"),
                        "total_latency_ms": total_ms,
                        "moderation_http_status": moderation_http_status,
                        "moderation_provider": moderation.get("provider", args.moderation_provider),
                        "moderation_model": moderation.get("model"),
                        "moderation_trials": moderation.get("trials", args.moderation_trials),
                        "moderation_latency_stats": moderation.get("latency_stats"),
                        "moderation_verdict": moderation_verdict,
                        "moderation_categories": moderation.get("categories"),
                        "moderation_response_preview": moderation.get("response_preview"),
                        "moderation_trial_results": moderation.get("trial_results"),
                        "attestation_http_status": attestation.get("http_status") if args.include_attestation else None,
                    }
                )

            except Exception as error:
                failures.append({"index": index, "error": str(error)})

            if index % 10 == 0 or index == sample_count:
                print(f"Progress: {index}/{sample_count}")

    completed = len(details)
    print("\n=== ToxicChat Latency Summary ===")
    print(f"Dataset: {args.dataset} [{args.split}]")
    print(f"Requested examples: {sample_count}")
    print(f"Completed: {completed}")
    print(f"Failures: {len(failures)}")
    print(f"Moderation provider: {args.moderation_provider}")
    print(f"Moderation trials/example: {args.moderation_trials}")
    print(f"Safe: {safe_count}")
    print(f"Unsafe: {unsafe_count}")

    if moderation_latencies:
        print_latency_stats("Moderation", moderation_latencies)

    if args.include_attestation and attestation_latencies:
        print_latency_stats("Attestation", attestation_latencies)

    if total_latencies:
        print_latency_stats("Total", total_latencies)

    if args.output_json:
        output_payload = {
            "dataset": args.dataset,
            "split": args.split,
            "requested_examples": sample_count,
            "completed": completed,
            "failures": failures,
            "results": details,
        }
        with open(args.output_json, "w", encoding="utf-8") as file:
            json.dump(output_payload, file, indent=2)
        print(f"Detailed results saved to: {args.output_json}")


if __name__ == "__main__":
    main()
