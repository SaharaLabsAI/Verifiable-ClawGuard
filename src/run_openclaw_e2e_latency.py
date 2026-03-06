#!/usr/bin/env python3
"""
Measure end-to-end OpenClaw inference latency from CLI invocations.

This script runs:
  openclaw agent --agent <agent> --message <text> --json

It supports input messages from either:
- ToxicChat (`lmsys/toxic-chat` test split, using `user_input`), or
- FactCheck dataset (`exp_data/knowledge_qa.jsonl`, using `prompt`).

The command output may contain non-JSON diagnostics before the JSON payload.
This script extracts and parses the JSON object automatically.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import time
from pathlib import Path
from statistics import mean, stdev
from typing import Any, Dict, List, Optional


def percentile(sorted_values: List[float], p: float) -> float:
    if not sorted_values:
        return 0.0
    index = int(round((p / 100.0) * (len(sorted_values) - 1)))
    return sorted_values[index]


def print_latency_stats(label: str, latencies: List[float]) -> None:
    if not latencies:
        return

    ordered = sorted(latencies)
    std_value = stdev(latencies) if len(latencies) > 1 else 0.0
    print(f"{label} avg (ms): {mean(latencies):.3f}")
    print(f"{label} std (ms): {std_value:.3f}")
    print(f"{label} min (ms): {ordered[0]:.3f}")
    print(f"{label} p50 (ms): {percentile(ordered, 50):.3f}")
    print(f"{label} p95 (ms): {percentile(ordered, 95):.3f}")
    print(f"{label} p99 (ms): {percentile(ordered, 99):.3f}")
    print(f"{label} max (ms): {ordered[-1]:.3f}")


def extract_json_from_mixed_output(raw_text: str) -> Dict[str, Any]:
    """Parse first JSON object found in mixed text output."""
    decoder = json.JSONDecoder()
    for index, ch in enumerate(raw_text):
        if ch != "{":
            continue
        try:
            parsed, _ = decoder.raw_decode(raw_text[index:])
        except json.JSONDecodeError:
            continue
        if isinstance(parsed, dict):
            return parsed
    raise ValueError("No JSON object found in command output")


def pick_toxicchat_config(dataset_name: str) -> Optional[str]:
    try:
        from datasets import get_dataset_config_names

        config_names = get_dataset_config_names(dataset_name)
    except Exception:
        return None

    if not config_names:
        return None

    for candidate in ["toxicchat0124", "default"]:
        if candidate in config_names:
            return candidate

    return config_names[0]


def load_toxicchat_inputs(dataset_name: str, split: str) -> List[str]:
    try:
        from datasets import load_dataset
    except Exception as error:
        raise RuntimeError("`datasets` package is required for toxicchat source") from error

    config_name = pick_toxicchat_config(dataset_name)
    if config_name:
        dataset = load_dataset(dataset_name, config_name, split=split)
    else:
        dataset = load_dataset(dataset_name, split=split)

    rows = [str(row["user_input"]).strip() for row in dataset if row.get("user_input")]
    rows = [text for text in rows if text]
    return [
        f"Respnd to the user input if it is safe; otherwise say you are unable to help.\n\n {text}"
        for text in rows
    ]


def load_factcheck_inputs(dataset_path: Path) -> List[str]:
    if not dataset_path.exists():
        raise FileNotFoundError(f"FactCheck dataset not found: {dataset_path}")

    rows: List[str] = []
    with dataset_path.open("r", encoding="utf-8") as file:
        for line in file:
            line = line.strip()
            if not line:
                continue
            payload = json.loads(line)
            prompt = payload.get("prompt")
            if isinstance(prompt, str) and prompt.strip():
                rows.append(prompt.strip())
    return rows


def run_openclaw(agent: str, message: str) -> Dict[str, Any]:
    command = [
        "openclaw",
        "agent",
        "--agent",
        agent,
        "--message",
        message,
        "--json",
    ]

    started = time.perf_counter()
    process = subprocess.run(command, capture_output=True, text=True)
    elapsed_ms = (time.perf_counter() - started) * 1000.0

    merged_output = ""
    if process.stdout:
        merged_output += process.stdout
    if process.stderr:
        if merged_output:
            merged_output += "\n"
        merged_output += process.stderr

    parsed = extract_json_from_mixed_output(merged_output)
    return {
        "elapsed_ms": elapsed_ms,
        "return_code": process.returncode,
        "raw_output": merged_output,
        "parsed": parsed,
    }


def maybe_get_agent_duration_ms(payload: Dict[str, Any]) -> Optional[float]:
    try:
        return float(payload["result"]["meta"]["durationMs"])
    except Exception:
        return None


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Measure OpenClaw e2e latency")
    parser.add_argument(
        "--source",
        choices=["toxicchat", "factcheck"],
        required=True,
        help="Input source for prompts",
    )
    parser.add_argument("--num-examples", type=int, default=50, help="Number of inputs to run")
    parser.add_argument("--agent", default="main", help="OpenClaw agent name")
    parser.add_argument("--toxicchat-dataset", default="lmsys/toxic-chat", help="HuggingFace dataset name")
    parser.add_argument("--toxicchat-split", default="test", help="Dataset split for toxicchat")
    parser.add_argument(
        "--factcheck-dataset-path",
        default="exp_data/knowledge_qa.jsonl",
        help="Path to factcheck JSONL dataset",
    )
    parser.add_argument(
        "--output-json",
        default=None,
        help="Optional output path for per-example detailed results",
    )
    return parser


def main() -> None:
    args = build_parser().parse_args()

    script_dir = Path(__file__).resolve().parent
    factcheck_path = Path(args.factcheck_dataset_path)
    if not factcheck_path.is_absolute():
        factcheck_path = script_dir / factcheck_path

    if args.source == "toxicchat":
        prompts = load_toxicchat_inputs(args.toxicchat_dataset, args.toxicchat_split)
    else:
        prompts = load_factcheck_inputs(factcheck_path)

    if not prompts:
        raise RuntimeError("No inputs found for the selected source")

    sample_count = min(args.num_examples, len(prompts))
    selected = prompts[:sample_count]

    wall_latencies: List[float] = []
    agent_latencies: List[float] = []
    failures: List[Dict[str, Any]] = []
    details: List[Dict[str, Any]] = []

    for index, prompt in enumerate(selected, start=1):
        try:
            result = run_openclaw(args.agent, prompt)
            payload = result["parsed"]
            wall_ms = float(result["elapsed_ms"])
            agent_ms = maybe_get_agent_duration_ms(payload)

            wall_latencies.append(wall_ms)
            if agent_ms is not None:
                agent_latencies.append(agent_ms)

            details.append(
                {
                    "index": index,
                    "prompt": prompt,
                    "wall_latency_ms": wall_ms,
                    "agent_duration_ms": agent_ms,
                    "return_code": result["return_code"],
                    "raw_agent_output": result["raw_output"],
                }
            )
        except Exception as error:
            failures.append({"index": index, "error": str(error), "prompt": prompt})

        if index % 10 == 0 or index == sample_count:
            print(f"Progress: {index}/{sample_count}")

    print("\n=== OpenClaw End-to-End Latency Summary ===")
    print(f"Source: {args.source}")
    print(f"Agent: {args.agent}")
    print(f"Requested examples: {sample_count}")
    print(f"Completed: {len(details)}")
    print(f"Failures: {len(failures)}")

    print_latency_stats("Wall (CLI end-to-end)", wall_latencies)
    if agent_latencies:
        print_latency_stats("Agent reported duration", agent_latencies)

    if args.output_json:
        output_payload = {
            "source": args.source,
            "agent": args.agent,
            "requested_examples": sample_count,
            "completed": len(details),
            "failures": failures,
            "results": details,
        }
        with open(args.output_json, "w", encoding="utf-8") as file:
            json.dump(output_payload, file, indent=2)
        print(f"Detailed results saved to: {args.output_json}")


if __name__ == "__main__":
    main()
