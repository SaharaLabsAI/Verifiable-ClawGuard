#!/usr/bin/env python3
"""
Latency Experiment Server (Runs INSIDE Nitro Enclave)

Purpose:
1. Measure moderation latency using OpenRouter Llama-Guard-3-8B.
2. Measure latency of attestation generation by calling local attestation server.

By default this server listens on localhost:8770 inside the enclave.
To expose it outside, pair it with:
  - vsock_to_tcp_bridge.py inside enclave (vsock:8770 -> tcp:8770)
  - vsock_proxy.py on parent EC2 (tcp:<public/local> -> vsock:8770)
"""

import os
import argparse
import re
import time
import asyncio
from statistics import mean, stdev
from typing import Any, Dict, List, Literal, Optional

import httpx
import uvicorn
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field


DEFAULT_OPENROUTER_BASE_URL = "https://openrouter.ai/api/v1"
DEFAULT_OPENROUTER_MODEL = "meta-llama/llama-guard-3-8b"
DEFAULT_OPENAI_BASE_URL = "https://api.openai.com/v1"
DEFAULT_OPENAI_MODEL = "gpt-5.1"
DEFAULT_ATTESTATION_URL = "http://127.0.0.1:8765/attestation"
DEFAULT_UNSAFE_CATEGORIES = """S1: Violent Crimes.
S2: Non-Violent Crimes.
S3: Sex Crimes.
S4: Child Exploitation.
S5: Defamation.
S6: Specialized Advice.
S7: Privacy.
S8: Intellectual Property.
S9: Indiscriminate Weapons.
S10: Hate.
S11: Self-Harm.
S12: Sexual Content.
S13: Elections.
S14: Code Interpreter Abuse."""


def is_running_in_enclave() -> bool:
    return os.path.exists("/dev/nsm")


class LatencyExperimentRequest(BaseModel):
    chat_text: Optional[str] = Field(
        default=None,
        description="Single text to moderate (backward-compatible path)",
    )
    user_input: Optional[str] = Field(
        default=None,
        description="User message for moderation",
    )
    model_output: Optional[str] = Field(
        default=None,
        description="Model output message for moderation",
    )
    role: str = Field(
        default="Agent",
        description="Which role to assess in the Llama Guard prompt: User or Agent",
    )
    unsafe_categories: Optional[str] = Field(
        default=None,
        description="Optional unsafe category block override",
    )
    nonce: Optional[str] = Field(
        default=None,
        description="Nonce to pass to attestation server",
    )
    include_metadata: bool = True
    custom_data: Optional[Dict[str, Any]] = None

    run_moderation: bool = True
    run_factcheck: bool = True
    run_attestation: bool = True
    guardrail_type: Literal["moderation", "factcheck"] = "moderation"

    openrouter_model: str = DEFAULT_OPENROUTER_MODEL
    openrouter_base_url: str = DEFAULT_OPENROUTER_BASE_URL
    openrouter_api_key: Optional[str] = None
    openai_model: str = DEFAULT_OPENAI_MODEL
    openai_base_url: str = DEFAULT_OPENAI_BASE_URL
    openai_api_key: Optional[str] = None
    moderation_provider: Literal["openrouter", "openai"] = "openrouter"
    moderation_trials: int = Field(
        default=1,
        ge=1,
        le=100,
        description="Number of moderation calls to run for latency statistics",
    )

    moderation_timeout_seconds: float = 30.0
    attestation_timeout_seconds: float = 30.0

    factcheck_text: Optional[str] = Field(
        default=None,
        description="Text input for FactCheck guardrail",
    )
    factcheck_trials: int = Field(
        default=1,
        ge=1,
        le=100,
        description="Number of FactCheck runs to execute for latency statistics",
    )


def build_llamaguard_prompt(request: LatencyExperimentRequest) -> str:
    role = request.role.strip().capitalize()
    if role not in {"User", "Agent"}:
        raise HTTPException(status_code=400, detail="role must be 'User' or 'Agent'.")

    unsafe_categories = request.unsafe_categories or DEFAULT_UNSAFE_CATEGORIES

    user_input = request.user_input or request.chat_text
    if not user_input:
        raise HTTPException(
            status_code=400,
            detail="For moderation, provide chat_text or user_input.",
        )

    model_output = request.model_output or ""

    if role == "Agent":
        return (
            "<|begin_of_text|><|start_header_id|>user<|end_header_id|>\n\n"
            f"Task: Check if there is unsafe content in '{role}' messages in conversations according to our safety policy with the below categories.\n\n"
            "<BEGIN UNSAFE CONTENT CATEGORIES>\n"
            f"{unsafe_categories}\n"
            "<END UNSAFE CONTENT CATEGORIES>\n\n"
            "<BEGIN CONVERSATION>\n\n"
            f"User: {user_input}\n\n"
            f"Agent: {model_output}\n\n"
            "<END CONVERSATION>\n\n"
            f"Provide your safety assessment for '{role}' in the above conversation:\n"
            "- First line must read 'safe' or 'unsafe'.\n"
            "- If unsafe, a second line must include a comma-separated list of violated categories."
            "<|eot_id|><|start_header_id|>assistant<|end_header_id|>\n"
        )

    return (
        "<|begin_of_text|><|start_header_id|>user<|end_header_id|>\n\n"
        f"Task: Check if there is unsafe content in '{role}' messages in conversations according to our safety policy with the below categories.\n\n"
        "<BEGIN UNSAFE CONTENT CATEGORIES>\n"
        f"{unsafe_categories}\n"
        "<END UNSAFE CONTENT CATEGORIES>\n\n"
        "<BEGIN CONVERSATION>\n\n"
        f"User: {user_input}\n\n"
        "<END CONVERSATION>\n\n"
        f"Provide your safety assessment for '{role}' in the above conversation:\n"
        "- First line must read 'safe' or 'unsafe'.\n"
        "- If unsafe, a second line must include a comma-separated list of violated categories."
        "<|eot_id|><|start_header_id|>assistant<|end_header_id|>\n"
    )

def build_openai_prompt(request: LatencyExperimentRequest) -> str:
    role = request.role.strip().capitalize()
    if role not in {"User", "Agent"}:
        raise HTTPException(status_code=400, detail="role must be 'User' or 'Agent'.")

    unsafe_categories = request.unsafe_categories or DEFAULT_UNSAFE_CATEGORIES

    user_input = request.user_input or request.chat_text
    if not user_input:
        raise HTTPException(
            status_code=400,
            detail="For moderation, provide chat_text or user_input.",
        )

    model_output = request.model_output or ""


    return (
        f"Task: Check if there is unsafe content in user messages in conversations according to our safety policy with the below categories.\n\n"
        "<BEGIN UNSAFE CONTENT CATEGORIES>\n"
        f"{unsafe_categories}\n"
        "<END UNSAFE CONTENT CATEGORIES>\n\n"
        "<BEGIN CONVERSATION>\n\n"
        f"User: {user_input}\n\n"
        f"Agent: {model_output}\n\n"
        "<END CONVERSATION>\n\n"
        f"Provide your safety assessment for user in the above conversation:\n"
        "- First line must read 'safe' or 'unsafe'.\n"
        "- If unsafe, a second line must include a comma-separated list of violated categories.\n"
        "- Starting from the third line: If safe, return a response. Otherwise, return an rejection reason that can be shown to the user."
    )



def parse_verdict(content: Optional[str]) -> Dict[str, Optional[str]]:
    if not content:
        return {"verdict": None, "categories": None}

    lines = [line.strip() for line in content.strip().splitlines() if line.strip()]
    if not lines:
        return {"verdict": None, "categories": None}

    full_text = "\n".join(lines)
    full_text_lower = full_text.lower()

    verdict = None
    if re.search(r"\bunsafe\b", full_text_lower):
        verdict = "unsafe"
    elif re.search(r"\bsafe\b", full_text_lower):
        verdict = "safe"

    categories = None
    if verdict == "unsafe":
        category_codes = re.findall(r"\bS([1-9]|1[0-4])\b", full_text, flags=re.IGNORECASE)
        if category_codes:
            normalized = []
            seen = set()
            for code in category_codes:
                token = f"S{int(code)}"
                if token not in seen:
                    seen.add(token)
                    normalized.append(token)
            categories = ", ".join(normalized)
        elif len(lines) > 1:
            categories = lines[1]

    return {"verdict": verdict, "categories": categories}


def percentile(sorted_values: List[float], p: float) -> float:
    if not sorted_values:
        return 0.0
    index = int(round((p / 100.0) * (len(sorted_values) - 1)))
    return sorted_values[index]


def summarize_latency(latencies: List[float]) -> Dict[str, float]:
    if not latencies:
        return {
            "count": 0,
            "avg_ms": 0.0,
            "std_ms": 0.0,
            "min_ms": 0.0,
            "p50_ms": 0.0,
            "p95_ms": 0.0,
            "p99_ms": 0.0,
            "max_ms": 0.0,
        }

    sorted_latencies = sorted(latencies)
    return {
        "count": len(latencies),
        "avg_ms": round(mean(latencies), 3),
        "std_ms": round(stdev(latencies), 3) if len(latencies) > 1 else 0.0,
        "min_ms": round(sorted_latencies[0], 3),
        "p50_ms": round(percentile(sorted_latencies, 50), 3),
        "p95_ms": round(percentile(sorted_latencies, 95), 3),
        "p99_ms": round(percentile(sorted_latencies, 99), 3),
        "max_ms": round(sorted_latencies[-1], 3),
    }


app = FastAPI(
    title="Enclave Latency Experiment Server",
    description="Measures moderation/factcheck and attestation latency from inside Nitro Enclave",
    version="1.0.0",
)


_FACTCHECK_INSTANCE = None


@app.get("/")
async def root() -> Dict[str, Any]:
    return {
        "service": "Latency Experiment Server",
        "version": "1.0.0",
        "running_in_tee": is_running_in_enclave(),
        "supported_guardrails": ["moderation", "factcheck"],
        "endpoints": {
            "/health": "Health check",
            "/experiment/latency": "Run moderation/factcheck + attestation latency experiment",
        },
    }


@app.get("/health")
async def health() -> Dict[str, Any]:
    return {
        "status": "healthy",
        "running_in_tee": is_running_in_enclave(),
        "attestation_server": DEFAULT_ATTESTATION_URL,
        "supported_guardrails": ["moderation", "factcheck"],
    }


@app.post("/guardrail/run")
async def run_guardrail_direct(request: LatencyExperimentRequest) -> Dict[str, Any]:
    """Run only the selected guardrail directly (without attestation)."""
    response: Dict[str, Any] = {
        "running_in_tee": is_running_in_enclave(),
        "guardrail_type": request.guardrail_type,
    }

    total_start = time.perf_counter()

    if request.guardrail_type == "moderation":
        response["moderation"] = await run_moderation(request)
    else:
        response["factcheck"] = await run_factcheck(request)

    response["total_latency_ms"] = round((time.perf_counter() - total_start) * 1000.0, 3)
    return response


def get_factcheck_instance() -> Any:
    global _FACTCHECK_INSTANCE
    if _FACTCHECK_INSTANCE is None:
        from factcheck import FactCheck

        _FACTCHECK_INSTANCE = FactCheck(
            api_config={'SERPER_API_KEY': os.getenv("SERPER_API_KEY"), 'OPENAI_API_KEY': os.getenv("OPENAI_API_KEY")},
        )
    return _FACTCHECK_INSTANCE


async def run_factcheck_once(request: LatencyExperimentRequest) -> Dict[str, Any]:
    text = request.factcheck_text or request.chat_text or request.user_input
    if not text:
        raise HTTPException(
            status_code=400,
            detail="For factcheck, provide factcheck_text, chat_text, or user_input.",
        )

    start = time.perf_counter()
    try:
        factcheck_instance = get_factcheck_instance()
        output = await asyncio.to_thread(factcheck_instance.check_text, text)
    except HTTPException:
        raise
    except Exception as error:
        elapsed_ms = round((time.perf_counter() - start) * 1000.0, 3)
        return {
            "latency_ms": elapsed_ms,
            "http_status": 500,
            "error": str(error),
        }

    elapsed_ms = round((time.perf_counter() - start) * 1000.0, 3)
    if not isinstance(output, dict):
        return {
            "latency_ms": elapsed_ms,
            "http_status": 500,
            "error": f"Unexpected FactCheck output type: {type(output).__name__}",
        }

    summary = output.get("summary")
    if summary is not None and not isinstance(summary, dict):
        summary = None

    return {
        "latency_ms": elapsed_ms,
        "http_status": 200,
        "summary": summary,
        "num_claims": summary.get("num_claims") if isinstance(summary, dict) else None,
        "num_verified_claims": summary.get("num_verified_claims") if isinstance(summary, dict) else None,
        "factuality": summary.get("factuality") if isinstance(summary, dict) else None,
        "response": output,
    }


async def run_factcheck(request: LatencyExperimentRequest) -> Dict[str, Any]:
    if request.factcheck_trials == 1:
        return await run_factcheck_once(request)

    trials: List[Dict[str, Any]] = []
    latencies: List[float] = []

    for trial_index in range(request.factcheck_trials):
        trial_result = await run_factcheck_once(request)
        trial_result["trial"] = trial_index + 1
        trials.append(trial_result)

        latency_ms = trial_result.get("latency_ms")
        if isinstance(latency_ms, (int, float)):
            latencies.append(float(latency_ms))

    latest = trials[-1]
    return {
        "trials": request.factcheck_trials,
        "latency_ms": summarize_latency(latencies).get("avg_ms", 0.0),
        "latency_stats": summarize_latency(latencies),
        "summary": latest.get("summary"),
        "num_claims": latest.get("num_claims"),
        "num_verified_claims": latest.get("num_verified_claims"),
        "factuality": latest.get("factuality"),
        "response": latest.get("response"),
        "trial_results": trials,
    }


async def run_openrouter_moderation_once(request: LatencyExperimentRequest) -> Dict[str, Any]:
    api_key = request.openrouter_api_key or os.getenv("OPENROUTER_API_KEY")
    if not api_key:
        raise HTTPException(
            status_code=400,
            detail="Missing OpenRouter API key. Set OPENROUTER_API_KEY or send openrouter_api_key.",
        )

    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }

    referer = os.getenv("OPENROUTER_REFERER")
    if referer:
        headers["HTTP-Referer"] = referer

    title = os.getenv("OPENROUTER_TITLE")
    if title:
        headers["X-Title"] = title

    prompt = build_llamaguard_prompt(request)

    payload = {
        "model": request.openrouter_model,
        "messages": [{"role": "user", "content": prompt}],
        "temperature": 0,
        "max_tokens": 64,
    }

    url = f"{request.openrouter_base_url.rstrip('/')}/chat/completions"
    start = time.perf_counter()

    async with httpx.AsyncClient(timeout=request.moderation_timeout_seconds) as client:
        response = await client.post(url, headers=headers, json=payload)

    elapsed_ms = round((time.perf_counter() - start) * 1000.0, 3)

    result: Dict[str, Any] = {
        "latency_ms": elapsed_ms,
        "http_status": response.status_code,
        "role": request.role,
    }

    try:
        body = response.json()
    except Exception:
        body = {"raw_text": response.text[:2000]}

    if response.status_code >= 400:
        result["error"] = body
        return result

    choice_preview = None
    if isinstance(body, dict):
        choices = body.get("choices")
        if isinstance(choices, list) and len(choices) > 0:
            message = choices[0].get("message", {})
            choice_preview = message.get("content")

    parsed = parse_verdict(choice_preview)

    result["model"] = request.openrouter_model
    result["response_preview"] = choice_preview
    result["verdict"] = parsed["verdict"]
    result["categories"] = parsed["categories"]
    result["openrouter_id"] = body.get("id") if isinstance(body, dict) else None

    return result


async def run_openai_moderation_once(request: LatencyExperimentRequest) -> Dict[str, Any]:
    api_key = request.openai_api_key or os.getenv("OPENAI_API_KEY")
    if not api_key:
        raise HTTPException(
            status_code=400,
            detail="Missing OpenAI API key. Set OPENAI_API_KEY or send openai_api_key.",
        )

    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }

    prompt = build_openai_prompt(request)

    payload = {
        "model": request.openai_model,
        "messages": [{"role": "user", "content": prompt}],
        "temperature": 0,
        "max_tokens": 64,
    }

    url = f"{request.openai_base_url.rstrip('/')}/chat/completions"
    start = time.perf_counter()

    async with httpx.AsyncClient(timeout=request.moderation_timeout_seconds) as client:
        response = await client.post(url, headers=headers, json=payload)

    elapsed_ms = round((time.perf_counter() - start) * 1000.0, 3)

    result: Dict[str, Any] = {
        "latency_ms": elapsed_ms,
        "http_status": response.status_code,
        "role": request.role,
    }

    try:
        body = response.json()
    except Exception:
        body = {"raw_text": response.text[:2000]}

    if response.status_code >= 400:
        result["error"] = body
        return result

    choice_preview = None
    if isinstance(body, dict):
        choices = body.get("choices")
        if isinstance(choices, list) and len(choices) > 0:
            message = choices[0].get("message", {})
            choice_preview = message.get("content")

    parsed = parse_verdict(choice_preview)

    result["model"] = request.openai_model
    result["response_preview"] = choice_preview
    result["verdict"] = parsed["verdict"]
    result["categories"] = parsed["categories"]
    result["openai_id"] = body.get("id") if isinstance(body, dict) else None

    return result


async def run_moderation(request: LatencyExperimentRequest) -> Dict[str, Any]:
    moderation_fn = (
        run_openai_moderation_once
        if request.moderation_provider == "openai"
        else run_openrouter_moderation_once
    )

    if request.moderation_trials == 1:
        result = await moderation_fn(request)
        result["provider"] = request.moderation_provider
        return result

    trials: List[Dict[str, Any]] = []
    latencies: List[float] = []

    for trial_index in range(request.moderation_trials):
        trial_result = await moderation_fn(request)
        trial_result["trial"] = trial_index + 1
        trials.append(trial_result)

        latency_ms = trial_result.get("latency_ms")
        if isinstance(latency_ms, (int, float)):
            latencies.append(float(latency_ms))

    latest = trials[-1]
    return {
        "provider": request.moderation_provider,
        "model": latest.get("model"),
        "role": request.role,
        "trials": request.moderation_trials,
        "latency_ms": summarize_latency(latencies).get("avg_ms", 0.0),
        "latency_stats": summarize_latency(latencies),
        "verdict": latest.get("verdict"),
        "categories": latest.get("categories"),
        "response_preview": latest.get("response_preview"),
        "trial_results": trials,
    }


async def run_attestation(request: LatencyExperimentRequest) -> Dict[str, Any]:
    payload: Dict[str, Any] = {
        "include_metadata": request.include_metadata,
    }
    if request.nonce is not None:
        payload["nonce"] = request.nonce
    if request.custom_data is not None:
        payload["custom_data"] = request.custom_data

    start = time.perf_counter()
    async with httpx.AsyncClient(timeout=request.attestation_timeout_seconds) as client:
        response = await client.post(DEFAULT_ATTESTATION_URL, json=payload)

    elapsed_ms = round((time.perf_counter() - start) * 1000.0, 3)

    try:
        body = response.json()
    except Exception:
        body = {"raw_text": response.text[:2000]}

    if response.status_code >= 400:
        return {
            "latency_ms": elapsed_ms,
            "http_status": response.status_code,
            "error": body,
        }

    return {
        "latency_ms": elapsed_ms,
        "http_status": response.status_code,
        "attestation_response": body,
    }


@app.post("/experiment/latency")
async def run_latency_experiment(request: LatencyExperimentRequest) -> Dict[str, Any]:
    if request.guardrail_type == "moderation":
        if not request.run_moderation and not request.run_attestation:
            raise HTTPException(
                status_code=400,
                detail="At least one of run_moderation or run_attestation must be true.",
            )
    elif request.guardrail_type == "factcheck":
        if not request.run_factcheck and not request.run_attestation:
            raise HTTPException(
                status_code=400,
                detail="At least one of run_factcheck or run_attestation must be true.",
            )

    response: Dict[str, Any] = {
        "running_in_tee": is_running_in_enclave(),
        "guardrail_type": request.guardrail_type,
    }

    total_start = time.perf_counter()

    if request.guardrail_type == "moderation":
        if request.run_moderation:
            response["moderation"] = await run_moderation(request)
    else:
        if request.run_factcheck:
            response["factcheck"] = await run_factcheck(request)

    if request.run_attestation:
        response["attestation"] = await run_attestation(request)

    response["total_latency_ms"] = round((time.perf_counter() - total_start) * 1000.0, 3)
    return response


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Enclave Latency Experiment Server")
    parser.add_argument(
        "--host",
        default="127.0.0.1",
        help="Host interface to bind (default: 127.0.0.1)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=int(os.getenv("LATENCY_EXPERIMENT_PORT", "8770")),
        help="Port to bind (default: 8770 or LATENCY_EXPERIMENT_PORT env)",
    )
    args = parser.parse_args()

    print("=" * 70)
    print("  Enclave Latency Experiment Server")
    print("=" * 70)
    print(f"Running in TEE: {is_running_in_enclave()}")
    print(f"Host: {args.host}")
    print(f"Port: {args.port}")
    print("Endpoint: POST /experiment/latency")
    print("=" * 70)

    uvicorn.run(
        app,
        host=args.host,
        port=args.port,
        log_level="info",
    )
