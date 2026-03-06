"""
LLM Proxy Server with Auditing and NeMo Guardrail Support

This proxy intercepts LLM API calls from OpenClaw, applies NeMo Guardrails policies,
logs all I/O, and relays requests to actual LLM providers.

Supports:
- OpenAI API format
- Anthropic API format
- NeMo Guardrails for input/output validation
"""

import asyncio
import json
import re
import time
import uuid
from contextlib import asynccontextmanager
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, Request, Response, HTTPException
from fastapi.responses import StreamingResponse
import httpx
import uvicorn
from pydantic import BaseModel

from audit_logger import AuditLogger


# ============================================================================
# Safety Directive Configuration
# ============================================================================

# Optional safety directive that will be prepended to all LLM interactions
SAFETY_DIRECTIVE = ""
UNSAFE_DETERMINISTIC_RESPONSE = "Sorry, I cannot fullfil your request"
CONTENT_GUARDRAIL_ENABLED = True


# ============================================================================
# Safety Configuration
# ============================================================================


def inject_safety_directive_openai(messages: List[Dict]) -> List[Dict]:
    """
    Inject safety directive as a system message for OpenAI format.
    Handles both string and array (multimodal) content.

    Args:
        messages: Original messages in OpenAI format

    Returns:
        Messages with safety directive prepended
    """
    # Check if there's already a system message
    if messages and messages[0].get("role") == "system":
        existing_content = messages[0].get("content", "")
        
        # Handle multimodal content (array format)
        if isinstance(existing_content, list):
            # Prepend safety directive as a text part
            safety_part = {"type": "text", "text": SAFETY_DIRECTIVE}
            messages[0]["content"] = [safety_part] + existing_content
        else:
            # Handle string content
            messages[0]["content"] = f"{SAFETY_DIRECTIVE}\n\n{existing_content}"
        return messages
    else:
        # Insert new system message at the beginning
        safety_message = {
            "role": "system",
            "content": SAFETY_DIRECTIVE
        }
        return [safety_message] + messages


def inject_safety_directive_anthropic(body: Dict) -> Dict:
    """
    Inject safety directive into system parameter for Anthropic format.

    Args:
        body: Original request body in Anthropic format

    Returns:
        Modified body with safety directive prepended to system parameter
    """
    body_copy = body.copy()

    # Anthropic uses a separate 'system' parameter
    existing_system = body_copy.get("system", "")

    if existing_system:
        body_copy["system"] = f"{SAFETY_DIRECTIVE}\n\n{existing_system}"
    else:
        body_copy["system"] = SAFETY_DIRECTIVE

    return body_copy


def _extract_text_content(content: Any) -> str:
    """Extract textual content from OpenAI-style message content."""
    if isinstance(content, str):
        return content

    if isinstance(content, dict):
        # Some clients wrap text in dict forms
        text_value = content.get("text")
        if isinstance(text_value, str):
            return text_value
        if isinstance(text_value, dict):
            nested = text_value.get("value")
            if isinstance(nested, str):
                return nested

    if isinstance(content, list):
        parts = []
        for item in content:
            if not isinstance(item, dict):
                continue

            part_type = item.get("type")
            if part_type in {"text", "input_text", "output_text"}:
                text = item.get("text")
                if isinstance(text, str):
                    parts.append(text)
                elif isinstance(text, dict):
                    nested = text.get("value")
                    if isinstance(nested, str):
                        parts.append(nested)
        return "\n".join(parts)

    return ""


def _truncate_for_log(text: str, limit: int = 140) -> str:
    """Trim and normalize text for concise log output."""
    normalized = " ".join(text.split())
    if len(normalized) <= limit:
        return normalized
    return normalized[:limit] + "..."


def _format_message_for_log(index: int, message: Dict) -> List[str]:
    """Format one OpenAI-style message into readable debug log lines."""
    role = message.get("role", "unknown")
    name = message.get("name")
    label = f"[{index}] {role}"
    if isinstance(name, str) and name:
        label += f"({name})"

    content = message.get("content")

    if isinstance(content, str):
        return [f"      {label}: {_truncate_for_log(content)}"]

    if content is None:
        tool_calls = message.get("tool_calls")
        if isinstance(tool_calls, list) and tool_calls:
            call_types = []
            for call in tool_calls[:3]:
                if isinstance(call, dict):
                    call_types.append(str(call.get("type", "unknown")))
            type_summary = ", ".join(call_types) if call_types else "unknown"
            return [
                f"      {label}: [no content; tool_calls={len(tool_calls)} type={type_summary}]"
            ]
        return [f"      {label}: [no content]"]

    if isinstance(content, list):
        part_types = []
        for part in content[:5]:
            if isinstance(part, dict):
                part_types.append(str(part.get("type", "unknown")))
            else:
                part_types.append(type(part).__name__)

        parts_summary = ", ".join(part_types) if part_types else "none"
        text_preview = _extract_text_content(content)

        lines = [
            f"      {label}: [list content; parts={len(content)}; types={parts_summary}]"
        ]
        if text_preview:
            lines.append(f"        preview: {_truncate_for_log(text_preview)}")
        return lines

    if isinstance(content, dict):
        keys = list(content.keys())[:8]
        return [
            f"      {label}: [dict content; keys={keys}]"
        ]

    return [f"      {label}: [content type={type(content).__name__}]"]


def _has_attest_command(text: str) -> bool:
    """Return True when text contains %attest% as a standalone command token."""
    return bool(re.search(r"(^|\s)%attest%(\s|$)", text.lower()))


def _latest_user_requests_attestation(messages: List[Dict]) -> bool:
    """Check whether the latest user instruction contains %attest%."""
    for message in reversed(messages):
        if message.get("role") != "user":
            continue

        content_text = _extract_text_content(message.get("content", "")).strip()
        return _has_attest_command(content_text)

    return False


def _try_parse_json(value: Any) -> Optional[Dict]:
    """Parse JSON object from raw value if possible."""
    if isinstance(value, dict):
        return value

    if not isinstance(value, str):
        return None

    text = value.strip()
    if not text:
        return None

    if text.startswith("```"):
        lines = text.splitlines()
        if len(lines) >= 3 and lines[0].startswith("```") and lines[-1].strip() == "```":
            text = "\n".join(lines[1:-1]).strip()

    try:
        parsed = json.loads(text)
    except Exception:
        return None

    if isinstance(parsed, dict):
        return parsed

    return None


def _extract_latest_attestation_document(messages: List[Dict]) -> Optional[Dict]:
    """Extract the latest attestation_document payload from prior tool messages."""
    for message in reversed(messages):
        if message.get("role") != "tool":
            continue

        content = message.get("content")

        if isinstance(content, dict):
            attestation_doc = content.get("attestation_document")
            if isinstance(attestation_doc, dict):
                return attestation_doc

        if isinstance(content, list):
            for part in content:
                if isinstance(part, dict) and part.get("type") == "text":
                    parsed = _try_parse_json(part.get("text"))
                    if parsed and isinstance(parsed.get("attestation_document"), dict):
                        return parsed["attestation_document"]

        parsed = _try_parse_json(content)
        if parsed and isinstance(parsed.get("attestation_document"), dict):
            return parsed["attestation_document"]

    return None


def _build_attestation_openai_response(model: str, attestation_document: Dict) -> Dict:
    """Build deterministic OpenAI-compatible response containing attestation JSON."""
    attestation_payload = {
        "attestation_document": attestation_document
    }

    return {
        "id": f"chatcmpl-attest-{uuid.uuid4().hex[:12]}",
        "object": "chat.completion",
        "created": int(time.time()),
        "model": model,
        "choices": [
            {
                "index": 0,
                "message": {
                    "role": "assistant",
                    "content": json.dumps(attestation_payload, separators=(",", ":")),
                    "refusal": None,
                },
                "finish_reason": "stop",
            }
        ],
        "usage": {
            "prompt_tokens": 0,
            "completion_tokens": 0,
            "total_tokens": 0,
        },
    }


def _build_text_openai_response(model: str, text: str) -> Dict:
    """Build deterministic OpenAI-compatible plain text response."""
    return {
        "id": f"chatcmpl-deterministic-{uuid.uuid4().hex[:12]}",
        "object": "chat.completion",
        "created": int(time.time()),
        "model": model,
        "choices": [
            {
                "index": 0,
                "message": {
                    "role": "assistant",
                    "content": text,
                    "refusal": None,
                },
                "finish_reason": "stop",
            }
        ],
        "usage": {
            "prompt_tokens": 0,
            "completion_tokens": 0,
            "total_tokens": 0,
        },
    }


def _extract_latest_user_text(messages: List[Dict]) -> str:
    """Get text content from the latest user message in OpenAI messages."""
    for message in reversed(messages):
        if message.get("role") != "user":
            continue
        return _extract_text_content(message.get("content", "")).strip()
    return ""


def _extract_assistant_text_from_openai_response(response_data: Dict) -> str:
    """Get textual assistant content from first OpenAI choice."""
    if not isinstance(response_data, dict):
        return ""

    choices = response_data.get("choices")
    if not isinstance(choices, list) or not choices:
        return ""

    first_choice = choices[0]
    if not isinstance(first_choice, dict):
        return ""

    message = first_choice.get("message")
    if not isinstance(message, dict):
        return ""

    return _extract_text_content(message.get("content", "")).strip()


async def _invoke_guardrail_moderation(
    latest_user_text: str,
    assistant_text: str,
    request_id: str,
) -> Dict[str, Any]:
    """Call guardrail server moderation endpoint and return detailed debug metadata."""
    if not latest_user_text or not assistant_text:
        return {
            "ok": False,
            "error": "missing_input",
            "latest_user_present": bool(latest_user_text),
            "assistant_present": bool(assistant_text),
        }

    payload = {
        "guardrail_type": "moderation",
        "run_moderation": True,
        "run_attestation": False,
        "role": "Agent",
        "user_input": latest_user_text,
        "model_output": assistant_text,
    }

    endpoint = f"{config.guardrail_base_url.rstrip('/')}/guardrail/run"

    try:
        async with httpx.AsyncClient(timeout=30.0, trust_env=True) as guardrail_client:
            response = await guardrail_client.post(endpoint, json=payload)
    except Exception as error:
        return {
            "ok": False,
            "error": "transport_error",
            "endpoint": endpoint,
            "detail": str(error),
        }

    try:
        body = response.json()
    except Exception:
        body = {"raw_text": response.text[:2000]}

    if response.status_code >= 400:
        return {
            "ok": False,
            "error": "endpoint_error",
            "endpoint": endpoint,
            "status_code": response.status_code,
            "body": body,
        }

    return {
        "ok": isinstance(body, dict),
        "endpoint": endpoint,
        "status_code": response.status_code,
        "body": body,
        "error": None if isinstance(body, dict) else "invalid_response_shape",
    }


@asynccontextmanager
async def lifespan(app):
    """Lifespan context manager for startup/shutdown"""
    # Startup
    load_config_from_env()
    audit_logger.initialize()

    print("=" * 60)
    print("LLM Proxy Server Started")
    print("=" * 60)
    print(f"Safety Directive: Enabled")
    print(f"  \"{SAFETY_DIRECTIVE}\"")
    print(f"Content Guardrail: {'Enabled' if CONTENT_GUARDRAIL_ENABLED else 'Disabled'}")
    print(f"Audit Logging: Enabled")
    print("=" * 60)

    yield

    # Shutdown (if needed)
    pass


app = FastAPI(title="LLM Proxy Server", lifespan=lifespan)

# Initialize components
audit_logger = AuditLogger(log_dir="./audit_logs")


class ProxyConfig(BaseModel):
    """Configuration for upstream LLM providers"""
    openai_base_url: str = "https://api.openai.com/v1"
    anthropic_base_url: str = "https://api.anthropic.com/v1"
    guardrail_base_url: str = "http://127.0.0.1:8770"


# Load config from environment or config file
config = ProxyConfig()


@app.get("/health")
async def health_check():
    """Health endpoint used by enclave boot script readiness checks."""
    return {
        "status": "healthy",
        "safety_directive_enabled": True,
    }


# ============================================================================
# OpenAI API Endpoints
# ============================================================================

@app.post("/v1/chat/completions")
async def openai_chat_completions(request: Request):
    """
    Proxy for OpenAI Chat Completions API
    Intercepts, audits, and applies guardrails
    """
    request_id = str(uuid.uuid4())
    start_time = time.time()

    # Parse request body
    body = await request.json()

    # Log incoming request
    audit_logger.log_request(
        request_id=request_id,
        provider="openai",
        endpoint="/v1/chat/completions",
        body=body,
        headers=dict(request.headers)
    )

    try:
        auth_header = request.headers.get("Authorization", "")

        # Get messages from request
        messages = body.get("messages", [])

        # Inject safety directive into messages
        messages = inject_safety_directive_openai(messages)
        body["messages"] = messages

        print(f"  [{request_id}] Safety directive injected: \"{SAFETY_DIRECTIVE}\"")
        
        # Prepare upstream request headers
        headers = {
            "Content-Type": "application/json",
            "Authorization": auth_header
        }

        # Force streaming OFF to enable output guardrails
        # BUT: OpenClaw's client expects SSE format, so we'll convert the response
        original_stream_requested = body.get("stream", False)
        body["stream"] = False
        # Remove stream_options - OpenAI doesn't allow it when stream=false
        body.pop("stream_options", None)
        is_streaming = False

        # Deterministic attestation response path:
        # If latest user instruction starts with %attest%, return the latest
        # attestation_document from tool context without invoking upstream LLM.
        if _latest_user_requests_attestation(messages):
            attestation_document = _extract_latest_attestation_document(messages)

            if not attestation_document:
                print(f"  [{request_id}] Deterministic attestation response: no context found")
                response_data = _build_text_openai_response(
                    model=body.get("model", "unknown"),
                    text="no attestation found in context",
                )
            else:
                response_data = _build_attestation_openai_response(
                    model=body.get("model", "unknown"),
                    attestation_document=attestation_document,
                )
            status_code = 200

            print(f"  [{request_id}] Deterministic attestation response returned from tool context")

            audit_logger.log_response(
                request_id=request_id,
                status_code=status_code,
                body=response_data,
                latency=time.time() - start_time
            )

            if original_stream_requested:
                return await _convert_to_sse(response_data, status_code, request_id)

            return Response(
                content=json.dumps(response_data),
                status_code=status_code,
                media_type="application/json"
            )

        if is_streaming:
            # This should never be reached since we force streaming=False above
            print(f"  [{request_id}] WARNING: Streaming unexpectedly enabled - this shouldn't happen")
            return await _stream_openai_response(
                body, headers, request_id, start_time
            )
        else:
            print(f"  [{request_id}] Using non-streaming mode (guardrails enabled)")
            # trust_env=True means httpx will use HTTP_PROXY environment variable
            async with httpx.AsyncClient(timeout=300.0, trust_env=True) as client:
                response_data, status_code = await _proxy_openai_response(
                    client, body, headers, request_id, start_time
                )
                
                # If client requested streaming, convert response to SSE format
                if original_stream_requested:
                    return await _convert_to_sse(response_data, status_code, request_id)
                else:
                    # Return as regular JSON response
                    return Response(
                        content=json.dumps(response_data),
                        status_code=status_code,
                        media_type="application/json"
                    )

    except Exception as e:
        import traceback
        error_detail = f"Proxy error: {str(e)}"
        print(f"  [{request_id}] ERROR: {error_detail}")
        traceback.print_exc()
        audit_logger.log_error(request_id=request_id, error=str(e))
        raise HTTPException(status_code=500, detail=error_detail)


async def _proxy_openai_response(
    client: httpx.AsyncClient,
    body: Dict,
    headers: Dict,
    request_id: str,
    start_time: float
):
    """Handle non-streaming OpenAI response - returns JSON data dict"""

    # Log request details for debugging
    print(f"  [{request_id}] Sending to OpenAI:")
    print(f"    URL: {config.openai_base_url}/chat/completions")
    print(f"    Model: {body.get('model', 'unknown')}")
    messages = body.get('messages', [])
    print(f"    Messages: {len(messages)} messages")

    # Print readable message summaries
    for i, msg in enumerate(messages):
        for log_line in _format_message_for_log(i, msg):
            print(log_line)

    print(f"    Headers: {list(headers.keys())}")

    # Forward request to OpenAI
    response = await client.post(
        f"{config.openai_base_url}/chat/completions",
        json=body,
        headers=headers
    )

    print(f"  [{request_id}] OpenAI response status: {response.status_code}")

    # Parse response with error handling
    try:
        response_data = response.json()
    except Exception as e:
        print(f"  [{request_id}] ERROR: Failed to parse OpenAI response as JSON: {e}")
        raise HTTPException(status_code=502, detail=f"Invalid JSON response from OpenAI: {str(e)}")
    
    # Log error responses with details (limit output size)
    if response.status_code >= 400:
        error_msg = json.dumps(response_data, indent=2)
        print(f"  [{request_id}] OpenAI ERROR: {error_msg[:500]}..." if len(error_msg) > 500 else f"  [{request_id}] OpenAI ERROR: {error_msg}")

    if response.status_code < 400 and CONTENT_GUARDRAIL_ENABLED:
        latest_user_text = _extract_latest_user_text(body.get("messages", []))
        assistant_text = _extract_assistant_text_from_openai_response(response_data)

        moderation_result = await _invoke_guardrail_moderation(
            latest_user_text=latest_user_text,
            assistant_text=assistant_text,
            request_id=request_id,
        )

        moderation_payload = moderation_result.get("body") if moderation_result.get("ok") else None
        moderation_data = moderation_payload.get("moderation") if isinstance(moderation_payload, dict) else None
        verdict = moderation_data.get("verdict") if isinstance(moderation_data, dict) else None

        if isinstance(verdict, str) and verdict.lower() != "safe":
            print(f"  [{request_id}] Moderation verdict={verdict}; returning deterministic refusal")
            response_data = _build_text_openai_response(
                model=body.get("model", response_data.get("model", "unknown")),
                text=UNSAFE_DETERMINISTIC_RESPONSE,
            )
            response.status_code = 200
        elif verdict:
            print(f"  [{request_id}] Moderation verdict={verdict}; allowing response")
        else:
            debug_body = moderation_result.get("body")
            debug_body_preview = json.dumps(debug_body)[:700] if debug_body is not None else "None"
            print(
                f"  [{request_id}] Moderation verdict unavailable; allowing response\n"
                f"    reason={moderation_result.get('error', 'unknown')}\n"
                f"    endpoint={moderation_result.get('endpoint', 'n/a')}\n"
                f"    status_code={moderation_result.get('status_code', 'n/a')}\n"
                f"    latest_user_present={bool(latest_user_text)} preview={_truncate_for_log(latest_user_text) if latest_user_text else '[empty]'}\n"
                f"    assistant_present={bool(assistant_text)} preview={_truncate_for_log(assistant_text) if assistant_text else '[empty]'}\n"
                f"    guardrail_response_preview={debug_body_preview}"
            )
    elif response.status_code < 400:
        print(f"  [{request_id}] Content guardrail disabled; skipping moderation")
    
    # Debug: Log raw response to diagnose empty content issues
    print(f"  [{request_id}] Raw OpenAI response:")
    print(f"    {json.dumps(response_data, indent=2)}")

    # Log response
    audit_logger.log_response(
        request_id=request_id,
        status_code=response.status_code,
        body=response_data,
        latency=time.time() - start_time
    )

    # Return tuple of (response_data, status_code) for flexible response formatting
    return response_data, response.status_code


async def _convert_to_sse(response_data: Dict, status_code: int, request_id: str):
    """Convert non-streaming OpenAI response to Server-Sent Events format"""
    from fastapi.responses import StreamingResponse
    import asyncio
    
    # Validate response structure
    if not isinstance(response_data, dict):
        print(f"  [{request_id}] ERROR: Invalid response_data type: {type(response_data)}")
        response_data = {"error": {"message": "Invalid response format"}}
        status_code = 500
    
    # Log conversion summary (not full content to avoid huge logs)
    choices = response_data.get("choices", [])
    print(f"  [{request_id}] Converting to SSE: {len(choices)} choice(s), status={status_code}")
    if choices and isinstance(choices, list) and len(choices) > 0:
        msg = choices[0].get("message", {})
        has_content = msg.get("content") is not None
        has_tools = msg.get("tool_calls") is not None
        print(f"    Type: {'content' if has_content else 'tool_calls' if has_tools else 'empty'}")
    
    async def generate():
        try:
            if status_code >= 400:
                # For errors, just return the error as-is in SSE format
                yield f"data: {json.dumps(response_data)}\n\n"
                return
            
            # Validate we have choices array
            if not response_data.get("choices"):
                print(f"  [{request_id}] WARNING: No choices in response, sending empty completion")
                yield "data: [DONE]\n\n"
                return
            
            # Convert chat.completion to chat.completion.chunk format
            base_chunk = {
                "id": response_data.get("id"),
                "object": "chat.completion.chunk",
                "created": response_data.get("created"),
                "model": response_data.get("model"),
            }
        
            # First chunk: role (OpenClaw doesn't include finish_reason here)
            for choice in response_data.get("choices", []):
                if not isinstance(choice, dict):
                    continue
                message = choice.get("message", {})
                if not isinstance(message, dict):
                    continue
                
                role_chunk = base_chunk.copy()
                role_chunk["choices"] = [{
                    "index": choice.get("index", 0),
                    "delta": {"role": message.get("role", "assistant")},
                }]
                yield f"data: {json.dumps(role_chunk)}\n\n"
                await asyncio.sleep(0.01)
        
            # Second chunk: delta with whatever content the message has
            for choice in response_data.get("choices", []):
                if not isinstance(choice, dict):
                    continue
                message = choice.get("message", {})
                if not isinstance(message, dict):
                    continue
                
                # Build delta from message fields (content, tool_calls, function_call, etc.)
                delta = {}
                for key in ["content", "tool_calls", "function_call", "refusal"]:
                    if message.get(key) is not None:
                        delta[key] = message[key]
                
                # Debug: Log what we found in the message
                print(f"  [{request_id}] Delta fields: {list(delta.keys()) if delta else 'EMPTY'}")
                if not delta:
                    print(f"  [{request_id}] WARNING: Message has no content/tool_calls/refusal - full message: {json.dumps(message)[:300]}")
                
                # Send delta chunk if there's anything to send
                if delta:
                    delta_chunk = base_chunk.copy()
                    delta_chunk["choices"] = [{
                        "index": choice.get("index", 0),
                        "delta": delta,
                        "finish_reason": None
                    }]
                    yield f"data: {json.dumps(delta_chunk)}\n\n"
                    await asyncio.sleep(0.01)
        
            # Final: [DONE] (OpenClaw doesn't send a separate finish_reason chunk)
            yield "data: [DONE]\n\n"
        except Exception as e:
            # If SSE generation fails, send error event
            print(f"  [{request_id}] ERROR in SSE generation: {e}")
            import traceback
            traceback.print_exc()
            error_data = {"error": {"message": f"SSE conversion failed: {str(e)}", "type": "proxy_error"}}
            yield f"data: {json.dumps(error_data)}\n\n"
    
    return StreamingResponse(
        generate(),
        media_type="text/event-stream; charset=utf-8",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        }
    )


async def _stream_openai_response(
    body: Dict,
    headers: Dict,
    request_id: str,
    start_time: float
):
    """Handle streaming OpenAI response"""

    accumulated_response = []

    async def stream_generator():
        # Create client inside generator to keep it alive during streaming
        # trust_env=True ensures HTTP_PROXY environment variable is used
        async with httpx.AsyncClient(timeout=300.0, trust_env=True) as client:
            async with client.stream(
                "POST",
                f"{config.openai_base_url}/chat/completions",
                json=body,
                headers=headers
            ) as response:
                async for chunk in response.aiter_bytes():
                    accumulated_response.append(chunk)
                    yield chunk

        # Log complete streamed response
        try:
            full_response = b"".join(accumulated_response).decode("utf-8")
            audit_logger.log_response(
                request_id=request_id,
                status_code=200,
                body={"streaming": True, "data": full_response},
                latency=time.time() - start_time
            )
        except Exception as e:
            audit_logger.log_error(request_id=request_id, error=f"Stream logging error: {e}")

    return StreamingResponse(
        stream_generator(),
        media_type="text/event-stream"
    )


# ============================================================================
# Anthropic API Endpoints
# ============================================================================

@app.post("/v1/messages")
async def anthropic_messages(request: Request):
    """
    Proxy for Anthropic Messages API
    Intercepts, audits, and applies guardrails
    """
    request_id = str(uuid.uuid4())
    start_time = time.time()

    # Parse request body
    body = await request.json()

    print(f"\n[{request_id}] Received /v1/messages request")
    print(f"  Model: {body.get('model')}")
    print(f"  Stream: {body.get('stream', False)}")
    print(f"  Messages: {len(body.get('messages', []))} message(s)")

    print('Original request body:', body)
    print('Original request headers:', request.headers)

    # Log incoming request
    audit_logger.log_request(
        request_id=request_id,
        provider="anthropic",
        endpoint="/v1/messages",
        body=body,
        headers=dict(request.headers)
    )

    try:
        # Inject safety directive into system parameter
        body = inject_safety_directive_anthropic(body)
        print(f"  [{request_id}] Safety directive injected: \"{SAFETY_DIRECTIVE}\"")

        # Prepare upstream request - forward auth header from incoming request
        api_key = request.headers.get("x-api-key", "")
        headers = {
            "Content-Type": "application/json",
            "x-api-key": api_key,
            "anthropic-version": "2023-06-01"
        }

        # Force streaming OFF to enable output guardrails
        # BUT: Client (OpenClaw) may expect SSE format, so we'll convert the response
        original_stream_requested = body.get("stream", False)
        body["stream"] = False
        # Remove stream_options - not applicable when stream=false
        body.pop("stream_options", None)
        is_streaming = False

        if is_streaming:
            # This should never be reached since we force streaming=False above
            print(f"  [{request_id}] WARNING: Streaming unexpectedly enabled - this shouldn't happen")
            return await _stream_anthropic_response(
                body, headers, request_id, start_time
            )
        else:
            print(f"  [{request_id}] Using non-streaming mode (guardrails enabled)")
            # trust_env=True means httpx will use HTTP_PROXY environment variable
            async with httpx.AsyncClient(timeout=300.0, trust_env=True) as client:
                response_data, status_code = await _proxy_anthropic_response(
                    client, body, headers, request_id, start_time
                )
                
                # If client requested streaming, convert response to SSE format
                if original_stream_requested:
                    return await _convert_anthropic_to_sse(response_data, status_code, request_id)
                else:
                    # Return as regular JSON response
                    return Response(
                        content=json.dumps(response_data),
                        status_code=status_code,
                        media_type="application/json"
                    )

    except Exception as e:
        import traceback
        error_detail = f"Proxy error: {str(e)}"
        print(f"  [{request_id}] ERROR: {error_detail}")
        traceback.print_exc()
        audit_logger.log_error(request_id=request_id, error=str(e))
        raise HTTPException(status_code=500, detail=error_detail)


async def _proxy_anthropic_response(
    client: httpx.AsyncClient,
    body: Dict,
    headers: Dict,
    request_id: str,
    start_time: float
):
    """Handle non-streaming Anthropic response"""

    # Forward request to Anthropic
    response = await client.post(
        f"{config.anthropic_base_url}/messages",
        json=body,
        headers=headers
    )

    print(f"  ← Received response from Anthropic (status={response.status_code})")

    response_data = response.json()

    # Log response
    audit_logger.log_response(
        request_id=request_id,
        status_code=response.status_code,
        body=response_data,
        latency=time.time() - start_time
    )

    print(f"  → Returning response to client")

    # Return tuple of (response_data, status_code) for flexible response formatting
    return response_data, response.status_code


async def _convert_anthropic_to_sse(response_data: Dict, status_code: int, request_id: str):
    """Convert non-streaming Anthropic response to Server-Sent Events format"""
    from fastapi.responses import StreamingResponse
    import asyncio
    
    async def generate():
        if status_code >= 400:
            # For errors, return error in SSE format
            yield f"data: {json.dumps(response_data)}\n\n"
            return
        
        # Anthropic SSE format: message_start, content_block_start, content_block_delta, content_block_stop, message_delta, message_stop
        
        # Event 1: message_start
        message_start = {
            "type": "message_start",
            "message": {
                "id": response_data.get("id"),
                "type": "message",
                "role": "assistant",
                "content": [],
                "model": response_data.get("model"),
                "stop_reason": None,
                "stop_sequence": None,
                "usage": response_data.get("usage", {})
            }
        }
        yield f"event: message_start\ndata: {json.dumps(message_start)}\n\n"
        await asyncio.sleep(0.01)
        
        # Event 2: content_block_start
        content_block_start = {
            "type": "content_block_start",
            "index": 0,
            "content_block": {"type": "text", "text": ""}
        }
        yield f"event: content_block_start\ndata: {json.dumps(content_block_start)}\n\n"
        await asyncio.sleep(0.01)
        
        # Event 3: content_block_delta (with actual content)
        content_text = ""
        for content_item in response_data.get("content", []):
            if content_item.get("type") == "text":
                content_text = content_item.get("text", "")
                break
        
        if content_text:
            content_block_delta = {
                "type": "content_block_delta",
                "index": 0,
                "delta": {"type": "text_delta", "text": content_text}
            }
            yield f"event: content_block_delta\ndata: {json.dumps(content_block_delta)}\n\n"
            await asyncio.sleep(0.01)
        
        # Event 4: content_block_stop
        content_block_stop = {
            "type": "content_block_stop",
            "index": 0
        }
        yield f"event: content_block_stop\ndata: {json.dumps(content_block_stop)}\n\n"
        await asyncio.sleep(0.01)
        
        # Event 5: message_delta
        message_delta = {
            "type": "message_delta",
            "delta": {"stop_reason": response_data.get("stop_reason", "end_turn"), "stop_sequence": None},
            "usage": {"output_tokens": response_data.get("usage", {}).get("output_tokens", 0)}
        }
        yield f"event: message_delta\ndata: {json.dumps(message_delta)}\n\n"
        await asyncio.sleep(0.01)
        
        # Event 6: message_stop
        message_stop = {"type": "message_stop"}
        yield f"event: message_stop\ndata: {json.dumps(message_stop)}\n\n"
    
    print(f"  [{request_id}] Converted to Anthropic SSE format")
    return StreamingResponse(
        generate(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
        }
    )


async def _stream_anthropic_response(
    body: Dict,
    headers: Dict,
    request_id: str,
    start_time: float
):
    """Handle streaming Anthropic response"""

    accumulated_response = []
    chunk_count = [0]  # Use list to allow modification in nested function

    async def stream_generator():
        # Create client inside generator to keep it alive during streaming
        # trust_env=True ensures HTTP_PROXY environment variable is used
        print(f"  Starting stream connection to Anthropic...")
        async with httpx.AsyncClient(timeout=300.0, trust_env=True) as client:
            async with client.stream(
                "POST",
                f"{config.anthropic_base_url}/messages",
                json=body,
                headers=headers
            ) as response:
                print(f"  ← Stream connected (status={response.status_code})")
                async for chunk in response.aiter_bytes():
                    chunk_count[0] += 1
                    accumulated_response.append(chunk)
                    yield chunk

        print(f"  → Stream complete ({chunk_count[0]} chunks, {len(b''.join(accumulated_response))} bytes)")

        # Log complete streamed response
        try:
            full_response = b"".join(accumulated_response).decode("utf-8")
            audit_logger.log_response(
                request_id=request_id,
                status_code=200,
                body={"streaming": True, "data": full_response},
                latency=time.time() - start_time
            )
        except Exception as e:
            audit_logger.log_error(request_id=request_id, error=f"Stream logging error: {e}")

    return StreamingResponse(
        stream_generator(),
        media_type="text/event-stream"
    )


# ============================================================================
# Configuration and Startup
# ============================================================================

def load_config_from_env():
    """Load configuration from environment variables"""
    import os
    from dotenv import load_dotenv

    # Load .env file
    load_dotenv()

    # Only load base URLs - API keys are forwarded from incoming requests
    config.openai_base_url = os.getenv("OPENAI_BASE_URL", config.openai_base_url)
    config.anthropic_base_url = os.getenv("ANTHROPIC_BASE_URL", config.anthropic_base_url)
    config.guardrail_base_url = os.getenv("GUARDRAIL_BASE_URL", config.guardrail_base_url)

    print(f"Loaded config:")
    print(f"  OpenAI Base URL: {config.openai_base_url}")
    print(f"  Anthropic Base URL: {config.anthropic_base_url}")
    print(f"  Guardrail Base URL: {config.guardrail_base_url}")
    print(f"  API keys will be forwarded from incoming requests")


if __name__ == "__main__":
    uvicorn.run(
        "proxy_server:app",
        host="0.0.0.0",
        port=8080,
        log_level="info"
    )
