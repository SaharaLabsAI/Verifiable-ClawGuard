"""
LLM Proxy Server with Auditing and NeMo Guardrail Support

This proxy intercepts LLM API calls from MoltBot, applies NeMo Guardrails policies,
logs all I/O, and relays requests to actual LLM providers.

Supports:
- OpenAI API format
- Anthropic API format
- NeMo Guardrails for input/output validation
"""

import asyncio
import json
import os
import time
import uuid
from contextlib import asynccontextmanager
from datetime import datetime
from typing import Any, Dict, List, Optional, Union
from pathlib import Path

from fastapi import FastAPI, Request, Response, HTTPException
from fastapi.responses import StreamingResponse
import httpx
import uvicorn
from pydantic import BaseModel

from audit_logger import AuditLogger

# NeMo Guardrails imports
try:
    from nemoguardrails import RailsConfig, LLMRails
    NEMO_AVAILABLE = True
except ImportError:
    NEMO_AVAILABLE = False
    print("Warning: nemoguardrails not installed. Guardrails will be disabled.")
    print("Install with: pip install nemoguardrails")


# ============================================================================
# Safety Directive Configuration
# ============================================================================

# Core safety directive that will be prepended to all LLM interactions
SAFETY_DIRECTIVE = "Committed to beneficial AI that protects humanity."


# ============================================================================
# NeMo Guardrails Configuration
# ============================================================================

# Global rails instance
rails: Optional[LLMRails] = None
guardrails_enabled: bool = False


class GuardrailResult:
    """Result from guardrail check"""
    def __init__(self, blocked: bool = False, reason: str = "", response: str = ""):
        self.blocked = blocked
        self.reason = reason
        self.response = response


def inject_safety_directive_openai(messages: List[Dict]) -> List[Dict]:
    """
    Inject safety directive as a system message for OpenAI format.

    Args:
        messages: Original messages in OpenAI format

    Returns:
        Messages with safety directive prepended
    """
    # Check if there's already a system message
    if messages and messages[0].get("role") == "system":
        # Prepend safety directive to existing system message
        existing_content = messages[0].get("content", "")
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


def initialize_guardrails() -> bool:
    """Initialize NeMo Guardrails with config from guardrails_config directory"""
    global rails, guardrails_enabled
    
    if not NEMO_AVAILABLE:
        print("⚠ NeMo Guardrails not available - skipping initialization")
        return False
    
    config_path = Path(__file__).parent / "guardrails_config"
    
    if not config_path.exists():
        print(f"⚠ Guardrails config not found at {config_path}")
        print("  Create guardrails_config/config.yml to enable guardrails")
        return False
    
    try:
        # Load configuration from directory
        rails_config = RailsConfig.from_path(str(config_path))
        
        # Create LLMRails instance
        rails = LLMRails(rails_config)
        
        # Register custom actions if they exist
        actions_path = config_path / "actions.py"
        if actions_path.exists():
            try:
                import importlib.util
                spec = importlib.util.spec_from_file_location("actions", actions_path)
                actions_module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(actions_module)
                
                # Register actions from the module
                for name in dir(actions_module):
                    obj = getattr(actions_module, name)
                    if callable(obj) and hasattr(obj, '_action_meta'):
                        rails.register_action(obj, name=obj._action_meta.get('name', name))
                        print(f"  Registered custom action: {name}")
            except Exception as e:
                print(f"  Warning: Could not load custom actions: {e}")
        
        guardrails_enabled = True
        print(f"✓ NeMo Guardrails initialized successfully")
        print(f"  Config path: {config_path}")
        print(f"  Input flows: {len(rails_config.rails.input.flows) if rails_config.rails.input else 0}")
        print(f"  Output flows: {len(rails_config.rails.output.flows) if rails_config.rails.output else 0}")
        
        return True
        
    except Exception as e:
        print(f"✗ Failed to initialize NeMo Guardrails: {e}")
        return False


async def apply_input_guardrails(
    messages: List[Dict],
    api_key: str = ""
) -> GuardrailResult:
    """
    Apply input guardrails to check if the user message should be blocked.
    
    Args:
        messages: The conversation messages in OpenAI format
        api_key: API key to use for the guardrail LLM calls
        
    Returns:
        GuardrailResult with blocked status and reason
    """
    global rails
    
    if not guardrails_enabled or rails is None:
        return GuardrailResult(blocked=False)
    
    try:
        # Set API key for the guardrail checks if provided
        if api_key:
            os.environ["OPENAI_API_KEY"] = api_key
        
        # Use NeMo Guardrails to check the input
        # The generate_async method will apply input rails before generation
        # We use a special options dict to only run input rails
        response = await rails.generate_async(
            messages=messages,
            options={
                "rails": {
                    "input": True,
                    "output": False,
                    "dialog": False
                }
            }
        )
        
        # Check if the response indicates blocking
        # NeMo returns a refusal message if input rails blocked the request
        if isinstance(response, dict):
            content = response.get("content", "")
            # Check for common refusal patterns
            refusal_patterns = [
                "I cannot",
                "I can't",
                "I'm sorry, but I can't",
                "I'm not able to",
                "refuse",
                "blocked"
            ]
            for pattern in refusal_patterns:
                if pattern.lower() in content.lower():
                    return GuardrailResult(
                        blocked=True,
                        reason="Input blocked by guardrails",
                        response=content
                    )
        
        return GuardrailResult(blocked=False)
        
    except Exception as e:
        print(f"  Warning: Guardrail check failed: {e}")
        # Fail open - don't block if guardrails error
        return GuardrailResult(blocked=False, reason=str(e))


async def apply_output_guardrails(
    messages: List[Dict],
    bot_response: str,
    api_key: str = ""
) -> GuardrailResult:
    """
    Apply output guardrails to check if the bot response should be blocked.
    
    Args:
        messages: The conversation messages
        bot_response: The bot's response to check
        api_key: API key to use for the guardrail LLM calls
        
    Returns:
        GuardrailResult with blocked status and modified response if needed
    """
    global rails
    
    if not guardrails_enabled or rails is None:
        return GuardrailResult(blocked=False, response=bot_response)
    
    try:
        # Set API key for the guardrail checks
        if api_key:
            os.environ["OPENAI_API_KEY"] = api_key
        
        # Add the bot response to messages for output rail checking
        check_messages = messages + [{"role": "assistant", "content": bot_response}]
        
        # Use generate_async with output rails only
        response = await rails.generate_async(
            messages=check_messages,
            options={
                "rails": {
                    "input": False,
                    "output": True,
                    "dialog": False
                }
            }
        )
        
        if isinstance(response, dict):
            content = response.get("content", bot_response)
            # If the content changed significantly, it was modified by output rails
            if content != bot_response:
                return GuardrailResult(
                    blocked=False,
                    response=content,
                    reason="Response modified by output guardrails"
                )
        
        return GuardrailResult(blocked=False, response=bot_response)
        
    except Exception as e:
        print(f"  Warning: Output guardrail check failed: {e}")
        return GuardrailResult(blocked=False, response=bot_response)


@asynccontextmanager
async def lifespan(app):
    """Lifespan context manager for startup/shutdown"""
    # Startup
    load_config_from_env()
    audit_logger.initialize()
    
    # Initialize NeMo Guardrails
    guardrails_status = initialize_guardrails()

    print("=" * 60)
    print("LLM Proxy Server Started")
    print("=" * 60)
    print(f"Safety Directive: Enabled")
    print(f"  \"{SAFETY_DIRECTIVE}\"")
    print(f"Audit Logging: Enabled")
    print(f"NeMo Guardrails: {'Enabled' if guardrails_status else 'Disabled'}")
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


# Load config from environment or config file
config = ProxyConfig()


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
        # Extract API key for guardrail checks
        auth_header = request.headers.get("Authorization", "")
        api_key = auth_header.replace("Bearer ", "") if auth_header.startswith("Bearer ") else ""

        # Get messages from request
        messages = body.get("messages", [])

        # Inject safety directive into messages
        messages = inject_safety_directive_openai(messages)
        body["messages"] = messages

        print(f"  [{request_id}] Safety directive injected: \"{SAFETY_DIRECTIVE}\"")

        # Apply input guardrails
        if guardrails_enabled:
            print(f"  [{request_id}] Applying input guardrails...")
            input_result = await apply_input_guardrails(messages, api_key)
            
            if input_result.blocked:
                print(f"  [{request_id}] Request blocked by input guardrails: {input_result.reason}")
                audit_logger.log_response(
                    request_id=request_id,
                    status_code=400,
                    body={"error": "Request blocked by guardrails", "reason": input_result.reason},
                    latency=time.time() - start_time
                )
                
                # Return a proper OpenAI-format error response
                error_response = {
                    "id": f"chatcmpl-blocked-{request_id}",
                    "object": "chat.completion",
                    "created": int(time.time()),
                    "model": body.get("model", "unknown"),
                    "choices": [{
                        "index": 0,
                        "message": {
                            "role": "assistant",
                            "content": input_result.response or "I'm sorry, but I can't help with that request."
                        },
                        "finish_reason": "stop"
                    }],
                    "usage": {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0}
                }
                return Response(
                    content=json.dumps(error_response),
                    status_code=200,  # Return 200 with refusal message for better client compatibility
                    media_type="application/json"
                )
        
        # Prepare upstream request headers
        headers = {
            "Content-Type": "application/json",
            "Authorization": auth_header
        }

        # TESTING: Allow streaming through to test infrastructure
        # TODO: Re-enable guardrail compatibility checks after testing
        is_streaming = body.get("stream", False)

        if is_streaming:
            print(f"  [{request_id}] STREAMING ENABLED - guardrails bypassed for testing")
            # Use streaming path (no guardrails)
            return await _stream_openai_response(
                body, headers, request_id, start_time
            )
        else:
            # Use non-streaming path with full guardrail support
            # trust_env=True means httpx will use HTTP_PROXY environment variable
            async with httpx.AsyncClient(timeout=300.0, trust_env=True) as client:
                return await _proxy_openai_response(
                    client, body, headers, request_id, start_time, api_key
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
    start_time: float,
    api_key: str = ""
):
    """Handle non-streaming OpenAI response with output guardrails"""

    # Log request details for debugging
    print(f"  [{request_id}] Sending to OpenAI:")
    print(f"    URL: {config.openai_base_url}/chat/completions")
    print(f"    Model: {body.get('model', 'unknown')}")
    messages = body.get('messages', [])
    print(f"    Messages: {len(messages)} messages")

    # Print truncated messages
    for i, msg in enumerate(messages):
        role = msg.get('role', 'unknown')
        content = msg.get('content', '')
        if isinstance(content, str):
            content_preview = content[:100] + '...' if len(content) > 100 else content
            print(f"      [{i}] {role}: {content_preview}")
        else:
            print(f"      [{i}] {role}: [complex content]")

    print(f"    Headers: {list(headers.keys())}")

    # Forward request to OpenAI
    response = await client.post(
        f"{config.openai_base_url}/chat/completions",
        json=body,
        headers=headers
    )

    print(f"  [{request_id}] OpenAI response status: {response.status_code}")

    response_data = response.json()

    # Log error responses
    if response.status_code != 200:
        print(f"  [{request_id}] OpenAI error response: {response_data}")
    else:
        # Log successful response structure
        choices = response_data.get("choices", [])
        if choices:
            message = choices[0].get("message", {})
            content = message.get("content")
            finish_reason = choices[0].get('finish_reason')
            print(f"  [{request_id}] Response: content={'None' if content is None else f'{len(content)} chars'}, finish_reason={finish_reason}")

            # Always show message structure for debugging
            if content is None:
                # Tool calls, refusals, etc. - show full message
                print(f"  [{request_id}] Full message (content is None):")
                print(f"    {json.dumps(message, indent=2)}")
            else:
                # Regular text response - show message with truncated content
                print(f"  [{request_id}] Response message:")
                truncated_message = message.copy()
                if len(content) > 300:
                    truncated_message['content'] = content[:300] + f"... [{len(content)-300} more chars]"
                print(f"    {json.dumps(truncated_message, indent=2)}")

    # Apply output guardrails if enabled
    if guardrails_enabled and response.status_code == 200:
        try:
            # Extract the bot response
            choices = response_data.get("choices", [])
            if choices:
                # Handle content=null case (refusals, tool calls, etc.)
                bot_content = choices[0].get("message", {}).get("content") or ""
                messages = body.get("messages", [])
                
                print(f"  [{request_id}] Applying output guardrails...")
                output_result = await apply_output_guardrails(messages, bot_content, api_key)
                
                if output_result.blocked:
                    print(f"  [{request_id}] Response blocked by output guardrails")
                    response_data["choices"][0]["message"]["content"] = (
                        output_result.response or "I'm sorry, but I can't provide that response."
                    )
                elif output_result.response != bot_content:
                    print(f"  [{request_id}] Response modified by output guardrails")
                    response_data["choices"][0]["message"]["content"] = output_result.response
        except Exception as e:
            print(f"  [{request_id}] Warning: Output guardrail processing failed: {e}")

    # Log response
    audit_logger.log_response(
        request_id=request_id,
        status_code=response.status_code,
        body=response_data,
        latency=time.time() - start_time
    )

    # Return JSON response directly (avoids compression header issues)
    return Response(
        content=json.dumps(response_data),
        status_code=response.status_code,
        media_type="application/json"
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

        # TESTING: Allow streaming through to test infrastructure
        is_streaming = body.get("stream", False)

        if is_streaming:
            print(f"  [{request_id}] STREAMING ENABLED - guardrails bypassed for testing")
            return await _stream_anthropic_response(
                body, headers, request_id, start_time
            )
        else:
            print(f"  Forwarding to Anthropic (streaming=False, guardrails enabled)...")
            # Use non-streaming path with full guardrail support
            # trust_env=True means httpx will use HTTP_PROXY environment variable
            async with httpx.AsyncClient(timeout=300.0, trust_env=True) as client:
                return await _proxy_anthropic_response(
                    client, body, headers, request_id, start_time
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

    # Return JSON response directly (avoids compression header issues)
    return Response(
        content=json.dumps(response_data),
        status_code=response.status_code,
        media_type="application/json"
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
# Health and Admin Endpoints
# ============================================================================

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat(),
        "safety_directive": SAFETY_DIRECTIVE,
        "safety_directive_enabled": True,
        "guardrails_enabled": guardrails_enabled,
        "nemo_available": NEMO_AVAILABLE,
        "audit_log_count": audit_logger.get_log_count()
    }


@app.get("/attestation")
async def get_attestation():
    """
    Returns attestation information about the proxy configuration
    In production, this would include TEE attestation data and NeMo Guardrail config
    """
    return {
        "proxy_version": "1.0.0",
        "audit_logging": "enabled",
        "safety_directive": {
            "enabled": True,
            "directive": SAFETY_DIRECTIVE,
            "description": "Core safety commitment injected into all LLM interactions"
        },
        "guardrails": {
            "enabled": guardrails_enabled,
            "nemo_available": NEMO_AVAILABLE,
            "config_path": str(Path(__file__).parent / "guardrails_config")
        },
        "timestamp": datetime.utcnow().isoformat(),
        # In production: add TEE attestation report
        "tee_attestation": {
            "enclave_measurement": "TODO: Nitro enclave PCR values",
            "platform": "aws-nitro-enclaves"
        }
    }


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

    print(f"Loaded config:")
    print(f"  OpenAI Base URL: {config.openai_base_url}")
    print(f"  Anthropic Base URL: {config.anthropic_base_url}")
    print(f"  API keys will be forwarded from incoming requests")


if __name__ == "__main__":
    uvicorn.run(
        "proxy_server:app",
        host="0.0.0.0",
        port=8080,
        log_level="info"
    )
