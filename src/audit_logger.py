"""
Audit Logger for LLM Proxy

Logs all requests, responses, and policy violations with:
- Tamper-evident logging
- Structured JSON format
- Query capabilities for verification
"""

import json
import hashlib
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional
import threading


class AuditLogger:
    """
    Comprehensive audit logger for LLM proxy traffic

    Logs include:
    - Request ID and timestamp
    - Full request body (messages, parameters)
    - Full response body
    - Latency metrics
    - Policy violations
    - Chain of custody (hash chain)
    """

    def __init__(self, log_dir: str = "./audit_logs"):
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(parents=True, exist_ok=True)

        # Current log file
        self.current_log_file = None
        self.lock = threading.Lock()

        # Hash chain for tamper detection
        self.last_hash = "0" * 64  # Genesis hash

        # Statistics
        self.stats = {
            "total_requests": 0,
            "total_violations": 0,
            "total_errors": 0
        }

    def initialize(self):
        """Initialize logger and create new log file"""
        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        self.current_log_file = self.log_dir / f"audit_{timestamp}.jsonl"

        # Load last hash from previous log if exists
        self._load_last_hash()

        # Write initialization entry
        self._write_log_entry({
            "type": "initialization",
            "timestamp": datetime.utcnow().isoformat(),
            "log_file": str(self.current_log_file),
            "previous_hash": self.last_hash
        })

    def log_request(
        self,
        request_id: str,
        provider: str,
        endpoint: str,
        body: Dict[str, Any],
        headers: Dict[str, Any]
    ):
        """Log incoming LLM request"""

        # Sanitize headers (remove sensitive data)
        safe_headers = {k: v for k, v in headers.items()
                       if k.lower() not in ["authorization", "x-api-key"]}

        entry = {
            "type": "request",
            "request_id": request_id,
            "timestamp": datetime.utcnow().isoformat(),
            "provider": provider,
            "endpoint": endpoint,
            "body": body,
            "headers": safe_headers,
            "extracted_data": self._extract_request_data(body, provider)
        }

        self._write_log_entry(entry)
        self.stats["total_requests"] += 1

    def log_response(
        self,
        request_id: str,
        status_code: int,
        body: Dict[str, Any],
        latency: float
    ):
        """Log LLM response"""

        entry = {
            "type": "response",
            "request_id": request_id,
            "timestamp": datetime.utcnow().isoformat(),
            "status_code": status_code,
            "latency_seconds": latency,
            "body": body,
            "extracted_data": self._extract_response_data(body)
        }

        self._write_log_entry(entry)

    def log_violation(
        self,
        request_id: str,
        violation_type: str,
        details: Dict[str, Any]
    ):
        """Log policy violation"""

        entry = {
            "type": "violation",
            "request_id": request_id,
            "timestamp": datetime.utcnow().isoformat(),
            "violation_type": violation_type,
            "details": details,
            "severity": "high"
        }

        self._write_log_entry(entry)
        self.stats["total_violations"] += 1

    def log_error(self, request_id: str, error: str):
        """Log error"""

        entry = {
            "type": "error",
            "request_id": request_id,
            "timestamp": datetime.utcnow().isoformat(),
            "error": error
        }

        self._write_log_entry(entry)
        self.stats["total_errors"] += 1

    def _write_log_entry(self, entry: Dict[str, Any]):
        """Write log entry with hash chain"""

        with self.lock:
            # Add previous hash to entry
            entry["previous_hash"] = self.last_hash

            # Compute current hash
            entry_json = json.dumps(entry, sort_keys=True)
            current_hash = hashlib.sha256(entry_json.encode()).hexdigest()
            entry["hash"] = current_hash

            # Write to file
            with open(self.current_log_file, "a") as f:
                f.write(json.dumps(entry) + "\n")

            # Update last hash
            self.last_hash = current_hash

    def _extract_request_data(self, body: Dict, provider: str) -> Dict:
        """Extract key data from request for easier querying"""

        if provider == "openai":
            messages = body.get("messages", [])
            return {
                "model": body.get("model"),
                "message_count": len(messages),
                "last_user_message": self._get_last_user_message(messages),
                "temperature": body.get("temperature"),
                "max_tokens": body.get("max_tokens")
            }

        elif provider == "anthropic":
            messages = body.get("messages", [])
            return {
                "model": body.get("model"),
                "message_count": len(messages),
                "last_user_message": self._get_last_user_message(messages),
                "max_tokens": body.get("max_tokens"),
                "system_prompt": body.get("system", "")[:100]  # First 100 chars
            }

        return {}

    def _extract_response_data(self, body: Dict) -> Dict:
        """Extract key data from response"""

        # Handle OpenAI format
        if "choices" in body:
            content = body.get("choices", [{}])[0].get("message", {}).get("content") or ""
            return {
                "finish_reason": body.get("choices", [{}])[0].get("finish_reason"),
                "response_text": content[:200] if content else "",
                "usage": body.get("usage", {})
            }

        # Handle Anthropic format
        elif "content" in body:
            content = body.get("content", [])
            text_content = "".join([c.get("text", "") for c in content if c.get("type") == "text"])
            return {
                "stop_reason": body.get("stop_reason"),
                "response_text": text_content[:200],
                "usage": body.get("usage", {})
            }

        return {}

    def _get_last_user_message(self, messages: List[Dict]) -> str:
        """Extract last user message content"""
        for msg in reversed(messages):
            if msg.get("role") == "user":
                content = msg.get("content", "")
                if isinstance(content, str):
                    return content[:200]  # First 200 chars
                elif isinstance(content, list):
                    # Handle multi-modal content
                    text_parts = [c.get("text", "") for c in content if c.get("type") == "text"]
                    return " ".join(text_parts)[:200]
        return ""

    def _load_last_hash(self):
        """Load last hash from most recent log file"""
        log_files = sorted(self.log_dir.glob("audit_*.jsonl"))
        if log_files:
            latest_log = log_files[-1]
            try:
                with open(latest_log, "r") as f:
                    lines = f.readlines()
                    if lines:
                        last_entry = json.loads(lines[-1])
                        self.last_hash = last_entry.get("hash", self.last_hash)
            except Exception as e:
                print(f"Warning: Could not load last hash: {e}")

    def get_log_count(self) -> int:
        """Get total number of log entries"""
        return self.stats["total_requests"]

    def verify_log_integrity(self) -> bool:
        """
        Verify hash chain integrity
        Returns True if log has not been tampered with
        """
        if not self.current_log_file or not self.current_log_file.exists():
            return True

        try:
            with open(self.current_log_file, "r") as f:
                previous_hash = None
                for line in f:
                    entry = json.loads(line)

                    # Verify hash chain
                    if previous_hash is not None:
                        if entry.get("previous_hash") != previous_hash:
                            return False

                    # Verify entry hash
                    claimed_hash = entry.pop("hash")
                    entry_json = json.dumps(entry, sort_keys=True)
                    computed_hash = hashlib.sha256(entry_json.encode()).hexdigest()

                    if claimed_hash != computed_hash:
                        return False

                    previous_hash = claimed_hash

                return True

        except Exception as e:
            print(f"Error verifying log integrity: {e}")
            return False

    def export_audit_report(self, request_id: Optional[str] = None) -> List[Dict]:
        """
        Export audit logs for a specific request or all requests
        Useful for providing to service providers for verification
        """
        if not self.current_log_file or not self.current_log_file.exists():
            return []

        entries = []
        with open(self.current_log_file, "r") as f:
            for line in f:
                entry = json.loads(line)
                if request_id is None or entry.get("request_id") == request_id:
                    entries.append(entry)

        return entries
