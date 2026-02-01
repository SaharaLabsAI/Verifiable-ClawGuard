"""
Guardrail Policy Engine

Enforces policies on LLM requests and responses:
- Content filtering (PII, sensitive data)
- Rate limiting
- Token usage limits
- Prompt injection detection
- Data usage restrictions
"""

import json
import hashlib
import re
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional
from pathlib import Path
from collections import defaultdict


class PolicyViolation(Exception):
    """Raised when a policy is violated"""

    def __init__(self, violation_type: str, details: Dict[str, Any]):
        self.violation_type = violation_type
        self.details = details
        super().__init__(f"Policy violation: {violation_type}")


class GuardrailPolicy:
    """
    Policy engine that validates LLM requests and responses
    against configured rules
    """

    def __init__(self, config_path: str = "./policy_config.json"):
        self.config_path = Path(config_path)
        self.policy_config = {}
        self.version = "1.0.0"

        # Rate limiting state
        self.rate_limit_state = defaultdict(list)

        # Token usage tracking
        self.token_usage = defaultdict(int)

    def load_policy(self):
        """Load policy configuration from file"""
        if self.config_path.exists():
            with open(self.config_path, "r") as f:
                self.policy_config = json.load(f)
        else:
            # Create default policy
            self.policy_config = self._get_default_policy()
            self._save_policy()

        print(f"Loaded policy configuration: {self.get_policy_hash()}")

    def _get_default_policy(self) -> Dict:
        """Return default policy configuration"""
        return {
            "version": self.version,
            "rules": {
                "pii_detection": {
                    "enabled": True,
                    "block_ssn": True,
                    "block_credit_card": True,
                    "block_email": False,
                    "block_phone": False
                },
                "content_filtering": {
                    "enabled": True,
                    "blocked_patterns": [
                        # Add regex patterns for content to block
                        "(?i)(password|secret|api[_-]?key)\\s*[:=]\\s*['\"]?[a-zA-Z0-9]{8,}",
                    ]
                },
                "rate_limiting": {
                    "enabled": True,
                    "requests_per_minute": 60,
                    "requests_per_hour": 1000
                },
                "token_limits": {
                    "enabled": True,
                    "max_tokens_per_request": 16000,
                    "max_tokens_per_day": 1000000
                },
                "prompt_injection": {
                    "enabled": True,
                    "detect_system_prompt_leakage": True,
                    "detect_jailbreak_attempts": True
                },
                "data_usage": {
                    "enabled": True,
                    "allowed_domains": [],  # Empty = allow all
                    "blocked_domains": ["internal.company.com"],
                    "require_user_consent": True
                }
            }
        }

    def _save_policy(self):
        """Save policy configuration to file"""
        with open(self.config_path, "w") as f:
            json.dump(self.policy_config, f, indent=2)

    def get_policy_hash(self) -> str:
        """Get hash of current policy configuration"""
        policy_json = json.dumps(self.policy_config, sort_keys=True)
        return hashlib.sha256(policy_json.encode()).hexdigest()

    def get_public_config(self) -> Dict:
        """Get public policy configuration (for attestation)"""
        return {
            "version": self.version,
            "enabled_rules": [
                rule_name for rule_name, rule_config in self.policy_config.get("rules", {}).items()
                if rule_config.get("enabled", False)
            ],
            "policy_hash": self.get_policy_hash()
        }

    # ========================================================================
    # Request Validation
    # ========================================================================

    def validate_request(self, body: Dict[str, Any], provider: str):
        """
        Validate incoming request against all policies
        Raises PolicyViolation if any rule is violated
        """

        # Extract messages
        messages = self._extract_messages(body, provider)

        # Check rate limiting
        self._check_rate_limit()

        # Check token limits
        self._check_token_limit(body.get("max_tokens", 0))

        # Check content filtering
        self._check_content_filtering(messages)

        # Check PII detection
        self._check_pii_detection(messages)

        # Check prompt injection
        self._check_prompt_injection(messages)

    def _extract_messages(self, body: Dict, provider: str) -> List[str]:
        """Extract text content from messages"""
        messages = []

        if provider == "openai" or provider == "anthropic":
            for msg in body.get("messages", []):
                content = msg.get("content", "")
                if isinstance(content, str):
                    messages.append(content)
                elif isinstance(content, list):
                    # Multi-modal content
                    for item in content:
                        if item.get("type") == "text":
                            messages.append(item.get("text", ""))

        return messages

    def _check_rate_limit(self):
        """Check rate limiting rules"""
        rules = self.policy_config.get("rules", {}).get("rate_limiting", {})
        if not rules.get("enabled"):
            return

        now = datetime.utcnow()
        client_id = "default"  # In production: extract from request context

        # Clean old entries
        self.rate_limit_state[client_id] = [
            ts for ts in self.rate_limit_state[client_id]
            if now - ts < timedelta(hours=1)
        ]

        # Check limits
        recent_requests = self.rate_limit_state[client_id]

        # Per minute
        requests_last_minute = sum(
            1 for ts in recent_requests
            if now - ts < timedelta(minutes=1)
        )
        if requests_last_minute >= rules.get("requests_per_minute", 60):
            raise PolicyViolation(
                "rate_limit_exceeded",
                {"limit": "requests_per_minute", "count": requests_last_minute}
            )

        # Per hour
        if len(recent_requests) >= rules.get("requests_per_hour", 1000):
            raise PolicyViolation(
                "rate_limit_exceeded",
                {"limit": "requests_per_hour", "count": len(recent_requests)}
            )

        # Record this request
        self.rate_limit_state[client_id].append(now)

    def _check_token_limit(self, requested_tokens: int):
        """Check token usage limits"""
        rules = self.policy_config.get("rules", {}).get("token_limits", {})
        if not rules.get("enabled"):
            return

        # Per request limit
        max_per_request = rules.get("max_tokens_per_request", 16000)
        if requested_tokens > max_per_request:
            raise PolicyViolation(
                "token_limit_exceeded",
                {"limit": "max_tokens_per_request", "requested": requested_tokens}
            )

        # Daily limit
        today = datetime.utcnow().date()
        daily_usage = self.token_usage[today]
        max_per_day = rules.get("max_tokens_per_day", 1000000)

        if daily_usage + requested_tokens > max_per_day:
            raise PolicyViolation(
                "token_limit_exceeded",
                {"limit": "max_tokens_per_day", "current": daily_usage}
            )

    def _check_content_filtering(self, messages: List[str]):
        """Check for blocked content patterns"""
        rules = self.policy_config.get("rules", {}).get("content_filtering", {})
        if not rules.get("enabled"):
            return

        blocked_patterns = rules.get("blocked_patterns", [])

        for message in messages:
            for pattern in blocked_patterns:
                if re.search(pattern, message):
                    raise PolicyViolation(
                        "content_blocked",
                        {
                            "reason": "matched_blocked_pattern",
                            "pattern": pattern[:50]  # Truncate for safety
                        }
                    )

    def _check_pii_detection(self, messages: List[str]):
        """Detect and block PII in messages"""
        rules = self.policy_config.get("rules", {}).get("pii_detection", {})
        if not rules.get("enabled"):
            return

        for message in messages:
            # SSN detection
            if rules.get("block_ssn"):
                ssn_pattern = r"\b\d{3}-\d{2}-\d{4}\b"
                if re.search(ssn_pattern, message):
                    raise PolicyViolation(
                        "pii_detected",
                        {"type": "ssn", "message": "Social Security Number detected"}
                    )

            # Credit card detection
            if rules.get("block_credit_card"):
                # Simple Luhn algorithm check
                cc_pattern = r"\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b"
                if re.search(cc_pattern, message):
                    raise PolicyViolation(
                        "pii_detected",
                        {"type": "credit_card", "message": "Credit card number detected"}
                    )

            # Email detection
            if rules.get("block_email"):
                email_pattern = r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"
                if re.search(email_pattern, message):
                    raise PolicyViolation(
                        "pii_detected",
                        {"type": "email", "message": "Email address detected"}
                    )

            # Phone number detection
            if rules.get("block_phone"):
                phone_pattern = r"\b\d{3}[-.]?\d{3}[-.]?\d{4}\b"
                if re.search(phone_pattern, message):
                    raise PolicyViolation(
                        "pii_detected",
                        {"type": "phone", "message": "Phone number detected"}
                    )

    def _check_prompt_injection(self, messages: List[str]):
        """Detect potential prompt injection attempts"""
        rules = self.policy_config.get("rules", {}).get("prompt_injection", {})
        if not rules.get("enabled"):
            return

        # Common jailbreak patterns
        jailbreak_patterns = [
            r"(?i)ignore (previous|above|prior) (instructions|rules)",
            r"(?i)(you are|act as|pretend).+(not|no longer).+(AI|assistant)",
            r"(?i)system prompt",
            r"(?i)developer mode",
            r"(?i)DAN mode",
        ]

        if rules.get("detect_jailbreak_attempts"):
            for message in messages:
                for pattern in jailbreak_patterns:
                    if re.search(pattern, message):
                        raise PolicyViolation(
                            "prompt_injection_detected",
                            {"type": "jailbreak_attempt", "pattern": pattern}
                        )

    # ========================================================================
    # Response Validation
    # ========================================================================

    def validate_response(self, body: Dict[str, Any], provider: str):
        """
        Validate LLM response against policies
        Can check for leaked information, inappropriate content, etc.
        """

        # Extract response text
        response_text = self._extract_response_text(body, provider)

        # Track token usage
        usage = body.get("usage", {})
        total_tokens = usage.get("total_tokens", 0)
        if total_tokens > 0:
            today = datetime.utcnow().date()
            self.token_usage[today] += total_tokens

        # Check for sensitive data in response
        self._check_response_content(response_text)

    def _extract_response_text(self, body: Dict, provider: str) -> str:
        """Extract text from response"""
        if "choices" in body:  # OpenAI format
            return body.get("choices", [{}])[0].get("message", {}).get("content", "")
        elif "content" in body:  # Anthropic format
            content = body.get("content", [])
            return "".join([c.get("text", "") for c in content if c.get("type") == "text"])
        return ""

    def _check_response_content(self, response_text: str):
        """Check response for policy violations"""
        # Could check for:
        # - System prompt leakage
        # - Internal information disclosure
        # - Inappropriate content generation

        # Example: check for potential prompt leakage
        rules = self.policy_config.get("rules", {}).get("prompt_injection", {})
        if rules.get("detect_system_prompt_leakage"):
            leakage_indicators = [
                r"(?i)my (system prompt|instructions) (is|are)",
                r"(?i)I (was instructed|am programmed) to",
            ]

            for pattern in leakage_indicators:
                if re.search(pattern, response_text):
                    raise PolicyViolation(
                        "system_prompt_leakage",
                        {"pattern": pattern}
                    )
