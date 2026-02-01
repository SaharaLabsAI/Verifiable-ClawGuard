"""
Custom actions for NeMo Guardrails.
These actions can be registered with LLMRails and called from Colang flows.
"""

from typing import Optional
from nemoguardrails.actions import action


@action(name="check_harmful_content")
async def check_harmful_content(bot_message: str) -> bool:
    """
    Check if the bot message contains harmful content.
    This is a simple keyword-based check. In production, you might want to use
    a more sophisticated model or API.
    
    Args:
        bot_message: The bot's response to check
        
    Returns:
        True if harmful content is detected, False otherwise
    """
    harmful_patterns = [
        "how to make a bomb",
        "how to hack into",
        "how to steal",
        "illegal drugs",
        "weapons manufacturing",
    ]
    
    message_lower = bot_message.lower()
    for pattern in harmful_patterns:
        if pattern in message_lower:
            return True
    
    return False


@action(name="log_guardrail_event")
async def log_guardrail_event(
    event_type: str,
    user_message: Optional[str] = None,
    bot_message: Optional[str] = None,
    blocked: bool = False,
    reason: Optional[str] = None
) -> dict:
    """
    Log guardrail events for auditing purposes.
    
    Args:
        event_type: Type of event (input_check, output_check, etc.)
        user_message: The user's message if applicable
        bot_message: The bot's message if applicable
        blocked: Whether the message was blocked
        reason: Reason for blocking if applicable
        
    Returns:
        A dictionary with the logged event details
    """
    import time
    
    event = {
        "timestamp": time.time(),
        "event_type": event_type,
        "blocked": blocked,
    }
    
    if user_message:
        event["user_message"] = user_message[:100]  # Truncate for logging
    if bot_message:
        event["bot_message"] = bot_message[:100]
    if reason:
        event["reason"] = reason
    
    # In production, you might want to write this to a file or send to a logging service
    print(f"[Guardrail Event] {event}")
    
    return event
