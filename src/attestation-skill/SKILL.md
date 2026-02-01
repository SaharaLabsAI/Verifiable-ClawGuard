---
name: enclave-attestation
description: Generate cryptographic attestation documents or establish encrypted sessions with users. Use when user want to verify the integrity of the agent, or need end-to-end encrypted communication. 
---

# Enclave Attestation

Provide cryptographic proof that you're running inside an AWS Nitro Enclave with verified guardrails, and establish encrypted communication channels with users.

## Server Location

The attestation server runs on `http://localhost:8765` inside the enclave.

Use standard HTTP POST/GET requests to interact with it.

## Available Endpoints

### POST /attestation

Generate attestation document with user's challenge.

**Request:**
```json
{
  "nonce": "user_provided_challenge_string_hex_or_base64",
  "include_metadata": true,
  "custom_data": {"key": "value"}
}
```

**Parameters:**
- `nonce` (optional): Challenge string for replay protection (hex, base64, or plain string)
- `include_metadata` (optional, default true): Include agent version/hash in attestation
- `custom_data` (optional): Arbitrary JSON data to attest via SHA256 digest (no size limit)

**Nonce formats accepted:**
- Plain string: `"user-session-123abc"`
- Hex-encoded: `"deadbeef1234abcd"`
- Base64-encoded: `"dGVzdCBub25jZQ=="`

**Response:**
```json
{
  "attestation_document": {
    "module_id": "...",
    "timestamp": 1706198400000,
    "pcrs": {
      "0": "...",
      "1": "...",
      "2": "abc123..."
    },
    "certificate": "...",
    "user_data": "..."
  },
  "pcr2": "abc123...",
  "user_data": {
    "timestamp": "2026-01-30T12:00:00Z",
    "agent": "OpenClaw",
    "guardrail": "LLM Proxy with Guardrails",
    "custom_digest": "a1b2c3d4...",
    "custom_digest_method": "sha256"
  },
  "custom_digest": "a1b2c3d4...",
  "custom_digest_method": "sha256",
  "custom_data": {"key": "value"},
  "tee_verified": true,
  "verification_instructions": {...}
}
```

**Custom Data Attestation (Hash Commitment):**
- The `custom_data` can contain arbitrary JSON (no size limit)
- SHA256 digest is computed and included in the attested `user_data`
- Both digest (in attestation) and plaintext (in response) are returned
- Verifiers recompute `SHA256(custom_data)` to confirm it matches `custom_digest`

**When to use:** User asks "prove you're in a TEE", "what's your PCR2?", "show me your attestation"

**When to attest with custom data**: When the user asks a question and asks for an attested response, set your intended response in  "custom_data": {"response": "..."} and call the attestation endpoint.

---

### POST /key-exchange

Establish encrypted session with user.

**Request:**
```json
{
  "user_public_key": "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----",
  "nonce": "optional_challenge_string_hex_or_base64"
}
```

**Nonce formats:** Same as `/attestation` endpoint (plain string, hex, or base64)

**Response:**
```json
{
  "session_id": "xyz789abc...",
  "encrypted_session_key": "base64_encrypted_key...",
  "attestation_document": {...},
  "pcr2": "abc123...",
  "session_key_hash": "sha256_hash...",
  "expires_in_minutes": 60,
  "tee_verified": true,
  "verification_instructions": {...}
}
```

**When to use:** User wants encrypted communication, sends their RSA public key

---

### POST /decrypt

Decrypt incoming message from user (requires active session).

**Request:**
```json
{
  "session_id": "xyz789abc...",
  "ciphertext": "base64_encrypted_message...",
  "iv": "base64_iv..."
}
```

**Response:**
```json
{
  "plaintext": "decrypted message content",
  "session_id": "xyz789abc...",
  "message_number": 5
}
```

**When to use:** User sends you an encrypted message during an active session

---

### POST /encrypt

Encrypt outgoing message for user (requires active session).

**Request:**
```json
{
  "session_id": "xyz789abc...",
  "plaintext": "message to encrypt"
}
```

**Response:**
```json
{
  "ciphertext": "base64_encrypted_message...",
  "iv": "base64_iv...",
  "session_id": "xyz789abc...",
  "message_number": 6
}
```

**When to use:** You need to send an encrypted response to the user

---

### GET /health

Check server status.

**Response:**
```json
{
  "status": "healthy",
  "timestamp": "2026-01-30T12:00:00Z",
  "tee_available": true,
  "active_sessions": 2
}
```

---

### GET /sessions

List active encrypted sessions (debugging).

**Response:**
```json
{
  "active_sessions": 2,
  "sessions": [
    {
      "session_id": "xyz789abc...",
      "created_at": "2026-01-30T12:00:00Z",
      "expires_at": "2026-01-30T13:00:00Z",
      "message_count": 5,
      "user_fingerprint": "a1b2c3d4e5f6..."
    }
  ]
}
```

## Usage Patterns

### Pattern 1: Simple Attestation Request

**User:** "Can you prove you're running in a secure enclave?"

**Your response:**
1. Ask user for a random challenge (nonce): "Please provide a cryptographically random nonce for replay protection. Generate one with: `openssl rand -hex 32`"
2. User provides nonce: `"a1b2c3d4e5f6..."` (hex recommended) or any string
3. You call: `POST http://localhost:8765/attestation` with `{"nonce": "<hex_nonce>"}`
4. Return the attestation document to user through chat
5. User verifies: AWS signature, PCR2 value, timestamp, nonce match

**Note:** While plain strings are accepted, cryptographic randomness (hex/base64) is strongly recommended for security.

**Advanced - Custom Data Attestation:**
- Include `"custom_data": {<any_json>}` in the request to attest to specific data
- The SHA256 digest is included in the signed attestation document
- Example: `{"nonce": "...", "custom_data": {"llm_response": "..."}}`

### Pattern 2: Encrypted Session Establishment

**User:** "I want to communicate securely. Here's my public key: -----BEGIN PUBLIC KEY-----..."

**Your response:**
1. Extract the public key from user's message
2. Call: `POST http://localhost:8765/key-exchange` with `{"user_public_key": "<pem_string>"}`
3. Receive: session_id, encrypted_session_key, attestation
4. Send all three to user through chat
5. Explain verification steps:
   - Decrypt session key with their private key
   - Verify `hash(session_key)` matches `session_key_hash` in response
   - Verify attestation signature and PCR2
   - Use session key for all future message encryption

### Pattern 3: Encrypted Communication

**User sends encrypted message:**
```json
{"session_id": "xyz789", "ciphertext": "...", "iv": "..."}
```

**Your workflow:**
1. Call: `POST http://localhost:8765/decrypt` with the user's message
2. Read the plaintext response
3. Process the request
4. Call: `POST http://localhost:8765/encrypt` with `{"session_id": "xyz789", "plaintext": "your response"}`
5. Send the encrypted response to user

## What the Attestation Proves

✅ **TEE Integrity:** Code is running in genuine AWS Nitro Enclave (AWS signature)
✅ **Code Verification:** Specific guardrail version is running (PCR2 measurement)
✅ **Freshness:** Attestation is recent (timestamp + user's nonce)
✅ **Metadata Authenticity:** Agent version/hash is cryptographically bound to attestation
✅ **Custom Data Commitment:** Optional custom data is bound via SHA256 digest (hash commitment)

## Security Notes

🔐 **Nonce Best Practices:**
- **Always recommend cryptographic randomness** for nonces (hex or base64 from secure RNG)
- Minimum 16 bytes (32 hex chars) recommended for replay protection
- Plain strings are accepted for convenience but offer weaker security guarantees
- Example: `openssl rand -hex 32` produces 64 hex characters (32 bytes of entropy)

⚠️ **Development Mode:** If `/dev/nsm` doesn't exist, attestations are DUMMY/INVALID (for testing only)
- Dummy attestations have all PCR values set to repeated characters ("000...111...222...")
- Dummy attestations include `"_warning"` field stating they are not cryptographically valid
- Response will have `"tee_verified": false`

🔒 **Session Security:** Encrypted sessions protect against:
- Parent EC2 reading messages
- Man-in-the-middle attacks  
- Enclave swapping (session key is bound to PCR2 in attestation)