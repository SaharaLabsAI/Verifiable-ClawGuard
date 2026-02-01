#!/usr/bin/env python3
"""
Attestation Server (Runs INSIDE Nitro Enclave)

This service provides:
1. Attestation generation using NSM device
2. Encrypted session establishment via key exchange
3. Session management for encrypted communication

The server is designed to be called by Clawdbot inside the enclave,
with results sent to users through chat.
"""

import os
import json
import base64
import hashlib
import secrets
from datetime import datetime, timedelta
from typing import Optional, Dict, Tuple, Any
from dataclasses import dataclass

from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel
import uvicorn

# Cryptography imports
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend


# ============================================================================
# NSM (Nitro Security Module) Integration
# ============================================================================

def is_running_in_enclave() -> bool:
    """Check if we're running inside a Nitro Enclave"""
    return os.path.exists("/dev/nsm")


def get_attestation_from_nsm(user_data: bytes, nonce: Optional[bytes] = None, public_key: Optional[bytes] = None) -> dict:
    """
    Generate attestation document using NSM device

    This uses the REAL aws-nsm-interface library to communicate with /dev/nsm
    Package: https://pypi.org/project/aws-nsm-interface/
    Repo: https://github.com/donkersgoed/aws-nsm-interface

    Args:
        user_data: Optional binary data to include in attestation (max 512 bytes for user_data,
                   or 1024 bytes combined with nonce and public_key)
        nonce: Optional binary nonce for freshness verification (max 512 bytes)
        public_key: Optional RSA public key in DER format for key attestation

    Returns:
        dict: Contains the attestation document and metadata
            - document: base64-encoded CBOR COSE_Sign1 attestation document
            - pcrs: Dictionary of PCR values (extracted from document)
            - timestamp: Current timestamp
            - module_id: Enclave module ID (from attestation)
            - user_data: The user_data that was included (base64)
            - nonce: The nonce that was included (base64)

    Raises:
        RuntimeError: If attestation generation fails
    """
    try:
        # Import required libraries
        import aws_nsm_interface
        import cbor2

        # Open NSM device in unbuffered binary mode
        # Note: aws_nsm_interface.open_nsm_device() uses text mode which causes
        # "not seekable" errors, so we open directly in binary unbuffered mode
        print(f"Opening /dev/nsm device...")
        nsm_fd = open('/dev/nsm', 'rb', buffering=0)
        print(f"NSM device opened successfully")

        try:
            # Get attestation document from NSM
            # The returned document is a CBOR-encoded COSE_Sign1 structure
            print(f"Requesting attestation from NSM...")
            print(f"  user_data size: {len(user_data) if user_data else 0} bytes")
            print(f"  nonce size: {len(nonce) if nonce else 0} bytes")
            print(f"  public_key: {type(public_key) if public_key else None}")

            result = aws_nsm_interface.get_attestation_doc(
                nsm_fd,
                user_data=user_data,
                nonce=nonce,
                public_key=public_key
            )
            print(f"Attestation document received: {type(result)}")

            # Extract the binary attestation document
            attestation_doc_binary = result['document']
            print(f"Document extracted: {len(attestation_doc_binary)} bytes")

            # Decode the CBOR COSE_Sign1 structure to extract metadata
            # The document structure is: COSE_Sign1 = [protected, unprotected, payload, signature]
            try:
                cose_sign1 = cbor2.loads(attestation_doc_binary)

                # The payload (index 2) contains the actual attestation document
                attestation_payload = cbor2.loads(cose_sign1[2])

                # Extract PCR values from the attestation document
                pcrs = {}
                if 'pcrs' in attestation_payload:
                    # PCRs are stored as binary data, convert to hex strings
                    for pcr_index, pcr_value in attestation_payload['pcrs'].items():
                        pcrs[str(pcr_index)] = pcr_value.hex()

                # Extract module_id
                module_id = attestation_payload.get('module_id', 'unknown')

                # Extract timestamp (milliseconds since epoch)
                timestamp = attestation_payload.get('timestamp', int(datetime.utcnow().timestamp() * 1000))

            except Exception as decode_error:
                print(f"Warning: Could not decode attestation document: {decode_error}")
                print("Returning base64-encoded document without parsed metadata")
                # If decoding fails, return the document anyway with minimal metadata
                pcrs = {}
                module_id = "could_not_decode"
                timestamp = int(datetime.utcnow().timestamp() * 1000)

            # Return structured response
            return {
                # Base64-encoded full attestation document (for verification)
                "document": base64.b64encode(attestation_doc_binary).decode('utf-8'),

                # Extracted metadata for convenience
                "module_id": module_id,
                "timestamp": timestamp,
                "digest": "SHA384",  # Nitro Enclaves use SHA384 for PCRs
                "pcrs": pcrs,

                # Echo back the input data
                "user_data": base64.b64encode(user_data).decode('utf-8') if user_data else None,
                "nonce": base64.b64encode(nonce).decode('utf-8') if nonce else None,

                # Certificate chain (embedded in COSE structure)
                "certificate": "embedded_in_cose_structure",
                "cabundle": ["embedded_in_cose_structure"],
            }

        finally:
            # Always close the NSM device
            nsm_fd.close()

    except ImportError as e:
        raise RuntimeError(str(e))
    except Exception as e:
        raise RuntimeError(f"Failed to generate attestation from NSM: {e}")


def get_dummy_attestation(user_data: bytes, nonce: Optional[bytes] = None) -> dict:
    """
    Generate dummy attestation for debugging outside TEE
    
    WARNING: This is NOT cryptographically secure and should only be used
    for development/debugging purposes.
    """
    return {
        "module_id": "dummy-enclave-id-for-debugging",
        "timestamp": int(datetime.utcnow().timestamp() * 1000),
        "digest": "SHA384",
        "pcrs": {
            "0": "0" * 96,  # Dummy PCR0
            "1": "1" * 96,  # Dummy PCR1
            "2": "2" * 96,  # Dummy PCR2 - THIS WOULD BE THE REAL GUARDRAIL MEASUREMENT
            "3": "3" * 96,
            "4": "4" * 96,
            "8": "8" * 96,
        },
        "certificate": "DUMMY_CERTIFICATE_NOT_VALID",
        "cabundle": ["DUMMY_CA_BUNDLE"],
        "public_key": "DUMMY_PUBLIC_KEY",
        "user_data": base64.b64encode(user_data).decode('utf-8') if user_data else None,
        "nonce": base64.b64encode(nonce).decode('utf-8') if nonce else None,
        "_warning": "THIS IS A DUMMY ATTESTATION FOR DEBUGGING ONLY - NOT CRYPTOGRAPHICALLY VALID"
    }


# ============================================================================
# Session Management
# ============================================================================

@dataclass
class SecureSession:
    """Represents an encrypted session with a user"""
    session_id: str
    session_key: bytes  # AES-256 key
    created_at: datetime
    expires_at: datetime
    user_public_key_fingerprint: str
    message_count: int = 0


class SessionManager:
    """Manages encrypted sessions"""
    
    def __init__(self, session_timeout_minutes: int = 60):
        self.sessions: Dict[str, SecureSession] = {}
        self.session_timeout = timedelta(minutes=session_timeout_minutes)
    
    def create_session(self, user_public_key_pem: str) -> Tuple[str, bytes]:
        """
        Create a new encrypted session
        
        Returns:
            (session_id, session_key)
        """
        # Generate session ID and key
        session_id = secrets.token_urlsafe(32)
        session_key = secrets.token_bytes(32)  # 256-bit AES key
        
        # Calculate fingerprint of user's public key
        fingerprint = hashlib.sha256(user_public_key_pem.encode()).hexdigest()[:16]
        
        # Create session
        now = datetime.utcnow()
        session = SecureSession(
            session_id=session_id,
            session_key=session_key,
            created_at=now,
            expires_at=now + self.session_timeout,
            user_public_key_fingerprint=fingerprint
        )
        
        self.sessions[session_id] = session
        
        return session_id, session_key
    
    def get_session(self, session_id: str) -> Optional[SecureSession]:
        """Get session if valid and not expired"""
        session = self.sessions.get(session_id)
        
        if not session:
            return None
        
        # Check expiration
        if datetime.utcnow() > session.expires_at:
            del self.sessions[session_id]
            return None
        
        return session
    
    def increment_message_count(self, session_id: str):
        """Increment message counter for a session"""
        session = self.sessions.get(session_id)
        if session:
            session.message_count += 1
    
    def cleanup_expired(self):
        """Remove expired sessions"""
        now = datetime.utcnow()
        expired = [sid for sid, sess in self.sessions.items() if now > sess.expires_at]
        for sid in expired:
            del self.sessions[sid]


# ============================================================================
# API Request/Response Models
# ============================================================================

class AttestationRequest(BaseModel):
    """Request for attestation generation"""
    nonce: Optional[str] = None  # User-provided challenge (hex, base64, or plain string)
    include_metadata: bool = True  # Include agent metadata in user_data
    custom_data: Optional[Dict[str, Any]] = None  # Custom data to attest via digest


class KeyExchangeRequest(BaseModel):
    """Request to establish encrypted session"""
    user_public_key: str  # PEM-encoded RSA public key
    nonce: Optional[str] = None  # Optional nonce for attestation (hex, base64, or plain string)


class EncryptedMessageRequest(BaseModel):
    """Encrypted message from user"""
    session_id: str
    ciphertext: str  # Base64-encoded encrypted data
    iv: str  # Base64-encoded IV/nonce


# ============================================================================
# FastAPI Application
# ============================================================================

app = FastAPI(
    title="Nitro Enclave Attestation & Secure Communication Server",
    description="Provides attestation and encrypted session capabilities inside TEE",
    version="1.0.0"
)

# Initialize session manager
session_manager = SessionManager(session_timeout_minutes=60)


@app.get("/")
async def root():
    """Service information"""
    return {
        "service": "Nitro Enclave Attestation Server",
        "version": "1.0.0",
        "running_in_tee": is_running_in_enclave(),
        "endpoints": {
            "/attestation": "Generate TEE attestation with challenge",
            "/key-exchange": "Establish encrypted session",
            "/encrypt": "Encrypt message with session key",
            "/decrypt": "Decrypt message from user",
            "/health": "Health check"
        },
        "note": "This server runs INSIDE the enclave and is called by Clawdbot"
    }


@app.get("/health")
async def health_check():
    """Health check endpoint"""
    session_manager.cleanup_expired()
    
    return {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat(),
        "tee_available": is_running_in_enclave(),
        "active_sessions": len(session_manager.sessions)
    }


@app.post("/attestation")
async def generate_attestation(request: AttestationRequest):
    """
    Generate attestation document with user-provided challenge
    
    This proves:
    1. Code is running in genuine AWS Nitro Enclave (AWS signature)
    2. Specific guardrail code is running (PCR2 value)
    3. Attestation is fresh (timestamp + user's nonce)
    4. Agent metadata is authentic (included in user_data)
    
    The attestation document can be verified externally by the user
    or service provider to confirm they're communicating with the
    correct attested enclave.
    """
    print(f"[{datetime.utcnow().isoformat()}] Attestation request received")
    
    try:
        # Decode nonce if provided
        nonce_bytes = None
        if request.nonce:
            try:
                # Try hex decoding first
                nonce_bytes = bytes.fromhex(request.nonce)
            except ValueError:
                try:
                    # Try base64 decoding
                    nonce_bytes = base64.b64decode(request.nonce)
                except Exception:
                    # Fallback: treat as plain UTF-8 string
                    nonce_bytes = request.nonce.encode('utf-8')
            print(f"  Nonce: {request.nonce[:32]}..." if len(request.nonce) > 32 else f"  Nonce: {request.nonce}")
        
        # Prepare user_data with agent metadata
        user_data_dict = {
            "timestamp": datetime.utcnow().isoformat(),
            "agent": "OpenClaw",
            "guardrail": "LLM Proxy with Guardrails",
        }

        if request.include_metadata:
            # Include agent version/hash if available
            agent_metadata_path = "/tmp/agent_metadata.json"
            if os.path.exists(agent_metadata_path):
                with open(agent_metadata_path, 'r') as f:
                    agent_metadata = json.load(f)
                    user_data_dict.update(agent_metadata)

        # Compute digest of custom_data if provided (hash commitment)
        custom_data_digest = None
        custom_data_plaintext = None
        if request.custom_data:
            # Serialize custom_data to canonical JSON for hashing
            custom_data_plaintext = json.dumps(request.custom_data, sort_keys=True)
            custom_data_digest = hashlib.sha256(custom_data_plaintext.encode('utf-8')).hexdigest()

            # Include digest in attested user_data
            user_data_dict["custom_digest"] = custom_data_digest
            user_data_dict["custom_digest_method"] = "sha256"

            print(f"  Custom data digest: {custom_data_digest[:16]}...")

        user_data_bytes = json.dumps(user_data_dict).encode('utf-8')
        
        # Generate attestation
        if is_running_in_enclave():
            print("  Generating attestation using NSM device...")
            attestation = get_attestation_from_nsm(user_data_bytes, nonce_bytes)
        else:
            print("  WARNING: Not in TEE - generating dummy attestation")
            attestation = get_dummy_attestation(user_data_bytes, nonce_bytes)
        
        # Extract PCR2 for convenience
        pcr2 = attestation.get("pcrs", {}).get("2", "")
        
        print(f"  ✓ Attestation generated")
        print(f"    PCR2: {pcr2[:32]}..." if len(pcr2) > 32 else f"    PCR2: {pcr2}")
        
        # Decode user_data for response
        user_data_decoded = None
        if attestation.get("user_data"):
            try:
                user_data_decoded = json.loads(
                    base64.b64decode(attestation["user_data"])
                )
            except Exception as e:
                print(f"  Warning: Could not decode user_data: {e}")

        # Build response
        response = {
            "attestation_document": attestation,
            "pcr2": pcr2,
            "user_data": user_data_decoded,
            "timestamp": datetime.utcnow().isoformat(),
            "tee_verified": is_running_in_enclave(),
            "verification_instructions": {
                "step_1": "Verify AWS signature using aws-nitro-enclaves-nsm-api",
                "step_2": "Compare PCR2 with your known guardrail measurement",
                "step_3": "Check timestamp is recent (< 5 minutes old)",
                "step_4": "Verify nonce matches your challenge (if provided)",
                "step_5": "Validate agent metadata in user_data"
            }
        }

        # Include custom data digest and plaintext if provided
        if custom_data_digest:
            response["custom_digest"] = custom_data_digest
            response["custom_digest_method"] = "sha256"
            response["custom_data"] = request.custom_data
            response["verification_instructions"]["step_6"] = "Verify custom_digest: hash(custom_data) == custom_digest"

        return response
    
    except Exception as e:
        print(f"  ✗ Error generating attestation: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Failed to generate attestation: {str(e)}"
        )


@app.post("/key-exchange")
async def establish_secure_session(request: KeyExchangeRequest):
    """
    Establish encrypted session with user via key exchange
    
    Protocol:
    1. User sends their RSA public key
    2. Server generates random session key (AES-256)
    3. Server encrypts session key with user's public key
    4. Server generates attestation with session key hash in user_data
    5. Server returns: encrypted session key + attestation
    
    This binds the session key to the attested enclave cryptographically.
    The user can verify:
    - The attestation is valid (AWS signature)
    - PCR2 matches expected guardrail
    - Session key hash in attestation matches decrypted key
    
    After verification, user can trust that encrypted messages go to
    the correct attested enclave, and parent EC2 cannot decrypt them.
    """
    print(f"[{datetime.utcnow().isoformat()}] Key exchange request received")
    
    try:
        # Load user's public key
        try:
            user_public_key = serialization.load_pem_public_key(
                request.user_public_key.encode('utf-8'),
                backend=default_backend()
            )
        except Exception as e:
            raise HTTPException(
                status_code=400,
                detail=f"Invalid public key format: {str(e)}"
            )
        
        # Create new session
        session_id, session_key = session_manager.create_session(request.user_public_key)
        
        print(f"  Created session: {session_id[:16]}...")
        
        # Encrypt session key with user's public key
        encrypted_session_key = user_public_key.encrypt(
            session_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        # Calculate session key hash for attestation
        session_key_hash = hashlib.sha256(session_key).hexdigest()
        
        # Prepare attestation user_data
        user_data_dict = {
            "session_id": session_id,
            "session_key_hash": session_key_hash,
            "timestamp": datetime.utcnow().isoformat(),
            "agent": "OpenClaw",
            "guardrail": "LLM Proxy with Guardrails",
            "key_exchange_version": "1.0"
        }
        
        # Include agent metadata if available
        agent_metadata_path = "/tmp/agent_metadata.json"
        if os.path.exists(agent_metadata_path):
            with open(agent_metadata_path, 'r') as f:
                agent_metadata = json.load(f)
                user_data_dict.update(agent_metadata)
        
        user_data_bytes = json.dumps(user_data_dict).encode('utf-8')
        
        # Decode nonce if provided
        nonce_bytes = None
        if request.nonce:
            try:
                nonce_bytes = bytes.fromhex(request.nonce)
            except ValueError:
                try:
                    nonce_bytes = base64.b64decode(request.nonce)
                except Exception:
                    # Fallback: treat as plain UTF-8 string
                    nonce_bytes = request.nonce.encode('utf-8')
        
        # Generate attestation
        if is_running_in_enclave():
            print("  Generating attestation using NSM device...")
            attestation = get_attestation_from_nsm(user_data_bytes, nonce_bytes)
        else:
            print("  WARNING: Not in TEE - generating dummy attestation")
            attestation = get_dummy_attestation(user_data_bytes, nonce_bytes)
        
        pcr2 = attestation.get("pcrs", {}).get("2", "")
        
        print(f"  ✓ Key exchange complete")
        print(f"    Session ID: {session_id[:16]}...")
        print(f"    PCR2: {pcr2[:32]}...")
        
        return {
            "session_id": session_id,
            "encrypted_session_key": base64.b64encode(encrypted_session_key).decode('utf-8'),
            "attestation_document": attestation,
            "pcr2": pcr2,
            "session_key_hash": session_key_hash,
            "expires_in_minutes": 60,
            "tee_verified": is_running_in_enclave(),
            "verification_instructions": {
                "step_1": "Decrypt session key using your private key",
                "step_2": "Verify hash(session_key) matches session_key_hash in response",
                "step_3": "Verify attestation signature (AWS)",
                "step_4": "Check PCR2 matches your expected guardrail measurement",
                "step_5": "Verify session_key_hash in attestation.user_data matches",
                "step_6": "Use session_key for AES-256-GCM encryption of all future messages"
            }
        }
    
    except HTTPException:
        raise
    except Exception as e:
        print(f"  ✗ Error in key exchange: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Key exchange failed: {str(e)}"
        )


@app.post("/decrypt")
async def decrypt_message(request: EncryptedMessageRequest):
    """
    Decrypt message from user
    
    Used by Clawdbot to decrypt incoming user messages that were
    encrypted with the session key.
    """
    try:
        # Get session
        session = session_manager.get_session(request.session_id)
        if not session:
            raise HTTPException(
                status_code=401,
                detail="Invalid or expired session"
            )
        
        # Decode ciphertext and IV
        ciphertext = base64.b64decode(request.ciphertext)
        iv = base64.b64decode(request.iv)
        
        # Decrypt using AES-GCM
        aesgcm = AESGCM(session.session_key)
        plaintext = aesgcm.decrypt(iv, ciphertext, None)
        
        # Increment message count
        session_manager.increment_message_count(request.session_id)
        
        return {
            "plaintext": plaintext.decode('utf-8'),
            "session_id": request.session_id,
            "message_number": session.message_count
        }
    
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=400,
            detail=f"Decryption failed: {str(e)}"
        )


@app.post("/encrypt")
async def encrypt_message(request: Request):
    """
    Encrypt message for user
    
    Used by Clawdbot to encrypt outgoing responses before sending
    through chat.
    
    Request body: {"session_id": "...", "plaintext": "..."}
    """
    try:
        body = await request.json()
        session_id = body.get("session_id")
        plaintext = body.get("plaintext")
        
        if not session_id or not plaintext:
            raise HTTPException(
                status_code=400,
                detail="Missing session_id or plaintext"
            )
        
        # Get session
        session = session_manager.get_session(session_id)
        if not session:
            raise HTTPException(
                status_code=401,
                detail="Invalid or expired session"
            )
        
        # Encrypt using AES-GCM
        aesgcm = AESGCM(session.session_key)
        iv = secrets.token_bytes(12)  # 96-bit IV for GCM
        ciphertext = aesgcm.encrypt(iv, plaintext.encode('utf-8'), None)
        
        # Increment message count
        session_manager.increment_message_count(session_id)
        
        return {
            "ciphertext": base64.b64encode(ciphertext).decode('utf-8'),
            "iv": base64.b64encode(iv).decode('utf-8'),
            "session_id": session_id,
            "message_number": session.message_count
        }
    
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=400,
            detail=f"Encryption failed: {str(e)}"
        )


@app.get("/sessions")
async def list_sessions():
    """List active sessions (for debugging)"""
    session_manager.cleanup_expired()
    
    return {
        "active_sessions": len(session_manager.sessions),
        "sessions": [
            {
                "session_id": sid[:16] + "...",
                "created_at": sess.created_at.isoformat(),
                "expires_at": sess.expires_at.isoformat(),
                "message_count": sess.message_count,
                "user_fingerprint": sess.user_public_key_fingerprint
            }
            for sid, sess in session_manager.sessions.items()
        ]
    }


if __name__ == "__main__":
    print("=" * 70)
    print("  Nitro Enclave Attestation & Secure Communication Server")
    print("=" * 70)
    print()
    print(f"Running in TEE: {is_running_in_enclave()}")
    if not is_running_in_enclave():
        print("  ⚠️  WARNING: Not running in Nitro Enclave!")
        print("  ⚠️  Attestations will be DUMMY/INVALID")
        print("  ⚠️  Use only for development/debugging")
    print()
    print("Starting server...")
    print("  Host: 127.0.0.1 (localhost only - called by Clawdbot)")
    print("  Port: 8765")
    print()
    print("Endpoints:")
    print("  POST /attestation     - Generate attestation with challenge")
    print("  POST /key-exchange    - Establish encrypted session")
    print("  POST /encrypt         - Encrypt message for user")
    print("  POST /decrypt         - Decrypt message from user")
    print("  GET  /sessions        - List active sessions")
    print("  GET  /health          - Health check")
    print()
    print("Usage by Clawdbot:")
    print("  curl -X POST http://localhost:8765/attestation \\")
    print("    -H 'Content-Type: application/json' \\")
    print("    -d '{\"nonce\": \"user_challenge_here\"}'")
    print()
    print("Press Ctrl+C to stop")
    print("=" * 70)
    print()
    
    uvicorn.run(
        app,
        host="127.0.0.1",  # Localhost only - called by Clawdbot
        port=8765,
        log_level="info"
    )
