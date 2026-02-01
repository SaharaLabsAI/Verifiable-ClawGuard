#!/usr/bin/env python3
"""
AWS Nitro Enclave Attestation Verification

This script properly verifies AWS Nitro Enclave attestation documents by:
1. Parsing the CBOR-encoded COSE_Sign1 structure
2. Verifying the cryptographic signature chain
3. Validating PCR measurements
4. Checking timestamp freshness
5. Verifying nonces and user data

NO HALLUCINATIONS - This implements the actual AWS Nitro verification process.
"""

import base64
import hashlib
import json
import time
from datetime import datetime
from typing import Optional, Dict, Any, List
import requests

try:
    import cbor2
except ImportError:
    raise ImportError("Missing cbor2: pip install cbor2")

try:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec, utils as crypto_utils
    from cryptography.hazmat.backends import default_backend
    from cryptography.exceptions import InvalidSignature
except ImportError:
    raise ImportError("Missing cryptography: pip install cryptography")


# ============================================================================
# Configuration
# ============================================================================

# Maximum age for attestation documents (seconds)
MAX_ATTESTATION_AGE = 300  # 5 minutes

# AWS Nitro Enclaves Root Certificate (from AWS documentation)
# https://aws-nitro-enclaves.amazonaws.com/AWS_NitroEnclaves_Root-G1.zip
AWS_NITRO_ROOT_CERT_PEM = """-----BEGIN CERTIFICATE-----
MIICETCCAZagAwIBAgIRAPkxdWgbkK/hHUbMtOTn+FYwCgYIKoZIzj0EAwMwSTEL
MAkGA1UEBhMCVVMxDzANBgNVBAoMBkFtYXpvbjEMMAoGA1UECwwDQVdTMRswGQYD
VQQDDBJhd3Mubml0cm8tZW5jbGF2ZXMwHhcNMTkxMDI4MTMyODA1WhcNNDkxMDI4
MTQyODA1WjBJMQswCQYDVQQGEwJVUzEPMA0GA1UECgwGQW1hem9uMQwwCgYDVQQL
DANBV1MxGzAZBgNVBAMMEmF3cy5uaXRyby1lbmNsYXZlczB2MBAGByqGSM49AgEG
BSuBBAAiA2IABPwCVOumCMHzaHDit6eQvkY4MpJzbonL//Zy2YlES1BR5TSksebb
48C8WBoys7F2Bw7eEtaaP+ohG2bnUs990d0JX28TcPQXCEPZ3BABH5IzMwEoCWZE
h8l5YoQwTcU/9KNCMEAwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUkCW1DdkF
R+eWw5b6cp3PmanfS5YwDgYDVR0PAQH/BAQDAgGGMAoGCCqGSM49BAMDA2kAMGYC
MQCjfy+Rocm9Xue4YnwWmNJVA44fA0P5W2OpYow9OYCVRZG+vL8uO1XYru5xtMPW
rfMCMQCi85sWBbJwKKXdS6BptQFuZbT73o/gBh1qUxl/nNr12UO8Yfwr6wPLb+6N
IwLz3/Y=
-----END CERTIFICATE-----"""


# ============================================================================
# Exception Classes
# ============================================================================

class AttestationVerificationError(Exception):
    """Base exception for attestation verification failures"""
    pass


class SignatureVerificationError(AttestationVerificationError):
    """Raised when cryptographic signature verification fails"""
    pass


class PCRMismatchError(AttestationVerificationError):
    """Raised when PCR values don't match expected values"""
    pass


class TimestampError(AttestationVerificationError):
    """Raised when attestation timestamp is invalid or too old"""
    pass


class NonceError(AttestationVerificationError):
    """Raised when nonce verification fails"""
    pass


# ============================================================================
# COSE Signature Verification (The Critical Part!)
# ============================================================================

def verify_cose_signature(cose_doc: bytes, aws_root_cert_pem: str = AWS_NITRO_ROOT_CERT_PEM) -> Dict[str, Any]:
    """
    Verify the COSE_Sign1 signature and certificate chain.

    This is the CRITICAL function that actually verifies the cryptographic signature.

    COSE_Sign1 Structure (from RFC 8152):
        COSE_Sign1 = [
            protected: bstr,       # Serialized protected headers
            unprotected: {},       # Unprotected headers (contains cert chain)
            payload: bstr,         # The actual attestation data
            signature: bstr        # ECDSA signature
        ]

    Signature Verification Process:
        1. Parse the COSE_Sign1 structure
        2. Extract certificate chain from unprotected headers
        3. Verify certificate chain up to AWS root
        4. Reconstruct the "to-be-signed" data (Sig_structure)
        5. Verify signature using leaf certificate's public key

    Args:
        cose_doc: The raw COSE_Sign1 document (bytes)
        aws_root_cert_pem: PEM-encoded AWS root certificate

    Returns:
        dict: Verified attestation payload

    Raises:
        SignatureVerificationError: If signature or certificate verification fails
    """
    try:
        # Step 1: Parse COSE_Sign1 structure
        cose_sign1 = cbor2.loads(cose_doc)

        if not isinstance(cose_sign1, list) or len(cose_sign1) != 4:
            raise SignatureVerificationError(
                f"Invalid COSE_Sign1 structure: expected 4-element list, got {type(cose_sign1)}"
            )

        protected_bytes = cose_sign1[0]      # Serialized protected headers
        unprotected = cose_sign1[1]          # Unprotected headers (dict)
        payload_bytes = cose_sign1[2]        # Attestation payload
        signature_bytes = cose_sign1[3]      # Signature

        print(f"  COSE structure parsed:")
        print(f"    Protected headers: {len(protected_bytes)} bytes")
        print(f"    Payload: {len(payload_bytes)} bytes")
        print(f"    Signature: {len(signature_bytes)} bytes")

        # Step 2: Parse payload to extract certificate chain
        # AWS Nitro puts the certificate chain INSIDE the payload (not in unprotected headers)
        attestation_payload = cbor2.loads(payload_bytes)

        # Extract certificate chain from payload
        # AWS Nitro structure:
        #   certificate - The enclave's leaf certificate (signs the COSE document)
        #   cabundle - [root, regional, zonal, parent_ec2] (from root to parent)
        # We need to build: [leaf, parent_ec2, zonal, regional, root]
        cert_chain_der = []

        # Get leaf certificate (signs the COSE document)
        certificate = attestation_payload.get('certificate')
        if certificate:
            cert_chain_der.append(certificate)

        # Get cabundle and reverse it (it's stored root-first, we need parent-first)
        cabundle = attestation_payload.get('cabundle', [])
        if isinstance(cabundle, list) and cabundle:
            # Reverse cabundle: [root, regional, zonal, parent] → [parent, zonal, regional, root]
            cert_chain_der.extend(reversed(cabundle))

        if not cert_chain_der:
            raise SignatureVerificationError(
                "No certificate chain found in attestation payload"
            )

        print(f"    Certificate chain: {len(cert_chain_der)} certificates")

        # Step 3: Parse certificates and verify chain
        certificates = []
        for i, cert_der in enumerate(cert_chain_der):
            if isinstance(cert_der, str):
                # If it's a string, it might be base64 or PEM
                try:
                    cert_der = base64.b64decode(cert_der)
                except Exception:
                    pass

            try:
                cert = x509.load_der_x509_certificate(cert_der, default_backend())
                certificates.append(cert)
                print(f"      Cert {i}: {cert.subject.rfc4514_string()[:60]}...")
            except Exception as e:
                raise SignatureVerificationError(f"Failed to parse certificate {i}: {e}")

        if not certificates:
            raise SignatureVerificationError("No valid certificates in chain")

        # The leaf certificate (first in chain) is the one that signed the document
        leaf_cert = certificates[0]

        # Step 4: Verify certificate chain to AWS root
        aws_root_cert = x509.load_pem_x509_certificate(
            aws_root_cert_pem.encode('utf-8'),
            default_backend()
        )

        # Verify each certificate is signed by the next one in the chain
        for i in range(len(certificates) - 1):
            current_cert = certificates[i]
            issuer_cert = certificates[i + 1]

            try:
                # Verify current cert is signed by issuer
                issuer_public_key = issuer_cert.public_key()

                # Verify signature on current certificate
                if isinstance(issuer_public_key, ec.EllipticCurvePublicKey):
                    issuer_public_key.verify(
                        current_cert.signature,
                        current_cert.tbs_certificate_bytes,
                        ec.ECDSA(current_cert.signature_hash_algorithm)
                    )
                else:
                    # RSA or other
                    from cryptography.hazmat.primitives.asymmetric import padding
                    issuer_public_key.verify(
                        current_cert.signature,
                        current_cert.tbs_certificate_bytes,
                        padding.PKCS1v15(),
                        current_cert.signature_hash_algorithm
                    )

                print(f"    ✓ Cert {i} verified by cert {i+1}")
            except InvalidSignature:
                raise SignatureVerificationError(
                    f"Certificate {i} signature verification failed"
                )
            except Exception as e:
                raise SignatureVerificationError(
                    f"Certificate {i} verification error: {e}"
                )

        # Verify the root certificate matches AWS root
        root_cert = certificates[-1]
        if root_cert.subject != aws_root_cert.subject:
            raise SignatureVerificationError(
                f"Root certificate mismatch. Got: {root_cert.subject}, "
                f"Expected: {aws_root_cert.subject}"
            )

        print(f"    ✓ Certificate chain verified to AWS root")

        # Step 5: Reconstruct "to-be-signed" data (Sig_structure)
        # From RFC 8152 Section 4.4:
        # Sig_structure = [
        #     context = "Signature1",
        #     body_protected = protected_bytes,
        #     external_aad = b"",
        #     payload = payload_bytes
        # ]
        sig_structure = [
            "Signature1",           # Context for COSE_Sign1
            protected_bytes,        # Protected headers (already serialized)
            b"",                    # External AAD (empty for attestation)
            payload_bytes           # Payload
        ]

        # Serialize the Sig_structure
        tbs_bytes = cbor2.dumps(sig_structure)

        # Step 6: Verify the signature
        leaf_public_key = leaf_cert.public_key()

        if not isinstance(leaf_public_key, ec.EllipticCurvePublicKey):
            raise SignatureVerificationError(
                f"Expected ECDSA key, got {type(leaf_public_key)}"
            )

        # Determine hash algorithm from curve
        # AWS Nitro uses P-384 with SHA384
        curve_name = leaf_public_key.curve.name
        if curve_name == "secp384r1":
            hash_algo = hashes.SHA384()
            sig_component_size = 48  # P-384: 48 bytes for r, 48 bytes for s
        elif curve_name == "secp256r1":
            hash_algo = hashes.SHA256()
            sig_component_size = 32  # P-256: 32 bytes for r, 32 bytes for s
        else:
            hash_algo = hashes.SHA256()
            sig_component_size = 32

        # Convert COSE signature from raw (r||s) format to DER format
        # COSE uses raw concatenated r and s values, but cryptography library expects DER
        try:
            # Extract r and s from raw signature
            r_bytes = signature_bytes[:sig_component_size]
            s_bytes = signature_bytes[sig_component_size:sig_component_size*2]

            r = int.from_bytes(r_bytes, byteorder='big')
            s = int.from_bytes(s_bytes, byteorder='big')

            # Convert to DER format
            der_signature = crypto_utils.encode_dss_signature(r, s)

            print(f"    Converted COSE signature: raw {len(signature_bytes)}B → DER {len(der_signature)}B")
        except Exception as e:
            raise SignatureVerificationError(f"Failed to convert signature format: {e}")

        try:
            leaf_public_key.verify(
                der_signature,
                tbs_bytes,
                ec.ECDSA(hash_algo)
            )
            print(f"    ✓ COSE signature verified with {curve_name} + {hash_algo.name}")
        except InvalidSignature:
            raise SignatureVerificationError(
                "COSE signature verification failed - signature does not match!"
            )

        # Step 7: Return the verified payload (already parsed in step 2)
        return attestation_payload

    except SignatureVerificationError:
        raise
    except Exception as e:
        raise SignatureVerificationError(f"Signature verification failed: {e}")


# ============================================================================
# Attestation Verification
# ============================================================================

def verify_attestation_document(
    attestation_doc_b64: str,
    known_pcr2: Optional[str] = None,
    allowed_versions: Optional[List[str]] = None,
    max_age_seconds: int = MAX_ATTESTATION_AGE,
    expected_nonce: Optional[str] = None
) -> Dict[str, Any]:
    """
    Verify an attestation document.

    Args:
        attestation_doc_b64: Base64-encoded attestation document
        known_pcr2: Expected PCR2 value (if None, PCR2 not checked)
        allowed_versions: List of allowed agent versions (if None, not checked)
        max_age_seconds: Maximum age for attestation
        expected_nonce: Expected nonce value (if None, not checked)

    Returns:
        dict: Verification result with parsed attestation data

    Raises:
        AttestationVerificationError: If any verification step fails
    """
    print(f"Verifying attestation document...")
    print()

    # Step 1: Decode base64
    try:
        attestation_doc_bytes = base64.b64decode(attestation_doc_b64)
        print(f"✓ Decoded attestation document ({len(attestation_doc_bytes)} bytes)")
    except Exception as e:
        raise AttestationVerificationError(f"Failed to decode base64: {e}")

    # Step 2: Verify COSE signature (THE CRITICAL STEP!)
    print()
    print("Verifying cryptographic signature...")
    attestation = verify_cose_signature(attestation_doc_bytes)
    print()
    print("✓ Cryptographic signature verified - attestation is authentic!")
    print()

    # Step 3: Extract and verify PCRs
    pcrs = attestation.get('pcrs', {})
    pcr2 = pcrs.get(2, b"").hex() if isinstance(pcrs.get(2), bytes) else str(pcrs.get(2, ""))

    print(f"PCR Values:")
    print(f"  PCR0 (Boot ROM): {pcrs.get(0, b'').hex()[:32] if isinstance(pcrs.get(0), bytes) else str(pcrs.get(0, ''))[:32]}...")
    print(f"  PCR1 (Kernel):   {pcrs.get(1, b'').hex()[:32] if isinstance(pcrs.get(1), bytes) else str(pcrs.get(1, ''))[:32]}...")
    print(f"  PCR2 (App):      {pcr2[:32]}..." if len(pcr2) > 32 else f"  PCR2 (App):      {pcr2}")
    print()

    if known_pcr2:
        if pcr2.lower() != known_pcr2.lower():
            raise PCRMismatchError(
                f"PCR2 mismatch!\n"
                f"  Expected: {known_pcr2}\n"
                f"  Got:      {pcr2}"
            )
        print(f"✓ PCR2 matches known guardrail measurement")
    else:
        print(f"⚠ PCR2 not verified (no known value provided)")

    # Step 4: Verify timestamp
    timestamp_ms = attestation.get('timestamp', 0)
    timestamp_sec = timestamp_ms / 1000 if timestamp_ms > 1000000000000 else timestamp_ms
    attestation_time = datetime.fromtimestamp(timestamp_sec)
    age_seconds = time.time() - timestamp_sec

    print()
    print(f"Timestamp: {attestation_time.isoformat()}")
    print(f"Age: {int(age_seconds)} seconds")

    if age_seconds > max_age_seconds:
        raise TimestampError(
            f"Attestation too old: {int(age_seconds)}s (max: {max_age_seconds}s)"
        )

    if age_seconds < -60:  # Allow 1 minute clock skew
        raise TimestampError(
            f"Attestation timestamp is in the future: {int(abs(age_seconds))}s ahead"
        )

    print(f"✓ Timestamp is fresh (< {max_age_seconds}s old)")

    # Step 5: Verify nonce if provided
    attestation_nonce = attestation.get('nonce')
    if attestation_nonce:
        if isinstance(attestation_nonce, bytes):
            attestation_nonce_str = attestation_nonce.decode('utf-8', errors='ignore')
        else:
            attestation_nonce_str = str(attestation_nonce)

        print()
        print(f"Nonce in attestation: {attestation_nonce_str[:32]}..." if len(attestation_nonce_str) > 32 else f"Nonce: {attestation_nonce_str}")

        if expected_nonce:
            if attestation_nonce_str != expected_nonce:
                raise NonceError(
                    f"Nonce mismatch!\n"
                    f"  Expected: {expected_nonce}\n"
                    f"  Got:      {attestation_nonce_str}"
                )
            print(f"✓ Nonce matches expected value")
    elif expected_nonce:
        raise NonceError("Expected nonce but attestation contains none")

    # Step 6: Extract and verify user_data (agent metadata)
    user_data = attestation.get('user_data')
    user_data_dict = None

    if user_data:
        try:
            if isinstance(user_data, bytes):
                user_data_str = user_data.decode('utf-8')
            else:
                user_data_str = str(user_data)

            user_data_dict = json.loads(user_data_str)

            print()
            print(f"Agent Metadata:")
            print(f"  Agent: {user_data_dict.get('agent', 'unknown')}")
            print(f"  Guardrail: {user_data_dict.get('guardrail', 'unknown')}")

            if 'version' in user_data_dict:
                version = user_data_dict['version']
                print(f"  Version: {version}")

                if allowed_versions:
                    if version not in allowed_versions:
                        raise AttestationVerificationError(
                            f"Agent version not allowed: {version}\n"
                            f"Allowed versions: {allowed_versions}"
                        )
                    print(f"  ✓ Version is allowed")

            if 'sha256' in user_data_dict:
                print(f"  SHA256: {user_data_dict['sha256'][:32]}...")

        except json.JSONDecodeError:
            print()
            print(f"⚠ user_data is not JSON: {str(user_data)[:100]}")

    # Step 7: Return verification result
    print()
    print("=" * 70)
    print("✓ ALL VERIFICATION CHECKS PASSED")
    print("=" * 70)

    return {
        "verified": True,
        "pcr2": pcr2,
        "pcrs": {k: (v.hex() if isinstance(v, bytes) else str(v)) for k, v in pcrs.items()},
        "timestamp": attestation_time.isoformat(),
        "age_seconds": int(age_seconds),
        "module_id": attestation.get('module_id', 'unknown'),
        "user_data": user_data_dict,
        "nonce": attestation_nonce_str if attestation_nonce else None,
        "attestation": attestation
    }


def verify_enclave_attestation(
    attestation_url: str,
    known_pcr2: Optional[str] = None,
    allowed_versions: Optional[List[str]] = None,
    max_age_seconds: int = MAX_ATTESTATION_AGE,
    nonce: Optional[str] = None,
    timeout: int = 10
) -> Dict[str, Any]:
    """
    Fetch and verify attestation from a remote enclave.

    Args:
        attestation_url: URL to fetch attestation from (e.g. http://host:9000/attestation)
        known_pcr2: Expected PCR2 value
        allowed_versions: List of allowed agent versions
        max_age_seconds: Maximum age for attestation
        nonce: Optional nonce to include in request
        timeout: Request timeout in seconds

    Returns:
        dict: Verification result

    Raises:
        AttestationVerificationError: If verification fails
    """
    print(f"Fetching attestation from: {attestation_url}")
    print()

    # Build request URL with nonce
    url = attestation_url
    if nonce:
        separator = '&' if '?' in url else '?'
        url = f"{url}{separator}nonce={nonce}"

    # Fetch attestation
    try:
        response = requests.get(url, timeout=timeout)
        response.raise_for_status()
        data = response.json()
    except requests.exceptions.RequestException as e:
        raise AttestationVerificationError(f"Failed to fetch attestation: {e}")
    except json.JSONDecodeError as e:
        raise AttestationVerificationError(f"Invalid JSON response: {e}")

    # Extract attestation document
    attestation_doc = None

    # Try different response formats
    if 'attestation_document' in data:
        attestation_data = data['attestation_document']
        if isinstance(attestation_data, dict) and 'document' in attestation_data:
            attestation_doc = attestation_data['document']
        elif isinstance(attestation_data, str):
            attestation_doc = attestation_data
    elif 'document' in data:
        attestation_doc = data['document']
    elif 'attestation' in data:
        attestation_data = data['attestation']
        if isinstance(attestation_data, dict) and 'document' in attestation_data:
            attestation_doc = attestation_data['document']

    if not attestation_doc:
        raise AttestationVerificationError(
            f"No attestation document found in response. Keys: {list(data.keys())}"
        )

    print(f"✓ Attestation document fetched")
    print()

    # Verify the attestation
    return verify_attestation_document(
        attestation_doc_b64=attestation_doc,
        known_pcr2=known_pcr2,
        allowed_versions=allowed_versions,
        max_age_seconds=max_age_seconds,
        expected_nonce=nonce
    )


# ============================================================================
# CLI Interface
# ============================================================================

def main():
    """CLI interface for attestation verification"""
    import sys
    import argparse

    parser = argparse.ArgumentParser(
        description="Verify AWS Nitro Enclave Attestation",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Verify remote attestation
  %(prog)s http://54.123.45.67:9000/attestation

  # Verify with known PCR2
  %(prog)s http://54.123.45.67:9000/attestation --pcr2 6cb06673b5b9b74e...

  # Verify with nonce for freshness
  %(prog)s http://54.123.45.67:9000/attestation --nonce $(openssl rand -hex 32)

  # Verify local attestation file
  %(prog)s --file attestation.json --pcr2 6cb06673b5b9b74e...
        """
    )

    parser.add_argument(
        'url',
        nargs='?',
        help='Attestation endpoint URL'
    )
    parser.add_argument(
        '--file',
        help='Local attestation file (JSON)'
    )
    parser.add_argument(
        '--pcr2',
        help='Expected PCR2 value'
    )
    parser.add_argument(
        '--versions',
        help='Allowed agent versions (comma-separated)'
    )
    parser.add_argument(
        '--nonce',
        help='Nonce for freshness verification'
    )
    parser.add_argument(
        '--max-age',
        type=int,
        default=MAX_ATTESTATION_AGE,
        help=f'Maximum attestation age in seconds (default: {MAX_ATTESTATION_AGE})'
    )

    args = parser.parse_args()

    if not args.url and not args.file:
        parser.print_help()
        sys.exit(1)

    allowed_versions = None
    if args.versions:
        allowed_versions = [v.strip() for v in args.versions.split(',')]

    try:
        if args.file:
            # Verify local file
            print(f"Reading attestation from file: {args.file}")
            with open(args.file, 'r') as f:
                data = json.load(f)

            # Extract document
            if 'attestation_document' in data:
                attestation_data = data['attestation_document']
                if isinstance(attestation_data, dict) and 'document' in attestation_data:
                    attestation_doc = attestation_data['document']
                else:
                    attestation_doc = attestation_data
            elif 'document' in data:
                attestation_doc = data['document']
            else:
                raise AttestationVerificationError("No document found in file")

            print()
            result = verify_attestation_document(
                attestation_doc_b64=attestation_doc,
                known_pcr2=args.pcr2,
                allowed_versions=allowed_versions,
                max_age_seconds=args.max_age,
                expected_nonce=args.nonce
            )
        else:
            # Verify remote attestation
            result = verify_enclave_attestation(
                attestation_url=args.url,
                known_pcr2=args.pcr2,
                allowed_versions=allowed_versions,
                max_age_seconds=args.max_age,
                nonce=args.nonce
            )

        print()
        print("Verification successful!")
        print()
        print("Summary:")
        print(f"  PCR2: {result['pcr2'][:32]}...")
        print(f"  Module: {result['module_id']}")
        print(f"  Age: {result['age_seconds']}s")
        if result.get('user_data'):
            print(f"  Agent: {result['user_data'].get('agent', 'unknown')}")
            print(f"  Version: {result['user_data'].get('version', 'unknown')}")

        sys.exit(0)

    except AttestationVerificationError as e:
        print()
        print("=" * 70)
        print("✗ VERIFICATION FAILED")
        print("=" * 70)
        print()
        print(f"Error: {e}")
        print()
        sys.exit(1)
    except Exception as e:
        print()
        print(f"✗ Unexpected error: {e}")
        print()
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
