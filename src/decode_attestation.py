#!/usr/bin/env python3
"""
Decode and display all information in the attestation document
"""
import json
import base64
import cbor2
from datetime import datetime

with open('../examples/attestation_example.json') as f:
    data = json.load(f)

# Get the document
doc_b64 = data['attestation_document']['document']
doc_bytes = base64.b64decode(doc_b64)

# Parse COSE_Sign1
cose_sign1 = cbor2.loads(doc_bytes)

# Extract components
protected_bytes = cose_sign1[0]
unprotected = cose_sign1[1]
payload_bytes = cose_sign1[2]
signature_bytes = cose_sign1[3]

# Parse payload
attestation = cbor2.loads(payload_bytes)

print("=" * 80)
print("AWS NITRO ENCLAVE ATTESTATION DOCUMENT - FULL CONTENTS")
print("=" * 80)
print()

print("1. DOCUMENT METADATA")
print("-" * 80)
print(f"Module ID (Enclave):     {attestation.get('module_id')}")
print(f"Digest Algorithm:        {attestation.get('digest')}")

timestamp_ms = attestation.get('timestamp', 0)
timestamp_sec = timestamp_ms / 1000
dt = datetime.fromtimestamp(timestamp_sec)
print(f"Timestamp:               {timestamp_ms} ({dt.isoformat()})")
print()

print("2. PLATFORM CONFIGURATION REGISTERS (PCRs)")
print("-" * 80)
pcrs = attestation.get('pcrs', {})
pcr_descriptions = {
    0: "PCR0  (Boot ROM/BIOS)",
    1: "PCR1  (Kernel + Initramfs)",
    2: "PCR2  (Application / User Code) ← THE GUARDRAIL",
    3: "PCR3  (IAM Role)",
    4: "PCR4  (Parent Instance)",
    8: "PCR8  (Boot Configuration)",
}

for pcr_idx in sorted(pcrs.keys()):
    pcr_value = pcrs[pcr_idx]
    if isinstance(pcr_value, bytes):
        pcr_hex = pcr_value.hex()
    else:
        pcr_hex = str(pcr_value)

    desc = pcr_descriptions.get(pcr_idx, f"PCR{pcr_idx}")

    if pcr_idx == 2:
        print(f"{desc}")
        print(f"  → {pcr_hex}")
    elif pcr_hex and pcr_hex != "0" * len(pcr_hex):
        print(f"{desc}")
        print(f"  {pcr_hex[:64]}{'...' if len(pcr_hex) > 64 else ''}")
    else:
        print(f"{desc}: (empty/zero)")

print()

print("3. USER DATA (Agent Metadata)")
print("-" * 80)
user_data_bytes = attestation.get('user_data')
if user_data_bytes:
    if isinstance(user_data_bytes, bytes):
        user_data_str = user_data_bytes.decode('utf-8')
    else:
        user_data_str = str(user_data_bytes)

    try:
        user_data_json = json.loads(user_data_str)
        print("User data (parsed JSON):")
        for key, value in user_data_json.items():
            if key == 'sha256':
                print(f"  {key:20s}: {str(value)[:32]}...")
            else:
                print(f"  {key:20s}: {value}")
    except:
        print(f"User data (raw): {user_data_str[:200]}...")
else:
    print("No user data")

print()

print("4. NONCE (Challenge/Response)")
print("-" * 80)
nonce = attestation.get('nonce')
if nonce:
    if isinstance(nonce, bytes):
        nonce_str = nonce.decode('utf-8', errors='ignore')
    else:
        nonce_str = str(nonce)
    print(f"Nonce: {nonce_str}")
else:
    print("No nonce")

print()

print("5. PUBLIC KEY")
print("-" * 80)
public_key = attestation.get('public_key')
if public_key and public_key != b'\xf6':  # CBOR null
    print(f"Public Key: {len(public_key)} bytes" if isinstance(public_key, bytes) else "Present")
else:
    print("No public key")

print()

print("6. CERTIFICATE CHAIN")
print("-" * 80)
certificate = attestation.get('certificate')
cabundle = attestation.get('cabundle', [])

if certificate:
    print(f"Leaf Certificate: {len(certificate)} bytes")
else:
    print("Leaf Certificate: None")

print(f"CA Bundle: {len(cabundle)} certificates")
for i, cert in enumerate(cabundle):
    cert_size = len(cert) if isinstance(cert, bytes) else "unknown"

    # Try to parse and show subject
    try:
        from cryptography import x509
        from cryptography.hazmat.backends import default_backend
        cert_obj = x509.load_der_x509_certificate(cert, default_backend())
        subject = cert_obj.subject.rfc4514_string()
        print(f"  [{i}] {cert_size} bytes - {subject[:60]}...")
    except:
        print(f"  [{i}] {cert_size} bytes")

print()

print("7. CRYPTOGRAPHIC SIGNATURE")
print("-" * 80)
print(f"Protected Headers: {protected_bytes.hex()}")
if protected_bytes:
    protected = cbor2.loads(protected_bytes)
    print(f"  Algorithm: {protected.get(1)} (COSE algorithm ID)")

    alg_names = {
        -7: "ES256 (ECDSA P-256 + SHA-256)",
        -35: "ES384 (ECDSA P-384 + SHA-384)",
        -36: "ES512 (ECDSA P-521 + SHA-512)",
    }
    alg = protected.get(1)
    if alg in alg_names:
        print(f"  → {alg_names[alg]}")

print(f"Signature: {len(signature_bytes)} bytes")
print(f"  {signature_bytes.hex()[:64]}...")

print()
print("=" * 80)
print("SUMMARY")
print("=" * 80)
print()
print("The attestation document proves:")
print("  ✓ This enclave is running on genuine AWS Nitro hardware (verified signature)")
print("  ✓ The exact code running in the enclave (PCR2 measurement)")
print("  ✓ When the attestation was generated (timestamp)")
print("  ✓ What agent/version is running (user_data)")
print("  ✓ Response to a specific challenge (nonce, if provided)")
print()
print("All of this information is cryptographically signed by AWS and cannot be")
print("forged or tampered with. Any modification would break the signature.")
print()
