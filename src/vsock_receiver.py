#!/usr/bin/env python3
"""
Vsock Receiver - Receives MoltBot tarball from parent EC2 instance

This script runs inside the Nitro Enclave and listens on vsock for
the MoltBot package to be injected by the parent instance.
"""

import socket
import hashlib
import json
import sys
import os
from pathlib import Path


def receive_agent_package(port: int = 9000, output_path: str = "/tmp/openclaw.tgz"):
    """
    Receive OpenClaw package via vsock from parent instance

    Args:
        port: Vsock port to listen on
        output_path: Where to save the received tarball

    Returns:
        dict: Metadata about the received package
    """
    print(f"[vsock] Listening on vsock port {port}...")

    # Create vsock socket
    # AF_VSOCK = vsock address family
    # SOCK_STREAM = TCP-like reliable connection
    sock = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)

    # VMADDR_CID_ANY means accept connections from any CID
    # In Nitro Enclaves, CID 3 = parent instance
    sock.bind((socket.VMADDR_CID_ANY, port))
    sock.listen(1)

    print("[vsock] Waiting for connection from parent instance...")
    conn, addr = sock.accept()
    print(f"[vsock] Connected! Sender CID: {addr[0]}")

    try:
        # Optimize socket buffers for large transfers
        conn.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 2 * 1024 * 1024)  # 2MB recv buffer

        # Step 1: Receive metadata length (4 bytes, big-endian)
        metadata_len_bytes = conn.recv(4)
        if len(metadata_len_bytes) != 4:
            raise ValueError("Failed to receive metadata length")

        metadata_len = int.from_bytes(metadata_len_bytes, 'big')
        print(f"[vsock] Expecting metadata: {metadata_len} bytes")

        # Step 2: Receive metadata JSON
        metadata_bytes = b""
        while len(metadata_bytes) < metadata_len:
            chunk = conn.recv(min(8192, metadata_len - len(metadata_bytes)))
            if not chunk:
                raise ValueError("Connection closed while receiving metadata")
            metadata_bytes += chunk

        metadata = json.loads(metadata_bytes.decode('utf-8'))
        print(f"[vsock] Receiving package: {metadata['package']} v{metadata['version']}")
        print(f"[vsock] Expected SHA256: {metadata['sha256']}")
        print(f"[vsock] OPENAI_API_KEY: {'provided' if (metadata.get('openai_api_key') or metadata.get('api_key')) else 'not provided'}")
        print(f"[vsock] OPENROUTER_API_KEY: {'provided' if metadata.get('openrouter_api_key') else 'not provided'}")
        print(f"[vsock] SERPER_API_KEY: {'provided' if metadata.get('serper_api_key') else 'not provided'}")
        print(f"[vsock] Gateway Token: {'provided' if metadata.get('gateway_token') else 'not provided'}")

        # Step 3: Receive tarball data and stream to disk
        print("[vsock] Receiving tarball data...")

        # Prepare output file
        output_path_obj = Path(output_path)
        output_path_obj.parent.mkdir(parents=True, exist_ok=True)

        last_progress = 0
        import time
        start_time = time.time()
        total_size = 0
        hasher = hashlib.sha256()

        # Stream directly to disk while hashing
        with open(output_path, 'wb') as f:
            while True:
                chunk = conn.recv(256 * 1024)  # 256KB chunks (matches sender)
                if not chunk:
                    break

                # Write and hash in one pass
                f.write(chunk)
                hasher.update(chunk)
                total_size += len(chunk)

                # Progress indicator every 50MB with speed
                current_mb = total_size / 1024 / 1024
                if current_mb - last_progress >= 50:
                    elapsed = time.time() - start_time
                    speed_mbps = current_mb / elapsed if elapsed > 0 else 0
                    print(f"[vsock]   Received: {current_mb:.1f} MB - {speed_mbps:.1f} MB/s")
                    last_progress = current_mb

        elapsed = time.time() - start_time
        speed_mbps = (total_size / 1024 / 1024) / elapsed if elapsed > 0 else 0
        print(f"[vsock] Received complete tarball: {total_size} bytes ({total_size / 1024 / 1024:.2f} MB in {elapsed:.1f}s - {speed_mbps:.1f} MB/s)")
        print(f"[vsock] ✓ Tarball saved to: {output_path}")

        # Step 4: Verify SHA256 hash
        print("[vsock] Verifying integrity...")
        actual_hash = hasher.hexdigest()
        expected_hash = metadata['sha256']

        if actual_hash != expected_hash:
            raise ValueError(
                f"Hash mismatch!\n"
                f"  Expected: {expected_hash}\n"
                f"  Got:      {actual_hash}"
            )

        print(f"[vsock] ✓ Hash verified: {actual_hash}")

        # Return metadata for attestation
        # Note: secrets are included here but won't be saved to metadata file (security)
        return {
            "package": metadata['package'],
            "version": metadata['version'],
            "sha256": actual_hash,
            "size_bytes": total_size,
            "received_from_cid": addr[0],
            "api_key": metadata.get('api_key', ''),  # Legacy compatibility
            "openai_api_key": metadata.get('openai_api_key', metadata.get('api_key', '')),
            "openrouter_api_key": metadata.get('openrouter_api_key', ''),
            "serper_api_key": metadata.get('serper_api_key', ''),
            "gateway_token": metadata.get('gateway_token', '')  # Return for config generation
        }

    except Exception as e:
        print(f"[vsock] ERROR: {e}", file=sys.stderr)
        raise
    finally:
        conn.close()
        sock.close()


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Receive agent package via vsock")
    parser.add_argument(
        "--port",
        type=int,
        default=9000,
        help="Vsock port to listen on (default: 9000)"
    )
    parser.add_argument(
        "--output",
        type=str,
        default="/tmp/openclaw.tgz",
        help="Output path for tarball (default: /tmp/openclaw.tgz)"
    )
    parser.add_argument(
        "--metadata-output",
        type=str,
        default="/tmp/agent_metadata.json",
        help="Output path for metadata JSON (default: /tmp/agent_metadata.json)"
    )
    parser.add_argument(
        "--apikey-output",
        type=str,
        default="/tmp/api_key",
        help="Output path for API key (default: /tmp/api_key)"
    )
    parser.add_argument(
        "--openai-apikey-output",
        type=str,
        default="/tmp/openai_api_key",
        help="Output path for OPENAI_API_KEY (default: /tmp/openai_api_key)"
    )
    parser.add_argument(
        "--openrouter-apikey-output",
        type=str,
        default="/tmp/openrouter_api_key",
        help="Output path for OPENROUTER_API_KEY (default: /tmp/openrouter_api_key)"
    )
    parser.add_argument(
        "--serper-apikey-output",
        type=str,
        default="/tmp/serper_api_key",
        help="Output path for SERPER_API_KEY (default: /tmp/serper_api_key)"
    )
    parser.add_argument(
        "--gateway-token-output",
        type=str,
        default="/tmp/gateway_token",
        help="Output path for gateway token (default: /tmp/gateway_token)"
    )

    args = parser.parse_args()

    try:
        result = receive_agent_package(port=args.port, output_path=args.output)

        # Save metadata for attestation (excluding secrets for security)
        metadata_to_save = {
            k: v
            for k, v in result.items()
            if k not in ['api_key', 'openai_api_key', 'openrouter_api_key', 'serper_api_key', 'gateway_token']
        }

        with open(args.metadata_output, 'w') as f:
            json.dump(metadata_to_save, f, indent=2)

        print(f"[vsock] ✓ Metadata saved to: {args.metadata_output}")

        # Save legacy API key file for backward compatibility
        if result.get('api_key'):
            with open(args.apikey_output, 'w') as f:
                f.write(result['api_key'])
            # Secure permissions: only readable by owner
            os.chmod(args.apikey_output, 0o600)
            print(f"[vsock] ✓ Legacy API key saved to: {args.apikey_output} (mode 0600)")
        else:
            print(f"[vsock] ⚠ No legacy API key provided")

        # Save OPENAI_API_KEY to separate file with secure permissions
        if result.get('openai_api_key'):
            with open(args.openai_apikey_output, 'w') as f:
                f.write(result['openai_api_key'])
            os.chmod(args.openai_apikey_output, 0o600)
            print(f"[vsock] ✓ OPENAI_API_KEY saved to: {args.openai_apikey_output} (mode 0600)")
        else:
            print(f"[vsock] ⚠ No OPENAI_API_KEY provided")

        # Save OPENROUTER_API_KEY to separate file with secure permissions
        if result.get('openrouter_api_key'):
            with open(args.openrouter_apikey_output, 'w') as f:
                f.write(result['openrouter_api_key'])
            os.chmod(args.openrouter_apikey_output, 0o600)
            print(f"[vsock] ✓ OPENROUTER_API_KEY saved to: {args.openrouter_apikey_output} (mode 0600)")
        else:
            print(f"[vsock] ⚠ No OPENROUTER_API_KEY provided")

        # Save SERPER_API_KEY to separate file with secure permissions
        if result.get('serper_api_key'):
            with open(args.serper_apikey_output, 'w') as f:
                f.write(result['serper_api_key'])
            os.chmod(args.serper_apikey_output, 0o600)
            print(f"[vsock] ✓ SERPER_API_KEY saved to: {args.serper_apikey_output} (mode 0600)")
        else:
            print(f"[vsock] ⚠ No SERPER_API_KEY provided")

        # Save gateway token to separate file with secure permissions
        if result.get('gateway_token'):
            with open(args.gateway_token_output, 'w') as f:
                f.write(result['gateway_token'])
            # Secure permissions: only readable by owner
            os.chmod(args.gateway_token_output, 0o600)
            print(f"[vsock] ✓ Gateway token saved to: {args.gateway_token_output} (mode 0600)")
        else:
            print(f"[vsock] ⚠ No gateway token provided")

        print("[vsock] ✓ Reception complete!")
        sys.exit(0)

    except Exception as e:
        print(f"[vsock] FATAL: {e}", file=sys.stderr)
        sys.exit(1)
