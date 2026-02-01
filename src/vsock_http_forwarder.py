#!/usr/bin/env python3
"""
Vsock HTTP Forwarder - Runs on parent EC2

Listens on vsock and forwards HTTP/HTTPS requests from the enclave to the internet.
This allows the guardrail proxy inside the enclave to reach OpenAI API.

Usage:
  python3 vsock_http_forwarder.py --vsock-port 8001
"""

import socket
import http.client
import sys
import argparse
import threading
import select
from urllib.parse import urlparse


def handle_connect_tunnel(client_sock, target, leftover_data):
    """Handle HTTPS CONNECT tunnel for TLS passthrough"""
    target_sock = None
    try:
        # Parse target (format: "host:port")
        if ':' in target:
            host, port = target.rsplit(':', 1)
            port = int(port)
        else:
            host = target
            port = 443

        print(f"[http-forwarder] CONNECT {host}:{port} - connecting...")

        # Connect to target server
        target_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        target_sock.settimeout(30)
        target_sock.connect((host, port))
        print(f"[http-forwarder] CONNECT {host}:{port} - connected to target")

        # Send success response
        response = b"HTTP/1.1 200 Connection Established\r\n\r\n"
        client_sock.sendall(response)
        print(f"[http-forwarder] CONNECT {host}:{port} - sent 200 to client")

        # If there's leftover data from the initial read, send it to target
        if leftover_data:
            print(f"[http-forwarder] CONNECT {host}:{port} - forwarding {len(leftover_data)} bytes of leftover data")
            target_sock.sendall(leftover_data)

        print(f"[http-forwarder] CONNECT {host}:{port} - starting bidirectional tunnel")

        # Bidirectional forwarding (TLS passthrough)
        sockets = [client_sock, target_sock]
        bytes_client_to_target = 0
        bytes_target_to_client = 0

        while True:
            readable, _, exceptional = select.select(sockets, [], sockets, 300)

            if exceptional:
                print(f"[http-forwarder] CONNECT {host}:{port} - exceptional condition")
                break

            if not readable:
                # Timeout
                print(f"[http-forwarder] CONNECT {host}:{port} - timeout")
                break

            for sock in readable:
                try:
                    data = sock.recv(8192)
                    if not data:
                        direction = "client" if sock is client_sock else "target"
                        print(f"[http-forwarder] CONNECT {host}:{port} - {direction} closed connection (EOF)")
                        print(f"[http-forwarder] CONNECT {host}:{port} - transferred {bytes_client_to_target} bytes C->T, {bytes_target_to_client} bytes T->C")
                        return

                    # Forward to the other socket
                    if sock is client_sock:
                        target_sock.sendall(data)
                        bytes_client_to_target += len(data)
                    else:
                        client_sock.sendall(data)
                        bytes_target_to_client += len(data)
                except Exception as e:
                    print(f"[http-forwarder] CONNECT {host}:{port} - forward error: {e}")
                    return

    except Exception as e:
        print(f"[http-forwarder] CONNECT tunnel error: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        try:
            error_resp = b"HTTP/1.1 502 Bad Gateway\r\n\r\nCONNECT failed"
            client_sock.sendall(error_resp)
        except:
            pass
    finally:
        if target_sock:
            try:
                target_sock.close()
            except:
                pass


def handle_http_request(client_sock, client_addr):
    """Handle a single HTTP request from the enclave"""
    print(f"[http-forwarder] Connection from CID {client_addr[0]}")

    try:
        # Read HTTP request headers first
        request_data = b""
        while b"\r\n\r\n" not in request_data:
            chunk = client_sock.recv(4096)
            if not chunk:
                print("[http-forwarder] Connection closed before headers complete")
                return
            request_data += chunk

        # Parse request line
        headers_end = request_data.index(b"\r\n\r\n")
        request_str = request_data[:headers_end].decode('utf-8', errors='ignore')
        lines = request_str.split('\r\n')
        request_line = lines[0]

        # Extract method, URL, version
        parts = request_line.split(' ', 2)
        if len(parts) < 3:
            print(f"[http-forwarder] Invalid request: {request_line}")
            return

        method, url, version = parts

        # Handle CONNECT method for HTTPS tunneling
        if method == "CONNECT":
            return handle_connect_tunnel(client_sock, url, request_data[headers_end + 4:])

        # For non-CONNECT methods, read the full request including body
        headers_complete = True
        content_length = 0

        # Extract Content-Length
        for line in lines:
            if line.lower().startswith('content-length:'):
                content_length = int(line.split(':')[1].strip())
                break

        # Read remaining body if needed
        body_start = headers_end + 4
        body_received = len(request_data) - body_start

        while body_received < content_length:
            chunk = client_sock.recv(4096)
            if not chunk:
                break
            request_data += chunk
            body_received += len(chunk)

        if not request_data:
            print("[http-forwarder] Empty request")
            return
        
        # Parse URL
        if url.startswith('http'):
            parsed = urlparse(url)
            host = parsed.hostname
            port = parsed.port or (443 if parsed.scheme == 'https' else 80)
            path = parsed.path or '/'
            if parsed.query:
                path += '?' + parsed.query
            use_https = parsed.scheme == 'https'
        else:
            # Extract from Host header
            host = None
            for line in lines[1:]:
                if line.lower().startswith('host:'):
                    host = line.split(':', 1)[1].strip()
                    break
            if not host:
                return
            port = 443
            path = url
            use_https = True
        
        print(f"[http-forwarder] {method} {host}{path}")
        
        # Build headers dict
        headers = {}
        body_start = request_data.find(b'\r\n\r\n') + 4
        body = request_data[body_start:] if body_start > 4 else None
        
        for line in lines[1:]:
            if ':' in line and line.strip():
                key, value = line.split(':', 1)
                headers[key.strip()] = value.strip()
        
        # Forward to target
        if use_https:
            conn = http.client.HTTPSConnection(host, port, timeout=300)
        else:
            conn = http.client.HTTPConnection(host, port, timeout=300)
        
        try:
            conn.request(method, path, body=body, headers=headers)
            response = conn.getresponse()
            response_body = response.read()
            
            # Build response
            response_line = f"HTTP/1.1 {response.status} {response.reason}\r\n"
            response_headers = ""
            for header, value in response.getheaders():
                response_headers += f"{header}: {value}\r\n"
            
            full_response = response_line.encode() + response_headers.encode() + b"\r\n" + response_body
            
            # Send back to enclave
            client_sock.sendall(full_response)
            
            print(f"[http-forwarder] Response: {response.status} ({len(response_body)} bytes)")
            
        finally:
            conn.close()
    
    except Exception as e:
        print(f"[http-forwarder] Error: {e}", file=sys.stderr)
        try:
            error_resp = b"HTTP/1.1 502 Bad Gateway\r\n\r\nProxy Error"
            client_sock.sendall(error_resp)
        except:
            pass
    
    finally:
        client_sock.close()


def main():
    parser = argparse.ArgumentParser(description="Vsock HTTP forwarder for Nitro Enclaves")
    parser.add_argument("--vsock-port", type=int, default=8001, 
                       help="Vsock port to listen on (default: 8001)")
    args = parser.parse_args()
    
    print("=" * 60)
    print("  Vsock HTTP Forwarder")
    print("=" * 60)
    print(f"Listening on vsock port {args.vsock_port}")
    print("Forwarding HTTP/HTTPS requests from enclave to internet")
    print()
    
    # Create vsock socket
    sock = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
    sock.bind((socket.VMADDR_CID_ANY, args.vsock_port))
    sock.listen(10)
    
    print("[http-forwarder] Ready")
    
    try:
        while True:
            client_sock, client_addr = sock.accept()
            
            # Handle in thread
            thread = threading.Thread(
                target=handle_http_request,
                args=(client_sock, client_addr),
                daemon=True
            )
            thread.start()
    
    except KeyboardInterrupt:
        print("\n[http-forwarder] Shutting down")
    finally:
        sock.close()


if __name__ == "__main__":
    main()
