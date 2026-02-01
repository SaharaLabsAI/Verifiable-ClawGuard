#!/usr/bin/env python3
"""
Local HTTP Proxy - Runs inside the Nitro Enclave

This proxy listens on localhost:8888 and forwards HTTP/HTTPS requests
to the parent EC2 instance via vsock. The parent then forwards to the internet.

Architecture:
  httpx client -> localhost:8888 -> vsock:8001 (parent) -> Internet

Usage:
  python3 local_http_proxy.py --vsock-port 8001 --parent-cid 3
"""

import socket
import select
import sys
import argparse
import threading


def handle_connect_tunnel(client_sock, vsock_sock, request_data):
    """Handle CONNECT tunnel - bidirectional forwarding after 200 response"""
    try:
        # Send CONNECT request to parent
        vsock_sock.sendall(request_data)

        # Read 200 Connection Established response
        response = b""
        while b"\r\n\r\n" not in response:
            chunk = vsock_sock.recv(4096)
            if not chunk:
                print(f"[local-proxy] CONNECT: No response from parent", file=sys.stderr)
                return
            response += chunk

        # Forward 200 response to client
        client_sock.sendall(response)
        print(f"[local-proxy] CONNECT: Tunnel established, starting bidirectional forwarding")

        # Now do bidirectional forwarding for TLS passthrough
        sockets = [client_sock, vsock_sock]
        while True:
            readable, _, exceptional = select.select(sockets, [], sockets, 300)

            if exceptional:
                break

            if not readable:
                break

            for sock in readable:
                try:
                    data = sock.recv(8192)
                    if not data:
                        return

                    # Forward to the other socket
                    if sock is client_sock:
                        vsock_sock.sendall(data)
                    else:
                        client_sock.sendall(data)
                except:
                    return

    except Exception as e:
        print(f"[local-proxy] CONNECT tunnel error: {e}", file=sys.stderr)


def forward_to_vsock(client_sock, client_addr, parent_cid, vsock_port):
    """Forward HTTP request from localhost to parent via vsock"""
    vsock_sock = None
    try:
        # Read HTTP request headers first
        request_data = b""
        while b"\r\n\r\n" not in request_data:
            chunk = client_sock.recv(4096)
            if not chunk:
                return
            request_data += chunk

        # Parse request method
        request_line = request_data.split(b"\r\n")[0].decode('utf-8', errors='ignore')
        method = request_line.split(' ')[0] if ' ' in request_line else ""

        # Connect to parent via vsock
        vsock_sock = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
        vsock_sock.connect((parent_cid, vsock_port))

        # Handle CONNECT specially
        if method == "CONNECT":
            return handle_connect_tunnel(client_sock, vsock_sock, request_data)

        # For non-CONNECT, read full request including body
        headers_end = request_data.index(b"\r\n\r\n")
        headers = request_data[:headers_end].decode('utf-8', errors='ignore')

        content_length = 0
        for line in headers.split('\r\n'):
            if line.lower().startswith('content-length:'):
                content_length = int(line.split(':')[1].strip())
                break

        body_received = len(request_data) - headers_end - 4
        while body_received < content_length:
            chunk = client_sock.recv(4096)
            if not chunk:
                break
            request_data += chunk
            body_received += len(chunk)

        if not request_data:
            client_sock.close()
            return

        # Send request to parent
        vsock_sock.sendall(request_data)
        
        # Receive response from parent
        response_data = b""
        while True:
            chunk = vsock_sock.recv(4096)
            if not chunk:
                break
            response_data += chunk
            
            # Check if we have complete response
            if b"\r\n\r\n" in response_data:
                headers_end = response_data.index(b"\r\n\r\n")
                headers = response_data[:headers_end].decode('utf-8', errors='ignore')
                
                # Check Content-Length
                content_length = 0
                for line in headers.split('\r\n'):
                    if line.lower().startswith('content-length:'):
                        content_length = int(line.split(':')[1].strip())
                        break
                
                if content_length > 0:
                    body_received = len(response_data) - headers_end - 4
                    if body_received >= content_length:
                        break
                else:
                    # No content-length, check for chunked encoding or connection close
                    if b"transfer-encoding: chunked" in headers.lower().encode():
                        # For chunked, wait for 0\r\n\r\n
                        if response_data.endswith(b"0\r\n\r\n"):
                            break
                    else:
                        # Keep reading until connection closes
                        pass
        
        # Send response back to client
        client_sock.sendall(response_data)
        
        vsock_sock.close()
        client_sock.close()

    except Exception as e:
        print(f"[local-proxy] Error: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
    finally:
        try:
            if vsock_sock:
                vsock_sock.close()
        except:
            pass
        try:
            client_sock.close()
        except:
            pass


def main():
    parser = argparse.ArgumentParser(description="Local HTTP proxy for enclave")
    parser.add_argument("--listen-port", type=int, default=8888,
                       help="Local port to listen on (default: 8888)")
    parser.add_argument("--parent-cid", type=int, default=3,
                       help="Parent EC2 CID (default: 3)")
    parser.add_argument("--vsock-port", type=int, default=8001,
                       help="Vsock port on parent (default: 8001)")
    
    args = parser.parse_args()
    
    print(f"[local-proxy] Starting HTTP proxy on localhost:{args.listen_port}")
    print(f"[local-proxy] Forwarding to parent CID {args.parent_cid}:{args.vsock_port}")
    
    # Create listening socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(('127.0.0.1', args.listen_port))
    sock.listen(10)
    
    print(f"[local-proxy] Ready")
    
    try:
        while True:
            client_sock, client_addr = sock.accept()
            
            # Handle in thread
            thread = threading.Thread(
                target=forward_to_vsock,
                args=(client_sock, client_addr, args.parent_cid, args.vsock_port),
                daemon=True
            )
            thread.start()
    
    except KeyboardInterrupt:
        print("\n[local-proxy] Shutting down")
    finally:
        sock.close()


if __name__ == "__main__":
    main()
