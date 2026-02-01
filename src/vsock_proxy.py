#!/usr/bin/env python3
"""
Vsock Proxy - Bidirectional proxy between TCP and vsock

This script runs on the PARENT EC2 INSTANCE and forwards traffic between:
- TCP port (accessible from outside) ←→ Vsock port (connects to enclave)

Use cases:
1. Forward MoltBot WebSocket: TCP :18789 ←→ Vsock CID:16 port:18789
2. Forward guardrail proxy: TCP :8080 ←→ Vsock CID:16 port:8080

Usage:
    # Forward MoltBot gateway
    ./vsock_proxy.py --tcp-port 18789 --vsock-cid 16 --vsock-port 18789

    # Forward guardrail proxy for debugging
    ./vsock_proxy.py --tcp-port 8080 --vsock-cid 16 --vsock-port 8080
"""

import socket
import select
import sys
import threading
import argparse
from typing import Tuple


class VsockProxy:
    """Bidirectional proxy between TCP and vsock"""

    def __init__(
        self,
        tcp_host: str,
        tcp_port: int,
        vsock_cid: int,
        vsock_port: int
    ):
        self.tcp_host = tcp_host
        self.tcp_port = tcp_port
        self.vsock_cid = vsock_cid
        self.vsock_port = vsock_port
        self.running = False

    def forward_data(self, source: socket.socket, destination: socket.socket, name: str):
        """Forward data from source to destination"""
        try:
            while self.running:
                # Wait for data with timeout
                ready = select.select([source], [], [], 1.0)
                if not ready[0]:
                    continue

                data = source.recv(8192)
                if not data:
                    print(f"  [{name}] Connection closed")
                    break

                destination.sendall(data)
        except Exception as e:
            print(f"  [{name}] Error: {e}")
        finally:
            try:
                source.close()
                destination.close()
            except:
                pass

    def handle_connection(self, tcp_conn: socket.socket, addr: Tuple[str, int]):
        """Handle a single TCP connection by proxying to vsock"""
        print(f"[+] New connection from {addr[0]}:{addr[1]}")

        try:
            # Connect to enclave via vsock
            vsock_conn = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
            vsock_conn.connect((self.vsock_cid, self.vsock_port))
            print(f"    ✓ Connected to enclave CID {self.vsock_cid}:{self.vsock_port}")

            # Create bidirectional forwarding threads
            tcp_to_vsock = threading.Thread(
                target=self.forward_data,
                args=(tcp_conn, vsock_conn, f"{addr[0]}:{addr[1]} → enclave"),
                daemon=True
            )
            vsock_to_tcp = threading.Thread(
                target=self.forward_data,
                args=(vsock_conn, tcp_conn, f"enclave → {addr[0]}:{addr[1]}"),
                daemon=True
            )

            tcp_to_vsock.start()
            vsock_to_tcp.start()

            # Wait for threads to finish
            tcp_to_vsock.join()
            vsock_to_tcp.join()

        except Exception as e:
            print(f"    ✗ Error connecting to enclave: {e}")
        finally:
            try:
                tcp_conn.close()
            except:
                pass
            print(f"[-] Connection closed: {addr[0]}:{addr[1]}")

    def start(self):
        """Start the proxy server"""
        print("=" * 60)
        print("  Vsock Proxy Server")
        print("=" * 60)
        print(f"  TCP:   {self.tcp_host}:{self.tcp_port}")
        print(f"  Vsock: CID {self.vsock_cid}:{self.vsock_port}")
        print("=" * 60)
        print()

        # Create TCP listening socket
        tcp_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        tcp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        try:
            tcp_sock.bind((self.tcp_host, self.tcp_port))
            tcp_sock.listen(10)
            print(f"✓ Listening on {self.tcp_host}:{self.tcp_port}")
            print(f"  Forwarding to enclave CID {self.vsock_cid}:{self.vsock_port}")
            print()
            print("Press Ctrl+C to stop")
            print()

            self.running = True

            while self.running:
                # Accept connections with timeout
                tcp_sock.settimeout(1.0)
                try:
                    tcp_conn, addr = tcp_sock.accept()

                    # Handle each connection in a thread
                    handler = threading.Thread(
                        target=self.handle_connection,
                        args=(tcp_conn, addr),
                        daemon=True
                    )
                    handler.start()

                except socket.timeout:
                    continue
                except KeyboardInterrupt:
                    print("\n\nShutting down...")
                    self.running = False
                    break

        except Exception as e:
            print(f"✗ Error: {e}")
            sys.exit(1)
        finally:
            tcp_sock.close()
            print("✓ Proxy stopped")


def main():
    parser = argparse.ArgumentParser(
        description="Vsock proxy for forwarding TCP ←→ Vsock",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Forward MoltBot WebSocket gateway
  %(prog)s --tcp-port 18789 --vsock-cid 16 --vsock-port 18789

  # Forward guardrail proxy for debugging
  %(prog)s --tcp-port 8080 --vsock-cid 16 --vsock-port 8080

  # Listen on specific IP
  %(prog)s --tcp-host 0.0.0.0 --tcp-port 18789 --vsock-cid 16 --vsock-port 18789
        """
    )

    parser.add_argument(
        "--tcp-host",
        type=str,
        default="127.0.0.1",
        help="TCP host to listen on (default: 127.0.0.1)"
    )
    parser.add_argument(
        "--tcp-port",
        type=int,
        required=True,
        help="TCP port to listen on"
    )
    parser.add_argument(
        "--vsock-cid",
        type=int,
        required=True,
        help="Vsock CID of the enclave"
    )
    parser.add_argument(
        "--vsock-port",
        type=int,
        required=True,
        help="Vsock port in the enclave"
    )

    args = parser.parse_args()

    # Create and start proxy
    proxy = VsockProxy(
        tcp_host=args.tcp_host,
        tcp_port=args.tcp_port,
        vsock_cid=args.vsock_cid,
        vsock_port=args.vsock_port
    )

    try:
        proxy.start()
    except KeyboardInterrupt:
        print("\n\nInterrupted")
        sys.exit(0)


if __name__ == "__main__":
    main()
