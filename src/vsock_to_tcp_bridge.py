#!/usr/bin/env python3
"""
Vsock-to-TCP Bridge - Runs INSIDE the enclave

Listens on vsock port and forwards to local TCP port.
This allows the parent EC2 to connect via vsock to services
running on TCP inside the enclave.

Usage (inside enclave):
    python3 vsock_to_tcp_bridge.py --vsock-port 18789 --tcp-port 18789
"""

import socket
import select
import sys
import threading
import argparse


class VsockToTcpBridge:
    """Bridge vsock connections to local TCP port"""

    def __init__(self, vsock_port: int, tcp_host: str, tcp_port: int):
        self.vsock_port = vsock_port
        self.tcp_host = tcp_host
        self.tcp_port = tcp_port
        self.running = False

    def forward_data(self, source: socket.socket, destination: socket.socket, name: str):
        """Forward data from source to destination"""
        try:
            while self.running:
                ready = select.select([source], [], [], 1.0)
                if not ready[0]:
                    continue

                data = source.recv(8192)
                if not data:
                    break

                destination.sendall(data)
        except Exception as e:
            pass  # Silent failure
        finally:
            try:
                source.close()
                destination.close()
            except:
                pass

    def handle_connection(self, vsock_conn: socket.socket):
        """Handle a single vsock connection by forwarding to TCP"""
        try:
            # Connect to local TCP service
            tcp_conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            tcp_conn.connect((self.tcp_host, self.tcp_port))

            # Create bidirectional forwarding threads
            vsock_to_tcp = threading.Thread(
                target=self.forward_data,
                args=(vsock_conn, tcp_conn, "vsock→tcp"),
                daemon=True
            )
            tcp_to_vsock = threading.Thread(
                target=self.forward_data,
                args=(tcp_conn, vsock_conn, "tcp→vsock"),
                daemon=True
            )

            vsock_to_tcp.start()
            tcp_to_vsock.start()

            vsock_to_tcp.join()
            tcp_to_vsock.join()

        except Exception as e:
            pass  # Silent failure
        finally:
            try:
                vsock_conn.close()
            except:
                pass

    def start(self):
        """Start the bridge server"""
        # Create vsock listening socket
        vsock_sock = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
        vsock_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        try:
            vsock_sock.bind((socket.VMADDR_CID_ANY, self.vsock_port))
            vsock_sock.listen(10)

            self.running = True

            while self.running:
                vsock_sock.settimeout(1.0)
                try:
                    vsock_conn, _ = vsock_sock.accept()

                    # Handle each connection in a thread
                    handler = threading.Thread(
                        target=self.handle_connection,
                        args=(vsock_conn,),
                        daemon=True
                    )
                    handler.start()

                except socket.timeout:
                    continue
                except KeyboardInterrupt:
                    self.running = False
                    break

        except Exception as e:
            sys.exit(1)
        finally:
            vsock_sock.close()


def main():
    parser = argparse.ArgumentParser(
        description="Vsock-to-TCP bridge (runs inside enclave)"
    )

    parser.add_argument(
        "--vsock-port",
        type=int,
        required=True,
        help="Vsock port to listen on"
    )
    parser.add_argument(
        "--tcp-host",
        type=str,
        default="127.0.0.1",
        help="TCP host to connect to (default: 127.0.0.1)"
    )
    parser.add_argument(
        "--tcp-port",
        type=int,
        required=True,
        help="TCP port to connect to"
    )

    args = parser.parse_args()

    bridge = VsockToTcpBridge(
        vsock_port=args.vsock_port,
        tcp_host=args.tcp_host,
        tcp_port=args.tcp_port
    )

    try:
        bridge.start()
    except KeyboardInterrupt:
        sys.exit(0)


if __name__ == "__main__":
    main()
