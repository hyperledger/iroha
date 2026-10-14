"""Disposable loopback HTTP owner for exact staking transport qualification."""
import socket
import threading
import time
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


@contextmanager
def observation_server(body=b"ok", *, status=200, headers=None, header_delay=0,
                       chunk_delay=0, chunk_size=8192, probe_before_body=False,
                       disconnect=False):
    state = {"calls": [], "body_writes": 0, "peer_closed": False,
             "finished": threading.Event()}
    response_headers = {"Content-Type": "application/x-norito", "Connection": "close"}
    response_headers.update(headers or {})

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *args):
            pass

        def do_POST(self):
            try:
                size = int(self.headers.get("Content-Length", "0"))
                assert 0 <= size <= 64 * 1024
                state["calls"].append((self.command, self.path, dict(self.headers), self.rfile.read(size)))
                if disconnect:
                    return
                time.sleep(header_delay)
                self.send_response(status)
                for key, value in response_headers.items():
                    self.send_header(key, value)
                self.end_headers()
                if probe_before_body:
                    self.connection.settimeout(1)
                    state["peer_closed"] = self.connection.recv(1) == b""
                    return
                for offset in range(0, len(body), chunk_size):
                    time.sleep(chunk_delay)
                    self.wfile.write(body[offset:offset + chunk_size])
                    self.wfile.flush()
                    state["body_writes"] += 1
            except (BrokenPipeError, ConnectionResetError):
                state["peer_closed"] = True
            except socket.timeout:
                state["peer_closed"] = False
            finally:
                self.close_connection = True
                state["finished"].set()

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    server.daemon_threads = True
    thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True)
    thread.start()
    state["url"] = f"http://127.0.0.1:{server.server_port}"
    try:
        yield state
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=1)
