"""Listener SSH señuelo (paramiko).

Levanta un servidor SSH falso que acepta cualquier contraseña (como los
honeypots reales), registra el intento de login y ofrece una shell falsa
que captura cada comando. Paramiko es bloqueante, por lo que el servidor
corre en un thread dedicado; los eventos se reportan con ``emit_sync``.
"""

import logging
import socketserver
import threading
from typing import Optional

from app.services.deception import personas, telemetry_svc

logger = logging.getLogger(__name__)

_host_key_lock = threading.Lock()
_host_key = None  # paramiko.RSAKey cacheado


def _get_host_key():
    """Genera (una vez) una host key RSA efímera para el señuelo."""
    global _host_key
    with _host_key_lock:
        if _host_key is None:
            import paramiko
            _host_key = paramiko.RSAKey.generate(2048)
        return _host_key


class SshListener:
    """Servidor SSH señuelo gestionado desde un thread."""

    proto = "ssh"
    MAX_COMMANDS = 50

    def __init__(self, device_id: str, role: str, host: str, port: int,
                 banner: Optional[str] = None, proto: Optional[str] = None):
        self.device_id = device_id
        self.role = role
        self.host = host
        self.port = port
        self.banner = banner
        if proto:
            self.proto = proto
        self._server: Optional[socketserver.ThreadingTCPServer] = None
        self._thread: Optional[threading.Thread] = None

    async def start(self) -> None:
        try:
            import paramiko  # noqa: F401
        except ImportError as exc:
            raise RuntimeError(
                "paramiko no está instalado; SSH señuelo deshabilitado"
            ) from exc

        _get_host_key()
        listener = self

        class _Handler(socketserver.BaseRequestHandler):
            def handle(inner_self):  # noqa: N805
                listener._handle_ssh(inner_self.request, inner_self.client_address)

        class _Server(socketserver.ThreadingTCPServer):
            allow_reuse_address = True
            daemon_threads = True

        self._server = _Server((self.host, self.port), _Handler)
        self.port = self._server.server_address[1]
        self._thread = threading.Thread(
            target=self._server.serve_forever, name=f"deception-ssh-{self.device_id}",
            daemon=True,
        )
        self._thread.start()
        logger.info("[deception] ssh %s:%s escuchando (%s)",
                    self.host, self.port, self.device_id)

    async def stop(self) -> None:
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
            self._server = None
        if self._thread is not None:
            self._thread.join(timeout=3)
            self._thread = None

    # ── Manejo en el thread ──────────────────────────────────

    def _handle_ssh(self, client_sock, addr) -> None:
        import paramiko

        src_ip, src_port = addr[0], addr[1]
        transport = paramiko.Transport(client_sock)
        try:
            banner = personas.banner_for(self.role, self.banner)
            transport.local_version = f"SSH-2.0-{banner}"
        except Exception:  # noqa: BLE001
            pass

        server = _SSHServer(self, src_ip, src_port)
        try:
            transport.add_server_key(_get_host_key())
            transport.start_server(server=server)
        except Exception as exc:  # noqa: BLE001
            logger.debug("[deception] SSH handshake falló con %s: %s", src_ip, exc)
            transport.close()
            return

        telemetry_svc.emit_sync(self.device_id, src_ip, "ssh", "connect",
                                src_port=src_port)
        chan = transport.accept(20)
        if chan is None:
            transport.close()
            return

        prompt = personas.prompt_for(self.role)
        try:
            chan.send(f"\r\n{prompt}")
            for _ in range(self.MAX_COMMANDS):
                data = chan.recv(1024)
                if not data:
                    break
                command = data.decode("utf-8", errors="replace").strip()
                if not command:
                    chan.send(prompt)
                    continue
                telemetry_svc.emit_sync(
                    self.device_id, src_ip, "ssh", "command",
                    username=server.username,
                    detail={"service": "ssh", "command": command},
                )
                response = personas.response_for(command)
                out = f"{response}\r\n{prompt}" if response else prompt
                chan.send(out)
        except Exception:  # noqa: BLE001
            pass
        finally:
            try:
                chan.close()
            except Exception:  # noqa: BLE001
                pass
            transport.close()


class _SSHServer:
    """Implementación perezosa de paramiko.ServerInterface.

    Se construye en runtime para no importar paramiko al cargar el módulo.
    """

    def __new__(cls, listener, src_ip, src_port):
        import paramiko

        class _ServerInterface(paramiko.ServerInterface):
            def __init__(self):
                self.listener = listener
                self.src_ip = src_ip
                self.src_port = src_port
                self.username = ""

            def check_auth_password(self, username, password):  # noqa: N802
                self.username = username
                telemetry_svc.emit_sync(
                    self.listener.device_id, self.src_ip, "ssh", "login_success",
                    username=username, success=True, src_port=self.src_port,
                    detail={"service": "ssh", "password": password},
                )
                return paramiko.AUTH_SUCCESSFUL

            def check_auth_publickey(self, username, key):  # noqa: N802
                return paramiko.AUTH_FAILED

            def get_allowed_auths(self, username):  # noqa: N802
                return "password"

            def check_channel_request(self, kind, chanid):  # noqa: N802
                return paramiko.OPEN_SUCCEEDED

            def check_channel_shell_request(self, channel):  # noqa: N802
                return True

            def check_channel_pty_request(self, *args, **kwargs):  # noqa: N802
                return True

        return _ServerInterface()
