"""NetPulse — Personas de dispositivos señuelo.

Define credenciales falsas, banners y comportamientos por rol. Son el
"guión" que siguen los listeners nativos: qué credenciales aceptar
(aunque en SSH se registra todo intento), qué banner devolver y qué
respuestas simular a comandos.

IMPORTANTE: todas las credenciales son de mentira. Nunca deben coincidir
con credenciales reales del entorno.
"""

from app.models.deception import DeceptionRole

# Credenciales débiles por defecto típicas de cada tipo de dispositivo.
# Se usan para decidir si un login se considera "exitoso" (en señuelos
# normalmente aceptamos igual para capturar el resto de la sesión).
DEFAULT_CREDENTIALS: dict[DeceptionRole, list[tuple[str, str]]] = {
    DeceptionRole.PC: [("admin", "admin"), ("user", "password"), ("administrador", "1234")],
    DeceptionRole.SERVER: [("root", "root"), ("root", "toor"), ("admin", "admin")],
    DeceptionRole.CAMERA: [("admin", "admin"), ("admin", "12345"), ("admin", "")],
    DeceptionRole.SWITCH: [("admin", "admin"), ("cisco", "cisco"), ("manager", "manager")],
    DeceptionRole.FIREWALL: [("admin", "admin"), ("admin", "Fortinet"), ("root", "fortinet")],
    DeceptionRole.ROUTER: [("admin", ""), ("admin", "admin"), ("cisco", "cisco")],
}

# Banners de identificación por rol (fallback si el servicio no define uno).
DEFAULT_BANNER: dict[DeceptionRole, str] = {
    DeceptionRole.PC: "OpenSSH_8.9",
    DeceptionRole.SERVER: "OpenSSH_8.2p1 Ubuntu-4ubuntu0.5",
    DeceptionRole.CAMERA: "Hikvision-Webs",
    DeceptionRole.SWITCH: "Cisco IOS SSH 1.25",
    DeceptionRole.FIREWALL: "FortiGate-60F",
    DeceptionRole.ROUTER: "MikroTik RouterOS 7.11",
}

# Prompt falso que se muestra tras un login "exitoso" (shell/CLI).
SHELL_PROMPT: dict[DeceptionRole, str] = {
    DeceptionRole.PC: "$ ",
    DeceptionRole.SERVER: "# ",
    DeceptionRole.CAMERA: "> ",
    DeceptionRole.SWITCH: "sw-access-01# ",
    DeceptionRole.FIREWALL: "fw-edge-01 # ",
    DeceptionRole.ROUTER: "[admin@router-core-01] > ",
}

# Respuestas simuladas a comandos frecuentes de atacantes (best-effort).
# Si el comando no está, se devuelve una respuesta genérica vacía.
COMMAND_RESPONSES: dict[str, str] = {
    "id": "uid=0(root) gid=0(root) groups=0(root)",
    "whoami": "root",
    "uname -a": "Linux decoy 5.15.0-91-generic #101-Ubuntu SMP x86_64 GNU/Linux",
    "hostname": "decoy",
    "pwd": "/root",
    "ls": "bin  boot  dev  etc  home  root  tmp  usr  var",
    "ls -la": "total 8\ndrwx------ 2 root root 4096 .\ndrwxr-xr-x 1 root root 4096 ..",
    "cat /etc/passwd": "root:x:0:0:root:/root:/bin/bash\nwww-data:x:33:33:www-data:/var/www:/usr/sbin/nologin",
    "ifconfig": "eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500",
    "ip addr": "1: lo: <LOOPBACK,UP> mtu 65536\n2: eth0: <BROADCAST,MULTICAST,UP> mtu 1500",
    "show version": "Cisco IOS Software, Version 15.2(4)E",
    "enable": "",
}


def credentials_for(role: DeceptionRole | str) -> list[tuple[str, str]]:
    """Credenciales señuelo para un rol (por defecto, las de PC)."""
    try:
        return DEFAULT_CREDENTIALS[DeceptionRole(role)]
    except (ValueError, KeyError):
        return DEFAULT_CREDENTIALS[DeceptionRole.PC]


def banner_for(role: DeceptionRole | str, override: str | None = None) -> str:
    """Banner para un rol, con override explícito si se indica."""
    if override:
        return override
    try:
        return DEFAULT_BANNER[DeceptionRole(role)]
    except (ValueError, KeyError):
        return DEFAULT_BANNER[DeceptionRole.PC]


def prompt_for(role: DeceptionRole | str) -> str:
    """Prompt de shell/CLI falso para un rol."""
    try:
        return SHELL_PROMPT[DeceptionRole(role)]
    except (ValueError, KeyError):
        return "$ "


def response_for(command: str) -> str:
    """Respuesta simulada a un comando (o cadena vacía)."""
    return COMMAND_RESPONSES.get(command.strip(), "")
