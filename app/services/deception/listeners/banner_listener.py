"""Listener señuelo para protocolos "banner" (RTSP, SMB, etc.).

Registra la interacción y, cuando el protocolo lo permite (RTSP),
responde con un banner válido. Para SMB u otros solo se captura el
intento (suficiente para saber que el atacante tocó el dispositivo).
"""

import asyncio

from app.services.deception.listeners.base import BaseListener

RTSP_RESPONSE = (
    b"RTSP/1.0 200 OK\r\n"
    b"CSeq: 1\r\n"
    b"Server: DSS/6.0\r\n"
    b"Public: OPTIONS, DESCRIBE, SETUP, PLAY, TEARDOWN\r\n\r\n"
)


class BannerListener(BaseListener):
    proto = "rtsp"
    READ_WAIT = 5.0

    async def handle(self, reader, writer, src_ip, src_port):
        event_type = "rtsp_request" if self.proto == "rtsp" else "other"
        try:
            data = await asyncio.wait_for(reader.read(4096), timeout=self.READ_WAIT)
        except asyncio.TimeoutError:
            data = b""

        preview = data.decode("latin-1", errors="replace")[:200]
        await self.emit(
            src_ip, event_type, src_port=src_port,
            detail={"service": self.proto, "request": preview},
        )

        if self.proto == "rtsp" and data.upper().startswith(b"OPTIONS"):
            await self.write(writer, RTSP_RESPONSE)
