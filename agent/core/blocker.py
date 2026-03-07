"""
DSIPS Blocker v3.0
- Har qanday blok: 1 soat (default), saytga kirish + ping ham bloklanadi
- Xizmat nazorati: SSH, FTP, SMTP, HTTP/S, MySQL, PostgreSQL, Redis...
- TCP/UDP flood himoya
- Whitelist — hech qachon bloklanmasin
"""

import asyncio
import logging
import shutil
import subprocess
import time
from typing import Dict, Optional

from agent.config.settings import Config

logger = logging.getLogger("dsips.blocker")

# Barcha hujumlar uchun default blok muddati — 1 soat
DEFAULT_BLOCK = 3600


class Blocker:
    def __init__(self, cfg: Config):
        self.cfg      = cfg
        self._blocked: Dict[str, dict] = {}   # ip → {expiry, reason, duration}
        self._backend = self._detect()
        logger.info(f"Firewall backend: {self._backend}")

    def _detect(self) -> str:
        b = self.cfg.firewall_backend
        if b != "auto":
            return b
        if shutil.which("ipset") and shutil.which("iptables"):
            return "ipset"
        if shutil.which("ufw"):
            r = subprocess.run(["ufw", "status"], capture_output=True, text=True)
            if "active" in r.stdout.lower():
                return "ufw"
        if shutil.which("iptables"):
            return "iptables"
        logger.warning("Firewall topilmadi — bloklash o'chirilgan.")
        return "none"

    async def _run(self, cmd: list) -> bool:
        try:
            p = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            _, stderr = await asyncio.wait_for(p.communicate(), timeout=10)
            if p.returncode != 0:
                logger.debug(f"CMD: {' '.join(cmd)} → {stderr.decode().strip()}")
                return False
            return True
        except Exception as e:
            logger.error(f"CMD xato: {e}")
            return False

    async def _ipset_init(self):
        """dsips_blocked ipset — hash:ip, timeout bilan."""
        await self._run([
            "ipset", "create", "dsips_blocked", "hash:ip",
            "timeout", "0", "maxelem", "65536"
        ])
        # INPUT bloklash
        exists = await self._run([
            "iptables", "-C", "INPUT", "-m", "set",
            "--match-set", "dsips_blocked", "src", "-j", "DROP"
        ])
        if not exists:
            await self._run([
                "iptables", "-I", "INPUT", "1", "-m", "set",
                "--match-set", "dsips_blocked", "src", "-j", "DROP"
            ])
        # OUTPUT bloklash (ping javobini ham to'xtatish)
        exists_out = await self._run([
            "iptables", "-C", "OUTPUT", "-m", "set",
            "--match-set", "dsips_blocked", "dst", "-j", "DROP"
        ])
        if not exists_out:
            await self._run([
                "iptables", "-I", "OUTPUT", "1", "-m", "set",
                "--match-set", "dsips_blocked", "dst", "-j", "DROP"
            ])

    async def setup_base_protection(self):
        """
        Server yoqilganda bir marta o'rnatiladi.
        Asosiy himoya qoidalari — oddiy foydalanuvchiga zarar yetkazmaydi.
        """
        if self._backend == "none":
            return

        logger.info("Asosiy himoya qoidalari o'rnatilmoqda...")

        # Loopback va established — avval ruxsat
        await self._run(["iptables", "-I", "INPUT", "1", "-i", "lo", "-j", "ACCEPT"])
        await self._run([
            "iptables", "-I", "INPUT", "2",
            "-m", "state", "--state", "ESTABLISHED,RELATED", "-j", "ACCEPT"
        ])

        # Invalid paketlar
        await self._run([
            "iptables", "-A", "INPUT",
            "-m", "state", "--state", "INVALID", "-j", "DROP"
        ])

        # TCP SYN flood — 200/s limit (oddiy traffic uchun yetarli)
        await self._run([
            "iptables", "-A", "INPUT", "-p", "tcp", "--syn",
            "-m", "limit", "--limit", "200/s", "--limit-burst", "500",
            "-j", "ACCEPT"
        ])
        await self._run([
            "iptables", "-A", "INPUT", "-p", "tcp", "--syn", "-j", "DROP"
        ])

        # UDP flood — 200/s limit
        await self._run([
            "iptables", "-A", "INPUT", "-p", "udp",
            "-m", "limit", "--limit", "200/s", "--limit-burst", "500",
            "-j", "ACCEPT"
        ])

        # ICMP (ping) — 20/s limit, to'liq o'chirmaslik
        await self._run([
            "iptables", "-A", "INPUT", "-p", "icmp",
            "-m", "limit", "--limit", "20/s", "--limit-burst", "50",
            "-j", "ACCEPT"
        ])
        await self._run([
            "iptables", "-A", "INPUT", "-p", "icmp", "-j", "DROP"
        ])

        logger.info("Asosiy himoya qoidalari o'rnatildi.")

    async def block(self, ip: str, duration: int, reason: str = "") -> bool:
        """
        IP ni bloklash — INPUT + OUTPUT + ICMP.
        duration: soniyalarda (default 3600 = 1 soat)
        Saytga kirish, ping, hamma narsa bloklanadi.
        """
        if self._backend == "none":
            return False

        # Whitelist tekshiruvi
        if ip in self.cfg.whitelisted_ips:
            logger.warning(f"Whitelist — bloklanmaydi: {ip}")
            return False

        # Allaqachon bloklangan
        if ip in self._blocked:
            exp = self._blocked[ip]["expiry"]
            if time.time() < exp:
                logger.debug(f"Allaqachon bloklangan: {ip}")
                return True
            else:
                # Muddati o'tgan — yangilash
                del self._blocked[ip]

        ok = False

        if self._backend == "ipset":
            await self._ipset_init()
            ok = await self._run([
                "ipset", "add", "dsips_blocked", ip,
                "timeout", str(duration), "-exist"
            ])

        elif self._backend == "iptables":
            # INPUT
            await self._run([
                "iptables", "-I", "INPUT", "1",
                "-s", ip, "-j", "DROP",
                "-m", "comment", "--comment", f"dsips:{reason[:40]}"
            ])
            # OUTPUT (sayt ham javob bermasin)
            await self._run([
                "iptables", "-I", "OUTPUT", "1",
                "-d", ip, "-j", "DROP",
                "-m", "comment", "--comment", f"dsips:{reason[:40]}"
            ])
            ok = True

        elif self._backend == "ufw":
            ok = await self._run(["ufw", "deny", "from", ip, "to", "any"])

        if ok:
            expiry = time.time() + duration
            self._blocked[ip] = {
                "expiry":   expiry,
                "reason":   reason,
                "duration": duration,
                "blocked_at": time.time(),
            }
            logger.info(f"BLOKLANDI: {ip} | {duration}s ({duration//3600}s) | {reason}")
            # ipset timeout o'zi hal qiladi, qolganlari uchun expire task
            if self._backend != "ipset":
                asyncio.create_task(self._expire(ip, duration))

        return ok

    async def unblock(self, ip: str) -> bool:
        if self._backend == "none":
            return False

        ok = False

        if self._backend == "ipset":
            ok = await self._run(["ipset", "del", "dsips_blocked", ip])

        elif self._backend == "iptables":
            await self._run([
                "iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"
            ])
            await self._run([
                "iptables", "-D", "OUTPUT", "-d", ip, "-j", "DROP"
            ])
            ok = True

        elif self._backend == "ufw":
            ok = await self._run([
                "ufw", "delete", "deny", "from", ip, "to", "any"
            ])

        if ok:
            self._blocked.pop(ip, None)
            logger.info(f"BLOK OCHILDI: {ip}")

        return ok

    async def _expire(self, ip: str, duration: int):
        await asyncio.sleep(duration)
        if ip in self._blocked:
            await self.unblock(ip)

    def is_blocked(self, ip: str) -> bool:
        info = self._blocked.get(ip)
        if not info:
            return False
        if time.time() > info["expiry"]:
            del self._blocked[ip]
            return False
        return True

    def remaining(self, ip: str) -> int:
        """Qancha vaqt qolgan (soniyada)."""
        info = self._blocked.get(ip)
        if not info:
            return 0
        return max(0, int(info["expiry"] - time.time()))

    def list_blocked(self) -> Dict[str, dict]:
        now = time.time()
        return {
            ip: {**info, "remaining": int(info["expiry"] - now)}
            for ip, info in self._blocked.items()
            if info["expiry"] > now
        }
