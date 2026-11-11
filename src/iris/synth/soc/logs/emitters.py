"""Raw log emitters: pure functions that render real-format log lines (builder brief file 04 §3).

Every emitter returns the exact text a real service writes, so MiniWazuh decodes and rules it
like production logs. Format varies per host (traditional vs ISO timestamp, auth.log vs
secure, nginx combined vs JSON) chosen from the telemetry seed, so a host is consistent over
time but hosts differ and no single variant dominates a batch (brief T-S6).

Emitters never contain attack *tooling*: they render the telemetry footprint of an action
(e.g. a failed-login line), not the action itself.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

_MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]

# realistic web user agents (benign browser mix + common tools), drawn per request upstream
USER_AGENTS = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/124.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) "
    "Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148",
    "curl/8.5.0",
    "python-requests/2.31.0",
)


def syslog_ts(ts: datetime) -> str:
    """Traditional syslog header stamp: ``Mar  3 08:41:11`` (day space-padded)."""
    return f"{_MONTHS[ts.month - 1]} {ts.day:2d} {ts.hour:02d}:{ts.minute:02d}:{ts.second:02d}"


@dataclass(frozen=True)
class HostStyle:
    """Per-host log-format variant (brief T-S6: diversity, consistency per host)."""

    web_format: str  # "combined" | "json"
    auth_path: str  # "/var/log/auth.log" | "/var/log/secure"

    @staticmethod
    def pick(rng: object) -> HostStyle:
        import random

        assert isinstance(rng, random.Random)
        return HostStyle(
            web_format=rng.choice(["combined", "combined", "json"]),
            auth_path=rng.choice(["/var/log/auth.log", "/var/log/secure"]),
        )


def _header(ts: datetime, host: str, program: str, pid: int) -> str:
    return f"{syslog_ts(ts)} {host} {program}[{pid}]: "


# ---------------------------------------------------------------- sshd


def ssh_accepted(
    ts: datetime, host: str, pid: int, user: str, srcip: str, srcport: int, method: str = "password"
) -> str:
    return _header(ts, host, "sshd", pid) + f"Accepted {method} for {user} from {srcip} port {srcport} ssh2"


def ssh_failed(
    ts: datetime,
    host: str,
    pid: int,
    user: str,
    srcip: str,
    srcport: int,
    invalid: bool = False,
    method: str = "password",
) -> str:
    who = f"invalid user {user}" if invalid else user
    return _header(ts, host, "sshd", pid) + f"Failed {method} for {who} from {srcip} port {srcport} ssh2"


def ssh_invalid_user(ts: datetime, host: str, pid: int, user: str, srcip: str) -> str:
    return _header(ts, host, "sshd", pid) + f"Invalid user {user} from {srcip}"


def ssh_disconnect(ts: datetime, host: str, pid: int, srcip: str) -> str:
    return _header(ts, host, "sshd", pid) + f"Received disconnect from {srcip}: 11: Bye Bye"


# ---------------------------------------------------------------- sudo / su


def sudo_command(ts: datetime, host: str, user: str, dstuser: str, tty: str, pwd: str, command: str) -> str:
    return (
        f"{syslog_ts(ts)} {host} sudo:    {user} : TTY={tty} ; PWD={pwd} ; USER={dstuser} ; COMMAND={command}"
    )


def su_session_opened(ts: datetime, host: str, pid: int, user: str, dstuser: str) -> str:
    return (
        _header(ts, host, "su", pid)
        + f"pam_unix(su:session): session opened for user {dstuser} by {user}(uid=1000)"
    )


# ---------------------------------------------------------------- web (nginx/apache combined)


def web_combined(
    ts: datetime,
    host: str,
    program: str,
    srcip: str,
    method: str,
    url: str,
    status: int,
    size: int,
    user_agent: str,
    user: str = "-",
    referrer: str = "-",
) -> str:
    stamp = ts.strftime("%d/%b/%Y:%H:%M:%S +0000")
    pid = 0  # access logs carry no pid; program header still present for predecoder
    return (
        f"{syslog_ts(ts)} {host} {program}[{pid}]: "
        f'{srcip} - {user} [{stamp}] "{method} {url} HTTP/1.1" {status} {size} "{referrer}" "{user_agent}"'
    )


# ---------------------------------------------------------------- postgres


def pg_log(ts: datetime, host: str, level: str, message: str) -> str:
    return f"{syslog_ts(ts)} {host} postgres[0]: {level}:  {message}"


# ---------------------------------------------------------------- generic / cron / systemd


def cron_session(ts: datetime, host: str, user: str, command: str) -> str:
    return f"{syslog_ts(ts)} {host} CRON[0]: ({user}) CMD ({command})"


def systemd_unit(ts: datetime, host: str, unit: str, action: str) -> str:
    return f"{syslog_ts(ts)} {host} systemd[1]: {unit}: {action}"
