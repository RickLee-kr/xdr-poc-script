"""SSH login failure attempt planning — bash invaliduser burst pattern."""

from __future__ import annotations

from dataclasses import dataclass

from dsp.protocols.base import SshProtocolError

SSH_PORT_DEFAULT = 22
MAX_HOSTS_DEFAULT = 2
# stellar_poc_followup.sh SSH_BURST_ATTEMPTS default
MAX_ATTEMPTS_PER_HOST_DEFAULT = 150
MAX_ATTEMPTS_TOTAL_DEFAULT = 150

# Bash burst uses invaliduser exclusively; extras match followup usernames pool head
DEFAULT_USERNAMES: tuple[str, ...] = (
    "invaliduser",
    "admin",
    "root",
    "test",
    "guest",
)
DEFAULT_PASSWORDS: tuple[str, ...] = ("Password123", "Welcome123", "Test123")


@dataclass(frozen=True)
class PlannedSshAttempt:
    host: str
    port: int
    username: str
    password_label: str

    @property
    def target(self) -> str:
        return f"{self.username}@{self.host}:{self.port}"


def plan_ssh_attempts(
    hosts: list[str],
    *,
    max_hosts: int = MAX_HOSTS_DEFAULT,
    max_per_host: int = MAX_ATTEMPTS_PER_HOST_DEFAULT,
    max_total: int = MAX_ATTEMPTS_TOTAL_DEFAULT,
    port: int = SSH_PORT_DEFAULT,
    usernames: tuple[str, ...] = DEFAULT_USERNAMES,
    passwords: tuple[str, ...] = DEFAULT_PASSWORDS,
) -> list[PlannedSshAttempt]:
    """
    Plan SSH authentication failure attempts — bash invaliduser burst model.

    Default: 150 attempts per host with invaliduser (pubkey-only safe ssh options).
    """
    if max_hosts < 1 or max_per_host < 1 or max_total < 1:
        raise SshProtocolError("attempt caps must be positive")
    if port <= 0:
        raise SshProtocolError("port must be positive")
    if not usernames:
        raise SshProtocolError("at least one username is required")
    if not passwords:
        raise SshProtocolError("at least one password label is required")

    selected = [h.strip() for h in hosts if h.strip()][:max_hosts]
    if not selected:
        raise SshProtocolError("at least one host is required")

    plans: list[PlannedSshAttempt] = []
    for host in selected:
        host_count = 0
        while host_count < max_per_host and len(plans) < max_total:
            plans.append(
                PlannedSshAttempt(
                    host=host,
                    port=port,
                    username=usernames[0],
                    password_label=passwords[host_count % len(passwords)],
                )
            )
            host_count += 1

    return plans
