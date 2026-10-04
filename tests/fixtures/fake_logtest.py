"""Тестовый двойник `wazuh-logtest`.

Реализует тот же контракт, что важен пайплайну: возвращает код 0, если
поданная на stdin строка сматчилась под критерии `-U <rule_id:level:decoder>`.

Флаг `--unsupported` имитирует движок, который не знает опции `-U`:
так проверяется честный переход в статус «не проверено».
"""

from __future__ import annotations

import sys

WATCHED = {
    "myapp-login": "login_failed",
    "sshd-failed-password": "Failed password",
}


def main() -> int:
    args = sys.argv[1:]
    if "--unsupported" in args:
        print("wazuh-logtest: unrecognized option '-U'", file=sys.stderr)
        print("Usage: wazuh-logtest [-vdhV]", file=sys.stderr)
        return 1

    spec = ""
    for index, value in enumerate(args):
        if value == "-U" and index + 1 < len(args):
            spec = args[index + 1]

    line = sys.stdin.readline()
    rule_id, _level, decoder = spec.split(":", 2) if spec.count(":") >= 2 else ("", "", "")
    needle = WATCHED.get(decoder)
    matched = bool(needle) and needle in line

    print(f"Phase 1: received {line.strip()!r}")
    print(f"Phase 3: rule_id={rule_id} decoder={decoder} matched={matched}")
    return 0 if matched else 1


if __name__ == "__main__":
    raise SystemExit(main())
