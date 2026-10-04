"""Справочники, по которым проверяются предложения модели.

Модель не является источником правды для полей, техник ATT&CK и compliance-маппинга
(docs/SECURITY.md, SEC-11). Здесь лежат allowlist-ы: всё, что выходит за их пределы,
считается ошибкой валидации, а не «почти правильным» ответом.
"""

from __future__ import annotations

#: Имена полей, допустимые в <order> декодера OSSEC/Wazuh.
#: Список намеренно узкий: нестандартное имя поля движок не примет.
OSSEC_ORDER_FIELDS: frozenset[str] = frozenset({
    "action",
    "date",
    "dstip",
    "dstport",
    "dstuser",
    "extra_data",
    "hostname",
    "id",
    "protocol",
    "srcip",
    "srcport",
    "srcuser",
    "status",
    "system_name",
    "time",
    "url",
})

#: Допустимые значения атрибута offset у <regex>.
DECODER_OFFSETS: frozenset[str] = frozenset({
    "after_parent",
    "after_prematch",
    "after_regex",
    "after_offset",
    "before_parent",
    "before_prematch",
})

#: Техники MITRE ATT&CK, которыми разрешено помечать правила.
#: Расширяйте осознанно: неверный маппинг = неверный отчёт о покрытии для CISO.
MITRE_TECHNIQUES: dict[str, str] = {
    "T1021": "Remote Services",
    "T1046": "Network Service Discovery",
    "T1055": "Process Injection",
    "T1059": "Command and Scripting Interpreter",
    "T1070": "Indicator Removal",
    "T1078": "Valid Accounts",
    "T1110": "Brute Force",
    "T1136": "Create Account",
    "T1190": "Exploit Public-Facing Application",
    "T1548": "Abuse Elevation Control Mechanism",
}

#: Регуляторные/стандартовые группы, на которые можно ссылаться в правилах.
COMPLIANCE_FRAMEWORKS: frozenset[str] = frozenset({
    "pci_dss",
    "gdpr",
    "hipaa",
    "nist_800_53",
    "tsc",
})

#: Паттерны, которые означают «правило подавляет всё подряд». Такие кандидаты
#: автоматически уходят на ручное ревью и не считаются готовыми (SEC-10).
BROAD_MATCH_PATTERNS: frozenset[str] = frozenset({
    ".*",
    "^.*",
    ".*$",
    "^.*$",
    ".+",
    "^.+$",
    "^",
    "$",
    "",
})

#: Максимальный уровень правила в OSSEC/Wazuh.
MAX_RULE_LEVEL = 16
