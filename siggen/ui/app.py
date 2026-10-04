"""Streamlit-интерфейс генератора.

Запуск: streamlit run siggen/ui/app.py

Логики генерации здесь нет — только ввод, запуск пайплайна и показ артефактов,
чтобы поведение UI и CLI не расходилось.
"""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path

# Запуск как файла (streamlit run ...) не добавляет корень репозитория в sys.path.
if __package__ in (None, ""):  # pragma: no cover - зависит от способа запуска
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

import streamlit as st  # noqa: E402

from siggen.config import Settings  # noqa: E402
from siggen.engine import LogtestRunner  # noqa: E402
from siggen.models import ConfigurationError, ProviderError  # noqa: E402
from siggen.pipeline import GenerateOptions, Registry, generate  # noqa: E402
from siggen.prompts import load_prompt  # noqa: E402
from siggen.providers import build_provider  # noqa: E402

DEMO_POSITIVE = "2024-05-12T10:15:03Z host1 myapp[2412]: login_failed user=admin src=10.0.0.5 attempts=3"
DEMO_NEGATIVE = "2024-05-12T10:16:41Z host1 myapp[2412]: login_ok user=admin src=10.0.0.5"

st.set_page_config(page_title="siggen — генератор SIEM-правил", page_icon="🛡️", layout="wide")
st.title("🛡️ siggen — генератор SIEM-правил для Wazuh/OSSEC")
st.caption(
    "Модель предлагает черновик детекции; идентификатор, XML и вердикт формирует "
    "наш код и движок анализа. Без прогона через движок артефакт не считается проверенным."
)

with st.sidebar:
    st.header("Настройки")
    engine = st.selectbox("Движок", ["wazuh", "ossec"], index=0)
    provider_name = st.selectbox("Провайдер модели", ["fake", "gigachat"], index=0)
    require_engine = st.checkbox(
        "Требовать прогон через движок", value=False,
        help="Включите в лаборатории: тогда недоступность wazuh-logtest даст провал, а не skip.",
    )
    st.divider()
    st.caption(
        f"Реестр ID: `{Settings().registry_path}` — заполняется только для артефактов, "
        "прошедших проверки."
    )
    st.markdown(
        "`fake` — детерминированная заглушка, понимает демонстрационные шаблоны "
        "(`login_failed`, `Failed password for`). Для своих логов включите `gigachat`."
    )

positive = st.text_area("Строка лога (positive)", value=DEMO_POSITIVE, height=80)
negative = st.text_area(
    "Строка-шум (negative)", value=DEMO_NEGATIVE, height=80,
    help="Обязательна: доказывает, что правило не срабатывает на нормальном трафике.",
)

if st.button("Сгенерировать и проверить", type="primary"):
    try:
        settings = Settings.from_env(engine=engine, provider=provider_name,
                                     require_engine=require_engine or None)
        out_dir = Path(tempfile.mkdtemp(prefix="siggen-ui-"))
        result = generate(
            log_input=positive,
            negative_input=negative or None,
            settings=settings,
            provider=build_provider(settings),
            prompt=load_prompt(),
            registry=Registry(settings.registry_path),
            runner=LogtestRunner(settings.engine, timeout=settings.engine_timeout),
            options=GenerateOptions(out_dir=out_dir, write_artifacts=True),
        )
        st.session_state["result"] = result
        st.session_state["out_dir"] = out_dir
    except (ConfigurationError, ProviderError) as exc:
        st.session_state.pop("result", None)
        st.error(str(exc))
    except Exception as exc:  # noqa: BLE001 - интерфейс не должен падать молча
        st.session_state.pop("result", None)
        st.exception(exc)

result = st.session_state.get("result")
if result is not None:
    bundle = result.bundle
    validation = bundle.validation

    if result.ok:
        st.success(f"Артефакт проверен: {bundle.engine}/{bundle.rule_id}")
    else:
        st.error("Артефакт не прошёл проверки — в прод его пускать нельзя")

    left, right = st.columns(2)
    with left:
        st.subheader("Проверки")
        st.dataframe(
            [
                {
                    "проверка": check.name,
                    "статус": "ok" if check.passed else "fail",
                    "уровень": check.severity,
                    "детали": check.detail,
                }
                for check in validation.checks
            ],
            use_container_width=True,
            hide_index=True,
        )
        st.write(f"**Движок:** `{validation.engine_status}` — {validation.engine_detail}")
        if validation.requires_manual_review:
            st.warning("Требует ручного ревью: " + "; ".join(validation.requires_manual_review))

    with right:
        st.subheader("Артефакты")
        st.caption(f"Провайдер: {bundle.provenance.provider} ({bundle.provenance.model}); "
                   f"промпт {bundle.provenance.prompt_name} v{bundle.provenance.prompt_version}")
        st.code(bundle.decoder_xml, language="xml")
        st.code(bundle.rule_xml, language="xml")
        out_dir = st.session_state.get("out_dir")
        if out_dir:
            ruleset = Path(out_dir) / f"{bundle.engine}-{bundle.rule_id}" / "local_rules.xml"
            if ruleset.is_file():
                st.download_button(
                    "Скачать local_rules.xml",
                    data=ruleset.read_text(encoding="utf-8"),
                    file_name=f"siggen-{bundle.engine}-{bundle.rule_id}.xml",
                    mime="application/xml",
                )

    with st.expander("Отчёт (markdown)"):
        st.markdown(result.report_markdown)
    with st.expander("Обоснование модели"):
        st.write(bundle.candidate.rationale or "—")
