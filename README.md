# siggen

An LLM drafts a Wazuh or OSSEC rule. Then siggen tries to prove it wrong.

Hand it one line from your logs and it comes back with a decoder, a rule, the
fixtures to test them with, and a report listing what it checked. The interesting
part is what it refuses to do: it won't call a rule ready until something other
than the language model says so.

## Why bother

Ask any LLM for an OSSEC decoder and you'll get XML that looks right. There's a
`<decoder>` tag, a plausible regex, a sensible `<order>`. It's also wrong fairly
often, in ways nobody notices until it's deployed:

- the regex has three capture groups and `<order>` declares two, so the decoder
  never loads;
- `<decoded_as>` names a decoder that doesn't exist;
- `<if_sid>` points at a rule someone retired two versions ago;
- the rule is broad enough to quietly swallow the alerts it was supposed to raise.

None of that shows up in a chat window. All of it shows up in `wazuh-logtest`.

So here the model writes a *draft* and nothing else. Rule IDs, the XML, and the
verdict all come from siggen.

## Quick start, offline

No API key, no network, no Wazuh install. The bundled `fake` provider is a
deterministic stub that recognizes two demo log shapes, so the whole pipeline runs
offline. You need Python 3.10+ and `pydantic`.

```bash
git clone https://github.com/M0nteCarl0/Gigachat-SIEM-rules-generator-.git
cd Gigachat-SIEM-rules-generator-
python -m siggen gen --log samples/positive.log --negative samples/negative.log
```

```
Правило:      wazuh/100100 (level=10)
Описание:     MyApp: повторный неуспешный вход для пользователя $(srcuser) с $(srcip)
Итог:         ГОТОВО К РЕВЬЮ
Проверки:     10 ok, 0 fail, 0 warn
Движок:       skipped — движок wazuh не найден в PATH: правило не проверено. Поднимите лабораторию из docker-compose.yml или укажите путь к бинарю.
Артефакты:    out\wazuh-100100
Отчёт:        out\report.md
```

`--log` takes a file and siggen uses its first non-empty line, so pointing it at a
whole log file won't break anything. It also won't do much yet; see
[Known gaps](#known-gaps).

The CLI prints in Russian at the moment, which is covered under Known gaps below.
Note the `skipped` on the engine line: siggen could not confirm the rule, and says
so instead of implying success.

## What a run leaves behind

Each run writes a self-contained directory you can drop into a pull request:

```
out/wazuh-100100/
  candidate.json     the model's proposal, after schema validation
  decoder.xml        decoder XML, assembled by siggen
  rule.xml           rule XML, assembled by siggen
  local_rules.xml    both wrapped in a <group>, ready to deploy
  positive.log       the line that must match
  negative.log       the line that must not
  provenance.json    provider, model, prompt version and hash, source line
  validation.json    every check, plus the engine verdict
  report.md          the same thing, for a human
```

Here's the decoder from that run:

```xml
<decoder name="myapp-login">
  <program_name>^myapp$</program_name>
  <prematch>login_failed </prematch>
  <regex offset="after_prematch">^user=(\S+) src=(\S+) attempts=\S+$</regex>
  <order>srcuser, srcip</order>
</decoder>
```

Look at the regex: two capture groups for the two fields in `<order>`, explicit
anchors, and the uninteresting `attempts=` tail consumed without capturing it. That
last detail matters. A third group with no corresponding field is one of the classic
ways a decoder gets rejected at load time, and it's checked mechanically rather than
left to the model's judgment.

## What gets checked

A clean run reports ten checks:

| Check | Fails when |
|---|---|
| `decoder_wellformed`, `rule_wellformed` | the XML doesn't parse, or the root tag is wrong |
| `rule_id_in_range`, `rule_id_unique` | the ID is outside your range, or already taken |
| `decoded_as_matches_decoder` | the rule references a decoder that isn't in the artifact |
| `order_fields_allowed` | `<order>` names a field the engine doesn't know |
| `order_matches_regex_groups` | capture groups and declared fields don't line up |
| `regex_compiles` | the pattern is broken |
| `decoder_offset_allowed` | `offset` isn't one of the values the engine accepts |
| `mitre_in_allowlist` | the technique isn't listed in `siggen/data.py` |

Seven more checks stay quiet unless they have something to say, so a clean report
isn't cluttered with rows that always pass:

| Check | Flags |
|---|---|
| `no_broad_suppression` | a rule that matches everything: `.*`, an empty match |
| `no_active_response` | generated rules never block hosts on their own |
| `level_not_zero`, `level_reasonable` | level 0, or a level too low to be a detection |
| `no_source_ip_whitelist` | the rule narrows itself to a single source |
| `groups_present` | the rule has no `<group>` |
| `negative_fixture_present` | no negative sample, so nothing proves the rule stays quiet |
| `no_duplicate` | a rule with the same fingerprint is already in the registry |

Errors block the run. Warnings don't, but they land in the report's "needs review"
list. A run that doesn't pass leaves the rule ID unallocated, so a rejected draft
doesn't burn a number.

## The engine is the real judge

Everything above is pre-flight. The part that counts is this: siggen feeds your
`positive` line to the engine and expects a match, then feeds the `negative` line and
expects silence. A rule that fires on both is a false positive, and it's rejected.

```bash
# wazuh-logtest on PATH: nothing extra to configure
python -m siggen gen --log samples/positive.log --negative samples/negative.log

# engine inside the lab container
python -m siggen gen --log samples/positive.log --negative samples/negative.log \
  --logtest "docker compose exec -T wazuh-manager /var/ossec/bin/wazuh-logtest"
```

If the engine isn't reachable, the status is `skipped` and the report says the rule is
unverified. If you'd rather that be a hard failure, add `--require-engine` and it
becomes one. That flag is what you want in CI.

`docker-compose.yml` brings up a throwaway Wazuh manager for exactly this purpose; the
steps for deploying the sample ruleset into it are in the file's header comments. Once
it's up, `python -m pytest -m integration` checks a generated rule against the real
binary. Those tests skip by default, and `tests/test_integration_engine.py` explains
how to enable them.

## Using a real model

```bash
# Credentials come from the environment. .env.example lists the variable names;
# nothing loads a .env file for you, so export them in your shell or your runner.
export GIGACHAT_CREDENTIALS="..."          # PowerShell: $env:GIGACHAT_CREDENTIALS = "..."
python -m siggen gen --provider gigachat --log my.log --negative noise.log
```

Credentials are read from the environment only, and TLS verification is on by
default. The switch to turn it off exists, but it logs a warning when you use it,
because that setting mostly helps whoever is sitting between you and the API.

The prompt lives in `prompts/detection.md` and carries a version number. Its SHA-256
goes into every `provenance.json`, so when a rule turns out to be noisy six months
later you can still tell which wording produced it.

## Known gaps

This is an early MVP, and the honest list is longer than the feature list.

- **No real Wazuh run yet.** The lab has never been brought up: no Docker daemon was
  available when this was written. The wiring from an external engine command through
  the exit codes to the verdict is tested end to end against a test double, but whether
  our XML and regex anchoring satisfy an actual `wazuh-logtest` is unconfirmed. Expect
  to touch `siggen/engine.py` the first time you point it at a live manager.
- **Russian runtime, English README.** CLI messages, XML comments, and the prompt are in
  Russian, so model-generated rule descriptions come out in Russian too. `docs/` is
  Russian as well. Translating `prompts/detection.md` and the message strings is the
  first job if you need English rules.
- **One log line per run.** No corpus handling: no ingest, no clustering of undecoded
  lines, no coverage report. That's Phase 4 in the roadmap, and it's where most of the
  value for a real SOC sits.
- **No Sigma, no Splunk, no Elastic.** The model returns JSON, not Sigma, and only
  Wazuh/OSSEC XML can be emitted.
- **The GigaChat provider is untested.** It's written against the official SDK but no
  test covers it, because the suite deliberately never touches the network. The
  Streamlit UI is in the same position: it runs on the same pipeline as the CLI, but
  nothing exercises it automatically.
- **The fake provider is a stub, not a detector.** Two hardcoded log shapes. Real logs
  need `--provider gigachat`.
- **The rule ID range is a guess.** It defaults to 100100–120000. Check it against your
  own manager before allocating anything; collisions are the fastest way to break a
  ruleset.

## Layout

```
siggen/
  cli.py          the gen and validate commands
  pipeline.py     orchestration, ID registry, report rendering
  models.py       the contracts: model draft in, checked artifact out
  providers.py    one interface, two implementations (fake, gigachat)
  prompts.py      loads versioned prompts from prompts/
  emit.py         builds XML
  validation.py   static checks and project policy
  engine.py       runs wazuh-logtest / ossec-logtest
  data.py         allowed fields, allowed ATT&CK techniques
  config.py       settings, environment variables
  ui/app.py       Streamlit front end
prompts/          the prompt, with its version
samples/          demo log lines
examples/         a real run's output, committed
tests/            88 tests, no network, no token, no engine required
docs/             roadmap, architecture, security notes
```

## Working on it

```bash
python -m pip install -e ".[dev]"    # you only need pydantic to run it
python -m pytest
```

The suite runs without network, token, or Wazuh: the model is replaced by
`FakeProvider` and the engine by `tests/fixtures/fake_logtest.py`. If you change the
prompt, expect the golden outputs under `examples/` to need regenerating.

## License

None chosen yet. `pyproject.toml` currently declares this as proprietary, which means
all rights reserved by default. If you plan to use it outside your own team, pick a
license first.
