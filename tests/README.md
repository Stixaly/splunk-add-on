# Tests

The suite runs without Splunk and without OpenCTI. The add-on ships its
dependencies in `TA-opencti-add-on/bin/ta_opencti_add_on/aob_py3`, and
`conftest.py` puts the same directories on `sys.path` that Splunk does, so the
tests import exactly the code that runs in production. Nothing is reimplemented
and no dependency is installed from PyPI other than pytest itself.

## Running them

```bash
pip install -r tests/requirements.txt
pytest
```

```bash
pytest tests/unit          # a single function or module at a time
pytest tests/regression    # behaviours that must not change
```

With coverage, the way CI measures it:

```bash
pytest --cov=input_module_opencti_indicators --cov=stix_pattern --cov=stix_converter --cov=utils --cov-report=term-missing
```

Only the four modules the add-on owns are measured. The vendored libraries are
third party code that is shipped, not maintained here.

## Layout

| Path | What it covers |
|------|----------------|
| `unit/test_input_module.py` | value normalisation, STIX unescaping, pattern parsing, `enrich_payload` |
| `unit/test_collect_events.py` | the stream loop, against a fake KV store and a fake stream |
| `unit/test_utils.py` | address and hash detection, deterministic STIX identifiers |
| `unit/test_stix_pattern.py` | the structural pattern parser, DNF expansion, routing |
| `unit/test_stix_converter.py` | sighting bundles, observable conversion |
| `unit/test_incident_converters.py` | incident and case bundles, CIM and field-mapping extraction |
| `regression/test_ioc_coverage.py` | the exact set of indicators that is ingested |
| `regression/test_conf_integrity.py` | the `.conf` and form files against the code |
| `regression/test_fixed_bugs.py` | one test per defect that has been fixed |

## The two regression tables

Two tests are deliberately written as tables that have to be edited by hand
when behaviour changes on purpose.

`regression/test_ioc_coverage.py` lists every pattern that is ingested and
every one that is knowingly not. Supporting a new observable type means moving
a line from `EXPECTED_GAPS` to `EXPECTED_COVERAGE`. A type that silently stops
being ingested fails instead of going unnoticed.

`regression/test_fixed_bugs.py` holds one test per defect, each naming the
behaviour that was wrong. Nothing should be removed from that file.

## Adding a test

Unit tests go next to the module they exercise. A test that pins a behaviour
someone could plausibly undo belongs in `regression/`, with a docstring saying
what was wrong before, so a later reader knows why the assertion is there.

The fixtures in `conftest.py` cover the usual needs: `input_module` gives the
modular input with its caches emptied, `markings` preloads the marking and
identity definitions, `stream_indicator` is an indicator shaped the way the
OpenCTI stream emits one, and `sighting_params` builds alert action parameters.
