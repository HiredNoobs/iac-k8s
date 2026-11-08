# Vector's unit tests

Tests for `../config/`: a file per source under the side that parses it (`collector/`,
`aggregator/`), and `collector/pipeline.yaml` for pod lines and the common end. CI runs them
(`.forgejo/workflows/lint.yml`). By hand, from this directory, one file per run (`vector test`
keeps every test's memory until it exits):

```sh
export NODE_NAME=cp-1 NODE_DOMAIN=hirednoobs.com
vector test ../config/common/*.yaml ../config/collector/*.yaml collector/<file>.yaml
vector test ../config/common/*.yaml ../config/aggregator/*.yaml aggregator/<file>.yaml
```

The remaps read `NODE_NAME` and `NODE_DOMAIN`. The aggregator's data paths are relative to the
working directory: here, `geo/` holds MaxMind's test databases ([geo/README.md](geo/README.md))
and `threat/` a few made-up indicators.

A test has one event: with several, Vector passes it if any one of them meets the conditions.
