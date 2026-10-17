Test databases for `config/aggregator/geo.yaml`'s tests, not the real data. The config's paths are
relative (`geo/city.mmdb`), so the tests run from `tests/`:

- `city.mmdb`: MaxMind's `GeoLite2-City-Test.mmdb`
- `asn.mmdb`: MaxMind's `GeoLite2-ASN-Test.mmdb`

From https://github.com/maxmind/MaxMind-DB/tree/0ee49278e35fd7bdf341ac236edbba20de1aceb9/test-data
(Apache-2.0 or MIT), sha256 96a73a347420a40b6773e052a2937088b79678a9ddf98f40f8fd7033210f3b4f and
5f2da5602a6947dae10486fe337d6112d2e37eaa2bc8d32e1fdeeeae645a3e4a. DB-IP's Lite files, which the
aggregator uses, have the same record layout.
