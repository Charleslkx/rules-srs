# Audited sing-box conversion

This fork builds its V2Ray data using the upstream workflow, then converts its
own `release/geosite.dat` and `release/geoip.dat` using V2Ray's official protobuf
definitions. It has no dependency on lyc8503/sing-box-rules.

The `sing-box` branch contains `geosite/<category>.json`,
`geosite/<category>.srs`, `geoip/<category>.json`, `geoip/<category>.srs`, and
`audit.json`. All source categories and each named attribute subset are exported.
Domain keyword, regex, suffix and exact rules keep their respective match types;
IPv4, IPv6 and inverse IP matching are preserved. Empty categories stay empty.
Compound V2Ray `@` filters require sing-box logical AND over the exported subsets.

The workflow checks DAT checksums, rejects unknown protobuf fields/domain types,
compares the published direct/proxy/reject text lists with the converted DAT sets
after case normalization and removal of redundant child-domain suffixes,
and compiles every JSON set using the pinned official sing-box 1.14.2 binary.
The output uses SRS version 1 for compatibility. `audit.json` records category and
rule counts, source commit and hashes, and every compiled file's SHA-256 hash.
Failed checks stop publishing and leave the existing output branch intact.

Enable GitHub Actions and run **Build V2Ray rules dat files** once after forking.
Successful builds trigger **Convert and audit sing-box rules** automatically.
For a conversion of the existing release snapshot, dispatch the latter manually.

These checks establish completeness relative to the supplied DAT snapshot.
They cannot establish that its upstream lists cover every website or that IP
geolocation always matches the desired proxy policy.

Local checks: `cd singbox && go test ./...`; then `go run . geosite.dat geoip.dat output`.
Run `python3 compile.py source output /path/to/sing-box <release-commit>` to compare
text lists and compile the output. Use a fresh output directory for each build.
