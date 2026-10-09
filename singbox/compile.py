"""Check published text lists against DAT conversion, then compile every set."""
import concurrent.futures
import hashlib
import json
import pathlib
import subprocess
import sys

source, output, binary, source_commit = sys.argv[1:]
source, output = pathlib.Path(source), pathlib.Path(output)
report = json.loads((output / "audit.json").read_text())
fields = {"domain": "domain_suffix", "full": "domain", "keyword": "domain_keyword", "regexp": "domain_regex"}

def canonical_suffixes(values):
    return {value for value in values if not any(".".join(value.split(".")[i:]) in values for i in range(1, len(value.split("."))))}

assert canonical_suffixes({"googleapis.cn", "services.googleapis.cn"}) == {"googleapis.cn"}
assert canonical_suffixes({"google.cn", "notgoogle.cn"}) == {"google.cn", "notgoogle.cn"}
text_checks = {}
for filename, category in (("direct-list.txt", "cn"), ("proxy-list.txt", "geolocation-!cn"), ("reject-list.txt", "category-ads-all")):
    expected = {field: set() for field in fields.values()}
    for line in (source / filename).read_text().splitlines():
        line = line.strip()
        if not line:
            continue
        prefix, separator, value = line.partition(":")
        if separator:
            if prefix not in fields:
                raise ValueError(f"Unknown rule type in {filename}: {prefix}")
            expected[fields[prefix]].add(value if prefix == "regexp" else value.lower())
        else:
            expected["domain_suffix"].add(line.lower())
    rules = json.loads((output / "geosite" / f"{category}.json").read_text())["rules"]
    actual = {field: set(rules[0].get(field, [])) for field in expected}
    redundant = len(expected["domain_suffix"]) - len(canonical_suffixes(expected["domain_suffix"]))
    expected["domain_suffix"] = canonical_suffixes(expected["domain_suffix"])
    actual["domain_suffix"] = canonical_suffixes(actual["domain_suffix"])
    for field in expected:
        if expected[field] != actual[field]:
            missing = sorted(expected[field] - actual[field])[:5]
            extra = sorted(actual[field] - expected[field])[:5]
            raise ValueError(f"{filename} {field}: missing={missing}, extra={extra}")
    text_checks[filename] = {"result": "equal after lowercase/suffix normalization", "redundant_suffix_rules": redundant}
report["text_list_checks"] = text_checks

paths = sorted(path for kind in ("geosite", "geoip") for path in (output / kind).glob("*.json"))
if len(paths) != len(report["counts"]):
    raise ValueError("Category coverage differs from DAT audit")

def compile_set(path):
    target = path.with_suffix(".srs")
    subprocess.run([binary, "rule-set", "compile", "--output", str(target), str(path)], check=True, capture_output=True)
    data = target.read_bytes()
    if data[:4] != b"SRS\x01":
        raise ValueError(f"Invalid SRS version/header: {target}")
    return str(target.relative_to(output)), hashlib.sha256(data).hexdigest()

with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
    report["srs_sha256"] = dict(pool.map(compile_set, paths))
report["source_commit"] = source_commit
report["compiler"] = subprocess.check_output([binary, "version"], text=True).splitlines()[0]
report["compiled_sets"] = len(paths)
ip_counts = {}
for name in ("cn", "private"):
    path = output / "geoip" / f"{name}.json"
    if path.exists():
        values = json.loads(path.read_text())["rules"][0]["ip_cidr"]
        ip_counts[name] = {"ipv4": sum(":" not in v for v in values), "ipv6": sum(":" in v for v in values)}
report["ip_counts"] = ip_counts
(output / "audit.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
print(json.dumps({"compiled_sets": len(paths), "cn_domains": report["counts"]["geosite/cn"], "cn_ip": ip_counts["cn"], "text_lists": report["text_list_checks"]}, indent=2))
