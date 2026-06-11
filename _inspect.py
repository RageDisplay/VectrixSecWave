import json, collections
d = json.load(open(r"reports/pentest_combined_safe_20260610_104811.json", encoding="utf-8"))
print("TOP KEYS:", list(d.keys()))
for k in d:
    v = d[k]
    if isinstance(v, (dict, list)):
        print(f"  {k}: {type(v).__name__} len={len(v)}")
    else:
        print(f"  {k}: {v!r}")

# find meta-ish
for mk in ("meta", "global_meta", "summary"):
    if mk in d:
        print(f"\n=== {mk} ===")
        print(json.dumps(d[mk], ensure_ascii=False, indent=2)[:3000])

# findings
findings = d.get("findings") or []
print("\nTOTAL FINDINGS:", len(findings))
sev = collections.Counter(f.get("severity") for f in findings)
print("BY SEVERITY:", dict(sev))
status = collections.Counter(f.get("status") for f in findings)
print("BY STATUS:", dict(status))
tgt = collections.Counter(f.get("target") for f in findings)
print("TARGETS:", len(tgt))
for t, c in tgt.most_common():
    print(f"   {t}: {c}")
owasp = collections.Counter(f.get("owasp_id") for f in findings)
print("OWASP:", dict(owasp))
titles = collections.Counter(f.get("title") for f in findings)
print("\nTOP TITLES:")
for t, c in titles.most_common(25):
    print(f"   {c:4}  {t}")
