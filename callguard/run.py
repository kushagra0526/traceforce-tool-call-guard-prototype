import json
from collections import Counter

from . import check, gen


def score(seeds, held):
    t, per = Counter(), {}
    for s in seeds:
        call, ctx, label, fam = gen.make_call(s, held)
        verdicts = {"mine": check.classify(call, ctx)[0], "kw": check.keyword(call)[0]}
        p = per.setdefault(fam, Counter())
        p["n"] += 1
        for name, v in verdicts.items():
            t[f"{name}_{'dangerous' if label else 'benign'}_{v.lower()}"] += 1
            p[f"{name}_{v.lower()}"] += 1
        t["dangerous" if label else "benign"] += 1
    return {"totals": dict(sorted(t.items())), "by_family": {k: dict(v) for k, v in sorted(per.items())}}


def main():
    out = {"dev": score(range(0, 1500), False), "held_out": score(range(10000, 11500), True)}
    json.dump(out, open("out/result.json", "w"), indent=1)
    for k, v in out.items():
        print(k, v["totals"])
        for f, c in v["by_family"].items():
            print("   ", f, c)


if __name__ == "__main__":
    main()
