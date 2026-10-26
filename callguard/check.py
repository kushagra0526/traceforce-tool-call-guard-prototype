"""Classify one agent tool call as ALLOW / REVIEW / BLOCK from its meaning on this machine, not its text.

Shell commands are tokenised, variables and ~ expanded from the call's environment, paths resolved against the
working directory and compared to protected locations. SQL is split into statements and judged against the
connection it will run on. Anything it cannot resolve is REVIEW, never ALLOW-by-default.
"""
import base64
import posixpath
import re
import shlex

PROTECTED_BRANCH = {"main", "master", "release"}
SECRET_RE = re.compile(r"(AKIA[0-9A-Z]{12,}|ghp_[A-Za-z0-9]{20,}|sk-[A-Za-z0-9]{20,})")
SENSITIVE = (".ssh", ".aws", ".env", ".netrc", ".gnupg")
SAFE_DIRS = {"node_modules", "dist", "build", ".venv", "__pycache__", ".pytest_cache", "target", ".next"}
SCRATCH = re.compile(r"^(tmp|temp|scratch)_", re.I)
RANK = {"ALLOW": 0, "REVIEW": 1, "BLOCK": 2}


def worst(a, b):
    return a if RANK[a[0]] >= RANK[b[0]] else b


def expand(tok, env):
    tok = re.sub(r"\$\{(\w+)\}|\$(\w+)", lambda m: env.get(m.group(1) or m.group(2), "?"), tok)
    return env["HOME"] + tok[1:] if tok == "~" or tok.startswith("~/") else tok


def resolve(tok, ctx):
    p = expand(tok, ctx["env"])
    return posixpath.normpath(p if p.startswith("/") else posixpath.join(ctx["cwd"], p))


def tokens(cmd):
    lex = shlex.shlex(cmd, posix=True, punctuation_chars="|&;")
    lex.whitespace_split = True
    return list(lex)


def split_segments(toks):
    segs, cur = [], []
    for t in toks:
        if t and set(t) <= set("|&;"):
            segs.append((cur, t))
            cur = []
        else:
            cur.append(t)
    segs.append((cur, ""))
    return [(s, sep) for s, sep in segs if s]


def rm_check(args, ctx):
    flags = "".join(a.lstrip("-") for a in args if a.startswith("-") and not a.startswith("--")) + \
        ("r" if "--recursive" in args else "")
    if "r" not in flags.lower():
        return ("ALLOW", "rm without -r")
    for a in (x for x in args if not x.startswith("-")):
        if "?" in expand(a, ctx["env"]):
            return ("REVIEW", f"rm target {a} has an unresolved variable")
        p = resolve(a, ctx)
        home, cwd = ctx["env"]["HOME"], ctx["cwd"]
        if p in ("/", home) or p.startswith(home + "/*") or cwd.startswith(p + "/") or p == cwd or \
                posixpath.basename(p) == ".git" and p.startswith(cwd) or \
                (p.startswith("/") and p.count("/") <= 2 and not p.startswith("/tmp")):
            return ("BLOCK", f"recursive delete of {p}")
        if p.startswith("/tmp/") or (p.startswith(cwd + "/") and posixpath.basename(p) in SAFE_DIRS):
            continue
        if not p.startswith(cwd + "/"):
            return ("REVIEW", f"recursive delete outside the project: {p}")
    return ("ALLOW", "build/cache or temp path")


def git_check(args):
    if not args or args[0] != "push":
        return ("ALLOW", "git, not a push")
    force = any(a in ("-f", "--force") for a in args) or any(a.startswith("+") for a in args[1:])
    refs = [a for a in args[1:] if not a.startswith("-")][1:]
    for r in refs:
        dst = r.split(":")[-1].lstrip("+").replace("refs/heads/", "")
        deleting = r.startswith(":")
        if dst in PROTECTED_BRANCH and (force or deleting):
            return ("BLOCK", f"{'delete' if deleting else 'force push'} on protected branch {dst}")
    return ("ALLOW", "push without overwriting a protected branch")


def net_check(prog, args, ctx, piped_to_shell):
    urls = [a for a in args if re.match(r"https?://", a)]
    host = (re.match(r"https?://([^/:]+)", urls[0]).group(1) if urls else "?")
    allowed = host in ctx["allowed_hosts"]
    if piped_to_shell and not allowed:
        return ("BLOCK", f"downloads from {host} and runs it")
    sent = []  # (flag, raw value)
    for i, a in enumerate(args):
        if a in ("-d", "--data", "--data-binary", "-F", "-T", "--upload-file", "-H", "--header") and i + 1 < len(args):
            sent.append((a, args[i + 1]))
    if not allowed:
        for flag, raw in sent:
            s = expand(raw, ctx["env"])
            path = raw.split("@", 1)[1] if "@" in raw else raw if flag in ("-T", "--upload-file") else ""
            if path and any(x in resolve(path, ctx) for x in SENSITIVE):
                return ("BLOCK", f"uploads a credential file to {host}")
            if SECRET_RE.search(s) or any(v and v in s for v in ctx["secrets"]):
                return ("BLOCK", f"sends a secret to {host}")
    return ("ALLOW", "network call to an allowed host or without sensitive data" if allowed or not sent else "no secret sent")


def shell_check(cmd, ctx, depth=0):
    try:
        segs = split_segments(tokens(cmd))
    except ValueError:
        return ("REVIEW", "cannot parse command")
    out = ("ALLOW", "nothing dangerous found")
    for i, (seg, sep) in enumerate(segs):
        while seg and seg[0] in ("sudo", "nohup", "time"):
            seg = seg[1:]
        if not seg:
            continue
        prog, args = seg[0], seg[1:]
        nxt = segs[i + 1][0][0] if sep == "|" and i + 1 < len(segs) else None
        if any("$(" in a or "`" in a for a in seg):
            out = worst(out, ("REVIEW", "command substitution"))
        if prog == "rm":
            out = worst(out, rm_check(args, ctx))
        elif prog == "find" and "-delete" in args:
            filtered = any(a in ("-name", "-iname", "-regex", "-mtime") for a in args)  # shortcut: any filter is trusted
            out = worst(out, ("ALLOW", "find with a name/time filter") if filtered or not args or args[0].startswith("-") else rm_check(["-r", args[0]], ctx))
        elif prog == "git":
            out = worst(out, git_check(args))
        elif prog in ("curl", "wget"):
            out = worst(out, net_check(prog, args, ctx, nxt in ("sh", "bash")))
        elif prog == "base64" and ("-d" in args or "--decode" in args) and nxt in ("sh", "bash") and depth < 2:
            prev = segs[i - 1][0] if i else []
            if prev and prev[0] == "echo" and len(prev) > 1:
                try:
                    out = worst(out, shell_check(base64.b64decode(prev[1]).decode(), ctx, depth + 1))
                except Exception:
                    out = worst(out, ("REVIEW", "undecodable payload piped to a shell"))
        elif prog == "psql" and "-c" in args:
            out = worst(out, sql_check(args[args.index("-c") + 1], ctx["env"].get("DATABASE_URL", ""), ctx))
    return out


def sql_check(sql, conn, ctx):
    prod = ctx["conns"].get(conn, "prod" in conn)
    sql = re.sub(r"/\*.*?\*/", " ", sql, flags=re.S)
    sql = re.sub(r"--[^\n]*", " ", sql)
    out = ("ALLOW", "no destructive statement on prod")
    for st in (s.strip() for s in sql.split(";") if s.strip()):
        low = re.sub(r"\s+", " ", st.lower())
        kind = low.split(" ")[0]
        table = re.sub(r"^(drop table|truncate table|truncate|delete from|update|drop database)( if exists)? ", "", low).split(" ")[0]
        no_where = " where " not in f" {low} " or re.search(r"where (1\s*=\s*1|true)\s*$", low)
        if kind in ("drop", "truncate") and not SCRATCH.match(table):
            r = ("BLOCK", f"{kind} {table} on {'prod' if prod else conn}") if prod else ("ALLOW", f"{kind} on a non-prod connection")
        elif kind in ("delete", "update") and no_where:
            r = ("BLOCK", f"{kind} without a real WHERE on prod") if prod else ("ALLOW", f"{kind} on a non-prod connection")
        else:
            r = ("ALLOW", "statement ok")
        out = worst(out, r)
    return out


def http_check(call, ctx):
    host = re.match(r"https?://([^/:]+)", call["url"]).group(1)
    blob = call.get("body", "") + " " + " ".join(call.get("headers", {}).values())
    if host not in ctx["allowed_hosts"] and (SECRET_RE.search(blob) or any(v and v in blob for v in ctx["secrets"])):
        return ("BLOCK", f"sends a secret to {host}")
    return ("ALLOW", "no secret to an unknown host")


def classify(call, ctx):
    t = call["tool"]
    if t == "shell":
        return shell_check(call["cmd"], ctx)
    if t == "db.query":
        return sql_check(call["sql"], call["conn"], ctx)
    if t == "http.post":
        return http_check(call, ctx)
    return ("REVIEW", f"unknown tool {t}")


def keyword(call):
    """Baseline: substring denylist over the call text."""
    text = " ".join(str(v) for v in call.values()).lower()
    bad = ["rm -rf", "rm -fr", "drop table", "drop database", "truncate", "delete from", "--force", " -f ", "curl", "wget",
           "| sh", "| bash", "base64", ".ssh", ".aws", "authorization", "bearer", "update "]
    return ("BLOCK", "keyword") if any(k in text for k in bad) else ("ALLOW", "no keyword")
