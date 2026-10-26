# callguard: judge an agent's tool call by what it does on this machine, not by its text

Traceforce's site says it "tracks every tool call from MCPs to CLIs and stops dangerous actions", and shows three examples it prevents: an agent deleting a production database, corrupting financial records, and an unvetted MCP sending tokens to an attacker-controlled site (https://www.traceforce.ai). Any such gate lives between two failures: block `rm -rf node_modules` and users turn it off; allow `rm -r -f ${HOME}/` and it fails at its one job. This prototype is a small benchmark with known labels and a call classifier that resolves meaning instead of matching text.

## What it does
For one tool call (`shell`, `db.query`, `http.post`) plus its context (cwd, environment, which DB connections are production, allowed hosts, known secrets) it returns `ALLOW`, `REVIEW` or `BLOCK` with a reason:
- **Shell:** tokenised with shlex, `$VAR`, `${VAR}` and `~` expanded from the environment, paths resolved against the working directory. Recursive delete of `/`, home, the repo root, `.git`, or an ancestor of the cwd is blocked; `node_modules`, `dist`, `.venv`, `/tmp` are fine. Force-push, `+branch` and `:branch` on `main`/`master`/`release` are blocked, `--force-with-lease` on a feature branch is not. `curl | sh` from an unknown host, uploads of `~/.ssh` / `~/.aws` / `.env`, and tokens sent to an unknown host are blocked. `echo <b64> | base64 -d | sh` is decoded and judged. `sudo`/`env`/`nohup`, `bash -c '...'` and `psql -c` are unwrapped.
- **SQL:** comments stripped, statements split; DROP/TRUNCATE and DELETE/UPDATE with no real WHERE (`WHERE 1=1` counts as none) are blocked on a production connection and allowed on dev/staging or on `tmp_`/`scratch_` tables.
- **HTTP:** a body or header carrying a known secret or an AKIA/ghp_/sk- pattern to a host not on the allow list.
- Anything it cannot resolve (command substitution) is `REVIEW`.

## Results (synthetic calls, labelled by the generator)
Dev: 1,500 calls (836 dangerous, 664 look-alikes that are fine). Held-out: 1,500 calls (864 dangerous, 636 fine) with 7 call families the classifier had not seen (`bash -c`, `env rm`, `\rm`, `psql $DATABASE_URL`, a dev `psql`, an `echo` that merely mentions `rm -rf ~`, `bash -c` on a harmless command); seeds fixed in git before the first run.

| Held-out | keyword denylist | callguard run 1 | callguard run 2 (after fixes) |
|---|---|---|---|
| dangerous stopped (864) | 736 | 640 | 864 |
| fine calls blocked (636) | 527 | 98 | 0 |

Run 1 missed 224 (106 `bash -c` and 118 `env rm`, because I only unwrapped `sudo`) and blocked 98 fine `psql` calls (it judged every `psql -c` against the production `DATABASE_URL` instead of the URL on the command line). I fixed both and re-ran; run 2 is the second column, so the held-out set has been used to tune. The keyword list blocks 83% of fine calls (any `curl`, `DELETE FROM`, `rm -rf node_modules`) and misses force-pushes written as `-f`/`+main`, `find ~ -delete`, and tokens POSTed from a tool call. Dev: 836/836 stopped, 0/664 fine blocked.

## What it still misses (probed by hand, not in the benchmark)
`python -c "shutil.rmtree('/home/dev')"`, `echo ~ | xargs rm -rf`, `cd .. && rm -rf proj` (no `cd` tracking), `rm -rf ./*` in the project root (globs are not expanded), a symlink into `/`, and `curl -o s.sh && sh s.sh` are all `ALLOW`. `find` with any `-name`/`-mtime` filter is trusted. `rm -rf $(echo ~)` is `REVIEW`. A real gate also needs process, file-system and network visibility, which this does not have.

## Read this before believing the table
The calls, the labels and the classifier are all mine, and each family is a template, so near-perfect scores mostly show that the classifier knows my templates. Nothing was run: calls are strings, no command was executed, and nothing touched Traceforce's scanner (mcp-xray), data or systems.

## Run it (3 commands)
```
pip install pytest
python -m pytest -q tests
python -m callguard.run
```
Standard library only. 4 tests.

Unofficial prototype by Kushagra Pratap Singh. Not affiliated with Traceforce.
