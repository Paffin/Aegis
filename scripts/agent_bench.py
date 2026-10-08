#!/usr/bin/env python3
"""Agent benchmark through Aegis (QA-02, QA-05, risks R6 and R7; tasks T0-05, T0-06, T2-15).

Runs a real coding agent (Claude Code, Codex CLI) on small repositories with tasks, in two modes:
  direct  agent -> tap -> provider              (the baseline)
  aegis   agent -> Aegis -> tap -> provider     (values replaced by pseudonyms on the way)
and scores each run with the task's own check (code that imports and runs the result). Half of the tasks
have their cause in a value that Aegis hides (a typo in a host, a special character in a password, two
addresses that must agree): that is where pseudonyms could cost success.

Measured per agent and mode: success rate, requests, tokens in/out, prompt-cache reads as a share of the
input, cost when the provider reports it, time. With --thinking Claude Code runs with extended thinking and
the run records whether the signatures of thinking blocks went back to the provider unchanged and were
accepted (M1a).

  REAL_KEY=sk-or-... python3 scripts/agent_bench.py --agent claude --mode direct --mode aegis --repeat 2
  python3 scripts/agent_bench.py --selftest        # each task fails before and passes after a reference fix; no model

REAL_KEY is read from the environment and never written to a file or printed. The tap
(scripts/real_tap.py) records what the provider really received; in aegis mode a value of a task found in
any request body is a leak and fails the run.
"""
import argparse, json, os, re, shutil, signal, subprocess, sys, tempfile, textwrap, time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


# ----------------------------------------------------------------------------------------------- tasks
class Task:
    def __init__(self, id, kind, prompt, files, check, solve, secrets=()):
        self.id, self.kind, self.prompt, self.files = id, kind, prompt, files
        self.check, self.solve, self.secrets = check, solve, secrets


def py(workdir, code):
    """Run python code in the work directory; True when it exits 0."""
    r = subprocess.run([sys.executable, "-B", "-c", "import sys; sys.path.insert(0, '.')\n" + textwrap.dedent(code)], cwd=workdir,
                       capture_output=True, timeout=60, env={"PATH": os.environ.get("PATH", ""), "PYTHONDONTWRITEBYTECODE": "1"})
    return r.returncode == 0


def edit(workdir, name, old, new):
    p = os.path.join(workdir, name)
    s = open(p).read()
    assert old in s, (name, old)
    open(p, "w").write(s.replace(old, new))


def clean(workdir):
    """No marker or pseudonym on the disk: restoration worked when the agent wrote a file."""
    for d, _, fs in os.walk(workdir):
        if "__pycache__" in d:
            continue
        for f in fs:
            t = open(os.path.join(d, f), errors="replace").read()
            if "aegis.invalid" in t or "[[" in t and "kind=" in t:
                return False
    return True


TASKS = []


def task(*a, **k):
    TASKS.append(Task(*a, **k))


# plain tasks: nothing to hide
task("fix_range", "plain", "В calc.py функция total(n) должна возвращать сумму чисел от 1 до n включительно, но считает не так. Исправь.",
     {"calc.py": "def total(n):\n    return sum(range(n))\n"},
     lambda w: py(w, "import calc; assert calc.total(10)==55 and calc.total(1)==1 and calc.total(0)==0"),
     lambda w: edit(w, "calc.py", "range(n)", "range(1, n + 1)"))

task("slugify", "plain", "Реализуй slugify(text) в util.py по описанию в докстринге.",
     {"util.py": 'def slugify(text):\n    """Lower case, letters and digits kept, every run of other characters becomes one hyphen,\n    no hyphen at the start or the end: \'Hello,  World!\' -> \'hello-world\'."""\n    raise NotImplementedError\n'},
     lambda w: py(w, "from util import slugify as s; assert s('Hello,  World!')=='hello-world' and s('  a--b ')=='a-b' and s('X1')=='x1' and s('')==''"),
     lambda w: edit(w, "util.py", "    raise NotImplementedError", "    import re\n    return re.sub(r'[^a-z0-9]+', '-', text.lower()).strip('-')"))

task("negative_stock", "plain", "В inventory.py метод remove позволяет уйти в минус. Если запрошено больше, чем есть, он должен бросать ValueError и ничего не менять.",
     {"inventory.py": "class Stock:\n    def __init__(self):\n        self.items = {}\n\n    def add(self, name, qty):\n        self.items[name] = self.items.get(name, 0) + qty\n\n    def remove(self, name, qty):\n        self.items[name] = self.items.get(name, 0) - qty\n"},
     lambda w: py(w, "from inventory import Stock\ns=Stock(); s.add('a',3); s.remove('a',2); assert s.items['a']==1\ntry:\n    s.remove('a',5)\nexcept ValueError:\n    assert s.items['a']==1\nelse:\n    raise SystemExit(1)"),
     lambda w: edit(w, "inventory.py", "        self.items[name] = self.items.get(name, 0) - qty", "        if self.items.get(name, 0) < qty:\n            raise ValueError(name)\n        self.items[name] = self.items.get(name, 0) - qty"))

task("rename", "plain", "Переименуй функцию get_usr в get_user во всех файлах проекта, чтобы тесты продолжали проходить.",
     {"users.py": "def get_usr(i):\n    return {'id': i}\n", "api.py": "from users import get_usr\n\ndef handle(i):\n    return get_usr(i)['id']\n", "tests.py": "from api import handle\nassert handle(7) == 7\n"},
     lambda w: py(w, "import tests, users\nassert hasattr(users,'get_user') and not hasattr(users,'get_usr')") and "get_usr" not in "".join(open(os.path.join(w, f)).read() for f in ("users.py", "api.py", "tests.py")),
     lambda w: [edit(w, f, "get_usr", "get_user") for f in ("users.py", "api.py")])

task("cli_flag", "plain", "Добавь в greet.py флаг --upper: с ним приветствие печатается заглавными буквами.",
     {"greet.py": "import argparse\n\np = argparse.ArgumentParser()\np.add_argument('name')\na = p.parse_args()\nprint(f'Hello, {a.name}')\n"},
     lambda w: subprocess.run([sys.executable, "greet.py", "--upper", "bob"], cwd=w, capture_output=True, text=True).stdout.strip() == "HELLO, BOB"
     and subprocess.run([sys.executable, "greet.py", "bob"], cwd=w, capture_output=True, text=True).stdout.strip() == "Hello, bob",
     lambda w: edit(w, "greet.py", "a = p.parse_args()\nprint(f'Hello, {a.name}')", "p.add_argument('--upper', action='store_true')\na = p.parse_args()\ns = f'Hello, {a.name}'\nprint(s.upper() if a.upper else s)"))

task("date_regex", "plain", "parse.py не разбирает даты вроде 2026-1-5 (один знак в месяце или дне). Исправь, не ломая 2026-01-05.",
     {"parse.py": "import re\n\nDATE = re.compile(r'(\\d{4})-(\\d{2})-(\\d{2})')\n\ndef parse(s):\n    m = DATE.fullmatch(s)\n    return tuple(map(int, m.groups())) if m else None\n"},
     lambda w: py(w, "from parse import parse as p; assert p('2026-1-5')==(2026,1,5) and p('2026-01-05')==(2026,1,5) and p('26-1-5') is None and p('2026-111-5') is None"),
     lambda w: edit(w, "parse.py", "(\\d{2})-(\\d{2})", "(\\d{1,2})-(\\d{1,2})"))

# hidden-value tasks: the cause is in a value Aegis replaces
task("host_typo", "hidden", "Приложение не подключается к базе данных. Найди причину и исправь её. Не меняй config.env.",
     {"config.env": "DB_HOST=prod-db01.corp.local\nDB_USER=svc_payment\n", "app.py": "HOST = \"prod-db1.corp.local\"\nPORT = 5432\n\ndef dsn():\n    return f\"postgres://{HOST}:{PORT}/clients\"\n"},
     lambda w: py(w, "import app; assert app.HOST=='prod-db01.corp.local'") and "DB_HOST=prod-db01.corp.local" in open(os.path.join(w, "config.env")).read() and clean(w),
     lambda w: edit(w, "app.py", "prod-db1.corp.local", "prod-db01.corp.local"),
     secrets=("prod-db01.corp.local", "prod-db1.corp.local"))

task("password_quote", "hidden", "Подключение к базе падает: в пароле из .env есть спецсимволы, а build_dsn в db.py подставляет его в URL как есть. Исправь db.py так, чтобы пароль в URL был закодирован. Сам пароль в .env не меняй.",
     {".env": "DB_USER=svc_payment\nDB_PASSWORD=p@ss/w0rd#9x\n", "db.py": "import os\n\ndef build_dsn():\n    u = os.environ['DB_USER']\n    p = os.environ['DB_PASSWORD']\n    return f'postgres://{u}:{p}@db.internal:5432/clients'\n"},
     lambda w: py(w, "import os\nos.environ['DB_USER']='svc_payment'; os.environ['DB_PASSWORD']='p@ss/w0rd#9x'\nimport db\nfrom urllib.parse import urlsplit, unquote\nu=urlsplit(db.build_dsn())\nassert unquote(u.password)=='p@ss/w0rd#9x' and u.hostname=='db.internal' and u.port==5432")
     and "DB_PASSWORD=p@ss/w0rd#9x" in open(os.path.join(w, ".env")).read() and clean(w),
     lambda w: edit(w, "db.py", "{p}", "{quote(p, safe='')}") or edit(w, "db.py", "import os\n", "import os\nfrom urllib.parse import quote\n"),
     secrets=("p@ss/w0rd#9x", "svc_payment"))

task("zone_typo", "hidden", "client.py обращается к сервису платежей по адресу, который не совпадает с тем, что записан в settings.yaml. Приведи client.py в соответствие с settings.yaml.",
     {"settings.yaml": "payments:\n  url: https://payments.corp.local/api\n", "client.py": "URL = 'https://payments.corp.lcoal/api'\n\ndef endpoint(path):\n    return URL + path\n"},
     lambda w: py(w, "import client; assert client.endpoint('/x')=='https://payments.corp.local/api/x'") and "https://payments.corp.local/api" in open(os.path.join(w, "settings.yaml")).read() and clean(w),
     lambda w: edit(w, "client.py", "corp.lcoal", "corp.local"),
     secrets=("payments.corp.local", "payments.corp.lcoal"))

task("token_name", "hidden", "client.py не находит токен доступа: в .env он есть. Исправь client.py. Значение токена не показывай и не меняй .env.",
     {".env": "INTERNAL_API_TOKEN=Tk9f3Kd02LmQx7Zp\nOTHER=1\n", "client.py": "import os\n\ndef headers():\n    return {'Authorization': 'Bearer ' + os.environ['API_TOKEN']}\n"},
     lambda w: py(w, "import os\nos.environ['INTERNAL_API_TOKEN']='Tk9f3Kd02LmQx7Zp'\nimport client\nassert client.headers()=={'Authorization':'Bearer Tk9f3Kd02LmQx7Zp'}") and "INTERNAL_API_TOKEN=Tk9f3Kd02LmQx7Zp" in open(os.path.join(w, ".env")).read() and clean(w),
     lambda w: edit(w, "client.py", "['API_TOKEN']", "['INTERNAL_API_TOKEN']"),
     secrets=("Tk9f3Kd02LmQx7Zp",))

task("ip_mismatch", "hidden", "Сервис не может достучаться до базы: адрес в allow-списке firewall.py не совпадает с адресом базы в hosts.ini. Исправь firewall.py.",
     {"hosts.ini": "[db]\nprimary = 10.20.30.41\n", "firewall.py": "ALLOW = ['10.20.30.14']\n\ndef allowed(ip):\n    return ip in ALLOW\n"},
     lambda w: py(w, "import firewall; assert firewall.allowed('10.20.30.41') and not firewall.allowed('10.20.30.14')") and "10.20.30.41" in open(os.path.join(w, "hosts.ini")).read() and clean(w),
     lambda w: edit(w, "firewall.py", "10.20.30.14", "10.20.30.41"),
     secrets=("10.20.30.41", "10.20.30.14"))

task("mail_domain", "hidden", "Оповещения не доходят: адрес в notify.py не совпадает с адресом дежурного в OWNERS. Исправь notify.py.",
     {"OWNERS": "on-call: ivan.petrov@company.ru\n", "notify.py": "TO = 'ivan.petrov@compnay.ru'\n\ndef send(msg):\n    return (TO, msg)\n"},
     lambda w: py(w, "import notify; assert notify.TO=='ivan.petrov@company.ru'") and "ivan.petrov@company.ru" in open(os.path.join(w, "OWNERS")).read() and clean(w),
     lambda w: edit(w, "notify.py", "compnay", "company"),
     secrets=("ivan.petrov@company.ru", "ivan.petrov@compnay.ru"))

BY_ID = {t.id: t for t in TASKS}


def materialize(t, w):
    for name, text in t.files.items():
        with open(os.path.join(w, name), "w") as f:
            f.write(text)


def selftest():
    bad = 0
    for t in TASKS:
        w = tempfile.mkdtemp(prefix="bench-")
        materialize(t, w)
        before = t.check(w)
        t.solve(w)
        after = t.check(w)
        ok = (not before) and after
        bad += not ok
        print(("ok   " if ok else "FAIL ") + f"{t.id:15} before={before} after={after}")
        shutil.rmtree(w, ignore_errors=True)
    print(f"{len(TASKS)} tasks, {sum(t.kind == 'hidden' for t in TASKS)} with the cause in a hidden value")
    return bad


# ----------------------------------------------------------------------------------------------- run
def free_ports(n):
    import socket
    socks = [socket.socket() for _ in range(n)]
    for s in socks:
        s.bind(("127.0.0.1", 0))
    ports = [s.getsockname()[1] for s in socks]
    for s in socks:
        s.close()
    return ports


def usage_of(chunks):
    """Tokens from what the provider sent: Anthropic Messages, Chat Completions and Responses, stream or not."""
    u = {"input": 0, "cache_read": 0, "cache_write": 0, "output": 0, "cost": 0.0}
    text = "".join(chunks)
    docs = []
    for line in text.splitlines():
        if line.startswith("data:") and line[5:].strip() not in ("", "[DONE]"):
            try:
                docs.append(json.loads(line[5:]))
            except ValueError:
                pass
    if not docs:
        try:
            docs = [json.loads(text)]
        except ValueError:
            return u
    for d in docs:
        us = None
        if isinstance(d.get("message"), dict) and "usage" in d["message"]:       # anthropic message_start
            us = d["message"]["usage"]
            u["input"] += us.get("input_tokens", 0)
            u["cache_read"] += us.get("cache_read_input_tokens", 0)
            u["cache_write"] += us.get("cache_creation_input_tokens", 0)
            u["output"] += us.get("output_tokens", 0)
            continue
        if d.get("type") == "message_delta" and "usage" in d:                    # anthropic: the final output count
            u["output"] = max(u["output"], d["usage"].get("output_tokens", 0))
            continue
        if isinstance(d.get("response"), dict) and isinstance(d["response"].get("usage"), dict):   # responses (`usage` is null in response.created)
            us = d["response"]["usage"]
            c = (us.get("input_tokens_details") or {}).get("cached_tokens", 0)
            u["input"] += us.get("input_tokens", 0) - c
            u["cache_read"] += c
            u["output"] += us.get("output_tokens", 0)
            u["cost"] += us.get("cost", 0) or 0
            continue
        if isinstance(d.get("usage"), dict):                                     # chat completions (or anthropic non-stream)
            us = d["usage"]
            if "prompt_tokens" in us:
                c = (us.get("prompt_tokens_details") or {}).get("cached_tokens", 0)
                u["input"] += us["prompt_tokens"] - c
                u["cache_read"] += c
                u["output"] += us.get("completion_tokens", 0)
            else:
                u["input"] += us.get("input_tokens", 0)
                u["cache_read"] += us.get("cache_read_input_tokens", 0)
                u["cache_write"] += us.get("cache_creation_input_tokens", 0)
                u["output"] += us.get("output_tokens", 0)
            u["cost"] += us.get("cost", 0) or 0
    return u


def signatures_of(chunks):
    """Signatures of thinking blocks in an answer (Anthropic: signature or signature_delta)."""
    return re.findall(r'"signature"\s*:\s*"([^"]{16,})"', "".join(chunks))


def agent_cmd(agent, mode, w, url, key, model, prompt, thinking):
    """Command line and environment of the agent. `url` is the Aegis address in aegis mode, the tap in direct mode."""
    home = os.path.join(w, "home")
    os.makedirs(home, exist_ok=True)
    work = os.path.join(w, "work")
    env = {"PATH": os.environ["PATH"], "HOME": home, "NO_PROXY": "127.0.0.1,localhost", "no_proxy": "127.0.0.1,localhost", "DISABLE_AUTOUPDATER": "1"}
    vk = "aegis-vk-bench"
    if agent == "claude":
        claude = shutil.which("claude")
        env.update(CLAUDE_CONFIG_DIR=os.path.join(home, ".claude"), ANTHROPIC_BASE_URL=url,
                   ANTHROPIC_SMALL_FAST_MODEL=model, ANTHROPIC_DEFAULT_HAIKU_MODEL=model)
        if mode == "aegis":
            env["ANTHROPIC_API_KEY"] = vk
        else:
            env.update(ANTHROPIC_AUTH_TOKEN=key, ANTHROPIC_API_KEY="")
        if thinking:
            env["MAX_THINKING_TOKENS"] = "4000"
        return [claude, "--bare", "-p", prompt, "--model", model, "--permission-mode", "acceptEdits",
                "--allowedTools", "Bash", "Read", "Edit", "Write", "Glob", "Grep", "--output-format", "json"], env, work
    if agent == "codex":
        codex = shutil.which("codex")
        env.update(CODEX_HOME=home, AEGIS_API_KEY=vk if mode == "aegis" else key)
        return [codex, "exec", "--skip-git-repo-check", "-s", "workspace-write", "-c", "model_provider=aegis",
                "-c", f'model_providers.aegis={{name="Aegis",base_url="{url}/v1",env_key="AEGIS_API_KEY",wire_api="responses"}}',
                "-c", f"model={model}", "-c", "web_search=disabled", prompt], env, work
    raise SystemExit(f"unknown agent {agent}")


def run_once(agent, mode, t, args, key):
    w = tempfile.mkdtemp(prefix="bench-")
    work = os.path.join(w, "work")
    os.makedirs(work)
    materialize(t, work)
    tap_p, gw_p, adm_p = free_ports(3)
    log = os.path.join(w, "tap.log")
    open(log, "w").close()
    procs = []
    try:
        tap_env = dict(os.environ, TAP_KEY=key, TAP_RESPONSES="1")
        procs.append(subprocess.Popen([sys.executable, os.path.join(ROOT, "scripts/real_tap.py"), str(tap_p), log, args.base], env=tap_env))
        url = f"http://127.0.0.1:{tap_p}"
        if mode == "aegis":
            import hashlib
            h = hashlib.sha256(b"aegis-vk-bench").hexdigest()
            cfg = {"listen": f"127.0.0.1:{gw_p}", "admin_listen": f"127.0.0.1:{adm_p}", "openai_base_url": url, "anthropic_base_url": url,
                   "anthropic_auth": "bearer", "internal_zones": ["corp.local", "company.ru"], "audit_path": os.path.join(w, "audit.jsonl"),
                   "virtual_keys": [{"sha256": h, "principal": "u:bench"}]}
            json.dump(cfg, open(os.path.join(w, "gw.json"), "w"))
            genv = dict(os.environ, AEGIS_K_TENANT="0123456789abcdef0123456789abcdef", AEGIS_K_AUDIT="fedcba9876543210fedcba9876543210",
                        AEGIS_OPENAI_KEY=key, AEGIS_ANTHROPIC_KEY=key)
            procs.append(subprocess.Popen([os.path.join(ROOT, "target/release/aegis-gateway"), os.path.join(w, "gw.json")], env=genv,
                                          stdout=open(os.path.join(w, "gw.log"), "w"), stderr=subprocess.STDOUT))
            for _ in range(100):
                if subprocess.run(["curl", "-sf", f"http://127.0.0.1:{adm_p}/readyz"], capture_output=True).returncode == 0:
                    break
                time.sleep(0.1)
            url = f"http://127.0.0.1:{gw_p}"
        cmd, env, cwd = agent_cmd(agent, mode, w, url, key, args.model_for(agent), t.prompt, args.thinking)
        t0 = time.time()
        timed_out = False
        try:
            r = subprocess.run(cmd, env=env, cwd=cwd, stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=args.timeout)
            out = r.stdout + r.stderr
        except subprocess.TimeoutExpired as e:
            timed_out, out = True, ""
        secs = time.time() - t0
    finally:
        for p in procs:
            p.send_signal(signal.SIGTERM)
        for p in procs:
            try:
                p.wait(timeout=5)
            except subprocess.TimeoutExpired:
                p.kill()
    rows = [json.loads(l) for l in open(log) if l.strip()]
    posts = [r for r in rows if r["method"] == "POST"]
    bodies = " ".join(r["body"] for r in rows)
    res = {"task": t.id, "kind": t.kind, "agent": agent, "mode": mode, "ok": bool(t.check(work)), "timed_out": timed_out, "secs": round(secs, 1),
           "requests": len(posts), "errors": sum(1 for r in rows if r["status"] != 200)}
    u = {"input": 0, "cache_read": 0, "cache_write": 0, "output": 0, "cost": 0.0}
    for r in posts:
        for k, v in usage_of(r.get("chunks", [])).items():
            u[k] += v
    res.update(u)
    if mode == "aegis":
        res["leaked"] = [s for s in t.secrets if s in bodies]
        if res["leaked"]:
            res["ok"] = False
    if args.thinking:
        sigs = []
        for r in posts:
            sigs.append(signatures_of(r.get("chunks", [])))
        seen = [s for ss in sigs for s in ss]
        later = " ".join(r["body"] for r in posts[1:])
        res["thinking_signatures"] = len(set(seen))
        res["signatures_returned"] = sum(1 for s in set(seen) if s in later)
    if args.keep:
        res["kept"] = w
    else:
        shutil.rmtree(w, ignore_errors=True)
    return res


def report(results):
    keys = sorted({(r["agent"], r["mode"]) for r in results})
    print("\n%-8s %-7s %-9s %6s %6s %8s %8s %9s %7s" % ("agent", "mode", "tasks", "pass", "reqs", "in", "out", "cache%", "secs"))
    summary = {}
    for a, m in keys:
        for kind in ("all", "plain", "hidden"):
            rs = [r for r in results if r["agent"] == a and r["mode"] == m and (kind == "all" or r["kind"] == kind)]
            if not rs:
                continue
            n = len(rs)
            ok = sum(r["ok"] for r in rs)
            tin = sum(r["input"] + r["cache_read"] + r["cache_write"] for r in rs)
            cr = sum(r["cache_read"] for r in rs)
            line = "%-8s %-7s %-9s %5.1f%% %6.1f %8d %8d %8.1f%% %7.1f" % (
                a, m, f"{kind}({n})", 100 * ok / n, sum(r["requests"] for r in rs) / n, tin / n, sum(r["output"] for r in rs) / n,
                100 * cr / tin if tin else 0, sum(r["secs"] for r in rs) / n)
            print(line)
            summary[(a, m, kind)] = (ok / n, cr / tin if tin else 0)
    for a in sorted({a for a, _ in keys}):
        for kind in ("all", "plain", "hidden"):
            d, g = summary.get((a, "direct", kind)), summary.get((a, "aegis", kind))
            if d and g:
                print(f"{a} {kind}: success direct {100*d[0]:.1f}% -> aegis {100*g[0]:.1f}% ({100*(g[0]-d[0]):+.1f} pp, target not worse than -3 pp); "
                      f"cache share direct {100*d[1]:.1f}% -> aegis {100*g[1]:.1f}% (target at least 98% of the baseline)")
    leaks = [r for r in results if r.get("leaked")]
    print(f"leaks to the provider in aegis mode: {sum(len(r['leaked']) for r in leaks)} in {len(leaks)} runs")
    th = [r for r in results if "thinking_signatures" in r]
    if th:
        print(f"thinking: {sum(r['thinking_signatures'] for r in th)} signatures seen, {sum(r['signatures_returned'] for r in th)} came back unchanged in a later request, "
              f"{sum(r['errors'] for r in th)} provider errors")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--agent", action="append", choices=["claude", "codex"])
    ap.add_argument("--mode", action="append", choices=["direct", "aegis"])
    ap.add_argument("--task", action="append", help="task id (default: all)")
    ap.add_argument("--repeat", type=int, default=1)
    ap.add_argument("--claude-model", default=os.environ.get("REAL_CLAUDE_MODEL", "anthropic/claude-haiku-4.5"))
    ap.add_argument("--codex-model", default=os.environ.get("REAL_MODEL", "openai/gpt-5-mini"))
    ap.add_argument("--base", default=os.environ.get("REAL_BASE", "https://openrouter.ai/api"))
    ap.add_argument("--timeout", type=int, default=300)
    ap.add_argument("--thinking", action="store_true", help="Claude Code with extended thinking; record signature round trips")
    ap.add_argument("--keep", action="store_true")
    ap.add_argument("--out", help="write the results as JSON")
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args()
    args.model_for = lambda agent: args.claude_model if agent == "claude" else args.codex_model
    if args.selftest:
        sys.exit(1 if selftest() else 0)
    key = os.environ.get("REAL_KEY")
    if not key:
        sys.exit("set REAL_KEY (read from the environment, never written)")
    agents, modes = args.agent or ["claude"], args.mode or ["direct", "aegis"]
    tasks = [BY_ID[i] for i in args.task] if args.task else TASKS
    subprocess.run(["cargo", "build", "-q", "--release", "-p", "aegis-gateway"], cwd=ROOT, check=True)
    results = []
    for rep in range(args.repeat):
        for a in agents:
            for t in tasks:
                for m in modes:
                    r = run_once(a, m, t, args, key)
                    r["repeat"] = rep
                    results.append(r)
                    print(f"{'ok  ' if r['ok'] else 'FAIL'} {a:6} {m:6} {t.id:15} reqs={r['requests']:2} in={r['input']+r['cache_read']+r['cache_write']:6} cache={r['cache_read']:6} "
                          f"out={r['output']:5} {r['secs']:5.1f}s{' LEAK ' + str(r['leaked']) if r.get('leaked') else ''}{' TIMEOUT' if r['timed_out'] else ''}", flush=True)
    report(results)
    if args.out:
        with open(args.out, "w") as f:
            json.dump(results, f, indent=1)


if __name__ == "__main__":
    main()
