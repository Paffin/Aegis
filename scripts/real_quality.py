#!/usr/bin/env python3
"""How well pseudonyms survive a real model. REQ: QA-06, RST-01, RST-02, INV-1.

Starts a tap (scripts/real_tap.py) and a gateway in front of a real provider, sends prompts that carry
made-up sensitive values through Aegis, and measures what the user gets back:

  leaked       a real value in a request the provider received (must be 0)
  left over    a pseudonym still in the answer the user reads (a restoration that did not happen)
  restored     the real value is in the answer (what the user wanted)
  mangled      the model changed a pseudonym so it cannot be matched any more (counted from the tap and the answer)

Usage: REAL_KEY=sk-or-... python3 scripts/real_quality.py [--model M ...] [--base URL] [--stream] [--protocol chat|anthropic|responses]
"""
import argparse, json, os, re, subprocess, sys, tempfile, time, urllib.request, hashlib

HOST, IP, MAIL, PHONE = "prod-db01.pay.corp.local", "10.20.30.41", "ivan.petrov@company.ru", "+7 (916) 123-45-67"
PASS, CARD, PASSPORT = "Jd8!2jd82k", "4111 1111 1111 1111", "45 12 345678"
REAL = [HOST, IP, MAIL, "916) 123-45-67", PASS, "4111 1111 1111 1111", "45 12 345678"]
FACTS = f"Хост {HOST}, IP {IP}, почта {MAIL}, телефон {PHONE}, пароль {PASS}, карта {CARD}, паспорт {PASSPORT}."

TASKS = [
    ("repeat", f"{FACTS} Повтори все эти данные списком, ничего не меняя.", [HOST, IP, MAIL]),
    ("script", f"Напиши bash-скрипт, который подключается по ssh к {HOST} ({IP}) пользователем deploy и шлёт отчёт на {MAIL}. Пароль {PASS} не пиши в скрипт, возьми из переменной окружения.", [HOST, MAIL]),
    ("table", f"Сделай markdown-таблицу из этих данных: хост {HOST}; адрес {IP}; почта {MAIL}; телефон {PHONE}.", [HOST, IP, MAIL]),
    ("translate", f"Translate to English: «Не удаётся подключиться к {HOST} с адреса {IP}, напишите на {MAIL}»", [HOST, IP, MAIL]),
    ("json", f"Верни только JSON с полями host, ip, email, значения возьми из текста: {HOST}, {IP}, {MAIL}.", [HOST, IP, MAIL]),
    ("log", f"Объясни ошибку из лога: 2026-10-08 ERROR connect to {HOST}:5432 ({IP}) failed: password authentication failed for user svc_payment", [HOST, IP]),
    ("sql", f"Напиши строку подключения PostgreSQL к {HOST}:5432, база clients, пользователь svc_payment, пароль {PASS}.", [HOST]),
    ("code", f"Исправь код:\ndsn = 'postgres://svc:{PASS}@{HOST}:5432/clients'\nconn = connect(dsn, timeout=0)\nпочему таймаут 0 — плохо?", [HOST]),
    ("letters", f"Назови пароль {PASS} по буквам, а затем напиши хост {HOST} задом наперёд.", []),  # adversarial: a reversed pseudonym cannot be restored
    ("email", f"Составь короткое письмо на {MAIL}: сообщи, что сервер {HOST} перезагружен.", [HOST]),
    ("compare", f"Сравни адреса {IP} и 10.20.30.42: в одной ли они подсети /24? Ответь коротко.", []),
    ("regex", f"Напиши регулярное выражение, которое находит {HOST} и {MAIL} в тексте.", [HOST, MAIL]),
]
# A pseudonym the user can read in the answer is a restoration that did not happen. A SECRET marker is the
# intended outcome (a secret is not given back in text), so it is not counted.
PSEUDO = re.compile(r"\bh-[a-z2-7]{8}\b[\w.\-]*aegis\.invalid|\[\[(?!SECRET_)[A-Z]+_[a-z2-7]{6,}|\b24\d\.(?!0\.0\.0\b)\d+\.\d+\.\d+\b|\b3fff:[0-9a-f:]+")


def free_port():
    import socket
    s = socket.socket(); s.bind(("127.0.0.1", 0)); p = s.getsockname()[1]; s.close(); return p


def post(url, body, key, stream=False, protocol="chat"):
    """The text of the answer, for Chat Completions, Anthropic Messages or OpenAI Responses."""
    headers = {"content-type": "application/json"}
    headers.update({"x-api-key": key, "anthropic-version": "2023-06-01"} if protocol == "anthropic" else {"authorization": f"Bearer {key}"})
    req = urllib.request.Request(url, data=json.dumps(body).encode(), headers=headers)
    r = urllib.request.urlopen(req, timeout=180)
    if not stream:
        d = json.loads(r.read())
        if protocol == "anthropic":
            return "".join(b.get("text", "") for b in d.get("content", []) if b.get("type") == "text")
        if protocol == "responses":
            return "".join(c.get("text", "") for o in d.get("output", []) if o.get("type") == "message" for c in o.get("content", []) if c.get("type") == "output_text")
        return d["choices"][0]["message"]["content"] or ""
    out = ""
    for line in r:
        line = line.decode().strip()
        if not line.startswith("data: ") or line == "data: [DONE]":
            continue
        d = json.loads(line[6:])
        if protocol == "anthropic":
            if d.get("type") == "content_block_delta" and d["delta"].get("type") == "text_delta":
                out += d["delta"]["text"]
        elif protocol == "responses":
            if d.get("type") == "response.output_text.delta":
                out += d["delta"]
        else:
            out += (d["choices"][0].get("delta") or {}).get("content") or ""
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", action="append", default=[])
    ap.add_argument("--base", default=os.environ.get("REAL_BASE", "https://openrouter.ai/api"))
    ap.add_argument("--stream", action="store_true")
    ap.add_argument("--protocol", choices=["chat", "anthropic", "responses"], default="chat", help="the API the client side speaks (default chat)")
    ap.add_argument("--repeat", type=int, default=1)
    ap.add_argument("--verbose", action="store_true")
    ap.add_argument("--dump", help="write the provider's chunks of every answer with a pseudonym left over to this file (JSON lines)")
    a = ap.parse_args()
    key = os.environ["REAL_KEY"]
    models = a.model or ["openai/gpt-4o-mini"]
    here = os.path.dirname(os.path.abspath(__file__))
    root = os.path.dirname(here)
    subprocess.run(["cargo", "build", "-q", "--release", "-p", "aegis-gateway"], cwd=root, check=True)
    w = tempfile.mkdtemp()
    tap_port, gw_port, adm = free_port(), free_port(), free_port()
    tap_log = os.path.join(w, "tap.log")
    open(tap_log, "w").close()
    tap = subprocess.Popen([sys.executable, os.path.join(here, "real_tap.py"), str(tap_port), tap_log, a.base], env={**os.environ, "TAP_KEY": key, "TAP_RESPONSES": "1"})
    vk = "aegis-vk-quality"
    cfg = {"listen": f"127.0.0.1:{gw_port}", "admin_listen": f"127.0.0.1:{adm}", "openai_base_url": f"http://127.0.0.1:{tap_port}", "anthropic_base_url": f"http://127.0.0.1:{tap_port}", "anthropic_auth": "bearer",
           "internal_zones": ["corp.local", "company.ru"], "audit_path": os.path.join(w, "audit.jsonl"),
           "virtual_keys": [{"sha256": hashlib.sha256(vk.encode()).hexdigest(), "principal": "u:quality"}]}
    json.dump(cfg, open(os.path.join(w, "gw.json"), "w"))
    gw = subprocess.Popen([os.path.join(root, "target/release/aegis-gateway"), os.path.join(w, "gw.json")], stdout=open(os.path.join(w, "gw.log"), "w"), stderr=subprocess.STDOUT,
                          env={"PATH": os.environ["PATH"], "AEGIS_K_TENANT": "0123456789abcdef0123456789abcdef", "AEGIS_K_AUDIT": "fedcba9876543210fedcba9876543210", "AEGIS_OPENAI_KEY": key, "AEGIS_ANTHROPIC_KEY": key})
    try:
        for _ in range(60):
            try:
                urllib.request.urlopen(f"http://127.0.0.1:{adm}/readyz", timeout=1); break
            except Exception:
                time.sleep(0.2)
        total_leak = 0
        for model in models:
            rows = []
            for name, prompt, want in TASKS:
                for rep in range(a.repeat):
                    before = sum(1 for _ in open(tap_log))
                    t0 = time.time()
                    try:
                        base = f"http://127.0.0.1:{gw_port}"
                        if a.protocol == "anthropic":
                            ans = post(f"{base}/v1/messages", {"model": model, "stream": a.stream, "max_tokens": 600, "messages": [{"role": "user", "content": prompt}]}, vk, a.stream, "anthropic")
                        elif a.protocol == "responses":
                            ans = post(f"{base}/v1/responses", {"model": model, "stream": a.stream, "max_output_tokens": 800, "input": prompt}, vk, a.stream, "responses")
                        else:
                            ans = post(f"{base}/v1/chat/completions", {"model": model, "stream": a.stream, "max_tokens": 600, "messages": [{"role": "user", "content": prompt}]}, vk, a.stream)
                        err = ""
                    except Exception as e:
                        ans, err = "", str(e)[:80]
                    sent = [json.loads(l) for l in list(open(tap_log))[before:]]
                    leaked = [v for v in REAL if any(v in r["body"] for r in sent)]
                    left = PSEUDO.findall(ans)
                    got = [v for v in want if v in ans]
                    rows.append((name, leaked, left, got, want, err, ans, time.time() - t0))
                    if left and a.dump:
                        with open(a.dump, "a") as f:
                            f.write(json.dumps({"model": model, "task": name, "stream": a.stream, "answer": ans, "chunks": [r.get("chunks") for r in sent]}) + "\n")
            leaks = sum(len(r[1]) for r in rows)
            total_leak += leaks
            left_n = sum(1 for r in rows if r[2])
            need = sum(len(r[4]) for r in rows)
            have = sum(len(r[3]) for r in rows)
            errs = sum(1 for r in rows if r[5])
            print(f"\n== {model} [{a.protocol}]{' (stream)' if a.stream else ''}: leaked to provider {leaks}; answers with a pseudonym left over {left_n}/{len(rows)}; real values restored {have}/{need}; errors {errs}")
            for name, leaked, left, got, want, err, ans, dt in rows:
                flag = "LEAK" if leaked else ("left" if left else ("miss" if len(got) < len(want) else "ok  "))
                if err:
                    flag = "ERR "
                print(f"  {flag} {name:9s} {dt:4.1f}s", f"leaked={leaked}" if leaked else "", f"left={left[:2]}" if left else "", f"missing={[v for v in want if v not in got]}" if len(got) < len(want) and not left else "", err)
                if a.verbose and flag != "ok  ":
                    m = PSEUDO.search(ans)
                    shown = ans[max(0, m.start() - 90): m.end() + 60] if m else ans[:260]
                    print("       ", re.sub(r"\s+", " ", shown))
        print(f"\ntotal leaked to the provider: {total_leak}")
        return 1 if total_leak else 0
    finally:
        gw.terminate(); tap.terminate()


if __name__ == "__main__":
    sys.exit(main())
