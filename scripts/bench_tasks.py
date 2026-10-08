"""Tasks 13..50 of the agent benchmark (QA-02); the first twelve live in agent_bench.py.

19 plain tasks (small bugs and small features, nothing to hide) and 19 hidden ones: the cause is in a value
that Aegis replaces (a typo in a host, a digit in a phone number, a name in another word order, a special
character in a password). A hidden task names the file to fix and never says which character is wrong.
"""
import os


def register(task, py, edit, clean):
    def rewrite(w, name, text):
        with open(os.path.join(w, name), "w") as f:
            f.write(text)

    def has(w, name, text):
        return text in open(os.path.join(w, name)).read()

    # ------------------------------------------------------------------------------------ plain (19)
    task("word_count", "plain", "Реализуй word_count(text) в util.py по докстрингу.",
         {"util.py": 'def word_count(text):\n    """Dict word -> count. Words are separated by any whitespace, case does not matter (keys are lower case)."""\n    raise NotImplementedError\n'},
         lambda w: py(w, "from util import word_count as c; assert c('A a b\\nB  b')=={'a':2,'b':3} and c('')=={}"),
         lambda w: edit(w, "util.py", "    raise NotImplementedError", "    from collections import Counter\n    return dict(Counter(text.lower().split()))"))

    task("flatten", "plain", "flatten в flat.py разворачивает только один уровень вложенности. Сделай так, чтобы разворачивались любые уровни; строки остаются целыми.",
         {"flat.py": "def flatten(x):\n    return [i for sub in x for i in sub]\n"},
         lambda w: py(w, "from flat import flatten as f; assert f([1,[2,[3,[4]]],5])==[1,2,3,4,5] and f(['ab',['c']])==['ab','c'] and f([])==[]"),
         lambda w: rewrite(w, "flat.py", "def flatten(x):\n    out = []\n    for i in x:\n        if isinstance(i, list):\n            out.extend(flatten(i))\n        else:\n            out.append(i)\n    return out\n"))

    task("chunks", "plain", "chunks(lst, n) в chunk.py теряет последний кусок. Исправь.",
         {"chunk.py": "def chunks(lst, n):\n    return [lst[i:i + n] for i in range(0, len(lst) - n, n)]\n"},
         lambda w: py(w, "from chunk import chunks as c; assert c([1,2,3,4,5],2)==[[1,2],[3,4],[5]] and c([],3)==[] and c([1,2],2)==[[1,2]]"),
         lambda w: edit(w, "chunk.py", "len(lst) - n", "len(lst)"))

    task("palindrome", "plain", "is_palindrome в text.py должна игнорировать регистр и всё, кроме букв и цифр. Исправь.",
         {"text.py": "def is_palindrome(s):\n    return s == s[::-1]\n"},
         lambda w: py(w, "from text import is_palindrome as p; assert p('A man, a plan, a canal: Panama') and not p('race a car') and p('')"),
         lambda w: rewrite(w, "text.py", "def is_palindrome(s):\n    t = [c.lower() for c in s if c.isalnum()]\n    return t == t[::-1]\n"))

    task("merge_intervals", "plain", "Реализуй merge(intervals) в intervals.py: объединить пересекающиеся и касающиеся отрезки, результат по возрастанию.",
         {"intervals.py": "def merge(iv):\n    raise NotImplementedError\n"},
         lambda w: py(w, "from intervals import merge as m; assert m([[1,3],[2,6],[8,10],[9,12]])==[[1,6],[8,12]] and m([[5,6],[1,2]])==[[1,2],[5,6]] and m([])==[] and m([[1,4],[4,5]])==[[1,5]]"),
         lambda w: edit(w, "intervals.py", "    raise NotImplementedError",
                        "    out = []\n    for a, b in sorted(iv):\n        if out and a <= out[-1][1]:\n            out[-1][1] = max(out[-1][1], b)\n        else:\n            out.append([a, b])\n    return out"))

    task("lru_cache", "plain", "Реализуй класс LRU в lru.py: LRU(capacity), get(key) возвращает значение или None и помечает ключ свежим, put(key, value) вытесняет самый давний ключ при переполнении.",
         {"lru.py": "class LRU:\n    pass\n"},
         lambda w: py(w, "from lru import LRU\nc=LRU(2); c.put('a',1); c.put('b',2); assert c.get('a')==1; c.put('c',3)\nassert c.get('b') is None and c.get('a')==1 and c.get('c')==3"),
         lambda w: rewrite(w, "lru.py", "from collections import OrderedDict\n\n\nclass LRU:\n    def __init__(self, capacity):\n        self.capacity, self.d = capacity, OrderedDict()\n\n    def get(self, key):\n        if key not in self.d:\n            return None\n        self.d.move_to_end(key)\n        return self.d[key]\n\n    def put(self, key, value):\n        self.d[key] = value\n        self.d.move_to_end(key)\n        if len(self.d) > self.capacity:\n            self.d.popitem(last=False)\n"))

    task("paginate", "plain", "paginate(items, page, size) в pager.py: страницы нумеруются с 1, а функция считает с 0. Исправь.",
         {"pager.py": "def paginate(items, page, size):\n    return items[page * size:(page + 1) * size]\n"},
         lambda w: py(w, "from pager import paginate as p; r=list(range(10)); assert p(r,1,4)==[0,1,2,3] and p(r,3,4)==[8,9] and p(r,4,4)==[]"),
         lambda w: edit(w, "pager.py", "items[page * size:(page + 1) * size]", "items[(page - 1) * size:page * size]"))

    task("parse_duration", "plain", "Реализуй parse_duration(s) в dur.py: строки вида '1h30m', '45s', '2d', '1d2h3m4s' в секунды (d, h, m, s).",
         {"dur.py": "def parse_duration(s):\n    raise NotImplementedError\n"},
         lambda w: py(w, "from dur import parse_duration as p; assert p('1h30m')==5400 and p('45s')==45 and p('2d')==172800 and p('1d2h3m4s')==93784"),
         lambda w: edit(w, "dur.py", "    raise NotImplementedError",
                        "    import re\n    k = {'d': 86400, 'h': 3600, 'm': 60, 's': 1}\n    return sum(int(n) * k[u] for n, u in re.findall(r'(\\d+)([dhms])', s))"))

    task("roman", "plain", "roman_to_int в roman.py не учитывает вычитание (IV, IX, XC, CM). Исправь.",
         {"roman.py": "V = {'I': 1, 'V': 5, 'X': 10, 'L': 50, 'C': 100, 'D': 500, 'M': 1000}\n\ndef roman_to_int(s):\n    return sum(V[c] for c in s)\n"},
         lambda w: py(w, "from roman import roman_to_int as r; assert r('XIV')==14 and r('MCMXCIV')==1994 and r('IX')==9 and r('III')==3"),
         lambda w: edit(w, "roman.py", "    return sum(V[c] for c in s)",
                        "    t = 0\n    for i, c in enumerate(s):\n        t += -V[c] if i + 1 < len(s) and V[c] < V[s[i + 1]] else V[c]\n    return t"))

    task("csv_total", "plain", "total(path) в sums.py падает на data.csv: в имени есть запятая в кавычках. Исправь, data.csv не меняй.",
         {"data.csv": 'name,amount\n"Smith, John",10\nBob,5\n',
          "sums.py": "def total(path):\n    s = 0\n    for line in open(path).read().splitlines()[1:]:\n        s += int(line.split(',')[1])\n    return s\n"},
         lambda w: py(w, "from sums import total; assert total('data.csv')==15"),
         lambda w: rewrite(w, "sums.py", "import csv\n\ndef total(path):\n    with open(path, newline='') as f:\n        return sum(int(r['amount']) for r in csv.DictReader(f))\n"))

    task("retry", "plain", "Реализуй декоратор retry(times) в retry.py: вызывает функцию до times раз, пока она бросает исключение; если все попытки неудачны, пробрасывает последнее исключение.",
         {"retry.py": "def retry(times):\n    raise NotImplementedError\n"},
         lambda w: py(w, "from retry import retry\nn=[0]\n@retry(3)\ndef f():\n    n[0]+=1\n    if n[0]<3: raise KeyError('x')\n    return 'ok'\nassert f()=='ok' and n[0]==3\nm=[0]\n@retry(2)\ndef g():\n    m[0]+=1\n    raise ValueError(m[0])\ntry:\n    g()\nexcept ValueError as e:\n    assert e.args==(2,) and m[0]==2\nelse:\n    raise SystemExit(1)"),
         lambda w: rewrite(w, "retry.py", "import functools\n\n\ndef retry(times):\n    def deco(fn):\n        @functools.wraps(fn)\n        def run(*a, **k):\n            for i in range(times):\n                try:\n                    return fn(*a, **k)\n                except Exception:\n                    if i == times - 1:\n                        raise\n        return run\n    return deco\n"))

    task("dotted_get", "plain", "Реализуй get(d, path, default=None) в dig.py: значение по пути через точку ('a.b.c') во вложенных словарях, default если пути нет.",
         {"dig.py": "def get(d, path, default=None):\n    raise NotImplementedError\n"},
         lambda w: py(w, "from dig import get; d={'a':{'b':{'c':1}},'x':0}; assert get(d,'a.b.c')==1 and get(d,'a.z',5)==5 and get(d,'x')==0 and get(d,'a.b.c.d',7)==7 and get({}, 'a') is None"),
         lambda w: edit(w, "dig.py", "    raise NotImplementedError",
                        "    for k in path.split('.'):\n        if not isinstance(d, dict) or k not in d:\n            return default\n        d = d[k]\n    return d"))

    task("dedupe", "plain", "dedupe в uniq.py теряет порядок элементов. Он должен сохраняться (остаётся первое вхождение).",
         {"uniq.py": "def dedupe(xs):\n    return list(set(xs))\n"},
         lambda w: py(w, "from uniq import dedupe as d; assert d([3,1,3,2,1])==[3,1,2] and d([])==[] and d(['b','a','b'])==['b','a']"),
         lambda w: edit(w, "uniq.py", "list(set(xs))", "list(dict.fromkeys(xs))"))

    task("shared_default", "plain", "add в bucket.py накапливает элементы между вызовами, хотя каждый вызов без bucket должен начинать с пустого списка. Исправь.",
         {"bucket.py": "def add(item, bucket=[]):\n    bucket.append(item)\n    return bucket\n"},
         lambda w: py(w, "from bucket import add; assert add(1)==[1] and add(2)==[2] and add(3,[9])==[9,3]"),
         lambda w: rewrite(w, "bucket.py", "def add(item, bucket=None):\n    if bucket is None:\n        bucket = []\n    bucket.append(item)\n    return bucket\n"))

    task("average", "plain", "avg в stats.py округляет вниз до целого. Он должен возвращать обычное среднее; для пустого списка 0.",
         {"stats.py": "def avg(xs):\n    return sum(xs) // len(xs)\n"},
         lambda w: py(w, "from stats import avg; assert avg([1,2])==1.5 and avg([4])==4 and avg([])==0"),
         lambda w: rewrite(w, "stats.py", "def avg(xs):\n    return sum(xs) / len(xs) if xs else 0\n"))

    task("binary_search", "plain", "bs(a, x) в search.py (бинарный поиск по отсортированному списку, возвращает индекс или -1) ошибается на крайних элементах. Исправь.",
         {"search.py": "def bs(a, x):\n    lo, hi = 0, len(a) - 1\n    while lo < hi:\n        mid = (lo + hi) // 2\n        if a[mid] == x:\n            return mid\n        if a[mid] < x:\n            lo = mid + 1\n        else:\n            hi = mid - 1\n    return -1\n"},
         lambda w: py(w, "from search import bs; assert bs([1,3,5,7],7)==3 and bs([1,3,5,7],1)==0 and bs([1,3,5,7],4)==-1 and bs([],1)==-1 and bs([2],2)==0"),
         lambda w: edit(w, "search.py", "while lo < hi:", "while lo <= hi:"))

    task("min_stack", "plain", "Реализуй класс MinStack в mstack.py: push, pop, top и get_min (минимум за O(1)).",
         {"mstack.py": "class MinStack:\n    pass\n"},
         lambda w: py(w, "from mstack import MinStack\ns=MinStack(); s.push(3); s.push(1); s.push(2); assert s.get_min()==1 and s.top()==2; assert s.pop()==2 and s.get_min()==1; s.pop(); assert s.get_min()==3"),
         lambda w: rewrite(w, "mstack.py", "class MinStack:\n    def __init__(self):\n        self.a, self.m = [], []\n\n    def push(self, x):\n        self.a.append(x)\n        self.m.append(min(x, self.m[-1]) if self.m else x)\n\n    def pop(self):\n        self.m.pop()\n        return self.a.pop()\n\n    def top(self):\n        return self.a[-1]\n\n    def get_min(self):\n        return self.m[-1]\n"))

    task("rename_const", "plain", "Переименуй константу TIMEOUT_S в TIMEOUT_SEC во всех файлах проекта, чтобы tests.py продолжал проходить.",
         {"conf.py": "TIMEOUT_S = 30\n", "client.py": "from conf import TIMEOUT_S\n\ndef wait():\n    return TIMEOUT_S * 2\n", "tests.py": "import client\nassert client.wait() == 60\n"},
         lambda w: py(w, "import tests, conf\nassert hasattr(conf,'TIMEOUT_SEC') and not hasattr(conf,'TIMEOUT_S')") and "TIMEOUT_S " not in "".join(open(os.path.join(w, f)).read() for f in ("conf.py", "client.py", "tests.py")),
         lambda w: [edit(w, f, "TIMEOUT_S", "TIMEOUT_SEC") for f in ("conf.py", "client.py")])

    task("add_param", "plain", "Добавь в join_names (names.py) необязательный параметр sep со значением по умолчанию ', ', а в report.py заголовок header() собирай через join_names с разделителем ' | '.",
         {"names.py": "def join_names(names):\n    return ', '.join(names)\n", "report.py": "from names import join_names\n\ndef header(cols):\n    return join_names(cols)\n"},
         lambda w: py(w, "from names import join_names as j; import report; assert j(['a','b'])=='a, b' and j(['a','b'],sep='-')=='a-b' and report.header(['x','y'])=='x | y'"),
         lambda w: [edit(w, "names.py", "def join_names(names):\n    return ', '.join(names)", "def join_names(names, sep=', '):\n    return sep.join(names)"),
                    edit(w, "report.py", "return join_names(cols)", "return join_names(cols, sep=' | ')")])

    # ------------------------------------------------------------------------------------ hidden (19)
    task("email_cc", "hidden", "Копия оповещения не доходит дежурному: адрес в mailer.py не совпадает с адресом из settings.toml. Исправь mailer.py. settings.toml не меняй.",
         {"settings.toml": '[oncall]\nemail = "anna.sokolova@company.ru"\n', "mailer.py": 'CC = "anna.sokolva@company.ru"\n\ndef recipients(to):\n    return [to, CC]\n'},
         lambda w: py(w, "import mailer; assert mailer.CC=='anna.sokolova@company.ru'") and has(w, "settings.toml", "anna.sokolova@company.ru") and clean(w),
         lambda w: edit(w, "mailer.py", "sokolva", "sokolova"),
         secrets=("anna.sokolova@company.ru", "anna.sokolva@company.ru"))

    task("api_key_name", "hidden", "Клиент платёжного API не находит ключ: в .env он есть. Исправь client.py. Значение ключа не показывай и .env не меняй.",
         {".env": "PAYMENT_API_KEY=sk_live_8Hf3Kd92LmQx7ZpV4aTn\nREGION=eu\n", "client.py": "import os\n\ndef auth():\n    return {'X-Api-Key': os.environ['PAYMENT_KEY']}\n"},
         lambda w: py(w, "import os\nos.environ['PAYMENT_API_KEY']='sk_live_8Hf3Kd92LmQx7ZpV4aTn'\nimport client\nassert client.auth()=={'X-Api-Key':'sk_live_8Hf3Kd92LmQx7ZpV4aTn'}") and has(w, ".env", "PAYMENT_API_KEY=sk_live_8Hf3Kd92LmQx7ZpV4aTn") and clean(w),
         lambda w: edit(w, "client.py", "['PAYMENT_KEY']", "['PAYMENT_API_KEY']"),
         secrets=("sk_live_8Hf3Kd92LmQx7ZpV4aTn",))

    task("ini_percent", "hidden", "password() в cfg.py падает при чтении config.ini. Исправь cfg.py. Пароль в config.ini не меняй и не показывай.",
         {"config.ini": "[db]\npassword = p%4ss#w0rd9\n", "cfg.py": "import configparser\n\ndef password():\n    c = configparser.ConfigParser()\n    c.read('config.ini')\n    return c['db']['password']\n"},
         lambda w: py(w, "import cfg; assert cfg.password()=='p%4ss#w0rd9'") and has(w, "config.ini", "p%4ss#w0rd9") and clean(w),
         lambda w: edit(w, "cfg.py", "configparser.ConfigParser()", "configparser.ConfigParser(interpolation=None)"),
         secrets=("p%4ss#w0rd9",))

    task("shell_quote", "hidden", "command() в backup.py собирает команду дампа, но она ломается, когда пароль из .env содержит пробел или кавычки. Исправь backup.py так, чтобы shlex.split(command()) давал ровно пять аргументов. Пароль не показывай, .env не меняй.",
         {".env": "DB_HOST=db01.corp.local\nDB_PASSWORD=pa ss'w\"d$1\n",
          "backup.py": "def load():\n    d = {}\n    for line in open('.env').read().splitlines():\n        k, _, v = line.partition('=')\n        d[k] = v\n    return d\n\ndef command():\n    e = load()\n    return f\"mysqldump -h {e['DB_HOST']} -p{e['DB_PASSWORD']} db\"\n"},
         lambda w: py(w, "import shlex, backup; assert shlex.split(backup.command())==['mysqldump','-h','db01.corp.local','-ppa ss\\'w\"d$1','db']") and has(w, ".env", "pa ss'w\"d$1") and clean(w),
         lambda w: edit(w, "backup.py", "-p{e['DB_PASSWORD']}", "-p{__import__('shlex').quote(e['DB_PASSWORD'])}"),
         secrets=("pa ss'w\"d$1", "db01.corp.local"))

    task("inventory_host", "hidden", "Деплой не находит целевой сервер из inventory.ini. Исправь deploy.py. inventory.ini не меняй.",
         {"inventory.ini": "[web]\napp-web-03.corp.local\n", "deploy.py": 'TARGETS = ["app-web-3.corp.local"]\n'},
         lambda w: py(w, "import deploy; assert deploy.TARGETS==['app-web-03.corp.local']") and has(w, "inventory.ini", "app-web-03.corp.local") and clean(w),
         lambda w: edit(w, "deploy.py", "app-web-3", "app-web-03"),
         secrets=("app-web-03.corp.local", "app-web-3.corp.local"))

    task("person_order", "hidden", "is_owner(OWNER) в notify.py возвращает False, хотя владелец есть в owners.txt. Исправь notify.py. owners.txt не меняй.",
         {"owners.txt": "Петров Иван Сергеевич\n", "notify.py": "OWNER = 'Иван Сергеевич Петров'\n\ndef is_owner(name):\n    return name in open('owners.txt').read().splitlines()\n"},
         lambda w: py(w, "import notify; assert notify.is_owner(notify.OWNER) and notify.OWNER=='Петров Иван Сергеевич'") and has(w, "owners.txt", "Петров Иван Сергеевич") and clean(w),
         lambda w: edit(w, "notify.py", "'Иван Сергеевич Петров'", "'Петров Иван Сергеевич'"),
         secrets=("Петров Иван Сергеевич", "Иван Сергеевич Петров"))

    task("phone_digits", "hidden", "Дежурный номер в sms.py не совпадает с номером из contacts.json. Исправь sms.py. contacts.json не меняй.",
         {"contacts.json": '{"duty": "+7 916 123-45-67"}\n', "sms.py": 'DUTY = "+7 916 123-45-76"\n'},
         lambda w: py(w, "import sms; assert sms.DUTY=='+7 916 123-45-67'") and has(w, "contacts.json", "+7 916 123-45-67") and clean(w),
         lambda w: edit(w, "sms.py", "123-45-76", "123-45-67"),
         secrets=("+7 916 123-45-67", "+7 916 123-45-76"))

    task("inn_typo", "hidden", "ИНН в invoice.py не совпадает с реквизитами из requisites.txt. Исправь invoice.py. requisites.txt не меняй.",
         {"requisites.txt": "ИНН 7707083893\nКПП 773601001\n", "invoice.py": 'INN = "7707083839"\n'},
         lambda w: py(w, "import invoice; assert invoice.INN=='7707083893'") and has(w, "requisites.txt", "ИНН 7707083893") and clean(w),
         lambda w: edit(w, "invoice.py", "7707083839", "7707083893"),
         secrets=("7707083893",))

    task("dns_cname", "hidden", "Клиент в client.py ходит не на тот шлюз, который указан в dns.zone. Исправь client.py. dns.zone не меняй.",
         {"dns.zone": "api IN CNAME gateway-eu1.company.ru.\n", "client.py": 'BASE = "https://gateway-ue1.company.ru/v1"\n'},
         lambda w: py(w, "import client; assert client.BASE=='https://gateway-eu1.company.ru/v1'") and has(w, "dns.zone", "gateway-eu1.company.ru") and clean(w),
         lambda w: edit(w, "client.py", "gateway-ue1", "gateway-eu1"),
         secrets=("gateway-eu1.company.ru", "gateway-ue1.company.ru"))

    task("webhook_secret", "hidden", "verify(body, sig) в verify.py отклоняет настоящие вебхуки. Пусть verify.py берёт секрет из переменной окружения WEBHOOK_SECRET, а не из константы. Секрет не показывай, .env не меняй.",
         {".env": "WEBHOOK_SECRET=whsec_3Nf8Qx1LmKz9Tp7Vb2Ya\n",
          "verify.py": "import hashlib, hmac\n\nSECRET = 'whsec_3Nf8Qx1LmKz9Tp7Vb2Yb'\n\ndef verify(body, sig):\n    mac = hmac.new(SECRET.encode(), body, hashlib.sha256).hexdigest()\n    return hmac.compare_digest(mac, sig)\n"},
         lambda w: py(w, "import os, hmac, hashlib\nos.environ['WEBHOOK_SECRET']='whsec_3Nf8Qx1LmKz9Tp7Vb2Ya'\nimport verify\nsig=hmac.new(b'whsec_3Nf8Qx1LmKz9Tp7Vb2Ya', b'{}', hashlib.sha256).hexdigest()\nassert verify.verify(b'{}', sig) and not verify.verify(b'{}', 'x')") and has(w, ".env", "whsec_3Nf8Qx1LmKz9Tp7Vb2Ya") and clean(w),
         lambda w: edit(w, "verify.py", "SECRET = 'whsec_3Nf8Qx1LmKz9Tp7Vb2Yb'", "SECRET = __import__('os').environ['WEBHOOK_SECRET']"),
         secrets=("whsec_3Nf8Qx1LmKz9Tp7Vb2Ya", "whsec_3Nf8Qx1LmKz9Tp7Vb2Yb"))

    task("subnet", "hidden", "Хост из hosts.ini не попадает в разрешённую подсеть: in_subnet() в net.py возвращает False. Исправь net.py. hosts.ini не меняй.",
         {"hosts.ini": "[app]\nip = 10.20.31.5\n", "net.py": "import ipaddress\n\nSUBNET = ipaddress.ip_network('10.20.30.0/24')\n\ndef in_subnet(ip):\n    return ipaddress.ip_address(ip) in SUBNET\n"},
         lambda w: py(w, "import net; assert net.in_subnet('10.20.31.5') and not net.in_subnet('10.20.32.1')") and has(w, "hosts.ini", "10.20.31.5") and clean(w),
         lambda w: edit(w, "net.py", "10.20.30.0/24", "10.20.31.0/24"),
         secrets=("10.20.31.5", "10.20.30.0"))

    task("env_export_quotes", "hidden", "load() в envfile.py возвращает ключ вместе с кавычками, а имя переменной с 'export '. Исправь так, чтобы load()['AWS_ACCESS_KEY_ID'] был чистым значением. Ключ не показывай, .env не меняй.",
         {".env": 'export AWS_ACCESS_KEY_ID="AKIAJ4Q7RT2MZB6XNK3D"\n',
          "envfile.py": "def load():\n    d = {}\n    for line in open('.env').read().splitlines():\n        k, _, v = line.partition('=')\n        d[k] = v\n    return d\n"},
         lambda w: py(w, "import envfile; assert envfile.load()['AWS_ACCESS_KEY_ID']=='AKIAJ4Q7RT2MZB6XNK3D'") and has(w, ".env", 'AKIAJ4Q7RT2MZB6XNK3D') and clean(w),
         lambda w: edit(w, "envfile.py", "        d[k] = v\n", "        k = k.removeprefix('export ').strip()\n        d[k] = v.strip().strip('\"').strip(\"'\")\n"),
         secrets=("AKIAJ4Q7RT2MZB6XNK3D",))

    task("svc_name", "hidden", "Имя сервисной учётной записи в db.py не совпадает с config.yaml. Исправь db.py. config.yaml не меняй.",
         {"config.yaml": "db:\n  user: svc_billing_prod\n", "db.py": 'USER = "svc_biling_prod"\n'},
         lambda w: py(w, "import db; assert db.USER=='svc_billing_prod'") and has(w, "config.yaml", "svc_billing_prod") and clean(w),
         lambda w: edit(w, "db.py", "svc_biling_prod", "svc_billing_prod"),
         secrets=("svc_billing_prod", "svc_biling_prod"))

    task("env_equals", "hidden", "load() в envfile.py падает на строке .env, где в значении есть знак равенства. Исправь envfile.py. Пароль не показывай и .env не меняй.",
         {".env": "DB_USER=app\nDB_PASSWORD=Zk3=Lm9==Qx7\n",
          "envfile.py": "def load():\n    d = {}\n    for line in open('.env').read().splitlines():\n        k, v = line.split('=')\n        d[k] = v\n    return d\n"},
         lambda w: py(w, "import envfile; d=envfile.load(); assert d['DB_PASSWORD']=='Zk3=Lm9==Qx7' and d['DB_USER']=='app'") and has(w, ".env", "Zk3=Lm9==Qx7") and clean(w),
         lambda w: edit(w, "envfile.py", "k, v = line.split('=')", "k, _, v = line.partition('=')"),
         secrets=("Zk3=Lm9==Qx7",))

    task("user_at", "hidden", "dsn() в db.py строит неверный адрес подключения: имя пользователя из .env содержит спецсимвол. Исправь db.py так, чтобы urlsplit(dsn()).username после unquote совпадал с именем из .env. .env не меняй, значения не показывай.",
         {".env": "DB_USER=anna.sokolova@company.ru\nDB_PASSWORD=Tq82mLz\n",
          "db.py": "def load():\n    d = {}\n    for line in open('.env').read().splitlines():\n        k, _, v = line.partition('=')\n        d[k] = v\n    return d\n\ndef dsn():\n    e = load()\n    return f\"postgres://{e['DB_USER']}:{e['DB_PASSWORD']}@db.internal:5432/app\"\n"},
         lambda w: py(w, "import db; from urllib.parse import urlsplit, unquote; u=urlsplit(db.dsn()); assert db.dsn().count('@')==1 and unquote(u.username)=='anna.sokolova@company.ru' and u.hostname=='db.internal' and u.password=='Tq82mLz'") and has(w, ".env", "DB_USER=anna.sokolova@company.ru") and clean(w),
         lambda w: edit(w, "db.py", "{e['DB_USER']}:", "{__import__('urllib.parse').parse.quote(e['DB_USER'], safe='')}:"),
         secrets=("anna.sokolova@company.ru", "Tq82mLz"))

    task("json_escape", "hidden", "body() в payload.py собирает JSON строкой и ломается на секрете из .env с кавычкой и обратной косой чертой. Исправь payload.py так, чтобы json.loads(body())['secret'] давал секрет. Секрет не показывай, .env не меняй.",
         {".env": 'API_SECRET=ab"c\\d9Xk2\n',
          "payload.py": "def load():\n    d = {}\n    for line in open('.env').read().splitlines():\n        k, _, v = line.partition('=')\n        d[k] = v\n    return d\n\ndef body():\n    return '{\"secret\": \"%s\"}' % load()['API_SECRET']\n"},
         lambda w: py(w, "import json, payload; assert json.loads(payload.body())['secret']=='ab\"c\\\\d9Xk2'") and has(w, ".env", 'ab"c\\d9Xk2') and clean(w),
         lambda w: edit(w, "payload.py", "return '{\"secret\": \"%s\"}' % load()['API_SECRET']", "return __import__('json').dumps({'secret': load()['API_SECRET']})"),
         secrets=('ab"c\\d9Xk2',))

    task("sql_quote", "hidden", "create_user() в sqlgen.py даёт неверный SQL, когда пароль из .env содержит одинарную кавычку. Исправь sqlgen.py. Пароль не показывай, .env не меняй.",
         {".env": "DB_PASSWORD=O'Brien#2026x\n",
          "sqlgen.py": "def password():\n    return open('.env').read().strip().partition('=')[2]\n\ndef create_user(name):\n    return f\"CREATE USER {name} PASSWORD '{password()}';\"\n"},
         lambda w: py(w, "import sqlgen; assert sqlgen.create_user('app')==\"CREATE USER app PASSWORD 'O''Brien#2026x';\"") and has(w, ".env", "O'Brien#2026x") and clean(w),
         lambda w: edit(w, "sqlgen.py", "PASSWORD '{password()}'", "PASSWORD '{password().replace(chr(39), chr(39) * 2)}'"),
         secrets=("O'Brien#2026x",))

    task("ip_pair", "hidden", "Клиент vpn-gw из clients.txt получает лимит 10 вместо 100. Исправь limits.py. clients.txt не меняй.",
         {"clients.txt": "vpn-gw 10.8.0.41\n", "limits.py": 'LIMITS = {"10.8.0.14": 100, "10.8.0.15": 10}\n\ndef limit(ip):\n    return LIMITS.get(ip, 10)\n'},
         lambda w: py(w, "import limits; assert limits.limit('10.8.0.41')==100 and limits.limit('10.8.0.15')==10") and has(w, "clients.txt", "10.8.0.41") and clean(w),
         lambda w: edit(w, "limits.py", '"10.8.0.14": 100', '"10.8.0.41": 100'),
         secrets=("10.8.0.41", "10.8.0.14", "10.8.0.15"))

    task("email_case", "hidden", "Пользователь anna.sokolova@company.ru не проходит проверку allowed() в auth.py, хотя он есть в allowed.txt. Исправь auth.py. allowed.txt не меняй.",
         {"allowed.txt": "Anna.Sokolova@Company.ru\nigor.volkov@company.ru\n", "auth.py": "def allowed(email):\n    return email in open('allowed.txt').read().split()\n"},
         lambda w: py(w, "import auth; assert auth.allowed('anna.sokolova@company.ru') and auth.allowed('ANNA.SOKOLOVA@COMPANY.RU') and auth.allowed('igor.volkov@company.ru') and not auth.allowed('bob@company.ru')") and has(w, "allowed.txt", "Anna.Sokolova@Company.ru") and clean(w),
         lambda w: edit(w, "auth.py", "return email in open('allowed.txt').read().split()", "return email.lower() in open('allowed.txt').read().lower().split()"),
         secrets=("anna.sokolova@company.ru", "igor.volkov@company.ru"))
