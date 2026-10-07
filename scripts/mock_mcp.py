"""A small MCP server over stdio for the tests of aegis-mcp (JSON-RPC, one message per line).

Tools: get_issue (a result with an e-mail), list_issues (a CSV table), query (runs "SQL": writes
the statement to MARK_FILE, so a test can tell whether it was executed), delete_repo (writes
"deleted" to MARK_FILE). Before the first message it prints a line that is not JSON, as careless
servers do.

Usage: mock_mcp.py MARK_FILE
"""
import json, sys

MARK = sys.argv[1]
print("mock-mcp starting (this line is not JSON)", flush=True)

TOOLS = [{"name": n, "description": n, "inputSchema": {"type": "object"}}
         for n in ("get_issue", "list_issues", "query", "delete_repo")]


def mark(s):
    with open(MARK, "a") as f:
        f.write(s + "\n")


def reply(id, result):
    print(json.dumps({"jsonrpc": "2.0", "id": id, "result": result}), flush=True)


for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    m = json.loads(line)
    method, id = m.get("method"), m.get("id")
    if method == "initialize":
        reply(id, {"protocolVersion": "2025-06-18", "capabilities": {"tools": {}}, "serverInfo": {"name": "mock", "version": "1"}})
    elif method == "tools/list":
        reply(id, {"tools": TOOLS})
    elif method == "tools/call":
        name, args = m["params"]["name"], m["params"].get("arguments", {})
        if name == "get_issue":
            body = {"id": 7, "title": "crash", "reporter": {"name": "Ann", "email": "ann@corp.local"}}
            reply(id, {"content": [{"type": "text", "text": json.dumps(body)}]})
        elif name == "list_issues":
            reply(id, {"content": [{"type": "text", "text": "id,title,email\n1,crash,ann@corp.local\n2,slow,bob@corp.local\n"}]})
        elif name == "query":
            mark("query: " + args.get("sql", ""))
            reply(id, {"content": [{"type": "text", "text": "ok"}]})
        elif name == "delete_repo":
            mark("deleted")
            reply(id, {"content": [{"type": "text", "text": "deleted"}]})
        else:
            print(json.dumps({"jsonrpc": "2.0", "id": id, "error": {"code": -32601, "message": "no such tool"}}), flush=True)
    elif id is not None:
        print(json.dumps({"jsonrpc": "2.0", "id": id, "error": {"code": -32601, "message": "unknown method"}}), flush=True)
