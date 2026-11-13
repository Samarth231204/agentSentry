# A2A: the three agents

Discovery, attacker and reporter are each an agent with an agent card and a JSON-RPC endpoint, served by `agentguard up`.

| Agent | Card | Endpoint | Skill |
|---|---|---|---|
| discovery | `GET /a2a/discovery/.well-known/agent.json` | `POST /a2a/discovery` | discover candidates in the project |
| attacker | `GET /a2a/attacker/.well-known/agent.json` | `POST /a2a/attacker` | run the attack suite against a loopback target |
| reporter | `GET /a2a/reporter/.well-known/agent.json` | `POST /a2a/reporter` | write report.md and report.json |

## Protocol

JSON-RPC 2.0 with the method `message/send`. The user message carries one text part that holds a JSON payload. The
response is an agent message with one text part that holds the JSON result. Errors use the standard codes: -32700 (parse),
-32600 (invalid request), -32601 (method not found), -32602 (invalid params), -32603 (internal). Internal errors never
include a traceback.

```json
{"jsonrpc": "2.0", "id": "1", "method": "message/send",
 "params": {"message": {"kind": "message", "messageId": "...", "role": "user",
   "parts": [{"kind": "text", "text": "{}"}]}}}
```

## Using them

The New run form has a checkbox: run discovery, attacker and reporter as A2A agents. The runner then calls the agents
over HTTP instead of in-process. Each call is an `a2a_call` trace event, and the run shows "Transport: A2A agents".

## Security rules

- The project folder is fixed by the server (`agentguard up --project`). A client cannot choose it.
- The attacker accepts only loopback targets.
- The reporter writes only under `.agentguard/a2a/`.

## Why our own implementation

The official `a2a-sdk` 1.x API is protobuf-based and changed quickly, and we did not adopt it for this release. Our
implementation follows the public shapes (agent card at `/.well-known/agent.json`, JSON-RPC `message/send`, text parts).
Interoperability with other A2A clients has not been verified; check it before claiming it.
