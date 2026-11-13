"""A2A-style agent interface: agent cards and JSON-RPC 2.0 `message/send` exchanges.

Implemented in-house against the public A2A shapes (agent card at
/.well-known/agent.json, JSON-RPC methods, text parts). The official SDK's 1.x API
is protobuf-based and was not adopted; see docs/a2a.md.
"""
