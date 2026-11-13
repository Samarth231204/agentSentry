"""Non-invasive instrumentation: the user's source is never edited.

wrappers.py  decorators that record what the agent did (tools, retrieval,
             memory, LLM calls, outbound requests) and can sandbox a tool.
hook.py      an import hook that applies the approved plan while the user's
             modules load, so the user's files stay untouched on disk.
target.py    generates the small ASGI app that the attacker talks to.
"""
