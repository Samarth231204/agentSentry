# Phase 3 — `manifest.py` (static analysis)

## 1. Summary

Phase 3 answers "what can this target do?" without ever executing it.
`agentguard/manifest.py` implements the full pipeline the design doc
specified, built in the prescribed order — the YAML escape hatch first so
nothing downstream ever blocks on discovery:

1. **`Manifest.from_yaml()` / `Manifest.to_yaml()`** — hand-authorable,
   permanent fallback.
2. **`scan_project()`** — AST-only structural scan: `@tool`/`@watch`-decorated
   functions, `Agent`/`Task`/`Crew` calls, vectorstore imports, and
   retrieval-shaped function names (`retrieve`, `search_docs`, ...).
3. **`build_index()`** — chunks target source into a Chroma collection for
   retrieval around each candidate.
4. **`synthesize()`** — AST candidates + retrieved context → one LLM call
   per candidate tool, judging `DESTRUCTIVE` vs `SAFE`; falls back to a
   pure-heuristic verdict (keyword match against `DESTRUCTIVE_HINTS`) if the
   LLM call fails, and falls back to `heuristic_manifest()` entirely if
   Chroma indexing itself fails.
5. **`Manifest.routing()`** — turns a manifest into the list of attacker
   categories it justifies (used directly by Phase 4).

## 2. Pipeline

```
samples/<name>/*.py
        │
        ▼
scan_project()                 ─── AST walk: FunctionDef decorators,
  candidates = {tools,             Call nodes (Agent/Task/Crew), Import
    rag_signals,                   nodes, retrieval-shaped func names
    memory_signals,
    agent_call_count}
        │
        ▼
build_index()                  ─── chunk .py files by top-level `def`,
  Chroma EphemeralClient           embed with a dependency-free hashing
  + _HashEmbeddingFunction         function (no model download)
        │
        ▼
synthesize()                   ─── per candidate tool: retrieve_context()
  for each candidate tool:         + one Groq call judging DESTRUCTIVE/SAFE
    retrieve_context()             (falls back to heuristic on any failure)
    chat(SYNTHESIS_PROMPT)
        │
        ▼
Manifest(tools, rag, memory, multi_agent)
        │
        ├─ .to_yaml() / .from_yaml()   round-trippable, hand-editable
        └─ .routing()                   -> Phase 4 attacker categories
```

## 3. Validation performed

| Check | Result |
|---|---|
| `to_yaml`/`from_yaml` round-trip on a hand-built `Manifest` | lossless; `routing()` unchanged after round-trip |
| Full AST+Chroma+LLM `synthesize()` against all 3 Phase 2 samples | ~2s total wall-clock for all three |
| `unsafe_tool` → `transfer_funds` flagged `destructive: true` | correct |
| `rag_leaky` → `rag.present: true` | correct (see bug below — required a fix) |
| `prompt_leak` → no tools, no rag, no memory (no false positives) | correct |
| Routing table matches the Phase 2 answer key exactly | `unsafe_tool`→`tool_misuse`, `rag_leaky`→`rag_poisoning`, `prompt_leak`→neither |
| Generated `manifest.yaml` saved per sample, reloaded via `from_yaml`, routing re-verified identical | pass, saved to `samples/<name>/manifest.yaml` |

## 4. Problems and bugs faced

- **`chromadb`'s default embedding function triggered an ~80MB on-demand
  ONNX model download that filled the sandbox's temp/log partition.** The
  first `EphemeralClient()` + `.add()` call silently kicked off downloading
  `all-MiniLM-L6-v2` from Chroma's CDN. The download was slow (throttled,
  multiple MiB/s at best) and chromadb's progress bar writes continuous
  carriage-return updates, which flooded the harness's captured-output log
  file and caused a real `ENOSPC` (no space left on device) — twice. `df -h
  /` also showed only 280Mi free on the actual disk at that point, so this
  wasn't purely a logging artifact. Fix: purged `pip cache` (freed ~2GB),
  removed the partial `~/.cache/chroma` download, and — more importantly —
  rewrote the embedding step to avoid the download entirely: `manifest.py`
  now uses `_make_hash_embedding_function()`, a small dependency-free
  bag-of-words hashing embedder (256-dim, MD5-bucketed word counts,
  L2-normalized). This is intentionally not semantic search — it's good
  enough for "retrieve context near a candidate name" in a small codebase,
  which is all `synthesize()` needs, and it has zero network/disk cost.
  Documented as a deliberate trade-off, not a TODO.

- **Custom `EmbeddingFunction` implementation crashed on `.query()` with
  `AttributeError: '_HashEmbeddingFunction' object has no attribute
  'embed_query'`.** chromadb's `EmbeddingFunction` is a `Protocol` whose
  `__init_subclass__` hook auto-wires `embed_query` (and return-value
  validation) onto real subclasses — a plain duck-typed class with just
  `__call__` doesn't get that wiring and fails at query time, not at index
  time (so the bug only surfaced once retrieval was exercised, not during
  `.add()`). Fix: made `_HashEmbeddingFunction` actually subclass
  `chromadb.api.types.EmbeddingFunction` and implement the full expected
  surface (`__init__`, `__call__`, `name`, `build_from_config`,
  `get_config`), which chromadb's own docstring lists as required.

- **`rag_leaky`'s RAG capability was invisible to the AST scanner.** The
  first heuristic pass reported `rag.present: false` for `rag_leaky` even
  though it's the RAG sample — because the scanner only looked for
  vectorstore *imports* (`chroma`, `pinecone`, `faiss`, ...), and
  `rag_leaky/app.py` hand-rolls retrieval with a plain Python
  keyword-matching function (`retrieve()`), no external library at all.
  This is a realistic gap, not a contrived one: plenty of real RAG
  implementations don't import a named vector-store package. Fix: added
  `RAG_FUNCNAME_HINTS` (`retrieve`, `search_docs`, `query_docs`,
  `lookup_docs`) and a second detection path off function names in
  `scan_project()`'s `FunctionDef` branch, independent of the
  decorator-based tool detection. Re-run confirmed `rag.present: true` and
  correct `rag_poisoning` routing afterward.

- **Disk space was already tight going in** (280Mi free before the pip
  cache purge) — worth flagging since Phase 4/5 still need to install
  `google-adk` and `crewai`, both non-trivial dependency trees. Purging pip
  cache bought ~2GB of headroom (2.1Gi free after); if installs in later
  phases hit `ENOSPC` again, that cache purge is the first thing to redo,
  and `~/.cache/chroma` should stay empty now that the hashing embedder
  means nothing writes there.
