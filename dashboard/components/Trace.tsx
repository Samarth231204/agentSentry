"use client";

import { useEffect, useMemo, useRef, useState } from "react";
import { traceStreamUrl } from "@/lib/api";
import type { TraceEvent } from "@/lib/types";
import { clock } from "@/lib/format";

const MAX_EVENTS_IN_VIEW = 5000;

/** Live view of trace.jsonl: replays the file, then follows new lines over SSE. */
export function TraceView({ runId }: { runId: string }) {
  const [events, setEvents] = useState<TraceEvent[]>([]);
  const [status, setStatus] = useState<"connecting" | "live" | "closed">("connecting");
  const [typeFilter, setTypeFilter] = useState("");
  const [query, setQuery] = useState("");
  const [follow, setFollow] = useState(true);
  const bottomRef = useRef<HTMLDivElement | null>(null);

  useEffect(() => {
    setEvents([]);
    const source = new EventSource(traceStreamUrl(runId));
    source.onopen = () => setStatus("live");
    source.addEventListener("trace", (msg) => {
      try {
        const event = JSON.parse((msg as MessageEvent<string>).data) as TraceEvent;
        setEvents((prev) => {
          const next = prev.length >= MAX_EVENTS_IN_VIEW ? prev.slice(1) : prev;
          return [...next, event];
        });
      } catch {
        // A malformed line is skipped; the backend already filters these.
      }
    });
    // The backend never ends the stream, so an error means the backend stopped.
    // Close instead of letting EventSource reconnect, which would replay the trace.
    source.onerror = () => {
      setStatus("closed");
      source.close();
    };
    return () => source.close();
  }, [runId]);

  const types = useMemo(() => {
    const set = new Set(events.map((e) => e.event_type));
    return Array.from(set).sort();
  }, [events]);

  const visible = useMemo(() => {
    const needle = query.trim().toLowerCase();
    return events.filter((e) => {
      if (typeFilter && e.event_type !== typeFilter) return false;
      if (!needle) return true;
      return (
        e.source.toLowerCase().includes(needle) ||
        e.event_type.toLowerCase().includes(needle) ||
        JSON.stringify(e.payload).toLowerCase().includes(needle)
      );
    });
  }, [events, typeFilter, query]);

  useEffect(() => {
    if (follow) bottomRef.current?.scrollIntoView({ block: "end" });
  }, [visible.length, follow]);

  return (
    <div>
      <div className="controls">
        <span className="small">
          Stream: <strong>{status}</strong> · {events.length} events
        </span>
        <select value={typeFilter} onChange={(e) => setTypeFilter(e.target.value)} aria-label="Filter by event type">
          <option value="">all event types</option>
          {types.map((t) => (
            <option key={t} value={t}>{t}</option>
          ))}
        </select>
        <input
          type="search"
          placeholder="search source, type or payload"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          aria-label="Search trace"
        />
        <label className="small">
          <input type="checkbox" checked={follow} onChange={(e) => setFollow(e.target.checked)} /> follow new events
        </label>
      </div>

      {events.length === 0 && status !== "closed" ? <p className="muted">Waiting for events…</p> : null}
      {status === "closed" ? (
        <div className="banner error">
          The live stream closed. Is `agentguard up` still running? Reload the page after restarting it.
        </div>
      ) : null}

      <div>
        {visible.map((event, i) => (
          <details className="event" key={`${event.timestamp}-${i}`}>
            <summary>
              <span className="mono muted">{clock(event.timestamp)}</span>
              <span className="event-type">{event.event_type}</span>
              <span className="muted small">{event.source}</span>
            </summary>
            <pre>{JSON.stringify(event.payload, null, 2)}</pre>
          </details>
        ))}
      </div>
      <div ref={bottomRef} />
    </div>
  );
}
