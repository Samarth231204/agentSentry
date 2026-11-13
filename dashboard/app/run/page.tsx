import { Suspense } from "react";
import { RunView } from "./RunView";

export default function RunPage() {
  return (
    <Suspense fallback={<p className="muted">Loading run…</p>}>
      <RunView />
    </Suspense>
  );
}
