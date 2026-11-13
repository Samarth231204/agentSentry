"use client";

import Markdown from "react-markdown";
import remarkGfm from "remark-gfm";

/** Renders report.md. Raw HTML in the markdown is not rendered (react-markdown default). */
export function ReportMarkdown({ markdown }: { markdown: string }) {
  return (
    <div className="markdown">
      <Markdown remarkPlugins={[remarkGfm]}>{markdown}</Markdown>
    </div>
  );
}
