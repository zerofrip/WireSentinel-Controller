import { useState } from "react";
import { postAiCopilotQuery, type CopilotQueryResult } from "../api";

export function AiCopilotPage() {
  const [query, setQuery] = useState("");
  const [result, setResult] = useState<CopilotQueryResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setLoading(true);
    setError(null);
    try {
      setResult(await postAiCopilotQuery(query));
    } catch (err) {
      setError(err instanceof Error ? err.message : "Query failed");
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-semibold">AI Copilot</h1>
      <form onSubmit={submit} className="rounded-lg border border-slate-800 bg-slate-900 p-4 space-y-3">
        <textarea
          className="w-full rounded bg-slate-800 border border-slate-700 p-3 text-sm min-h-24"
          placeholder="Ask about investigations, threats, or recommended actions…"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
        />
        <button
          type="submit"
          disabled={loading || !query.trim()}
          className="rounded bg-cyan-700 px-4 py-2 text-sm disabled:opacity-50"
        >
          {loading ? "Analyzing…" : "Run query"}
        </button>
      </form>
      {error && <p className="text-red-400">{error}</p>}
      {result && (
        <div className="rounded-lg border border-slate-800 bg-slate-900 p-4 space-y-2">
          <div className="text-sm text-slate-400">Model: {result.response.model_id}</div>
          <p className="text-sm whitespace-pre-wrap">{result.response.response_text}</p>
        </div>
      )}
    </div>
  );
}
