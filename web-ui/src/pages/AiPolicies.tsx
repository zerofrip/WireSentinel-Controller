import { useEffect, useState } from "react";
import { fetchAiPolicies, generateAiPolicy, type PoliciesSummary } from "../api";

export function AiPoliciesPage() {
  const [summary, setSummary] = useState<PoliciesSummary | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [context, setContext] = useState("zero trust access");

  async function load() {
    setSummary(await fetchAiPolicies());
  }

  useEffect(() => {
    load().catch((e: Error) => setError(e.message));
  }, []);

  async function generate() {
    setError(null);
    try {
      await generateAiPolicy(context);
      await load();
    } catch (e) {
      setError(e instanceof Error ? e.message : "Generate failed");
    }
  }

  if (error) return <p className="text-red-400">{error}</p>;
  if (!summary) return <p>Loading policies…</p>;

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-semibold">AI Policy Suggestions</h1>
      <div className="flex gap-2">
        <input className="flex-1 rounded bg-slate-800 border border-slate-700 px-3 py-2 text-sm" value={context} onChange={(e) => setContext(e.target.value)} />
        <button className="rounded bg-cyan-700 px-4 py-2 text-sm" onClick={generate}>Generate</button>
      </div>
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <Stat label="Suggestions" value={summary.suggestion_count} />
        <Stat label="Pending" value={summary.pending_suggestions} />
      </div>
      <div className="rounded-lg border border-slate-800 bg-slate-900 p-4">
        <ul className="space-y-2 text-sm">
          {summary.suggestions.map((s) => (
            <li key={s.id} className="p-2 rounded bg-slate-800/50">
              <div className="font-medium">{s.title}</div>
              <div className="text-slate-400">{s.policy_kind} · {s.status}</div>
              {s.rationale && <div className="text-slate-500 mt-1">{s.rationale}</div>}
            </li>
          ))}
        </ul>
      </div>
    </div>
  );
}

function Stat({ label, value }: { label: string; value: number }) {
  return (
    <div className="rounded-lg border border-slate-800 bg-slate-900 p-4">
      <div className="text-sm text-slate-400">{label}</div>
      <div className="text-3xl font-bold mt-2">{value}</div>
    </div>
  );
}
