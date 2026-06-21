import { useEffect, useState } from "react";
import { fetchAiKnowledgeGraph, type KnowledgeGraphSummary } from "../api";

export function AiKnowledgeGraphPage() {
  const [summary, setSummary] = useState<KnowledgeGraphSummary | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    fetchAiKnowledgeGraph().then(setSummary).catch((e: Error) => setError(e.message));
  }, []);

  if (error) return <p className="text-red-400">{error}</p>;
  if (!summary) return <p>Loading knowledge graph…</p>;

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-semibold">AI Knowledge Graph</h1>
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <Stat label="Nodes" value={summary.node_count} />
        <Stat label="Edges" value={summary.edge_count} />
      </div>
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <Panel title="Nodes">
          <ul className="space-y-2 text-sm">
            {summary.nodes.map((n) => (
              <li key={n.id} className="p-2 rounded bg-slate-800/50">
                <div className="font-medium">{n.label}</div>
                <div className="text-slate-400">{n.node_kind} · {n.entity_ref ?? "—"}</div>
              </li>
            ))}
          </ul>
        </Panel>
        <Panel title="Edges">
          <ul className="space-y-2 text-sm">
            {summary.edges.map((e) => (
              <li key={e.id} className="p-2 rounded bg-slate-800/50">
                <div className="font-medium">{e.edge_kind}</div>
                <div className="text-slate-400">{e.source_node_id.slice(0, 8)} → {e.target_node_id.slice(0, 8)}</div>
              </li>
            ))}
          </ul>
        </Panel>
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

function Panel({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div className="rounded-lg border border-slate-800 bg-slate-900 p-4">
      <h2 className="text-sm font-medium text-slate-400 mb-3">{title}</h2>
      {children}
    </div>
  );
}
