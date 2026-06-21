import { useEffect, useState } from "react";
import { fetchXdrAttackGraph, type AttackGraphSummary } from "../api";

export function XdrAttackGraphPage() {
  const [summary, setSummary] = useState<AttackGraphSummary | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    fetchXdrAttackGraph()
      .then(setSummary)
      .catch((e: Error) => setError(e.message));
  }, []);

  if (error) return <p className="text-red-400">{error}</p>;
  if (!summary) return <p>Loading attack graph…</p>;

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-semibold">Attack Graph</h1>
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <Stat label="Nodes" value={summary.node_count} />
        <Stat label="Edges" value={summary.edge_count} />
      </div>
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <Panel title="Nodes" empty="No graph nodes">
          {summary.nodes.map((n) => (
            <li key={n.id} className="p-2 rounded bg-slate-800/50 text-sm">
              <div className="font-medium">{n.label}</div>
              <div className="text-slate-400">{n.node_kind}</div>
            </li>
          ))}
        </Panel>
        <Panel title="Edges" empty="No graph edges">
          {summary.edges.map((e) => (
            <li key={e.id} className="p-2 rounded bg-slate-800/50 text-sm">
              <div className="font-medium">{e.edge_kind}</div>
              <div className="text-slate-400">
                {e.source_node_id} → {e.target_node_id}
              </div>
            </li>
          ))}
        </Panel>
      </div>
    </div>
  );
}

function Panel({
  title,
  empty,
  children,
}: {
  title: string;
  empty: string;
  children: React.ReactNode;
}) {
  const items = Array.isArray(children) ? children : [children];
  const hasItems = items.some(Boolean);
  return (
    <div className="rounded-lg border border-slate-800 bg-slate-900 p-4">
      <h2 className="text-sm font-medium text-slate-400 mb-3">{title}</h2>
      {!hasItems ? (
        <p className="text-sm text-slate-500">{empty}</p>
      ) : (
        <ul className="space-y-2">{children}</ul>
      )}
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
