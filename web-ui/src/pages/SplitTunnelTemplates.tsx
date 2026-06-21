import { useEffect, useState } from "react";
import {
  createSplitTemplate,
  deleteSplitTemplate,
  fetchSplitTemplates,
  updateSplitTemplateMode,
  type SplitTemplatesSummary,
  type SplitTunnelTemplate,
} from "../api";

const MODES = ["disabled", "merge", "override"] as const;

export function SplitTunnelTemplatesPage() {
  const [summary, setSummary] = useState<SplitTemplatesSummary | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [name, setName] = useState("");
  const [mode, setMode] = useState<string>("disabled");
  const [activeTemplateId, setActiveTemplateId] = useState<string>("");

  async function load() {
    const data = await fetchSplitTemplates();
    setSummary(data);
    setMode(data.mode.mode);
    setActiveTemplateId(data.mode.active_template_id ?? "");
  }

  useEffect(() => {
    load().catch((e: Error) => setError(e.message));
  }, []);

  async function addTemplate() {
    if (!name.trim()) return;
    setError(null);
    try {
      await createSplitTemplate({
        name: name.trim(),
        description: "",
        default_route: { type: "direct" },
        enabled: true,
      });
      setName("");
      await load();
    } catch (e) {
      setError(e instanceof Error ? e.message : "Create failed");
    }
  }

  async function saveMode() {
    setError(null);
    try {
      await updateSplitTemplateMode({
        mode,
        active_template_id: activeTemplateId || null,
      });
      await load();
    } catch (e) {
      setError(e instanceof Error ? e.message : "Mode update failed");
    }
  }

  async function removeTemplate(template: SplitTunnelTemplate) {
    setError(null);
    try {
      await deleteSplitTemplate(template.id);
      await load();
    } catch (e) {
      setError(e instanceof Error ? e.message : "Delete failed");
    }
  }

  if (error) return <p className="text-red-400">{error}</p>;
  if (!summary) return <p>Loading split tunnel templates…</p>;

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-semibold">Split Tunnel Templates</h1>
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <Stat label="Templates" value={summary.template_count} />
        <Stat label="Enabled" value={summary.enabled_count} />
      </div>
      <div className="rounded-lg border border-slate-800 bg-slate-900 p-4 space-y-3 max-w-xl">
        <h2 className="font-medium">Template mode</h2>
        <select
          className="w-full rounded bg-slate-800 border border-slate-700 px-3 py-2 text-sm"
          value={mode}
          onChange={(e) => setMode(e.target.value)}
        >
          {MODES.map((m) => (
            <option key={m} value={m}>
              {m}
            </option>
          ))}
        </select>
        <select
          className="w-full rounded bg-slate-800 border border-slate-700 px-3 py-2 text-sm"
          value={activeTemplateId}
          onChange={(e) => setActiveTemplateId(e.target.value)}
        >
          <option value="">No active template</option>
          {summary.templates.map((t) => (
            <option key={t.id} value={t.id}>
              {t.name}
            </option>
          ))}
        </select>
        <button className="rounded bg-cyan-700 px-4 py-2 text-sm" onClick={saveMode}>
          Save mode
        </button>
      </div>
      <div className="flex gap-2">
        <input
          className="flex-1 rounded bg-slate-800 border border-slate-700 px-3 py-2 text-sm"
          placeholder="Template name"
          value={name}
          onChange={(e) => setName(e.target.value)}
        />
        <button className="rounded bg-cyan-700 px-4 py-2 text-sm" onClick={addTemplate}>
          Add template
        </button>
      </div>
      <div className="rounded-lg border border-slate-800 bg-slate-900 p-4">
        <ul className="space-y-2 text-sm">
          {summary.templates.map((template) => (
            <li key={template.id} className="p-2 rounded bg-slate-800/50 flex items-center justify-between">
              <div>
                <div className="font-medium">{template.name}</div>
                <div className="text-slate-400">
                  {template.enabled ? "enabled" : "disabled"} · {template.description || "no description"}
                </div>
              </div>
              <button className="text-red-400 text-xs" onClick={() => removeTemplate(template)}>
                Delete
              </button>
            </li>
          ))}
          {summary.templates.length === 0 && (
            <li className="text-slate-500">No split tunnel templates yet.</li>
          )}
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
