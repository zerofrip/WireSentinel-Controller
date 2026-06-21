import { useEffect, useState } from "react";
import { fetchDevices } from "../api";

export function DevicesPage() {
  const [devices, setDevices] = useState<Array<Record<string, unknown>>>([]);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    fetchDevices()
      .then(setDevices)
      .catch((e: Error) => setError(e.message));
  }, []);

  if (error) return <p className="text-red-400">{error}</p>;

  return (
    <div>
      <h1 className="text-2xl font-semibold mb-6">Devices</h1>
      <div className="overflow-x-auto rounded border border-slate-800">
        <table className="min-w-full text-sm">
          <thead className="bg-slate-900 text-slate-400">
            <tr>
              <th className="px-4 py-2 text-left">Name</th>
              <th className="px-4 py-2 text-left">Status</th>
              <th className="px-4 py-2 text-left">OS</th>
              <th className="px-4 py-2 text-left">Last heartbeat</th>
            </tr>
          </thead>
          <tbody>
            {devices.map((d) => (
              <tr key={String(d.id)} className="border-t border-slate-800">
                <td className="px-4 py-2">{String(d.name)}</td>
                <td className="px-4 py-2">{String(d.status)}</td>
                <td className="px-4 py-2">{String(d.os ?? "-")}</td>
                <td className="px-4 py-2">{String(d.last_heartbeat_at ?? "-")}</td>
              </tr>
            ))}
            {devices.length === 0 && (
              <tr>
                <td colSpan={4} className="px-4 py-6 text-slate-500">
                  No devices enrolled yet.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
