import { useEffect, useState } from "react";
import { fetchMixnetRoutes, type MixnetRouteRecord } from "../api";

export function AnonymousRoutesPage() {
  const [routes, setRoutes] = useState<MixnetRouteRecord[]>([]);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    fetchMixnetRoutes()
      .then(setRoutes)
      .catch((e: Error) => setError(e.message));
  }, []);

  if (error) return <p className="text-red-400">{error}</p>;

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-semibold">Anonymous Routes</h1>
      <div className="rounded-lg border border-slate-800 bg-slate-900 p-4">
        <h2 className="text-sm font-medium text-slate-400 mb-3">{routes.length} route(s)</h2>
        {routes.length === 0 ? (
          <p className="text-sm text-slate-500">No anonymous routes reported</p>
        ) : (
          <ul className="space-y-2 text-sm">
            {routes.map((r) => (
              <li key={r.id} className="p-3 rounded bg-slate-800/50">
                <div className="flex justify-between gap-2">
                  <span className="font-medium">{r.label}</span>
                  <span className={r.active ? "text-cyan-400" : "text-slate-500"}>
                    {r.active ? "active" : "inactive"}
                  </span>
                </div>
                <p className="text-xs text-slate-400 mt-1">
                  {r.hops.join(" → ")}
                  {r.socks_port != null ? ` · SOCKS :${r.socks_port}` : ""}
                </p>
              </li>
            ))}
          </ul>
        )}
      </div>
    </div>
  );
}
