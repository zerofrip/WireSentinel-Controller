export function UpdatesPage() {
  return (
    <div>
      <h1 className="text-2xl font-semibold mb-6">Updates</h1>
      <div className="rounded border border-slate-800 bg-slate-900 p-6 max-w-xl">
        <p className="text-slate-300">
          Controller update channel integration is planned for a later phase. This page will surface
          available controller and agent bundle versions once the release feed is wired up.
        </p>
        <ul className="mt-4 text-sm text-slate-400 list-disc pl-5 space-y-1">
          <li>Current UI: v0.1.0</li>
          <li>API: /api/v1/*</li>
          <li>Check GitHub releases for WireSentinel-Controller artifacts</li>
        </ul>
      </div>
    </div>
  );
}
