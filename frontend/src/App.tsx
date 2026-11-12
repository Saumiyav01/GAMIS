// P0 foundation shell only. No backend integration exists yet (API arrives in P11).
export default function App() {
  return (
    <main className="mx-auto max-w-2xl p-8">
      <h1 className="text-2xl font-semibold">GAMIS</h1>
      <p className="mt-2 text-slate-600">Governed Autonomous Multi-Agent Investigation System</p>
      <p className="mt-6 rounded border border-amber-300 bg-amber-50 p-3 text-sm">
        Status: P0 only. The supervisor, workers, gateway, and API are not implemented yet.
      </p>
    </main>
  );
}
