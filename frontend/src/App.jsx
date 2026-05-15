import { useState } from "react";
import "./index.css";

function App() {
  const [backendData, setBackendData] = useState(null);
  const [databaseData, setDatabaseData] = useState(null);
  const [loading, setLoading] = useState(false);

  const API_BASE_URL = "http://127.0.0.1:8000";

  const testBackend = async () => {
    setLoading(true);

    try {
      const response = await fetch(`${API_BASE_URL}/health`);
      const data = await response.json();
      setBackendData(data);
    } catch (error) {
      setBackendData({
        status: "error",
        message: error.message,
      });
    }

    setLoading(false);
  };

  const testDatabase = async () => {
    setLoading(true);

    try {
      const response = await fetch(`${API_BASE_URL}/db-test`);
      const data = await response.json();
      setDatabaseData(data);
    } catch (error) {
      setDatabaseData({
        status: "error",
        message: error.message,
      });
    }

    setLoading(false);
  };

  return (
    <div className="min-h-screen bg-white px-6 py-10 text-slate-900">
      <div className="mx-auto max-w-4xl">
        <div className="rounded-2xl border border-slate-200 bg-white p-8 shadow-sm">
          <p className="text-sm font-semibold uppercase tracking-wide text-blue-600">
            ThreatIntel Agent
          </p>

          <h1 className="mt-3 text-3xl font-bold">
            Root Connection Test
          </h1>

          <p className="mt-3 text-slate-600">
            Testing frontend, Tailwind CSS, backend API, and Oracle database connection.
          </p>

          <div className="mt-8 grid gap-5 md:grid-cols-3">
            <div className="rounded-xl border border-slate-200 p-5">
              <h2 className="text-lg font-semibold">Frontend</h2>
              <p className="mt-2 text-sm text-green-600">
                React frontend is running.
              </p>
              <p className="mt-2 text-xs text-slate-500">
                Tailwind is working if this card has spacing, border, and styling.
              </p>
            </div>

            <div className="rounded-xl border border-slate-200 p-5">
              <h2 className="text-lg font-semibold">Backend</h2>

              <button
                onClick={testBackend}
                className="mt-4 rounded-lg bg-slate-900 px-4 py-2 text-sm font-medium text-white hover:bg-slate-700"
              >
                Test Backend
              </button>

              <pre className="mt-4 max-h-48 overflow-auto rounded-lg bg-slate-50 p-3 text-xs">
                {backendData
                  ? JSON.stringify(backendData, null, 2)
                  : "Not tested yet"}
              </pre>
            </div>

            <div className="rounded-xl border border-slate-200 p-5">
              <h2 className="text-lg font-semibold">Database</h2>

              <button
                onClick={testDatabase}
                className="mt-4 rounded-lg bg-blue-600 px-4 py-2 text-sm font-medium text-white hover:bg-blue-500"
              >
                Test Database
              </button>

              <pre className="mt-4 max-h-48 overflow-auto rounded-lg bg-slate-50 p-3 text-xs">
                {databaseData
                  ? JSON.stringify(databaseData, null, 2)
                  : "Not tested yet"}
              </pre>
            </div>
          </div>

          {loading && (
            <p className="mt-6 text-sm text-slate-500">
              Testing connection...
            </p>
          )}
        </div>
      </div>
    </div>
  );
}

export default App;