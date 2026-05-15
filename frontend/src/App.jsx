import { useEffect, useState } from "react";
import "./index.css";

const API_BASE_URL = "http://127.0.0.1:8000";

function App() {
  const [page, setPage] = useState("create");
  const [analyses, setAnalyses] = useState([]);
  const [selectedAnalysis, setSelectedAnalysis] = useState(null);
  const [message, setMessage] = useState("");

  const [form, setForm] = useState({
    title: "",
    source_type: "TEXT",
    raw_content: "",
  });

  const fetchAnalyses = async () => {
    try {
      const response = await fetch(`${API_BASE_URL}/analysis`);
      const data = await response.json();

      if (data.status === "ok") {
        setAnalyses(data.analyses);
      }
    } catch (error) {
      setMessage(`Failed to fetch analyses: ${error.message}`);
    }
  };

  const createAnalysis = async (event) => {
    event.preventDefault();
    setMessage("Saving analysis...");

    try {
      const response = await fetch(`${API_BASE_URL}/analysis/create`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          title: form.title,
          source_type: form.source_type,
          raw_content: form.raw_content,
          user_id: 1,
        }),
      });

      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.detail || "Failed to create analysis");
      }

      setMessage(`Analysis created successfully. ID: ${data.analysis_id}`);

      setForm({
        title: "",
        source_type: "TEXT",
        raw_content: "",
      });

      await fetchAnalyses();
      await viewAnalysis(data.analysis_id);
    } catch (error) {
      setMessage(error.message);
    }
  };

  const viewAnalysis = async (analysisId) => {
    try {
      const response = await fetch(`${API_BASE_URL}/analysis/${analysisId}`);
      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.detail || "Failed to load analysis");
      }

      setSelectedAnalysis(data.analysis);
      setPage("detail");
    } catch (error) {
      setMessage(error.message);
    }
  };

  useEffect(() => {
    fetchAnalyses();
  }, []);

  return (
    <div className="min-h-screen bg-white text-slate-900">
      <div className="mx-auto max-w-6xl px-6 py-8">
        <header className="flex items-center justify-between border-b border-slate-200 pb-5">
          <div>
            <p className="text-sm font-semibold uppercase tracking-wide text-blue-600">
              ThreatIntel Agent
            </p>
            <h1 className="mt-1 text-3xl font-bold">
              Analysis Flow Test
            </h1>
          </div>

          <nav className="flex gap-3">
            <button
              onClick={() => setPage("create")}
              className="rounded-lg border border-slate-300 px-4 py-2 text-sm hover:bg-slate-50"
            >
              Create
            </button>

            <button
              onClick={() => {
                fetchAnalyses();
                setPage("dashboard");
              }}
              className="rounded-lg bg-slate-900 px-4 py-2 text-sm text-white hover:bg-slate-700"
            >
              Dashboard
            </button>
          </nav>
        </header>

        {message && (
          <div className="mt-5 rounded-lg border border-slate-200 bg-slate-50 p-4 text-sm text-slate-700">
            {message}
          </div>
        )}

        {page === "create" && (
          <main className="mt-8 rounded-2xl border border-slate-200 p-6 shadow-sm">
            <h2 className="text-xl font-semibold">
              Create Analysis
            </h2>

            <p className="mt-2 text-sm text-slate-600">
              This saves report text into Oracle without AI processing yet.
            </p>

            <form onSubmit={createAnalysis} className="mt-6 space-y-5">
              <div>
                <label className="block text-sm font-medium">
                  Report Title
                </label>
                <input
                  type="text"
                  value={form.title}
                  onChange={(event) =>
                    setForm({ ...form, title: event.target.value })
                  }
                  className="mt-2 w-full rounded-lg border border-slate-300 px-4 py-2 outline-none focus:border-blue-500"
                  placeholder="Example: Phishing Campaign Report"
                  required
                />
              </div>

              <div>
                <label className="block text-sm font-medium">
                  Source Type
                </label>
                <select
                  value={form.source_type}
                  onChange={(event) =>
                    setForm({ ...form, source_type: event.target.value })
                  }
                  className="mt-2 w-full rounded-lg border border-slate-300 px-4 py-2 outline-none focus:border-blue-500"
                >
                  <option value="TEXT">TEXT</option>
                  <option value="URL">URL</option>
                  <option value="PDF">PDF</option>
                </select>
              </div>

              <div>
                <label className="block text-sm font-medium">
                  Report Content
                </label>
                <textarea
                  value={form.raw_content}
                  onChange={(event) =>
                    setForm({ ...form, raw_content: event.target.value })
                  }
                  className="mt-2 min-h-48 w-full rounded-lg border border-slate-300 px-4 py-3 outline-none focus:border-blue-500"
                  placeholder="Paste sample threat report content here..."
                  required
                />
              </div>

              <button
                type="submit"
                className="rounded-lg bg-blue-600 px-5 py-2 text-sm font-medium text-white hover:bg-blue-500"
              >
                Save Analysis
              </button>
            </form>
          </main>
        )}

        {page === "dashboard" && (
          <main className="mt-8">
            <h2 className="text-xl font-semibold">
              Dashboard
            </h2>

            <p className="mt-2 text-sm text-slate-600">
              Saved analyses from Oracle database.
            </p>

            <div className="mt-6 overflow-hidden rounded-2xl border border-slate-200">
              <table className="w-full text-left text-sm">
                <thead className="bg-slate-50 text-slate-600">
                  <tr>
                    <th className="px-4 py-3">ID</th>
                    <th className="px-4 py-3">Title</th>
                    <th className="px-4 py-3">Source</th>
                    <th className="px-4 py-3">Status</th>
                    <th className="px-4 py-3">Action</th>
                  </tr>
                </thead>

                <tbody>
                  {analyses.map((item) => (
                    <tr key={item.analysis_id} className="border-t border-slate-200">
                      <td className="px-4 py-3">{item.analysis_id}</td>
                      <td className="px-4 py-3 font-medium">{item.title}</td>
                      <td className="px-4 py-3">{item.source_type}</td>
                      <td className="px-4 py-3">{item.status}</td>
                      <td className="px-4 py-3">
                        <button
                          onClick={() => viewAnalysis(item.analysis_id)}
                          className="rounded-lg border border-slate-300 px-3 py-1 text-xs hover:bg-slate-50"
                        >
                          View
                        </button>
                      </td>
                    </tr>
                  ))}

                  {analyses.length === 0 && (
                    <tr>
                      <td colSpan="5" className="px-4 py-6 text-center text-slate-500">
                        No analyses saved yet.
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </main>
        )}

        {page === "detail" && selectedAnalysis && (
          <main className="mt-8 rounded-2xl border border-slate-200 p-6 shadow-sm">
            <button
              onClick={() => setPage("dashboard")}
              className="mb-5 rounded-lg border border-slate-300 px-3 py-1 text-sm hover:bg-slate-50"
            >
              Back to Dashboard
            </button>

            <div className="flex items-start justify-between gap-4">
              <div>
                <h2 className="text-2xl font-bold">
                  {selectedAnalysis.title}
                </h2>
                <p className="mt-2 text-sm text-slate-600">
                  Analysis ID: {selectedAnalysis.analysis_id} | Source: {selectedAnalysis.source_type}
                </p>
              </div>

              <span className="rounded-full bg-green-50 px-3 py-1 text-sm font-medium text-green-700">
                {selectedAnalysis.status}
              </span>
            </div>

            <section className="mt-6">
              <h3 className="font-semibold">Executive Summary</h3>
              <p className="mt-2 rounded-lg bg-slate-50 p-4 text-sm text-slate-700">
                {selectedAnalysis.executive_summary}
              </p>
            </section>

            <section className="mt-6">
              <h3 className="font-semibold">Raw Content</h3>
              <pre className="mt-2 max-h-80 overflow-auto whitespace-pre-wrap rounded-lg bg-slate-50 p-4 text-sm text-slate-700">
                {selectedAnalysis.raw_content}
              </pre>
            </section>

            <section className="mt-6">
              <h3 className="font-semibold">Final Report Placeholder</h3>
              <p className="mt-2 rounded-lg bg-slate-50 p-4 text-sm text-slate-700">
                {selectedAnalysis.final_report}
              </p>
            </section>
          </main>
        )}
      </div>
    </div>
  );
}

export default App;