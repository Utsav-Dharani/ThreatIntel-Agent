import { useEffect, useMemo, useState } from "react";
import ReactMarkdown from "react-markdown";
import remarkGfm from "remark-gfm";
import "./index.css";

const API_BASE_URL =
  import.meta.env.VITE_API_BASE_URL || "http://127.0.0.1:8000";

const CLIENT_ID_KEY = "threatintel_client_id";
const REPORT_ALIAS_KEY = "threatintel_report_alias_map";

const PROCESSING_MESSAGES = [
  "Preparing the submitted report...",
  "Analyzing threat context and behavior...",
  "Extracting IOCs, CVEs, and threat entities...",
  "Mapping behavior to MITRE ATT&CK...",
  "Calculating risk and confidence...",
  "Generating your analyst-ready intelligence brief...",
];

const SAMPLE_TEXT = `Security researchers observed a phishing campaign targeting enterprise employees in the finance and healthcare sectors. The attackers sent emails that appeared to come from internal IT support and asked users to verify their account access.

The emails contained links to a fake Microsoft 365 login portal hosted at secure-login-update[.]com. Users who entered credentials were redirected to the legitimate Microsoft login page to reduce suspicion. Analysts also observed suspicious authentication attempts from the IP address 185.199.110.153 after several users submitted their passwords.

The campaign used credential harvesting and attempted to access cloud email accounts. Some affected accounts showed abnormal inbox rule creation, including forwarding rules to external email addresses. Security teams also found a suspicious file named invoice_review.js attached to some messages.

Observed indicators include:
- Domain: secure-login-update[.]com
- URL: hxxps://secure-login-update[.]com/verify
- IP Address: 185.199.110.153
- File name: invoice_review.js
- Email sender: it-support-alerts@example-mail[.]com

The activity is consistent with phishing for initial access, user execution through malicious links, and possible account takeover using stolen credentials. No CVEs were observed in this report.

Recommended actions include blocking the suspicious domain, reviewing email gateway logs, resetting affected user passwords, enforcing multi-factor authentication, and hunting for suspicious inbox forwarding rules.`;

const SAMPLE_URL_TITLE = "CISA Medusa Ransomware Advisory";
const SAMPLE_URL =
  "https://www.cisa.gov/news-events/cybersecurity-advisories/aa25-071a";

const SAMPLE_PDF_TITLE = "Medusa Ransomware PDF Advisory";
const SAMPLE_PDF_URL = "https://www.ic3.gov/CSA/2025/250312.pdf";

function getGuestClientId() {
  let clientId = localStorage.getItem(CLIENT_ID_KEY);

  if (!clientId) {
    clientId =
      crypto.randomUUID?.() ||
      `guest_${Date.now()}_${Math.random().toString(16).slice(2)}`;

    localStorage.setItem(CLIENT_ID_KEY, clientId);
  }

  return clientId;
}

function SidebarToggleButton({ sidebarOpen, setSidebarOpen }) {
  return (
    <button
      onClick={() => setSidebarOpen(!sidebarOpen)}
      className="flex h-11 w-11 items-center justify-center rounded-xl border border-white/10 bg-white/5 hover:bg-white/10"
      title={sidebarOpen ? "Collapse sidebar" : "Expand sidebar"}
    >
      <span className="space-y-1.5">
        <span className="block h-0.5 w-5 rounded-full bg-cyan-200" />
        <span className="block h-0.5 w-5 rounded-full bg-cyan-200" />
        <span className="block h-0.5 w-5 rounded-full bg-cyan-200" />
      </span>
    </button>
  );
}

function calculateReportQuality(analysis) {
  const threatEntities = Array.isArray(analysis.threat_entities)
    ? analysis.threat_entities
    : [];
  const indicators = Array.isArray(analysis.indicators)
    ? analysis.indicators
    : [];
  const cves = Array.isArray(analysis.cves) ? analysis.cves : [];
  const mitre = Array.isArray(analysis.mitre_techniques)
    ? analysis.mitre_techniques
    : [];
  const recommendations = Array.isArray(analysis.recommendations)
    ? analysis.recommendations
    : [];
  const findings = Array.isArray(analysis.evidence_findings)
    ? analysis.evidence_findings
    : [];
  const attackChain = Array.isArray(analysis.attack_chain_steps)
    ? analysis.attack_chain_steps
    : [];

  const hasSummary = Boolean(analysis.executive_summary);
  const hasFinalReport = Boolean(analysis.final_report);
  const hasRisk = Boolean(analysis.risk_level) && analysis.risk_score !== null;

  const completenessChecks = [
    hasSummary,
    hasFinalReport,
    hasRisk,
    threatEntities.length > 0,
    mitre.length > 0,
    recommendations.length > 0,
    findings.length > 0,
    attackChain.length > 0,
  ];

  const completeness = Math.round(
    (completenessChecks.filter(Boolean).length / completenessChecks.length) * 100
  );

  const evidenceGrounding =
    findings.length === 0
      ? 0
      : Math.round(
          (findings.filter((item) => item.evidence_text).length / findings.length) * 100
        );

  const actionability = Math.min(
    100,
    Math.round((recommendations.length / 5) * 100)
  );

  const cyberRelevance = Math.min(
    100,
    Math.round(
      ((mitre.length > 0 ? 35 : 0) +
        (indicators.length > 0 ? 25 : 0) +
        (threatEntities.length > 0 ? 20 : 0) +
        (cves.length > 0 ? 10 : 0) +
        (attackChain.length > 0 ? 10 : 0))
    )
  );

  const reportLength = (analysis.final_report || "").length;
  const readability = Math.min(
    100,
    Math.round(
      (hasSummary ? 25 : 0) +
        (hasFinalReport ? 25 : 0) +
        (reportLength > 800 ? 25 : reportLength > 300 ? 15 : 5) +
        (recommendations.length > 0 ? 25 : 0)
    )
  );

  const overall = Math.round(
    (completeness +
      evidenceGrounding +
      actionability +
      cyberRelevance +
      readability) /
      5
  );

  return {
    overall,
    completeness,
    evidenceGrounding,
    actionability,
    cyberRelevance,
    readability,
  };
}

function ReportQualityPanel({ analysis }) {
  const quality = calculateReportQuality(analysis);

  const items = [
    {
      label: "Completeness",
      value: quality.completeness,
      description: "Checks whether key report sections are present.",
    },
    {
      label: "Evidence Grounding",
      value: quality.evidenceGrounding,
      description: "Checks whether findings include supporting evidence.",
    },
    {
      label: "Actionability",
      value: quality.actionability,
      description: "Checks whether useful recommendations were generated.",
    },
    {
      label: "Cyber Relevance",
      value: quality.cyberRelevance,
      description: "Checks for MITRE, IOCs, CVEs, entities, and attack chain.",
    },
    {
      label: "Readability",
      value: quality.readability,
      description: "Checks whether the final brief is complete and readable.",
    },
  ];

  return (
    <section className="rounded-3xl border border-white/10 bg-white p-6 text-slate-950 shadow-2xl">
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div>
          <h3 className="text-xl font-black">Report Quality</h3>
          <p className="mt-2 text-sm text-slate-600">
            Quality score based on completeness, evidence, relevance, actionability, and readability.
          </p>
        </div>

        <div className="rounded-2xl bg-slate-950 px-5 py-4 text-center text-white">
          <p className="text-xs font-bold uppercase tracking-wide text-cyan-300">
            Overall
          </p>
          <p className="text-3xl font-black">{quality.overall}%</p>
        </div>
      </div>

      <div className="mt-6 grid gap-4 md:grid-cols-2 xl:grid-cols-5">
        {items.map((item) => (
          <div
            key={item.label}
            className="rounded-2xl border border-slate-200 bg-slate-50 p-4"
          >
            <div className="flex items-center justify-between gap-3">
              <p className="text-sm font-black">{item.label}</p>
              <p className="text-sm font-black text-cyan-700">{item.value}%</p>
            </div>

            <div className="mt-3 h-2 overflow-hidden rounded-full bg-slate-200">
              <div
                className="h-full rounded-full bg-cyan-500"
                style={{ width: `${item.value}%` }}
              />
            </div>

            <p className="mt-3 text-xs leading-5 text-slate-500">
              {item.description}
            </p>
          </div>
        ))}
      </div>

      <p className="mt-4 text-xs leading-5 text-slate-500">
        This is a quality signal, not a verified accuracy score. Important findings should be reviewed before real-world security use.
      </p>
    </section>
  );
}

function loadReportAliasMap() {
  try {
    return JSON.parse(localStorage.getItem(REPORT_ALIAS_KEY) || "{}");
  } catch {
    return {};
  }
}

function saveReportAliasMap(map) {
  localStorage.setItem(REPORT_ALIAS_KEY, JSON.stringify(map));
}

function createReportCode(existingCodes = []) {
  let code = "";

  do {
    const randomPart = Math.random().toString(36).slice(2, 6).toUpperCase();
    code = `TIA-2026-${randomPart}`;
  } while (existingCodes.includes(code));

  return code;
}

function parseHashRoute() {
  const hash = window.location.hash.replace("#", "");

  if (!hash || hash === "dashboard") {
    return { page: "dashboard", reportKey: null };
  }

  if (hash === "analyze") {
    return { page: "analyze", reportKey: null };
  }

  if (hash.startsWith("report/")) {
    return {
      page: "report",
      reportKey: hash.split("/")[1] || null,
    };
  }

  return { page: "dashboard", reportKey: null };
}

const CLIENT_ID = getGuestClientId();

function App() {
  const [route, setRoute] = useState({ page: "dashboard", reportKey: null });
  const [showGuide, setShowGuide] = useState(false);
  const [sidebarOpen, setSidebarOpen] = useState(true);

  const [inputMode, setInputMode] = useState("TEXT");
  const [analyses, setAnalyses] = useState([]);
  const [selectedAnalysis, setSelectedAnalysis] = useState(null);
  const [aliasMap, setAliasMap] = useState(loadReportAliasMap());

  const [message, setMessage] = useState("");
  const [loading, setLoading] = useState(false);
  const [loadingStep, setLoadingStep] = useState(0);
  const [loadingProgress, setLoadingProgress] = useState(0);

  const [form, setForm] = useState({
    title: "",
    raw_content: "",
    url: "",
  });

  const [pdfFile, setPdfFile] = useState(null);

  const safeArray = (value) => {
    return Array.isArray(value) ? value : [];
  };

  const ensureReportAliases = (items) => {
    const currentMap = loadReportAliasMap();
    const existingCodes = Object.values(currentMap);
    let changed = false;

    items.forEach((item) => {
      const key = String(item.analysis_id);

      if (!currentMap[key]) {
        currentMap[key] = createReportCode(existingCodes);
        existingCodes.push(currentMap[key]);
        changed = true;
      }
    });

    if (changed) {
      saveReportAliasMap(currentMap);
    }

    setAliasMap(currentMap);
    return currentMap;
  };

  const getReportCode = (analysisId) => {
    const key = String(analysisId);
    return aliasMap[key] || "TIA-2026-NEW";
  };

  const getOrCreateReportCode = (analysisId) => {
    const key = String(analysisId);
    const currentMap = loadReportAliasMap();

    if (currentMap[key]) {
      setAliasMap(currentMap);
      return currentMap[key];
    }

    const code = createReportCode(Object.values(currentMap));
    currentMap[key] = code;

    saveReportAliasMap(currentMap);
    setAliasMap(currentMap);

    return code;
  };

  const resolveAnalysisIdFromReportKey = (reportKey) => {
    if (!reportKey) return null;

    const currentMap = loadReportAliasMap();

    const match = Object.entries(currentMap).find(
      ([, code]) => code === reportKey
    );

    if (match) {
      return Number(match[0]);
    }

    if (/^\d+$/.test(reportKey)) {
      return Number(reportKey);
    }

    return null;
  };

  const navigate = (page, id = null) => {
    let nextHash = `#${page}`;

    if (page === "report" && id) {
      const reportCode = getOrCreateReportCode(id);
      nextHash = `#report/${reportCode}`;
    }

    if (window.location.hash === nextHash) {
      setRoute(parseHashRoute());
      window.scrollTo({ top: 0, behavior: "smooth" });
      return;
    }

    window.location.hash = nextHash;
  };

  useEffect(() => {
    if (!window.location.hash) {
      window.history.replaceState(null, "", "#dashboard");
    }

    setRoute(parseHashRoute());

    const onHashChange = () => {
      setRoute(parseHashRoute());
      window.scrollTo({ top: 0, behavior: "smooth" });
    };

    window.addEventListener("hashchange", onHashChange);

    const guideSeen = localStorage.getItem("threatintel_guide_seen");
    if (!guideSeen) {
      setShowGuide(true);
    }

    return () => window.removeEventListener("hashchange", onHashChange);
  }, []);

  useEffect(() => {
    fetchAnalyses();
  }, []);

  useEffect(() => {
    if (route.page === "report" && route.reportKey) {
      const analysisId = resolveAnalysisIdFromReportKey(route.reportKey);

      if (!analysisId) {
        setSelectedAnalysis(null);
        setMessage("This report was not found in your browser session.");
        return;
      }

      viewAnalysis(analysisId);
    }
  }, [route]);

  useEffect(() => {
    if (!loading) {
      setLoadingStep(0);
      setLoadingProgress(0);
      return;
    }

    setLoadingProgress(8);
    setLoadingStep(0);

    const timer = setInterval(() => {
      setLoadingProgress((previous) => {
        let increment = 1;

        if (previous < 40) increment = 10;
        else if (previous < 70) increment = 6;
        else if (previous < 90) increment = 3;
        else increment = 1;

        const nextProgress = Math.min(previous + increment, 96);
        const nextStep = Math.min(
          PROCESSING_MESSAGES.length - 1,
          Math.floor((nextProgress / 100) * PROCESSING_MESSAGES.length)
        );

        setLoadingStep(nextStep);

        return nextProgress;
      });
    }, 900);

    return () => clearInterval(timer);
  }, [loading]);

  const dashboardStats = useMemo(() => {
    const total = analyses.length;
    const completed = analyses.filter((item) => item.status === "COMPLETED").length;
    const highRisk = analyses.filter((item) =>
      ["HIGH", "CRITICAL"].includes(item.risk_level)
    ).length;

    const scores = analyses
      .map((item) => Number(item.risk_score))
      .filter((score) => !Number.isNaN(score));

    const avgRisk = scores.length
      ? Math.round(scores.reduce((sum, value) => sum + value, 0) / scores.length)
      : 0;

    return {
      total,
      completed,
      highRisk,
      avgRisk,
    };
  }, [analyses]);

  const riskCounts = useMemo(() => {
    return analyses.reduce(
      (acc, item) => {
        const level = item.risk_level || "UNKNOWN";
        acc[level] = (acc[level] || 0) + 1;
        return acc;
      },
      {
        CRITICAL: 0,
        HIGH: 0,
        MEDIUM: 0,
        LOW: 0,
        UNKNOWN: 0,
      }
    );
  }, [analyses]);

  const fetchAnalyses = async () => {
    try {
      const response = await fetch(
        `${API_BASE_URL}/analysis?client_id=${encodeURIComponent(CLIENT_ID)}`
      );

      const data = await response.json();

      if (data.status === "ok") {
        ensureReportAliases(data.analyses);
        setAnalyses(data.analyses);
      }
    } catch (error) {
      setMessage(`Unable to load your reports: ${error.message}`);
    }
  };

  const viewAnalysis = async (analysisId) => {
    setLoading(true);

    try {
      const response = await fetch(
        `${API_BASE_URL}/analysis/${analysisId}?client_id=${encodeURIComponent(CLIENT_ID)}`
      );

      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.detail || "Unable to load report");
      }

      ensureReportAliases([data.analysis]);
      setSelectedAnalysis(data.analysis);
    } catch (error) {
      setMessage(error.message);
    } finally {
      setLoading(false);
    }
  };

  const exportMarkdown = async (analysisId, title) => {
    try {
      const response = await fetch(
        `${API_BASE_URL}/analysis/${analysisId}/export/markdown?client_id=${encodeURIComponent(CLIENT_ID)}`
      );

      if (!response.ok) {
        const data = await response.json();
        throw new Error(data.detail || "Unable to export report");
      }

      const markdown = await response.text();
      const blob = new Blob([markdown], { type: "text/markdown" });
      const url = URL.createObjectURL(blob);

      const safeTitle = (title || "threat-intel-report")
        .replace(/[^a-z0-9]/gi, "-")
        .toLowerCase();

      const link = document.createElement("a");
      link.href = url;
      link.download = `${safeTitle}.md`;
      link.click();

      URL.revokeObjectURL(url);
    } catch (error) {
      setMessage(error.message);
    }
  };

  const shareViaEmail = (analysis) => {
    const reportCode = getReportCode(analysis.analysis_id);

    const subject = `Threat Intelligence Brief: ${analysis.title}`;

    const body = [
      `ThreatIntel Agent Report`,
      ``,
      `Report: ${reportCode}`,
      `Title: ${analysis.title}`,
      `Risk Level: ${analysis.risk_level || "N/A"}`,
      `Risk Score: ${analysis.risk_score || "N/A"}`,
      `Confidence: ${analysis.confidence_score || "N/A"}`,
      ``,
      `Executive Summary:`,
      `${analysis.executive_summary || "No summary available."}`,
      ``,
      `Note: For sensitive reports, use your organization's approved encrypted email or secure sharing channel.`,
    ].join("\n");

    window.location.href = `mailto:?subject=${encodeURIComponent(
      subject
    )}&body=${encodeURIComponent(body)}`;
  };

  const runThreatIntelAgent = async (event) => {
    event.preventDefault();

    setLoading(true);
    setMessage("Your report is being analyzed...");

    try {
      let response;

      if (inputMode === "TEXT") {
        response = await fetch(`${API_BASE_URL}/analysis/analyze-text`, {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
          },
          body: JSON.stringify({
            title: form.title,
            raw_content: form.raw_content,
            user_id: 1,
            client_id: CLIENT_ID,
          }),
        });
      }

      if (inputMode === "URL") {
        response = await fetch(`${API_BASE_URL}/analysis/analyze-url`, {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
          },
          body: JSON.stringify({
            title: form.title,
            url: form.url,
            user_id: 1,
            client_id: CLIENT_ID,
          }),
        });
      }

      if (inputMode === "PDF") {
        const formData = new FormData();
        formData.append("title", form.title);
        formData.append("user_id", "1");
        formData.append("client_id", CLIENT_ID);
        formData.append("file", pdfFile);

        response = await fetch(`${API_BASE_URL}/analysis/analyze-pdf`, {
          method: "POST",
          body: formData,
        });
      }

      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.detail || "Analysis failed");
      }

      setLoadingProgress(100);
      setMessage(
        `Report completed. Risk: ${data.risk_level} | Score: ${data.risk_score}`
      );

      setForm({
        title: "",
        raw_content: "",
        url: "",
      });

      setPdfFile(null);

      await fetchAnalyses();
      navigate("report", data.analysis_id);
    } catch (error) {
      setMessage(error.message);
    } finally {
      setLoading(false);
    }
  };

  const canSubmit = () => {
    if (!form.title.trim()) return false;

    if (inputMode === "TEXT") {
      return form.raw_content.trim().length >= 20;
    }

    if (inputMode === "URL") {
      return form.url.trim().length >= 10;
    }

    if (inputMode === "PDF") {
      return Boolean(pdfFile);
    }

    return false;
  };

  const closeGuide = () => {
    localStorage.setItem("threatintel_guide_seen", "true");
    setShowGuide(false);
  };

  return (
    <div className="h-screen overflow-hidden bg-slate-950 text-slate-100">
      <div className="fixed inset-0 -z-10 bg-[radial-gradient(circle_at_top_left,_rgba(34,211,238,0.18),_transparent_34%),radial-gradient(circle_at_top_right,_rgba(59,130,246,0.16),_transparent_30%),linear-gradient(180deg,_#020617,_#0f172a)]" />

      {loading && (
        <LoadingOverlay
          message={PROCESSING_MESSAGES[loadingStep]}
          progress={loadingProgress}
        />
      )}

      {showGuide && (
        <GuideModal
          closeGuide={closeGuide}
          goAnalyze={() => {
            closeGuide();
            navigate("analyze");
          }}
        />
      )}

      <div className="flex h-screen overflow-hidden">
        <Sidebar
          route={route}
          navigate={navigate}
          openGuide={() => setShowGuide(true)}
          sidebarOpen={sidebarOpen}
          setSidebarOpen={setSidebarOpen}
        />

        <div className="flex min-w-0 flex-1 flex-col overflow-hidden">
          <TopBar
            route={route}
            navigate={navigate}
            openGuide={() => setShowGuide(true)}
            sidebarOpen={sidebarOpen}
            setSidebarOpen={setSidebarOpen}
          />

          <main
              className={
                route.page === "report"
                  ? "flex-1 overflow-y-auto px-4 py-6 sm:px-6 lg:px-8"
                  : "flex-1 overflow-hidden px-4 py-6 sm:px-6 lg:px-8"
              }
            >
            {message && (
              <div className="mb-6 rounded-2xl border border-cyan-400/20 bg-cyan-400/10 p-4 text-sm text-cyan-100">
                {message}
              </div>
            )}

            {route.page === "dashboard" && (
              <DashboardPage
                analyses={analyses}
                dashboardStats={dashboardStats}
                riskCounts={riskCounts}
                fetchAnalyses={fetchAnalyses}
                navigate={navigate}
                getReportCode={getReportCode}
              />
            )}

            {route.page === "analyze" && (
              <AnalyzePage
                inputMode={inputMode}
                setInputMode={setInputMode}
                form={form}
                setForm={setForm}
                pdfFile={pdfFile}
                setPdfFile={setPdfFile}
                runThreatIntelAgent={runThreatIntelAgent}
                loading={loading}
                canSubmit={canSubmit}
              />
            )}

            {route.page === "report" && selectedAnalysis && (
              <DetailPage
                selectedAnalysis={selectedAnalysis}
                safeArray={safeArray}
                navigate={navigate}
                exportMarkdown={exportMarkdown}
                shareViaEmail={shareViaEmail}
                reportCode={getReportCode(selectedAnalysis.analysis_id)}
              />
            )}
          </main>
        </div>
      </div>
    </div>
  );
}

function Sidebar({
  route,
  navigate,
  openGuide,
  sidebarOpen,
  setSidebarOpen,
}) {
  return (
    <aside
      className={
        sidebarOpen
          ? "hidden w-72 shrink-0 border-r border-white/10 bg-slate-950/80 p-5 backdrop-blur-xl transition-all duration-300 xl:flex xl:flex-col"
          : "hidden w-20 shrink-0 border-r border-white/10 bg-slate-950/80 p-4 backdrop-blur-xl transition-all duration-300 xl:flex xl:flex-col"
      }
    >
      <div className={sidebarOpen ? "flex items-center justify-between" : "flex justify-center"}>
        {sidebarOpen && (
          <div>
            <p className="text-xs font-bold uppercase tracking-[0.35em] text-cyan-300">
              ThreatIntel
            </p>
            <h1 className="mt-3 text-2xl font-black text-white">
              Agent Console
            </h1>
          </div>
        )}

        {!sidebarOpen && (
          <p className="text-lg font-black text-cyan-300">
            TIA
          </p>
        )}

        {sidebarOpen && (
          <SidebarToggleButton
            sidebarOpen={sidebarOpen}
            setSidebarOpen={setSidebarOpen}
          />
        )}
      </div>

      {!sidebarOpen && (
        <div className="mt-6 flex justify-center">
          <SidebarToggleButton
            sidebarOpen={sidebarOpen}
            setSidebarOpen={setSidebarOpen}
          />
        </div>
      )}

      <nav className="mt-10 space-y-3">
        <SideNavButton
          active={route.page === "dashboard"}
          label="Dashboard"
          shortLabel="D"
          description="Overview and saved reports"
          sidebarOpen={sidebarOpen}
          onClick={() => navigate("dashboard")}
        />

        <SideNavButton
          active={route.page === "analyze"}
          label="New Analysis"
          shortLabel="N"
          description="Analyze Text, URL, or PDF"
          sidebarOpen={sidebarOpen}
          onClick={() => navigate("analyze")}
        />
      </nav>

      {sidebarOpen && (
        <div className="mt-auto space-y-3">
          <div className="rounded-2xl border border-cyan-400/20 bg-cyan-400/10 p-4">
            <div className="flex items-center justify-between gap-3">
              <p className="text-sm font-bold text-cyan-200">
                Research Demo
              </p>

              <button
                onClick={openGuide}
                className="rounded-lg bg-cyan-400 px-3 py-1.5 text-xs font-bold text-slate-950 hover:bg-cyan-300"
              >
                Guide
              </button>
            </div>

            <p className="mt-2 text-[11px] leading-4 text-slate-300">
              AI findings may be incomplete. Verify important results before real-world use.
            </p>
          </div>

          <p className="text-center text-[11px] leading-4 text-slate-500">
            © 2026 ThreatIntel Agent.
            <br />
            Developed by Utsav Dharani.
          </p>
        </div>
      )}
    </aside>
  );
}

function SideNavButton({
  active,
  label,
  shortLabel,
  description,
  sidebarOpen,
  onClick,
}) {
  if (!sidebarOpen) {
    return (
      <button
        onClick={onClick}
        className={
          active
            ? "flex h-12 w-12 items-center justify-center rounded-2xl border border-cyan-400/30 bg-cyan-400/15 text-sm font-black text-cyan-200"
            : "flex h-12 w-12 items-center justify-center rounded-2xl border border-white/10 bg-white/5 text-sm font-black text-slate-300 hover:bg-white/10"
        }
        title={label}
      >
        {shortLabel}
      </button>
    );
  }

  return (
    <button
      onClick={onClick}
      className={
        active
          ? "w-full rounded-2xl border border-cyan-400/30 bg-cyan-400/15 p-4 text-left"
          : "w-full rounded-2xl border border-white/10 bg-white/5 p-4 text-left hover:bg-white/10"
      }
    >
      <p className="font-bold text-white">{label}</p>
      <p className="mt-1 text-xs text-slate-400">{description}</p>
    </button>
  );
}

function TopBar({ route, navigate, openGuide, sidebarOpen, setSidebarOpen }) {
  return (
    <header className="sticky top-0 z-30 border-b border-white/10 bg-slate-950/80 px-4 py-4 backdrop-blur-xl sm:px-6 lg:px-8">
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <p className="text-xs font-bold uppercase tracking-[0.28em] text-cyan-300">
            AI Threat Intelligence Workspace
          </p>
          <h2 className="mt-1 text-xl font-black text-white md:text-2xl">
            {route.page === "dashboard" && "Dashboard Overview"}
            {route.page === "analyze" && "Run New Threat Analysis"}
            {route.page === "report" && "Threat Intelligence Report"}
          </h2>
        </div>

        <div className="flex flex-wrap gap-2">
          

          <button
            onClick={openGuide}
            className="rounded-xl border border-cyan-400/40 px-4 py-2 text-sm font-semibold text-cyan-200 hover:bg-cyan-400/10"
          >
            Guide
          </button>

          <button
            onClick={() => navigate("analyze")}
            className="rounded-xl border border-cyan-400/40 px-4 py-2 text-sm font-semibold text-cyan-200 hover:bg-cyan-400/10"
          >
            New Analysis
          </button>

          <button
            onClick={() => navigate("dashboard")}
            className="rounded-xl bg-cyan-400 px-4 py-2 text-sm font-bold text-slate-950 hover:bg-cyan-300"
          >
            Dashboard
          </button>
        </div>
      </div>
    </header>
  );
}

function LoadingOverlay({ message, progress }) {
  const safeProgress = Math.min(100, Math.max(0, Math.round(progress || 0)));

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-slate-950/85 px-6 backdrop-blur-sm">
      <div className="w-full max-w-xl rounded-3xl border border-cyan-400/20 bg-slate-900 p-8 shadow-2xl">
        <div className="relative mx-auto flex h-24 w-24 items-center justify-center rounded-full border border-cyan-400/30 bg-cyan-400/10">
          <div className="absolute h-16 w-16 animate-spin rounded-full border-4 border-cyan-300 border-t-transparent" />
          <span className="relative text-xl font-black text-cyan-100">
            {safeProgress}%
          </span>
        </div>

        <h2 className="mt-6 text-center text-2xl font-black text-white">
          Processing Threat Intelligence
        </h2>

        <p className="mt-3 text-center text-sm leading-6 text-slate-300">
          {message}
        </p>

        <div className="mt-6 h-2 overflow-hidden rounded-full bg-slate-800">
          <div
            className="h-full rounded-full bg-gradient-to-r from-cyan-300 via-blue-400 to-violet-400 transition-all duration-700"
            style={{
              width: `${safeProgress}%`,
            }}
          />
        </div>

        <p className="mt-5 text-center text-xs text-slate-400">
          Estimated progress. Please keep this page open while the analysis completes.
        </p>
      </div>
    </div>
  );
}

function GuideModal({ closeGuide, goAnalyze }) {
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-slate-950/80 p-4 backdrop-blur-md">
      <div className="w-full max-w-4xl overflow-hidden rounded-3xl border border-white/10 bg-white text-slate-950 shadow-2xl">
        <div className="bg-gradient-to-r from-slate-950 via-blue-950 to-cyan-900 p-8 text-white">
          <p className="text-xs font-bold uppercase tracking-[0.35em] text-cyan-300">
            Welcome to ThreatIntel Agent
          </p>
          <h2 className="mt-3 text-3xl font-black">
            Turn reports into structured threat intelligence
          </h2>
          <p className="mt-3 max-w-3xl text-sm leading-6 text-slate-300">
            Submit a threat report as text, URL, or PDF. The system extracts key
            details, maps behaviors to MITRE ATT&CK, scores risk, and generates
            an analyst-ready brief.
          </p>
        </div>

        <div className="grid gap-6 p-8 md:grid-cols-3">
          <GuideCard
            title="1. Submit a source"
            text="Paste report text, provide a public URL, or upload a text-based PDF."
          />
          <GuideCard
            title="2. Review analysis"
            text="Get IOCs, CVEs, MITRE mapping, risk score, recommendations, and evidence."
          />
          <GuideCard
            title="3. Export or share"
            text="Download Markdown or share a short report summary through your email client."
          />
        </div>

        <div className="border-t border-slate-200 bg-slate-50 p-6">
          <div className="flex flex-wrap items-center justify-between gap-4">
            <p className="text-sm text-slate-600">
              This is a research and portfolio project. Generated output may be incomplete or inaccurate, so verify important findings before using them in real security decisions.
            </p>

            <div className="flex gap-3">
              <button
                onClick={closeGuide}
                className="rounded-xl border border-slate-300 px-4 py-2 text-sm font-bold text-slate-700 hover:bg-white"
              >
                Close
              </button>

              <button
                onClick={goAnalyze}
                className="rounded-xl bg-slate-950 px-4 py-2 text-sm font-bold text-white hover:bg-slate-800"
              >
                Start Analysis
              </button>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

function GuideCard({ title, text }) {
  return (
    <div className="rounded-2xl border border-slate-200 bg-slate-50 p-5">
      <h3 className="font-black">{title}</h3>
      <p className="mt-2 text-sm leading-6 text-slate-600">{text}</p>
    </div>
  );
}

function DashboardPage({
  analyses,
  dashboardStats,
  riskCounts,
  fetchAnalyses,
  navigate,
  getReportCode,
}) {
  return (
    <div className="flex h-full min-h-0 flex-col gap-4">
      <section className="grid shrink-0 gap-4 md:grid-cols-4">
        <StatCard label="Total Reports" value={dashboardStats.total} />
        <StatCard label="Completed" value={dashboardStats.completed} />
        <StatCard label="High/Critical" value={dashboardStats.highRisk} />
        <StatCard label="Average Risk" value={dashboardStats.avgRisk} />
      </section>

      <section className="grid min-h-0 flex-1 gap-6 xl:grid-cols-3">
        <div className="flex min-h-0 flex-col rounded-3xl border border-white/10 bg-white p-6 text-slate-950 shadow-2xl xl:col-span-2">
          <div className="flex shrink-0 flex-wrap items-center justify-between gap-4">
            <div>
              <h3 className="text-2xl font-black">Recent Intelligence Briefs</h3>
              <p className="mt-2 text-sm text-slate-600">
                Your recent reports in this browser session.
              </p>
            </div>

            <div className="flex gap-3">
              <button
                onClick={fetchAnalyses}
                className="rounded-xl border border-slate-300 px-4 py-2 text-sm font-bold hover:bg-slate-50"
              >
                Refresh
              </button>

              <button
                onClick={() => navigate("analyze")}
                className="rounded-xl bg-slate-950 px-4 py-2 text-sm font-bold text-white hover:bg-slate-800"
              >
                New Analysis
              </button>
            </div>
          </div>

          <div className="mt-5 min-h-0 flex-1 overflow-auto rounded-2xl border border-slate-200">
            <table className="w-full text-left text-sm">
              <thead className="sticky top-0 z-10 bg-slate-100 text-slate-600">
                <tr>
                  <th className="px-4 py-3">Report</th>
                  <th className="px-4 py-3">Title</th>
                  <th className="px-4 py-3">Source</th>
                  <th className="px-4 py-3">Risk</th>
                  <th className="px-4 py-3">Score</th>
                  <th className="px-4 py-3">Status</th>
                  <th className="px-4 py-3">Action</th>
                </tr>
              </thead>

              <tbody>
                {analyses.map((item) => (
                  <tr key={item.analysis_id} className="border-t border-slate-200">
                    <td className="px-4 py-3 font-bold text-cyan-700">
                      {getReportCode(item.analysis_id)}
                    </td>
                    <td className="max-w-xs px-4 py-3 font-bold">
                      {item.title}
                    </td>
                    <td className="px-4 py-3">{item.source_type}</td>
                    <td className="px-4 py-3">
                      <RiskBadge risk={item.risk_level} />
                    </td>
                    <td className="px-4 py-3">{item.risk_score || "N/A"}</td>
                    <td className="px-4 py-3">
                      <StatusBadge status={item.status} />
                    </td>
                    <td className="px-4 py-3">
                      <button
                        onClick={() => navigate("report", item.analysis_id)}
                        className="rounded-lg bg-slate-950 px-3 py-2 text-xs font-bold text-white hover:bg-slate-800"
                      >
                        View
                      </button>
                    </td>
                  </tr>
                ))}

                {analyses.length === 0 && (
                  <tr>
                    <td colSpan="7" className="px-4 py-10 text-center text-slate-500">
                      No reports yet. Start a new analysis to see results here.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </div>

        <div className="min-h-0 overflow-hidden">
          <RiskPanel riskCounts={riskCounts} />
        </div>
      </section>
    </div>
  );
}

function AnalyzePage({
  inputMode,
  setInputMode,
  form,
  setForm,
  pdfFile,
  setPdfFile,
  runThreatIntelAgent,
  loading,
  canSubmit,
}) {
  return (
    <div className="grid h-full min-h-0 gap-6 xl:grid-cols-5">
      <section className="flex min-h-0 flex-col rounded-3xl border border-white/10 bg-white p-6 text-slate-950 shadow-2xl xl:col-span-4">
        <div className="shrink-0">
          <div className="flex flex-wrap items-start justify-between gap-4">
            <div>
              <h2 className="text-3xl font-black">Run Threat Analysis</h2>
              <p className="mt-2 max-w-3xl text-sm leading-6 text-slate-600">
                Submit a report and receive a structured threat intelligence brief
                with risk, evidence, MITRE mapping, and recommendations.
              </p>
            </div>

            <span className="rounded-full bg-cyan-50 px-4 py-2 text-xs font-black text-cyan-700">
              Research preview
            </span>
          </div>

          <div className="mt-5 grid gap-3 rounded-2xl bg-slate-100 p-2 md:grid-cols-3">
            {["TEXT", "URL", "PDF"].map((mode) => (
              <button
                key={mode}
                type="button"
                onClick={() => setInputMode(mode)}
                className={
                  inputMode === mode
                    ? "rounded-xl bg-slate-950 px-4 py-3 text-sm font-black text-white shadow"
                    : "rounded-xl px-4 py-3 text-sm font-black text-slate-600 hover:bg-white"
                }
              >
                {mode === "TEXT" && "Text Report"}
                {mode === "URL" && "URL Report"}
                {mode === "PDF" && "PDF Upload"}
              </button>
            ))}
          </div>
        </div>

        <form onSubmit={runThreatIntelAgent} className="mt-5 flex min-h-0 flex-1 flex-col gap-4">
          <div className="shrink-0">
            <label className="block text-sm font-black">Report Title</label>
            <input
              type="text"
              value={form.title}
              onChange={(event) =>
                setForm({ ...form, title: event.target.value })
              }
              className="mt-2 w-full rounded-xl border border-slate-300 px-4 py-3 outline-none transition focus:border-cyan-500 focus:ring-4 focus:ring-cyan-100"
              placeholder="Example: Enterprise Phishing Campaign"
              required
            />
          </div>

          {inputMode === "TEXT" && (
            <div className="flex min-h-0 flex-1 flex-col">
              <div className="flex shrink-0 items-center justify-between gap-3">
                <label className="block text-sm font-black">
                  Threat Report Text
                </label>

                <button
                  type="button"
                  onClick={() =>
                    setForm({
                      ...form,
                      title:
                        form.title ||
                        "Enterprise Phishing and Credential Theft Campaign",
                      raw_content: SAMPLE_TEXT,
                    })
                  }
                  className="rounded-lg border border-slate-300 px-3 py-1 text-xs font-bold hover:bg-slate-50"
                >
                  Use Sample
                </button>
              </div>

              <textarea
                value={form.raw_content}
                onChange={(event) =>
                  setForm({ ...form, raw_content: event.target.value })
                }
                className="mt-2 min-h-0 flex-1 rounded-xl border border-slate-300 px-4 py-3 outline-none transition focus:border-cyan-500 focus:ring-4 focus:ring-cyan-100"
                placeholder="Paste threat report text here..."
                required
              />
            </div>
          )}

          {inputMode === "URL" && (
            <div className="shrink-0">
              <div className="flex items-center justify-between gap-3">
                <label className="block text-sm font-black">
                  Threat Report URL
                </label>

                <button
                  type="button"
                  onClick={() =>
                    setForm({
                      ...form,
                      title: form.title || SAMPLE_URL_TITLE,
                      url: SAMPLE_URL,
                    })
                  }
                  className="rounded-lg border border-slate-300 px-3 py-1 text-xs font-bold hover:bg-slate-50"
                >
                  Use Sample URL
                </button>
              </div>

              <input
                type="url"
                value={form.url}
                onChange={(event) =>
                  setForm({ ...form, url: event.target.value })
                }
                className="mt-2 w-full rounded-xl border border-slate-300 px-4 py-3 outline-none transition focus:border-cyan-500 focus:ring-4 focus:ring-cyan-100"
                placeholder="https://example.com/security-advisory"
                required
              />

              <p className="mt-2 text-xs leading-5 text-slate-500">
                Best with public advisories. If a page cannot be read automatically, use Text Report mode.
              </p>
            </div>
          )}

          {inputMode === "PDF" && (
            <div className="shrink-0">
              <div className="flex items-center justify-between gap-3">
                <label className="block text-sm font-black">
                  Upload PDF Threat Report
                </label>

                <div className="flex gap-2">
                  <a
                    href={SAMPLE_PDF_URL}
                    target="_blank"
                    rel="noreferrer"
                    className="rounded-lg border border-slate-300 px-3 py-1 text-xs font-bold hover:bg-slate-50"
                  >
                    Open Sample PDF
                  </a>

                  <button
                    type="button"
                    onClick={() => {
                      setInputMode("URL");
                      setForm({
                        ...form,
                        title: form.title || SAMPLE_PDF_TITLE,
                        url: SAMPLE_PDF_URL,
                      });
                    }}
                    className="rounded-lg border border-slate-300 px-3 py-1 text-xs font-bold hover:bg-slate-50"
                  >
                    Analyze PDF URL
                  </button>
                </div>
              </div>

              <input
                type="file"
                accept="application/pdf"
                onChange={(event) => setPdfFile(event.target.files?.[0] || null)}
                className="mt-2 w-full rounded-xl border border-dashed border-slate-300 bg-slate-50 px-4 py-8 text-sm outline-none transition file:mr-4 file:rounded-lg file:border-0 file:bg-slate-950 file:px-4 file:py-2 file:text-sm file:font-bold file:text-white hover:bg-slate-100"
                required
              />

              {pdfFile && (
                <p className="mt-2 text-xs text-slate-600">
                  Selected: {pdfFile.name}
                </p>
              )}

              <p className="mt-2 text-xs leading-5 text-slate-500">
                Text-based PDFs work best. Image-only PDFs may not extract correctly.
              </p>
            </div>
          )}

          <div className="shrink-0">
            <button
              type="submit"
              disabled={loading || !canSubmit()}
              className="w-full rounded-xl bg-gradient-to-r from-cyan-500 to-blue-600 px-5 py-3 text-sm font-black text-white shadow-lg shadow-cyan-500/20 transition hover:from-cyan-400 hover:to-blue-500 disabled:cursor-not-allowed disabled:opacity-50 md:w-auto"
            >
              Generate Intelligence Brief
            </button>
          </div>
        </form>
      </section>

      <aside className="hidden min-h-0 overflow-y-auto xl:block">
        <div className="space-y-4">
          <ProductValueCard
            title="What you’ll get"
            items={[
              "Executive threat summary",
              "Risk score and confidence",
              "IOC and CVE extraction",
              "MITRE ATT&CK mapping",
              "Evidence-backed findings",
              "Markdown report export",
            ]}
          />

          <ProductValueCard
            title="Supported sources"
            items={[
              "Threat report text",
              "Public security advisory URL",
              "Text-based PDF report",
              "Sample/demo content",
            ]}
          />

          <ProductValueCard
            title="Research note"
            items={[
              "AI output may be incomplete",
              "Verify critical findings manually",
              "Use as analyst support, not final truth",
              "Best for defensive security review",
            ]}
          />
        </div>
      </aside>
    </div>
  );
}

function DetailPage({
  selectedAnalysis,
  safeArray,
  navigate,
  exportMarkdown,
  shareViaEmail,
  reportCode,
}) {
  return (
    <div className="space-y-6">
      <section className="rounded-3xl border border-white/10 bg-white p-6 text-slate-950 shadow-2xl">
        <div className="flex flex-wrap items-start justify-between gap-4">
          <div>
            <p className="text-xs font-black uppercase tracking-[0.25em] text-cyan-700">
              Intelligence Brief
            </p>
            <h2 className="mt-2 text-3xl font-black">
              {selectedAnalysis.title}
            </h2>
            <p className="mt-2 text-sm text-slate-600">
              Report: {reportCode} | Source: {selectedAnalysis.source_type}
            </p>
          </div>

          <div className="flex flex-wrap gap-3">
            <StatusBadge status={selectedAnalysis.status} />
            <RiskBadge risk={selectedAnalysis.risk_level} />
            <InfoPill label="Score" value={selectedAnalysis.risk_score || "N/A"} />
            <InfoPill label="Confidence" value={selectedAnalysis.confidence_score || "N/A"} />
          </div>
        </div>

        <div className="mt-6 grid gap-4 lg:grid-cols-4">
          <SummaryMetric label="Threat Entities" value={safeArray(selectedAnalysis.threat_entities).length} />
          <SummaryMetric label="IOCs" value={safeArray(selectedAnalysis.indicators).length} />
          <SummaryMetric label="MITRE Techniques" value={safeArray(selectedAnalysis.mitre_techniques).length} />
          <SummaryMetric label="Findings" value={safeArray(selectedAnalysis.evidence_findings).length} />
        </div>

        <div className="mt-6 rounded-2xl bg-slate-100 p-5">
          <h3 className="font-black">Executive Summary</h3>
          <p className="mt-2 text-sm leading-6 text-slate-700">
            {selectedAnalysis.executive_summary || "No summary available."}
          </p>
        </div>

        <div className="mt-6 flex flex-wrap gap-3">
          <button
            onClick={() => navigate("analyze")}
            className="rounded-xl bg-slate-950 px-4 py-2 text-sm font-bold text-white hover:bg-slate-800"
          >
            New Analysis
          </button>

          <button
            onClick={() =>
              exportMarkdown(selectedAnalysis.analysis_id, selectedAnalysis.title)
            }
            className="rounded-xl border border-slate-300 px-4 py-2 text-sm font-bold hover:bg-slate-50"
          >
            Export Markdown
          </button>

          <button
            onClick={() => shareViaEmail(selectedAnalysis)}
            className="rounded-xl border border-slate-300 px-4 py-2 text-sm font-bold hover:bg-slate-50"
          >
            Share via Email
          </button>
        </div>
      </section>

      <ReportQualityPanel analysis={selectedAnalysis} />

      <section className="rounded-3xl border border-white/10 bg-white p-6 text-slate-950 shadow-2xl">
        <h3 className="text-xl font-black">Investigation Trace</h3>
        <p className="mt-2 text-sm text-slate-600">
          Step-by-step record of how this report was processed.
        </p>

        <div className="mt-5 grid gap-4 md:grid-cols-2 xl:grid-cols-3">
          {safeArray(selectedAnalysis.agent_steps)
            .sort((a, b) => a.step_order - b.step_order)
            .map((step) => (
              <div
                key={step.step_id}
                className="rounded-2xl border border-slate-200 bg-slate-50 p-4"
              >
                <p className="text-xs font-black uppercase tracking-wide text-cyan-700">
                  Step {step.step_order}
                </p>
                <h4 className="mt-1 font-black">{step.agent_name}</h4>
                <p className="mt-2 text-xs leading-5 text-slate-600">
                  {step.output_summary}
                </p>
                <p className="mt-3 text-xs font-black text-green-700">
                  {step.status}
                </p>
              </div>
            ))}
        </div>
      </section>

      <section className="grid gap-6 xl:grid-cols-2">
        <DataTable
          title="Threat Entities"
          rows={safeArray(selectedAnalysis.threat_entities)}
          columns={["entity_type", "entity_value", "confidence"]}
        />

        <DataTable
          title="Indicators of Compromise"
          rows={safeArray(selectedAnalysis.indicators)}
          columns={["indicator_type", "indicator_value", "is_malicious", "confidence"]}
        />
      </section>

      <section className="grid gap-6 xl:grid-cols-2">
        <DataTable
          title="CVEs"
          rows={safeArray(selectedAnalysis.cves)}
          columns={["cve_id", "severity", "cvss_score", "affected_product"]}
        />

        <DataTable
          title="MITRE ATT&CK Mapping"
          rows={safeArray(selectedAnalysis.mitre_techniques)}
          columns={["technique_id", "technique_name", "tactic", "confidence"]}
        />
      </section>

      <section className="rounded-3xl border border-white/10 bg-white p-6 text-slate-950 shadow-2xl">
        <h3 className="text-xl font-black">Attack Chain</h3>

        <div className="mt-5 max-h-[430px] space-y-4 overflow-y-auto pr-2">
          {safeArray(selectedAnalysis.attack_chain_steps)
            .sort((a, b) => a.step_order - b.step_order)
            .map((step) => (
              <div key={step.chain_step_id} className="rounded-2xl border border-slate-200 p-4">
                <p className="text-xs font-black uppercase tracking-wide text-blue-700">
                  Step {step.step_order} | {step.phase_name}
                </p>
                <h4 className="mt-1 font-black">{step.step_title}</h4>
                <p className="mt-2 text-sm leading-6 text-slate-600">
                  {step.step_description}
                </p>
                {step.related_technique_id && (
                  <p className="mt-2 text-xs font-bold text-slate-500">
                    Related MITRE: {step.related_technique_id}
                  </p>
                )}
              </div>
            ))}

          {safeArray(selectedAnalysis.attack_chain_steps).length === 0 && (
            <p className="text-sm text-slate-500">No attack chain steps found.</p>
          )}
        </div>
      </section>

      <section className="rounded-3xl border border-white/10 bg-white p-6 text-slate-950 shadow-2xl">
        <h3 className="text-xl font-black">Recommendations</h3>

        <div className="mt-5 grid max-h-[430px] gap-4 overflow-y-auto pr-2 md:grid-cols-2">
          {safeArray(selectedAnalysis.recommendations).map((item) => (
            <div key={item.recommendation_id} className="rounded-2xl border border-slate-200 p-4">
              <p className="text-xs font-black uppercase tracking-wide text-red-700">
                {item.priority} | {item.category}
              </p>
              <p className="mt-2 text-sm font-bold">
                {item.recommendation_text}
              </p>
              <p className="mt-2 text-xs leading-5 text-slate-600">
                {item.reason}
              </p>
            </div>
          ))}

          {safeArray(selectedAnalysis.recommendations).length === 0 && (
            <p className="text-sm text-slate-500">No recommendations found.</p>
          )}
        </div>
      </section>

      <section className="rounded-3xl border border-white/10 bg-white p-6 text-slate-950 shadow-2xl">
        <h3 className="text-xl font-black">Evidence-backed Findings</h3>
        <p className="mt-2 text-sm text-slate-600">
          Findings grounded in evidence from the submitted source.
        </p>

        <div className="mt-5 max-h-[430px] space-y-4 overflow-y-auto pr-2">
          {safeArray(selectedAnalysis.evidence_findings).map((finding) => (
            <div key={finding.finding_id} className="rounded-2xl border border-slate-200 p-4">
              <p className="text-xs font-black uppercase tracking-wide text-purple-700">
                {finding.severity} | Confidence: {finding.confidence}
              </p>
              <h4 className="mt-1 font-black">{finding.finding_title}</h4>
              <p className="mt-2 text-sm leading-6 text-slate-600">
                {finding.finding_description}
              </p>
              <blockquote className="mt-3 rounded-xl border-l-4 border-purple-400 bg-purple-50 p-3 text-xs leading-5 text-slate-700">
                Evidence: {finding.evidence_text}
              </blockquote>
            </div>
          ))}

          {safeArray(selectedAnalysis.evidence_findings).length === 0 && (
            <p className="text-sm text-slate-500">No evidence findings found.</p>
          )}
        </div>
      </section>

      <section className="rounded-3xl border border-white/10 bg-white p-6 text-slate-950 shadow-2xl">
        <h3 className="text-xl font-black">Final Analyst Report</h3>
        <div className="mt-5 max-h-[650px] overflow-y-auto rounded-2xl bg-slate-50 p-6">
          <MarkdownReport content={selectedAnalysis.final_report || "No final report available."} />
        </div>
      </section>
    </div>
  );
}

function ProductValueCard({ title, items }) {
  return (
    <div className="rounded-3xl border border-white/10 bg-white/10 p-5 shadow-2xl backdrop-blur">
      <h3 className="font-black text-white">{title}</h3>

      <div className="mt-4 space-y-3">
        {items.map((item) => (
          <div key={item} className="flex items-start gap-3">
            <div className="mt-1 h-2 w-2 rounded-full bg-cyan-300" />
            <p className="text-sm leading-5 text-slate-300">{item}</p>
          </div>
        ))}
      </div>
    </div>
  );
}

function StatCard({ label, value }) {
  return (
    <div className="rounded-3xl border border-white/10 bg-white/10 p-6 shadow-2xl backdrop-blur">
      <p className="text-sm text-slate-300">{label}</p>
      <p className="mt-2 text-4xl font-black text-white">{value}</p>
    </div>
  );
}

function RiskPanel({ riskCounts }) {
  const total = Math.max(
    1,
    riskCounts.CRITICAL +
      riskCounts.HIGH +
      riskCounts.MEDIUM +
      riskCounts.LOW +
      riskCounts.UNKNOWN
  );

  const items = [
    { label: "Critical", key: "CRITICAL", className: "bg-red-500" },
    { label: "High", key: "HIGH", className: "bg-orange-500" },
    { label: "Medium", key: "MEDIUM", className: "bg-yellow-400" },
    { label: "Low", key: "LOW", className: "bg-green-500" },
    { label: "Unknown", key: "UNKNOWN", className: "bg-slate-400" },
  ];

  return (
    <div className="rounded-3xl border border-white/10 bg-white/10 p-6 shadow-2xl backdrop-blur">
      <h3 className="text-xl font-black text-white">Risk Distribution</h3>
      <p className="mt-2 text-sm text-slate-300">
        Visual summary of your reports.
      </p>

      <div className="mt-6 space-y-4">
        {items.map((item) => {
          const count = riskCounts[item.key] || 0;
          const percentage = Math.round((count / total) * 100);

          return (
            <div key={item.key}>
              <div className="mb-2 flex items-center justify-between text-sm">
                <span className="font-bold text-slate-200">{item.label}</span>
                <span className="text-slate-400">{count}</span>
              </div>
              <div className="h-3 overflow-hidden rounded-full bg-slate-800">
                <div
                  className={`h-full rounded-full ${item.className}`}
                  style={{ width: `${percentage}%` }}
                />
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}

function SummaryMetric({ label, value }) {
  return (
    <div className="rounded-2xl border border-slate-200 bg-slate-50 p-4">
      <p className="text-xs font-bold uppercase tracking-wide text-slate-500">
        {label}
      </p>
      <p className="mt-2 text-2xl font-black text-slate-950">{value}</p>
    </div>
  );
}

function DataTable({ title, rows, columns }) {
  return (
    <section className="flex h-[420px] flex-col rounded-3xl border border-white/10 bg-white p-6 text-slate-950 shadow-2xl">
      <h3 className="text-xl font-black">{title}</h3>

      <div className="mt-5 flex-1 overflow-auto rounded-2xl border border-slate-200">
        <table className="w-full text-left text-sm">
          <thead className="sticky top-0 z-10 bg-slate-100 text-slate-600">
            <tr>
              {columns.map((column) => (
                <th key={column} className="px-4 py-3">
                  {column.replaceAll("_", " ").toUpperCase()}
                </th>
              ))}
            </tr>
          </thead>

          <tbody>
            {rows.map((row, index) => (
              <tr key={index} className="border-t border-slate-200">
                {columns.map((column) => (
                  <td key={column} className="px-4 py-3 align-top">
                    {row[column] === null || row[column] === undefined || row[column] === ""
                      ? "N/A"
                      : String(row[column])}
                  </td>
                ))}
              </tr>
            ))}

            {rows.length === 0 && (
              <tr>
                <td
                  colSpan={columns.length}
                  className="px-4 py-8 text-center text-slate-500"
                >
                  No data found.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </section>
  );
}

function MarkdownReport({ content }) {
  return (
    <div className="max-w-none text-slate-800">
      <ReactMarkdown
        remarkPlugins={[remarkGfm]}
        components={{
          h1: ({ children }) => (
            <h1 className="mb-4 mt-6 text-3xl font-black text-slate-950">
              {children}
            </h1>
          ),
          h2: ({ children }) => (
            <h2 className="mb-3 mt-6 text-2xl font-black text-slate-950">
              {children}
            </h2>
          ),
          h3: ({ children }) => (
            <h3 className="mb-3 mt-5 text-xl font-black text-slate-950">
              {children}
            </h3>
          ),
          h4: ({ children }) => (
            <h4 className="mb-2 mt-4 text-lg font-black text-slate-950">
              {children}
            </h4>
          ),
          p: ({ children }) => (
            <p className="mb-4 text-sm leading-7 text-slate-700">
              {children}
            </p>
          ),
          ul: ({ children }) => (
            <ul className="mb-4 list-disc space-y-2 pl-6 text-sm leading-7 text-slate-700">
              {children}
            </ul>
          ),
          ol: ({ children }) => (
            <ol className="mb-4 list-decimal space-y-2 pl-6 text-sm leading-7 text-slate-700">
              {children}
            </ol>
          ),
          li: ({ children }) => <li className="pl-1">{children}</li>,
          strong: ({ children }) => (
            <strong className="font-black text-slate-950">{children}</strong>
          ),
          code: ({ children }) => (
            <code className="rounded-md bg-slate-200 px-1.5 py-0.5 text-sm font-bold text-slate-950">
              {children}
            </code>
          ),
          blockquote: ({ children }) => (
            <blockquote className="mb-4 border-l-4 border-cyan-400 bg-cyan-50 p-4 text-sm text-slate-700">
              {children}
            </blockquote>
          ),
        }}
      >
        {content}
      </ReactMarkdown>
    </div>
  );
}

function RiskBadge({ risk }) {
  if (risk === "CRITICAL") {
    return (
      <span className="rounded-full bg-red-100 px-3 py-1 text-xs font-black text-red-700">
        CRITICAL
      </span>
    );
  }

  if (risk === "HIGH") {
    return (
      <span className="rounded-full bg-orange-100 px-3 py-1 text-xs font-black text-orange-700">
        HIGH
      </span>
    );
  }

  if (risk === "MEDIUM") {
    return (
      <span className="rounded-full bg-yellow-100 px-3 py-1 text-xs font-black text-yellow-700">
        MEDIUM
      </span>
    );
  }

  if (risk === "LOW") {
    return (
      <span className="rounded-full bg-green-100 px-3 py-1 text-xs font-black text-green-700">
        LOW
      </span>
    );
  }

  return (
    <span className="rounded-full bg-slate-100 px-3 py-1 text-xs font-black text-slate-600">
      N/A
    </span>
  );
}

function StatusBadge({ status }) {
  if (status === "FAILED") {
    return (
      <span className="rounded-full bg-red-100 px-3 py-1 text-xs font-black text-red-700">
        FAILED
      </span>
    );
  }

  if (status === "PROCESSING") {
    return (
      <span className="rounded-full bg-blue-100 px-3 py-1 text-xs font-black text-blue-700">
        PROCESSING
      </span>
    );
  }

  return (
    <span className="rounded-full bg-green-100 px-3 py-1 text-xs font-black text-green-700">
      {status || "UNKNOWN"}
    </span>
  );
}

function InfoPill({ label, value }) {
  return (
    <span className="rounded-full bg-blue-100 px-3 py-1 text-xs font-black text-blue-700">
      {label}: {value}
    </span>
  );
}

export default App;