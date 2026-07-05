import { useMemo } from "react";
import type { ExportData, Finding } from "../types";
import {
  computeSummary,
  findingsByModule,
  httpByContentType,
  httpByMethod,
  httpByStatusCodeExact,
  severityCounts,
} from "../utils/parse";
import Hero from "./Hero";
import SeverityDonut from "./SeverityDonut";

interface Props {
  data: ExportData;
  scanDuration?: string;
  generatedAt?: string;
  reportTitle?: string;
  scanTarget?: string;
  agentName?: string;
  inputTokens?: number;
  outputTokens?: number;
  costUSD?: number;
  reportSharedURL?: string;
}

const DEFAULT_REPORT_SHARED_URL = "https://console.vigolium.com/shared/audit-reports/";

// Per-token pricing from GitHub Copilot's published pricing table.
// Source: docs.github.com/en/copilot/reference/copilot-billing/models-and-pricing
// All prices are USD per 1M tokens.
//
// HOW TO UPDATE:
//   1. Visit the source URL above and compare against this table.
//   2. Update the affected model entry (or add a new one).
//   3. Run `bun run build` in platform/static-reports/ and copy
//      dist/template.html to public/static-reports/template.html.
//   4. Rebuild vigolium with `make install`.
//   5. Note the change in UPDATE.md's "Sync history" table.
//
// NOTE: Claude Sonnet 5 promotional pricing ($2 in / $10 out) ends 2026-08-31;
// revert to standard Sonnet rates ($3 in / $15 out) after that date.
type ModelPricing = {
  input: number;       // standard input tokens
  cachedInput: number; // cache-read input tokens (prompt cache hit)
  cacheWrite: number;  // cache-write tokens (first write to prompt cache)
  output: number;      // output / completion tokens
};

const MODEL_PRICING: Record<string, ModelPricing> = {
  // Anthropic — via GitHub Copilot
  "claude-sonnet-5":    { input:  2.00, cachedInput: 0.20, cacheWrite:  2.50, output: 10.00 }, // promo ≤2026-08-31
  "claude-sonnet-4.6":  { input:  3.00, cachedInput: 0.30, cacheWrite:  3.75, output: 15.00 },
  "claude-sonnet-4.5":  { input:  3.00, cachedInput: 0.30, cacheWrite:  3.75, output: 15.00 },
  "claude-sonnet-4":    { input:  3.00, cachedInput: 0.30, cacheWrite:  3.75, output: 15.00 },
  "claude-opus-4.5":    { input:  5.00, cachedInput: 0.50, cacheWrite:  6.25, output: 25.00 },
  "claude-opus-4.6":    { input:  5.00, cachedInput: 0.50, cacheWrite:  6.25, output: 25.00 },
  "claude-opus-4.7":    { input:  5.00, cachedInput: 0.50, cacheWrite:  6.25, output: 25.00 },
  "claude-opus-4.8":    { input:  5.00, cachedInput: 0.50, cacheWrite:  6.25, output: 25.00 },
  "claude-haiku-4.5":   { input:  1.00, cachedInput: 0.10, cacheWrite:  1.25, output:  5.00 },
  "claude-fable-5":     { input: 10.00, cachedInput: 1.00, cacheWrite: 12.50, output: 50.00 },
  // OpenAI — via GitHub Copilot
  "gpt-5-mini":         { input:  0.25, cachedInput: 0.025, cacheWrite: 0, output:  2.00 },
  "gpt-5.3-codex":      { input:  1.75, cachedInput: 0.175, cacheWrite: 0, output: 14.00 },
  "gpt-5.4":            { input:  2.50, cachedInput: 0.25,  cacheWrite: 0, output: 15.00 },
  "gpt-5.4-mini":       { input:  0.75, cachedInput: 0.075, cacheWrite: 0, output:  4.50 },
  "gpt-5.4-nano":       { input:  0.20, cachedInput: 0.02,  cacheWrite: 0, output:  1.25 },
  "gpt-5.5":            { input:  5.00, cachedInput: 0.50,  cacheWrite: 0, output: 30.00 },
  // Google — via GitHub Copilot
  "gemini-2.5-pro":     { input:  1.25, cachedInput: 0.125, cacheWrite: 0, output: 10.00 },
  "gemini-3-flash":     { input:  0.50, cachedInput: 0.05,  cacheWrite: 0, output:  3.00 },
  "gemini-3.1-pro":     { input:  2.00, cachedInput: 0.20,  cacheWrite: 0, output: 12.00 },
  "gemini-3.5-flash":   { input:  1.50, cachedInput: 0.15,  cacheWrite: 0, output:  9.00 },
  // GitHub fine-tuned
  "raptor-mini":        { input:  0.25, cachedInput: 0.025, cacheWrite: 0, output:  2.00 },
  // Microsoft — via GitHub Copilot
  "mai-code-1-flash":   { input:  0.75, cachedInput: 0.075, cacheWrite: 0, output:  4.50 },
  // Moonshot AI
  "kimi-k2.7-code":     { input:  0.95, cachedInput: 0.19,  cacheWrite: 0, output:  4.00 },
};

/** Derive per-token costs from model pricing table.
 *  Extracts model name from agentName (e.g. "copilot/claude-sonnet-5" → "claude-sonnet-5").
 *  Returns undefined when the model is not in the table or token counts are missing. */
function computeCosts(
  agentName: string | undefined,
  inputTokens: number | undefined,
  outputTokens: number | undefined,
): { inputCost: number | undefined; outputCost: number | undefined } {
  if (!agentName) return { inputCost: undefined, outputCost: undefined };
  const model = agentName.includes("/") ? agentName.split("/").pop()! : agentName;
  const pricing = MODEL_PRICING[model.toLowerCase()];
  if (!pricing) return { inputCost: undefined, outputCost: undefined };
  return {
    inputCost:  inputTokens  ? (inputTokens  * pricing.input)  / 1_000_000 : undefined,
    outputCost: outputTokens ? (outputTokens * pricing.output) / 1_000_000 : undefined,
  };
}

const SEV_ORDER = ["critical", "high", "medium", "low", "suspect", "info", "n/a"] as const;

function sevCssVar(k: string): string {
  return `var(--sev-${k === "n/a" ? "na" : k})`;
}

const SEV_LABEL: Record<string, string> = {
  critical: "Critical",
  high: "High",
  medium: "Medium",
  low: "Low",
  suspect: "Suspect",
  info: "Info",
  "n/a": "N/A",
};

const CONF_ORDER = ["certain", "firm", "tentative", "suspect"] as const;
const CONF_LABEL: Record<string, string> = {
  certain: "Certain",
  firm: "Firm",
  tentative: "Tentative",
  suspect: "Suspect",
};

const METHOD_VARS: Record<string, string> = {
  GET: "var(--m-get)",
  POST: "var(--m-post)",
  PUT: "var(--m-put)",
  PATCH: "var(--m-patch)",
  DELETE: "var(--m-delete)",
  HEAD: "var(--m-head)",
  OPTIONS: "var(--m-options)",
};

// Distinct, theme-aware palette so each content-type chip reads differently.
const CT_PALETTE = [
  "var(--m-post)",
  "var(--m-get)",
  "var(--m-options)",
  "var(--m-patch)",
  "var(--m-put)",
  "var(--sev-suspect)",
  "var(--m-delete)",
  "var(--m-head)",
] as const;

function statusCodeColor(status: string): string {
  switch (status.charAt(0)) {
    case "2": return "var(--v-success)";
    case "3": return "var(--v-info)";
    case "4": return "var(--v-accent-2)";
    case "5": return "var(--v-error)";
    default: return "var(--v-text-muted)";
  }
}

function buildCrossTab(findings: Finding[]) {
  const matrix: Record<string, Record<string, number>> = {};
  for (const sev of SEV_ORDER) {
    matrix[sev] = {};
    for (const conf of CONF_ORDER) matrix[sev][conf] = 0;
  }
  for (const f of findings) {
    const sev = (f.severity || "info").toLowerCase();
    const conf = (f.confidence || "").toLowerCase();
    const s = SEV_ORDER.includes(sev as typeof SEV_ORDER[number]) ? sev : "info";
    const c = conf === "certain" ? "certain" : conf === "firm" ? "firm" : conf === "tentative" ? "tentative" : "suspect";
    matrix[s][c]++;
  }
  return matrix;
}

function formatDate(value?: string): string {
  if (!value) {
    return new Date().toLocaleDateString(undefined, {
      weekday: "long", year: "numeric", month: "long", day: "numeric",
      hour: "2-digit", minute: "2-digit", timeZoneName: "short",
    });
  }
  const parsed = new Date(value);
  if (isNaN(parsed.getTime())) return value;
  return parsed.toLocaleDateString(undefined, {
    weekday: "long", year: "numeric", month: "long", day: "numeric",
    hour: "2-digit", minute: "2-digit", timeZoneName: "short",
  });
}

export default function StatisticsTab({ data, scanDuration, generatedAt, reportTitle, scanTarget, agentName, inputTokens, outputTokens, costUSD, reportSharedURL }: Props) {
  const summary = useMemo(() => {
    const s = computeSummary(data);
    if (scanDuration) s.scanDuration = scanDuration;
    return s;
  }, [data, scanDuration]);

  const counts = useMemo(() => severityCounts(data.findings), [data.findings]);
  const total = data.findings.length;

  const crossTab = useMemo(() => buildCrossTab(data.findings), [data.findings]);

  const modules = useMemo(() => findingsByModule(data.findings).slice(0, 12), [data.findings]);
  const modMax = Math.max(1, ...modules.map((m) => m.count));

  const methods = useMemo(() => httpByMethod(data.httpRecords), [data.httpRecords]);
  const statusCodes = useMemo(() => httpByStatusCodeExact(data.httpRecords), [data.httpRecords]);
  const contentTypes = useMemo(() => httpByContentType(data.httpRecords).slice(0, 8), [data.httpRecords]);
  const methodsTotal = data.httpRecords.length;

  const activeSevs = SEV_ORDER.filter((s) => (counts[s] || 0) > 0);

  return (
    <>
      <Hero
        title="Scan metrics & distributions."
        metaTitle={reportTitle || "Vigolium Scan Report"}
        eyebrow={<><span style={{ background: "var(--v-accent)", color: "var(--v-surface)", padding: "2px 8px" }}>STATISTICS</span><span>METRICS</span></>}
        lede={summary.scanDuration && summary.scanDuration !== "N/A"
          ? `Severity, confidence, and HTTP traffic distribution across the ${summary.scanDuration} sweep window.`
          : "Severity, confidence, and HTTP traffic distribution across the scan window."}
        action={{ label: "Print", icon: "print", onClick: () => window.print() }}
        secondaryAction={{
          label: "Raw Report URL",
          icon: "archive",
          href: reportSharedURL || DEFAULT_REPORT_SHARED_URL,
          highlight: !!reportSharedURL && reportSharedURL !== DEFAULT_REPORT_SHARED_URL,
        }}
        titleBlock={[
          { label: "Generated at", value: formatDate(generatedAt) },
          { label: "Target", value: scanTarget || summary.target },
          { label: "Total Findings", value: String(total) },
          { label: "Duration", value: summary.scanDuration === "N/A" ? <span style={{ color: "darkmagenta" }}>N/A</span> : <span style={{ color: "var(--v-info)" }}>{summary.scanDuration}</span> },
          ...(agentName ? [{ label: "Agent/LLM", value: <span style={{ color: "var(--v-accent)" }}>{agentName}</span> }] : []),
          ...(agentName ? [{
            label: "Tokens",
            value: (() => {
              // copilot-cli: only output tokens are available today.
              // cached and write will auto-populate when the data pipeline provides them
              // (extend HTMLReportMeta + DB query with cachedInputTokens / cacheWriteTokens).
              const isCopilot = agentName.startsWith("copilot");
              const inTok  = isCopilot ? "n/a" : (inputTokens  ?? 0).toLocaleString();
              const cacTok = "n/a"; // cached input tokens — not yet exposed by any agent
              const wrTok  = "n/a"; // cache write tokens  — not yet exposed by any agent
              const outTok = (outputTokens ?? 0).toLocaleString();
              return <span style={{ color: "var(--v-info)" }}>in: {inTok} · cached: {cacTok} · write: {wrTok} · out: {outTok}</span>;
            })()
          }] : []),
          ...(agentName ? [{
            label: "Cost",
            value: (() => {
              const { inputCost, outputCost } = computeCosts(agentName, inputTokens, outputTokens);
              const isCopilot = agentName.startsWith("copilot");
              const inLabel  = isCopilot || inputCost  === undefined ? "n/a" : `~$${inputCost.toFixed(4)}`;
              const cacLabel = "n/a"; // cached input cost — no cached token data yet
              const wrLabel  = "n/a"; // cache write cost  — no cache write token data yet
              const outLabel = outputCost !== undefined ? `~$${outputCost.toFixed(4)}` : (costUSD !== undefined ? `~$${costUSD.toFixed(4)}` : "n/a");
              // Sum all known cost components; grows automatically as more become available
              const knownCosts = [inputCost, outputCost].filter((c): c is number => c !== undefined);
              const totalLabel = knownCosts.length > 0
                ? `~$${knownCosts.reduce((a, b) => a + b, 0).toFixed(4)}`
                : (costUSD !== undefined ? `~$${costUSD.toFixed(4)}` : "n/a");
              return <span style={{ color: "var(--v-info)" }}>in: {inLabel} · cached: {cacLabel} · write: {wrLabel} · out: {outLabel} · <strong>total: {totalLabel}</strong></span>;
            })()
          }] : []),
          { label: "Status", value: <span style={{ color: "var(--v-success)" }}>● COMPLETED</span> },
        ]}
      />

      <div className="stats-grid">
        {/* Donut + legend + severity bar */}
        <div className="card span-6">
          <h3>Severity distribution</h3>
          <div className="donut-wrap" style={{ gap: 20 }}>
            <SeverityDonut counts={counts} size={150} />
            <div className="donut-legend" style={{ flex: 1 }}>
              {SEV_ORDER.map((k) => {
                const v = counts[k] || 0;
                const pct = total ? Math.round((v / total) * 100) : 0;
                return (
                  <div key={k} className="row">
                    <i style={{ background: sevCssVar(k) }} />
                    <span className="lbl">{SEV_LABEL[k]}</span>
                    <span className="val">{v}</span>
                    <span className="pct">{pct}%</span>
                  </div>
                );
              })}
            </div>
          </div>
          <div style={{ marginTop: "auto" }}>
            <div className="severity-bar">
              {SEV_ORDER.map((k) => {
                const v = counts[k] || 0;
                if (!v || !total) return null;
                return <span key={k} style={{ width: `${(v / total) * 100}%`, background: sevCssVar(k) }} />;
              })}
            </div>
          </div>
        </div>

        {/* Severity × Confidence cross-tab */}
        <div className="card span-6">
          <h3>Severity &times; Confidence</h3>
          <div style={{ overflowX: "auto" }}>
            <table className="cross-tab">
              <thead>
                <tr>
                  <th className="cross-tab-corner">
                    <span className="cross-tab-corner-bl">Severity</span>
                    <span className="cross-tab-corner-tr">Confidence</span>
                  </th>
                  {CONF_ORDER.map((c) => (
                    <th key={c}>{CONF_LABEL[c]}</th>
                  ))}
                  <th>Total</th>
                </tr>
              </thead>
              <tbody>
                {SEV_ORDER.map((sev) => {
                  const row = crossTab[sev];
                  const rowTotal = CONF_ORDER.reduce((s, c) => s + (row[c] || 0), 0);
                  return (
                    <tr key={sev}>
                      <td className="cross-tab-sev" style={{ color: sevCssVar(sev) }}>
                        {SEV_LABEL[sev]}
                      </td>
                      {CONF_ORDER.map((c) => {
                        const v = row[c] || 0;
                        const intensity = total > 0 ? Math.min(v / total, 1) : 0;
                        return (
                          <td
                            key={c}
                            className="cross-tab-cell"
                            style={{
                              background: v > 0
                                ? `color-mix(in srgb, ${sevCssVar(sev)} ${Math.max(12, Math.round(intensity * 100 + 15))}%, transparent)`
                                : undefined,
                            }}
                          >
                            {v}
                          </td>
                        );
                      })}
                      <td className="cross-tab-total">{rowTotal}</td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>

        {/* Top modules */}
        <div className="card span-6">
          <h3>Top modules by finding count</h3>
          {modules.length > 0 ? (
            <div className="mod-list">
              {modules.map((m) => (
                <div key={m.module} className="mod-row">
                  <span className="name" title={m.module}>
                    {m.module}
                  </span>
                  <span className="bar">
                    <i style={{ width: `${(m.count / modMax) * 100}%` }} />
                  </span>
                  <span className="n">{m.count}</span>
                </div>
              ))}
            </div>
          ) : (
            <p style={{ color: "var(--v-text-muted)", fontSize: 11 }}>No findings yet.</p>
          )}
        </div>

        {/* HTTP distribution */}
        <div className="card span-6">
          <h3>HTTP distribution</h3>
          {methodsTotal > 0 ? (
            <>
              <div className="dist-block">
                <span className="dist-label">By method</span>
                <div className="method-grid">
                  {methods.map((m) => (
                    <div
                      key={m.method}
                      className="method-chip"
                      style={{ color: METHOD_VARS[m.method] || "var(--v-text-muted)" }}
                    >
                      <span>{m.method}</span>
                      <span className="v">{m.count.toLocaleString()}</span>
                    </div>
                  ))}
                </div>
              </div>

              <div className="dist-block">
                <span className="dist-label">By status code</span>
                <div className="method-grid">
                  {statusCodes.map((s) => (
                    <div
                      key={s.status}
                      className="method-chip"
                      style={{ color: statusCodeColor(s.status) }}
                    >
                      <span>{s.status}</span>
                      <span className="v">{s.count.toLocaleString()}</span>
                    </div>
                  ))}
                </div>
              </div>

              <div className="dist-block">
                <span className="dist-label">By content type</span>
                <div className="ct-list">
                  {contentTypes.map((c, i) => (
                    <div
                      key={c.type}
                      className="method-chip"
                      style={{ color: CT_PALETTE[i % CT_PALETTE.length] }}
                    >
                      <span title={c.type}>{c.type}</span>
                      <span className="v">{c.count.toLocaleString()}</span>
                    </div>
                  ))}
                </div>
              </div>

              <div style={{ marginTop: 12, fontSize: 10, color: "var(--v-text-muted)" }}>
                Across {methodsTotal.toLocaleString()} captured request
                {methodsTotal === 1 ? "" : "s"}
              </div>
            </>
          ) : (
            <p style={{ color: "var(--v-text-muted)", fontSize: 11 }}>
              No HTTP traffic captured.
            </p>
          )}
        </div>
      </div>
    </>
  );
}
