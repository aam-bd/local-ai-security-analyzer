/**
 * Frontend logic for Local AI Security Log Analyzer.
 * Connects to FastAPI backend, consumes Server-Sent Events,
 * and renders interactive incident findings.
 */

document.addEventListener("DOMContentLoaded", () => {
  // UI Elements
  const dropzone = document.getElementById("dropzone");
  const fileInput = document.getElementById("fileInput");
  const loadSampleBtn = document.getElementById("loadSampleBtn");
  const selectedFileLabel = document.getElementById("selectedFileLabel");
  const startAnalysisBtn = document.getElementById("startAnalysisBtn");
  const resumeAnalysisBtn = document.getElementById("resumeAnalysisBtn");
  const reduceCallsCheckbox = document.getElementById("reduceCallsCheckbox");
  const modelSelect = document.getElementById("modelSelect");

  const activeModelLabel = document.getElementById("activeModelLabel");
  const ramProgressBar = document.getElementById("ramProgressBar");
  const ramText = document.getElementById("ramText");

  const metricRam = document.getElementById("metricRam");
  const metricCpu = document.getElementById("metricCpu");
  const metricLatency = document.getElementById("metricLatency");
  const metricTokens = document.getElementById("metricTokens");

  const progressCard = document.getElementById("progressCard");
  const chunkCounter = document.getElementById("chunkCounter");
  const chunkRange = document.getElementById("chunkRange");
  const analysisProgressBar = document.getElementById("analysisProgressBar");
  const progressStatus = document.getElementById("progressStatus");

  const summaryCard = document.getElementById("summaryCard");
  const reportSubtext = document.getElementById("reportSubtext");
  const countCritical = document.getElementById("countCritical");
  const countHigh = document.getElementById("countHigh");
  const countMedium = document.getElementById("countMedium");
  const countLow = document.getElementById("countLow");
  const countTotal = document.getElementById("countTotal");

  const findingsContainer = document.getElementById("findingsContainer");
  const filterChips = document.querySelectorAll(".filter-chip");
  const exportJsonBtn = document.getElementById("exportJsonBtn");
  const exportMdBtn = document.getElementById("exportMdBtn");

  let currentReport = null;
  let activeFilter = "all";

  // 1. Initial Telemetry & Models Fetch
  async function fetchTelemetry() {
    try {
      const resp = await fetch("/api/metrics");
      if (resp.ok) {
        const data = await resp.json();
        metricRam.textContent = `${data.process_ram_mb} MB`;
        metricCpu.textContent = `${data.cpu_percent}%`;
        metricLatency.textContent = `${data.model_inference_ms} ms`;
        metricTokens.textContent = data.total_tokens_processed.toLocaleString();

        ramText.textContent = `${data.process_ram_mb} MB / 4,096 MB`;
        const ramPct = Math.min(100, (data.process_ram_mb / 4096) * 100);
        ramProgressBar.style.width = `${ramPct}%`;

        if (ramPct > 75) {
          ramProgressBar.style.background = "#ef4444";
        } else if (ramPct > 50) {
          ramProgressBar.style.background = "#f59e0b";
        } else {
          ramProgressBar.style.background = "linear-gradient(90deg, #10b981, #3b82f6)";
        }
      }
    } catch (e) {
      console.warn("Telemetry fetch error:", e);
    }
  }

  async function fetchModels() {
    try {
      const resp = await fetch("/api/models");
      if (resp.ok) {
        const data = await resp.json();
        activeModelLabel.textContent = data.active_model;
        modelSelect.value = data.active_backend;
      }
    } catch (e) {
      console.warn("Models fetch error:", e);
    }
  }

  fetchTelemetry();
  fetchModels();
  setInterval(fetchTelemetry, 2500);

  // 2. Model Selection Change
  modelSelect.addEventListener("change", async (e) => {
    const selected = e.target.value;
    try {
      const resp = await fetch(`/api/models/select?backend=${selected}`, { method: "POST" });
      if (resp.ok) {
        const data = await resp.json();
        activeModelLabel.textContent = data.active_model;
      }
    } catch (err) {
      alert("Failed to switch model: " + err.message);
    }
  });

  // 3. File Upload & Ingestion
  dropzone.addEventListener("click", () => fileInput.click());

  dropzone.addEventListener("dragover", (e) => {
    e.preventDefault();
    dropzone.classList.add("dragover");
  });

  dropzone.addEventListener("dragleave", () => dropzone.classList.remove("dragover"));

  dropzone.addEventListener("drop", (e) => {
    e.preventDefault();
    dropzone.classList.remove("dragover");
    if (e.dataTransfer.files.length > 0) {
      handleFileUpload(e.dataTransfer.files[0]);
    }
  });

  fileInput.addEventListener("change", (e) => {
    if (e.target.files.length > 0) {
      handleFileUpload(e.target.files[0]);
    }
  });

  async function handleFileUpload(file) {
    const formData = new FormData();
    formData.append("file", file);

    selectedFileLabel.textContent = `Uploading ${file.name}...`;
    try {
      const resp = await fetch("/api/upload", {
        method: "POST",
        body: formData
      });
      const data = await resp.json();
      if (resp.ok) {
        selectedFileLabel.textContent = `${data.filename} (${(data.size_bytes / 1024).toFixed(1)} KB)`;
      } else {
        alert("Upload error: " + data.detail);
        selectedFileLabel.textContent = "Upload failed.";
      }
    } catch (err) {
      alert("Network error: " + err.message);
      selectedFileLabel.textContent = "Upload error.";
    }
  }

  loadSampleBtn.addEventListener("click", async () => {
    try {
      const resp = await fetch("/api/load-sample", { method: "POST" });
      const data = await resp.json();
      if (resp.ok) {
        selectedFileLabel.textContent = `${data.filename} (${(data.size_bytes / 1024).toFixed(1)} KB)`;
      } else {
        alert("Failed to load sample: " + data.detail);
      }
    } catch (err) {
      alert("Error: " + err.message);
    }
  });

  let lastProcessedChunk = 1;

  // 4. Start Analysis & Stream Server-Sent Events (SSE)
  startAnalysisBtn.addEventListener("click", () => {
    startAnalysis(1);
  });

  if (resumeAnalysisBtn) {
    resumeAnalysisBtn.addEventListener("click", () => {
      startAnalysis(lastProcessedChunk);
    });
  }

  function startAnalysis(fromChunk = 1) {
    startAnalysisBtn.disabled = true;
    startAnalysisBtn.textContent = "⏳ Analyzing Logs...";
    if (resumeAnalysisBtn) resumeAnalysisBtn.style.display = "none";

    progressCard.style.display = "block";
    summaryCard.style.display = "none";
    if (fromChunk === 1) {
      analysisProgressBar.style.width = "0%";
      chunkCounter.textContent = "0/0";
      findingsContainer.innerHTML = '<div class="empty-state"><div class="empty-icon">⚙️</div><p>Processing chunks through local model. Findings will appear dynamically...</p></div>';
    }
    progressStatus.textContent = fromChunk > 1
      ? `Resuming analysis from chunk ${fromChunk}...`
      : "Connecting to streaming analysis pipeline...";

    const reduceCallsParam = reduceCallsCheckbox && reduceCallsCheckbox.checked ? "&reduce_calls=true" : "";
    const eventSource = new EventSource(`/api/analyze/stream?resume_from=${fromChunk}${reduceCallsParam}`);

    eventSource.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data);
        handleStreamEvent(data, eventSource);
      } catch (err) {
        console.error("Error parsing SSE event:", err);
      }
    };

    eventSource.onerror = (err) => {
      console.error("SSE stream error:", err);
      eventSource.close();
      startAnalysisBtn.disabled = false;
      startAnalysisBtn.textContent = "🚀 Start Security Analysis";
      if (resumeAnalysisBtn && lastProcessedChunk > 1) {
        resumeAnalysisBtn.style.display = "inline-flex";
        resumeAnalysisBtn.textContent = `⏯️ Resume from Chunk ${lastProcessedChunk}`;
      }
      progressStatus.textContent = "Stream completed or paused.";
    };
  }

  function handleStreamEvent(data, eventSource) {
    if (data.type === "start") {
      chunkCounter.textContent = `0 / ${data.total_chunks}`;
      progressStatus.textContent = `Analyzing ${data.filename} (${data.total_lines} lines, ${data.total_tokens.toLocaleString()} tokens)...`;
    } else if (data.type === "chunk_progress") {
      lastProcessedChunk = data.chunk_index;
      const pct = Math.round((data.chunk_index / data.total_chunks) * 100);
      analysisProgressBar.style.width = `${pct}%`;
      chunkCounter.textContent = `${data.chunk_index} / ${data.total_chunks}`;
      chunkRange.textContent = `Lines: ${data.start_line} - ${data.end_line}`;

      const skipBadge = data.skipped_call ? " [⚡ Fast-Pathed Benign Chunk]" : "";
      progressStatus.textContent = `Processed chunk ${data.chunk_index} (${data.tokens} tokens) in ${data.inference_time_ms.toFixed(0)} ms.${skipBadge} Active suspects: ${data.active_suspects}.`;

      metricRam.textContent = `${data.ram_mb} MB`;
      metricLatency.textContent = `${data.inference_time_ms.toFixed(0)} ms`;
    } else if (data.type === "complete") {
      eventSource.close();
      startAnalysisBtn.disabled = false;
      startAnalysisBtn.textContent = "🚀 Re-run Security Analysis";
      if (resumeAnalysisBtn) resumeAnalysisBtn.style.display = "none";
      analysisProgressBar.style.width = "100%";
      progressStatus.textContent = `Analysis complete! Unified incident report generated in ${data.report.total_duration_seconds}s.`;

      currentReport = data.report;
      renderReportSummary(data.report);
      renderFindings(data.report.findings);
    }
  }

  // 5. Render Executive Summary & Badges
  function renderReportSummary(report) {
    summaryCard.style.display = "block";
    reportSubtext.textContent = `${report.filename} • ${report.total_lines} lines • ${report.total_chunks} parts • Peak RAM: ${report.peak_ram_mb} MB • Duration: ${report.total_duration_seconds}s`;

    countCritical.textContent = report.summary_counts.Critical || 0;
    countHigh.textContent = report.summary_counts.High || 0;
    countMedium.textContent = report.summary_counts.Medium || 0;
    countLow.textContent = report.summary_counts.Low || 0;
    countTotal.textContent = report.summary_counts.Total || 0;
  }

  // 6. Render Findings
  function renderFindings(findings) {
    if (!findings || findings.length === 0) {
      findingsContainer.innerHTML = '<div class="empty-state"><div class="empty-icon">✅</div><p>No confirmed security attacks found in analyzed logs.</p></div>';
      return;
    }

    const filtered = activeFilter === "all"
      ? findings
      : findings.filter(f => f.severity.toLowerCase() === activeFilter.toLowerCase());

    if (filtered.length === 0) {
      findingsContainer.innerHTML = `<div class="empty-state"><p>No ${activeFilter} severity findings.</p></div>`;
      return;
    }

    findingsContainer.innerHTML = filtered.map(f => {
      const sevClass = `sev-${f.severity.toLowerCase()}`;
      const linesList = f.evidence_lines && f.evidence_lines.length > 0
        ? f.evidence_lines.join(", ")
        : "N/A";

      const evidenceHtml = f.evidence && f.evidence.length > 0
        ? f.evidence.map(e => `
            <div class="evidence-line">
              <span class="evidence-line-num">[L${e.line_number}]</span>
              <span>${escapeHtml(e.raw_snippet)}</span>
            </div>
          `).join("")
        : '<div class="evidence-line">No raw snippets recorded.</div>';

      return `
        <div class="finding-item ${sevClass}">
          <div class="finding-header">
            <div class="finding-title-group">
              <span class="sev-pill ${f.severity.toLowerCase()}">${f.severity}</span>
              <span class="finding-title">${escapeHtml(f.attack_type)}</span>
              <span class="target-badge">Target: ${escapeHtml(f.target_or_id)}</span>
            </div>
            <span class="font-mono text-muted" style="font-size: 0.75rem;">Lines: ${linesList}</span>
          </div>

          <div class="finding-body">
            <p class="finding-reason"><strong>Analysis:</strong> ${escapeHtml(f.reason)}</p>
            <div class="finding-action"><strong>Recommended Action:</strong> ${escapeHtml(f.suggested_action)}</div>
          </div>

          <div class="evidence-drawer">
            <div class="evidence-toggle" onclick="toggleEvidence(this)">
              ▶ Ground-Truth Evidence (${f.evidence.length} log lines)
            </div>
            <div class="evidence-content" style="display: none;">
              ${evidenceHtml}
            </div>
          </div>
        </div>
      `;
    }).join("");
  }

  // Helper: toggle evidence drawer
  window.toggleEvidence = function(el) {
    const content = el.nextElementSibling;
    if (content.style.display === "none") {
      content.style.display = "block";
      el.textContent = el.textContent.replace("▶", "▼");
    } else {
      content.style.display = "none";
      el.textContent = el.textContent.replace("▼", "▶");
    }
  };

  // 7. Severity Filter Chips
  filterChips.forEach(chip => {
    chip.addEventListener("click", () => {
      filterChips.forEach(c => c.classList.remove("active"));
      chip.classList.add("active");
      activeFilter = chip.dataset.filter;
      if (currentReport) {
        renderFindings(currentReport.findings);
      }
    });
  });

  // 8. Export Report JSON & Markdown
  exportJsonBtn.addEventListener("click", () => {
    if (!currentReport) return;
    const blob = new Blob([JSON.stringify(currentReport, null, 2)], { type: "application/json" });
    downloadBlob(blob, `Security_Report_${currentReport.filename}.json`);
  });

  exportMdBtn.addEventListener("click", () => {
    if (!currentReport) return;
    const md = generateMarkdownReport(currentReport);
    const blob = new Blob([md], { type: "text/markdown" });
    downloadBlob(blob, `Security_Report_${currentReport.filename}.md`);
  });

  function downloadBlob(blob, filename) {
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  }

  function generateMarkdownReport(r) {
    let md = `# Security Incident Report: ${r.filename}\n\n`;
    md += `**Total Lines Analyzed**: ${r.total_lines} | **Total Parts**: ${r.total_chunks} | **Duration**: ${r.total_duration_seconds}s | **Peak RAM**: ${r.peak_ram_mb} MB\n`;
    md += `**Model Runtime**: ${r.model_used}\n\n`;
    md += `### Executive Summary\n`;
    md += `- **Critical**: ${r.summary_counts.Critical}\n`;
    md += `- **High**: ${r.summary_counts.High}\n`;
    md += `- **Medium**: ${r.summary_counts.Medium}\n`;
    md += `- **Low**: ${r.summary_counts.Low}\n`;
    md += `- **Total Confirmed Incidents**: ${r.summary_counts.Total}\n\n`;
    md += `## Detailed Findings\n\n`;

    r.findings.forEach((f, idx) => {
      md += `### ${idx + 1}. [${f.severity}] ${f.attack_type}\n`;
      md += `- **Target Entity**: \`${f.target_or_id}\`\n`;
      md += `- **Evidence Lines**: ${f.evidence_lines.join(", ")}\n`;
      md += `- **Reason**: ${f.reason}\n`;
      md += `- **Suggested Mitigation**: ${f.suggested_action}\n\n`;
    });
    return md;
  }

  function escapeHtml(str) {
    if (!str) return "";
    return str.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
  }
});

