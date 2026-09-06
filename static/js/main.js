document.addEventListener("DOMContentLoaded", () => {
    const dropZone = document.getElementById("dropZone");
    const fileInput = document.getElementById("fileInput");
    const browseBtn = document.getElementById("browseBtn");
    const fileList = document.getElementById("fileList");
    const fileItems = document.getElementById("fileItems");
    const clearFiles = document.getElementById("clearFiles");
    const scanBtn = document.getElementById("scanBtn");
    const scanningSection = document.getElementById("scanningSection");
    const resultsSection = document.getElementById("resultsSection");
    const scanStatus = document.getElementById("scanStatus");
    const progressFill = document.getElementById("progressFill");
    const progressText = document.getElementById("progressText");
    const codeInput = document.getElementById("codeInput");
    const languageSelect = document.getElementById("languageSelect");
    const filenameInput = document.getElementById("filenameInput");
    const downloadReport = document.getElementById("downloadReport");
    const newScan = document.getElementById("newScan");
    const searchFindings = document.getElementById("searchFindings");

    let selectedFiles = [];
    let currentScanId = null;
    let currentFindings = [];

    // Tab switching
    document.querySelectorAll(".tab-btn").forEach(btn => {
        btn.addEventListener("click", () => {
            document.querySelectorAll(".tab-btn").forEach(b => b.classList.remove("active"));
            document.querySelectorAll(".tab-content").forEach(c => c.classList.remove("active"));
            btn.classList.add("active");
            document.getElementById(btn.dataset.tab).classList.add("active");
            updateScanButton();
        });
    });

    // Navigation
    document.querySelectorAll(".nav-link").forEach(link => {
        link.addEventListener("click", (e) => {
            e.preventDefault();
            document.querySelectorAll(".nav-link").forEach(l => l.classList.remove("active"));
            link.classList.add("active");

            const section = link.dataset.section;
            document.querySelectorAll(".hero-section, .upload-section, .results-section, .scanning-section, .about-section, .owasp-section").forEach(s => {
                s.style.display = "none";
            });

            if (section === "scanner") {
                document.querySelector(".hero-section").style.display = "";
                document.querySelector(".upload-section").style.display = "";
                if (resultsSection.dataset.visible === "true") resultsSection.style.display = "";
            } else {
                const el = document.getElementById(section);
                if (el) el.style.display = "";
            }
        });
    });

    // File browsing
    browseBtn.addEventListener("click", () => fileInput.click());
    dropZone.addEventListener("click", (e) => {
        if (e.target === dropZone || e.target.closest(".upload-icon") || e.target.tagName === "H3" || e.target.tagName === "P") {
            fileInput.click();
        }
    });

    // Drag and drop
    dropZone.addEventListener("dragover", (e) => {
        e.preventDefault();
        dropZone.classList.add("dragover");
    });

    dropZone.addEventListener("dragleave", () => {
        dropZone.classList.remove("dragover");
    });

    dropZone.addEventListener("drop", (e) => {
        e.preventDefault();
        dropZone.classList.remove("dragover");
        const files = Array.from(e.dataTransfer.files);
        addFiles(files);
    });

    fileInput.addEventListener("change", () => {
        addFiles(Array.from(fileInput.files));
        fileInput.value = "";
    });

    function addFiles(files) {
        files.forEach(file => {
            const ext = file.name.split(".").pop().toLowerCase();
            const allowed = ["py","js","ts","jsx","tsx","html","java","php","rb","go","cs","yml","yaml","json","env","cfg","conf","ini","txt"];
            if (allowed.includes(ext)) {
                selectedFiles.push(file);
            }
        });
        renderFileList();
        updateScanButton();
    }

    function renderFileList() {
        if (selectedFiles.length === 0) {
            fileList.style.display = "none";
            return;
        }
        fileList.style.display = "";
        fileItems.innerHTML = selectedFiles.map((file, i) => `
            <div class="file-item">
                <div class="file-name">
                    <i class="fas fa-file-code" style="color: var(--accent-primary)"></i>
                    ${escapeHtml(file.name)}
                    <span class="file-ext">${file.name.split(".").pop()}</span>
                </div>
                <div style="display:flex;align-items:center;gap:12px;">
                    <span class="file-size">${formatSize(file.size)}</span>
                    <button class="file-remove" onclick="removeFile(${i})">
                        <i class="fas fa-xmark"></i>
                    </button>
                </div>
            </div>
        `).join("");
    }

    window.removeFile = (index) => {
        selectedFiles.splice(index, 1);
        renderFileList();
        updateScanButton();
    };

    clearFiles.addEventListener("click", () => {
        selectedFiles = [];
        renderFileList();
        updateScanButton();
    });

    function updateScanButton() {
        const activeTab = document.querySelector(".tab-btn.active").dataset.tab;
        if (activeTab === "upload-tab") {
            scanBtn.disabled = selectedFiles.length === 0;
        } else {
            scanBtn.disabled = !codeInput.value.trim();
        }
    }

    codeInput.addEventListener("input", updateScanButton);

    // Scan
    scanBtn.addEventListener("click", async () => {
        const activeTab = document.querySelector(".tab-btn.active").dataset.tab;

        document.querySelector(".hero-section").style.display = "none";
        document.querySelector(".upload-section").style.display = "none";
        resultsSection.style.display = "none";
        scanningSection.style.display = "";

        const statuses = [
            "Initializing security scanners...",
            "Loading detection patterns...",
            "Parsing source code...",
            "Checking for injection vulnerabilities...",
            "Scanning for XSS patterns...",
            "Detecting hardcoded secrets...",
            "Analyzing cryptographic implementations...",
            "Checking security configurations...",
            "Scanning for sensitive data exposure...",
            "Generating security report..."
        ];

        let statusIndex = 0;
        let progress = 0;

        const statusInterval = setInterval(() => {
            statusIndex = Math.min(statusIndex + 1, statuses.length - 1);
            scanStatus.textContent = statuses[statusIndex];
            progress = Math.min(progress + Math.random() * 12 + 3, 90);
            progressFill.style.width = progress + "%";
            progressText.textContent = Math.round(progress) + "%";
        }, 400);

        try {
            let result;
            if (activeTab === "upload-tab") {
                result = await scanFiles();
            } else {
                result = await scanPastedCode();
            }

            clearInterval(statusInterval);
            progressFill.style.width = "100%";
            progressText.textContent = "100%";
            scanStatus.textContent = "Scan complete!";

            setTimeout(() => {
                scanningSection.style.display = "none";
                displayResults(result);
            }, 600);

        } catch (error) {
            clearInterval(statusInterval);
            scanningSection.style.display = "none";
            document.querySelector(".hero-section").style.display = "";
            document.querySelector(".upload-section").style.display = "";
            alert("Scan failed: " + error.message);
        }
    });

    async function scanFiles() {
        const formData = new FormData();
        selectedFiles.forEach(file => formData.append("files", file));

        const response = await fetch("/scan", { method: "POST", body: formData });
        if (!response.ok) {
            const err = await response.json();
            throw new Error(err.error || "Scan failed");
        }
        return response.json();
    }

    async function scanPastedCode() {
        const response = await fetch("/scan-paste", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                code: codeInput.value,
                language: languageSelect.value,
                filename: filenameInput.value || `pasted_code.${languageSelect.value}`
            })
        });
        if (!response.ok) {
            const err = await response.json();
            throw new Error(err.error || "Scan failed");
        }
        return response.json();
    }

    function displayResults(result) {
        currentScanId = result.scan_id;
        currentFindings = result.findings;
        resultsSection.dataset.visible = "true";
        resultsSection.style.display = "";

        document.getElementById("totalFindings").textContent = result.total_findings;
        document.getElementById("criticalCount").textContent = result.critical;
        document.getElementById("highCount").textContent = result.high;
        document.getElementById("mediumCount").textContent = result.medium;
        document.getElementById("lowCount").textContent = result.low;
        document.getElementById("filesScanned").textContent = result.files_scanned;
        document.getElementById("totalLines").textContent = result.total_lines;
        document.getElementById("scanTime").textContent = result.timestamp;

        const riskBadge = document.getElementById("riskBadge");
        riskBadge.textContent = result.risk_level;
        riskBadge.className = "risk-badge " + result.risk_level.toLowerCase();

        const riskFill = document.getElementById("riskMeterFill");
        riskFill.style.left = `calc(${result.risk_score}% - 8px)`;

        renderFindings(result.findings);
        renderLanguageStats(result.language_stats);

        resultsSection.scrollIntoView({ behavior: "smooth" });
    }

    function renderFindings(findings) {
        const container = document.getElementById("findingsList");

        if (findings.length === 0) {
            container.innerHTML = `
                <div class="no-findings">
                    <h3><i class="fas fa-check-circle"></i> No Vulnerabilities Found!</h3>
                    <p>Your code passed all security checks. Keep maintaining secure coding practices.</p>
                </div>`;
            return;
        }

        container.innerHTML = findings.map(f => `
            <div class="finding-card severity-${f.severity}" data-severity="${f.severity}">
                <div class="finding-card-header">
                    <span class="finding-vuln-name">${escapeHtml(f.vulnerability)}</span>
                    <span class="severity-badge ${f.severity}">${f.severity.toUpperCase()}</span>
                </div>
                <div class="finding-meta">
                    <span><i class="fas fa-folder"></i> ${escapeHtml(f.file_path)}</span>
                    <span><i class="fas fa-code"></i> Line ${f.line_number}</span>
                    <span><i class="fas fa-layer-group"></i> ${escapeHtml(f.category)}</span>
                    <span><i class="fas fa-bullseye"></i> ${f.confidence.toUpperCase()} confidence</span>
                </div>
                <div class="finding-code">${escapeHtml(f.line_content.trim())}</div>
                <div class="finding-description">${escapeHtml(f.description)}</div>
                <div class="finding-remediation">
                    <strong><i class="fas fa-lightbulb"></i> Remediation:</strong> ${escapeHtml(f.remediation)}
                </div>
                <div class="finding-refs">
                    ${f.owasp_ref ? `<span class="ref-tag">${escapeHtml(f.owasp_ref)}</span>` : ""}
                    ${f.cwe_id ? `<span class="ref-tag">${escapeHtml(f.cwe_id)}</span>` : ""}
                </div>
            </div>
        `).join("");
    }

    function renderLanguageStats(stats) {
        const card = document.getElementById("langStatsCard");
        const container = document.getElementById("langStats");

        if (!stats || Object.keys(stats).length === 0) {
            card.style.display = "none";
            return;
        }

        card.style.display = "";
        container.innerHTML = Object.entries(stats).map(([lang, count]) => `
            <div class="lang-chip">
                <i class="fas fa-code" style="color: var(--accent-primary)"></i>
                <strong>${escapeHtml(lang)}</strong>
                <span style="color: var(--text-muted)">${count} file(s)</span>
            </div>
        `).join("");
    }

    // Filter findings
    document.querySelectorAll(".filter-btn").forEach(btn => {
        btn.addEventListener("click", () => {
            document.querySelectorAll(".filter-btn").forEach(b => b.classList.remove("active"));
            btn.classList.add("active");

            const filter = btn.dataset.filter;
            if (filter === "all") {
                renderFindings(currentFindings);
            } else {
                renderFindings(currentFindings.filter(f => f.severity === filter));
            }
        });
    });

    // Search findings
    searchFindings.addEventListener("input", () => {
        const query = searchFindings.value.toLowerCase();
        if (!query) {
            renderFindings(currentFindings);
            return;
        }
        const filtered = currentFindings.filter(f =>
            f.vulnerability.toLowerCase().includes(query) ||
            f.description.toLowerCase().includes(query) ||
            f.file_path.toLowerCase().includes(query) ||
            f.category.toLowerCase().includes(query)
        );
        renderFindings(filtered);
    });

    // Download report
    downloadReport.addEventListener("click", () => {
        if (currentScanId) {
            window.location.href = `/report/${currentScanId}`;
        }
    });

    // New scan
    newScan.addEventListener("click", () => {
        resultsSection.style.display = "none";
        resultsSection.dataset.visible = "false";
        document.querySelector(".hero-section").style.display = "";
        document.querySelector(".upload-section").style.display = "";
        selectedFiles = [];
        renderFileList();
        codeInput.value = "";
        filenameInput.value = "";
        updateScanButton();
        currentScanId = null;
        currentFindings = [];

        document.querySelectorAll(".nav-link").forEach(l => l.classList.remove("active"));
        document.querySelector('.nav-link[data-section="scanner"]').classList.add("active");

        window.scrollTo({ top: 0, behavior: "smooth" });
    });

    // Helpers
    function formatSize(bytes) {
        if (bytes < 1024) return bytes + " B";
        if (bytes < 1048576) return (bytes / 1024).toFixed(1) + " KB";
        return (bytes / 1048576).toFixed(1) + " MB";
    }

    function escapeHtml(text) {
        const div = document.createElement("div");
        div.textContent = text;
        return div.innerHTML;
    }
});
