const BADGE_STYLES = {
    BLOCKED:  "bg-rose-500/20 text-rose-400 border-rose-500/30",
    CACHED:   "bg-sky-500/20 text-sky-400 border-sky-500/30",
    RESOLVED: "bg-emerald-500/20 text-emerald-400 border-emerald-500/30",
    FAILED:   "bg-amber-500/20 text-amber-400 border-amber-500/30",
};

function pct(part, total) {
    return total > 0 ? Math.round((part / total) * 100) + "%" : "0%";
}

async function get_stats() {
    try {
        const response = await fetch("/api/state");
        const res = await response.json();

        const blocked = res.stats.blocked;
        const cached = res.stats.cached;
        const forwarded = res.stats.resolved;
        const total = res.stats.total;

        // 1. Update counters
        document.getElementById("totalCount").textContent = total;
        document.getElementById("blockedCount").textContent = blocked;
        document.getElementById("cachedCount").textContent = cached;
        document.getElementById("resolvedCount").textContent = forwarded;

        // 2. Update percentages
        document.getElementById("blockedPct").textContent = pct(blocked, total);
        document.getElementById("resolvedPct").textContent = pct(forwarded, total);
        document.getElementById("cachedPct").textContent = pct(cached, total);

        // 3. Update toggle button & stream status
        updateToggleUI(res.blocking_enabled);

        // 4. Render live query stream, blocked domains, and allowlist pills
        renderLogs(res.logs || [], res.blocking_enabled);
        renderBlockedList(res.blocklist || []);
        renderAllowlist(res.allowlist || []);
    } catch (err) {
        console.error("Failed to fetch state:", err);
    }
}

function updateToggleUI(enabled) {
    const toggleBtn = document.getElementById("toggleBtn");
    const dot = document.getElementById("statusDot");
    const streamStatus = document.getElementById("streamStatus");

    if (enabled) {
        toggleBtn.textContent = "Blocking: ON";
        toggleBtn.className = "px-3 py-1.5 rounded-lg text-xs font-semibold bg-emerald-500/20 text-emerald-300 border border-emerald-500/30 hover:bg-emerald-500/30 transition";
        dot.className = "h-3 w-3 rounded-full bg-emerald-400 animate-pulse";
        streamStatus.textContent = "LIVE";
    } else {
        toggleBtn.textContent = "Blocking: PAUSED";
        toggleBtn.className = "px-3 py-1.5 rounded-lg text-xs font-semibold bg-amber-500/20 text-amber-300 border border-amber-500/30 hover:bg-amber-500/30 transition";
        dot.className = "h-3 w-3 rounded-full bg-amber-400";
        streamStatus.textContent = "PAUSED";
    }
}

function renderLogs(logs, blockingEnabled) {
    const feed = document.getElementById("twitchFeed");
    const dimmedClass = blockingEnabled ? "opacity-100" : "opacity-45 grayscale";

    feed.innerHTML = logs.map(l => {
        const badge = BADGE_STYLES[l.action] || "bg-slate-800 text-slate-400";
        return `
            <div class="px-2.5 py-1.5 rounded-lg bg-slate-950/70 border border-slate-800/80 flex items-baseline gap-2 leading-snug ${dimmedClass}">
                <span class="text-slate-500 shrink-0">${l.time}</span>
                <span class="px-1.5 py-0.5 rounded border text-[10px] font-bold shrink-0 ${badge}">${l.action}</span>
                <span class="text-slate-200 truncate" title="${l.domain}">${l.domain}</span>
                <span class="text-slate-500 ml-auto shrink-0">${l.latency_ms}ms</span>
            </div>
        `;
    }).join("");
}

function renderBlockedList(blockedDomains) {
    const listEl = document.getElementById("blockedList");
    document.getElementById("blockedListCount").textContent = `${blockedDomains.length} domains`;

    listEl.innerHTML = blockedDomains.map(domain => `
        <div class="flex items-center justify-between px-3 py-1.5 rounded-lg bg-slate-950/70 border border-slate-800/80">
            <span class="font-mono text-slate-200 truncate" title="${domain}">${domain}</span>
            <button onclick="removeFromBlocklist('${domain}')"
                class="ml-2 px-2 py-0.5 rounded bg-rose-500/15 text-rose-400 hover:bg-rose-500/30 border border-rose-500/30 text-[11px] font-semibold shrink-0 transition">
                Delete
            </button>
        </div>
    `).join("");
}

function renderAllowlist(allowedDomains) {
    const pillsEl = document.getElementById("allowlistPills");
    if (!pillsEl) return;

    pillsEl.innerHTML = allowedDomains.map(domain => `
        <span class="inline-flex items-center gap-1 px-2 py-0.5 rounded bg-sky-500/15 text-sky-300 border border-sky-500/25 text-[11px]">
            ${domain}
            <button onclick="removeFromAllowlist('${domain}')" class="hover:text-white font-bold">×</button>
        </span>
    `).join("");
}

// --- API Actions ---

async function addToBlocklist(domain) {
    if (!domain) return;
    await fetch("/api/block", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ domain })
    });
    get_stats();
}

async function removeFromBlocklist(domain) {
    await fetch(`/api/block/${encodeURIComponent(domain)}`, {
        method: "DELETE"
    });
    get_stats();
}

async function addToAllowlist(domain) {
    if (!domain) return;
    await fetch("/api/allow", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ domain })
    });
    get_stats();
}

async function removeFromAllowlist(domain) {
    await fetch(`/api/allow/${encodeURIComponent(domain)}`, {
        method: "DELETE"
    });
    get_stats();
}

async function toggleBlocking() {
    await fetch("/api/toggle", { method: "POST" });
    get_stats();
}

async function clearCache() {
    await fetch("/api/cache/clear", { method: "POST" });
    get_stats();
}

// --- Event Listeners ---

const binp = document.getElementById("blockInput");
const bbtn = document.getElementById("blockBtn");

bbtn.addEventListener("click", () => {
    addToBlocklist(binp.value.trim());
    binp.value = "";
});

binp.addEventListener("keydown", (e) => {
    if (e.key === "Enter") {
        addToBlocklist(binp.value.trim());
        binp.value = "";
    }
});

const ainp = document.getElementById("allowInput");
const abtn = document.getElementById("allowBtn");

abtn.addEventListener("click", () => {
    addToAllowlist(ainp.value.trim());
    ainp.value = "";
});

ainp.addEventListener("keydown", (e) => {
    if (e.key === "Enter") {
        addToAllowlist(ainp.value.trim());
        ainp.value = "";
    }
});

document.getElementById("toggleBtn").addEventListener("click", toggleBlocking);
document.getElementById("clearCacheBtn").addEventListener("click", clearCache);

// --- Start Polling ---
get_stats();
setInterval(get_stats, 1500);