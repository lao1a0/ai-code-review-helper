function getCookie(name) {
    const parts = document.cookie.split(';').map(v => v.trim());
    for (const p of parts) {
        if (p.startsWith(name + '=')) return decodeURIComponent(p.substring(name.length + 1));
    }
    return null;
}

function setCookie(name, value, days) {
    const d = new Date();
    d.setTime(d.getTime() + (days * 24 * 60 * 60 * 1000));
    const expires = "expires=" + d.toUTCString();
    document.cookie = `${name}=${encodeURIComponent(value)};${expires};path=/;SameSite=Lax`;
}

function apiKey() {
    return getCookie('ADMIN_API_KEY');
}

function showStatus(text, isError = false) {
    const box = document.getElementById('globalStatus');
    box.hidden = false;
    box.textContent = text;
    box.className = isError ? 'status error' : 'status ok';
    window.setTimeout(() => {
        box.hidden = true;
    }, 3500);
}

async function apiFetch(url, options = {}) {
    const headers = Object.assign({}, options.headers || {});
    const k = apiKey();
    if (k) headers['X-Admin-API-Key'] = k;
    if (!headers['Content-Type'] && options.body) headers['Content-Type'] = 'application/json';

    const resp = await fetch(url, Object.assign({}, options, { headers }));
    const text = await resp.text();
    let data = null;
    try { data = text ? JSON.parse(text) : null; } catch { data = { raw: text }; }
    if (!resp.ok) {
        const msg = (data && data.error) ? data.error : `HTTP ${resp.status}`;
        throw new Error(msg);
    }
    return data;
}

const MODAL_STACK = [];

function _applyModalZ() {
    const base = 1000;
    MODAL_STACK.forEach((it, i) => {
        const zBackdrop = base + i * 2;
        const zModal = base + i * 2 + 1;
        it.backdrop.style.zIndex = String(zBackdrop);
        it.modal.style.zIndex = String(zModal);
    });
    document.body.style.overflow = MODAL_STACK.length ? 'hidden' : '';
}

function _removeFromStack(backdropId, modalId) {
    const idx = MODAL_STACK.findIndex(it => it.backdropId === backdropId && it.modalId === modalId);
    if (idx >= 0) MODAL_STACK.splice(idx, 1);
}

function openModal(backdropId, modalId, opts = {}) {
    const backdrop = document.getElementById(backdropId);
    const modal = document.getElementById(modalId);
    if (!backdrop || !modal) return;

    // Avoid "double open" entries.
    _removeFromStack(backdropId, modalId);

    if (opts.closeOthers) {
        // Close all other modals first to prevent accidental overlay blocks.
        for (const it of [...MODAL_STACK].reverse()) {
            it.backdrop.hidden = true;
            it.modal.hidden = true;
        }
        MODAL_STACK.length = 0;
    }

    backdrop.hidden = false;
    modal.hidden = false;

    MODAL_STACK.push({ backdropId, modalId, backdrop, modal });
    _applyModalZ();
}

function closeModal(backdropId, modalId) {
    const backdrop = document.getElementById(backdropId);
    const modal = document.getElementById(modalId);
    if (backdrop) backdrop.hidden = true;
    if (modal) modal.hidden = true;
    _removeFromStack(backdropId, modalId);
    _applyModalZ();
}

function closeTopModal() {
    const top = MODAL_STACK[MODAL_STACK.length - 1];
    if (!top) return;
    closeModal(top.backdropId, top.modalId);
}

function renderTags(container, tags, opts = {}) {
    container.innerHTML = '';
    (tags || []).forEach(t => {
        const span = document.createElement('span');
        span.className = 'tag ' + (opts.className || '');
        span.textContent = String(t);
        container.appendChild(span);
    });
}

function toMermaid(graph) {
    const nodes = graph.nodes || [];
    const edges = graph.edges || [];

    const labels = {};
    for (const n of nodes) labels[n.id] = n.label || n.id;

    let out = 'graph TD\n';
    for (const e of edges) {
        const from = e.from;
        const to = e.to;
        if (!from || !to) continue;
        const fromLabel = labels[from] || from;
        const toLabel = labels[to] || to;
        out += `  ${sanitizeId(from)}["${escapeMermaid(fromLabel)}"] --> ${sanitizeId(to)}["${escapeMermaid(toLabel)}"]\n`;
    }
    if (edges.length === 0) out += '  A["No call edges found in diff context"]\n';
    return out;
}

function sanitizeId(s) {
    return String(s).replaceAll(':', '_').replaceAll('/', '_').replaceAll('.', '_').replaceAll('-', '_');
}

function escapeMermaid(s) {
    return String(s).replaceAll('"', '\\"');
}

let SKILLS = [];
let AGENT_SETTINGS = {};
let CURRENT_REVIEW_KEY = null; // {vcs_type, identifier, pr_mr_id}

async function loadSkills() {
    const data = await apiFetch('/api/skills');
    SKILLS = data.skills || [];
    return SKILLS;
}

function selectedSkillNames(pickerEl) {
    const names = [];
    pickerEl.querySelectorAll('input[type=checkbox][data-skill]').forEach(cb => {
        if (cb.checked) names.push(cb.getAttribute('data-skill'));
    });
    return names;
}

function renderSkillPicker(pickerEl, selectedNames = []) {
    pickerEl.innerHTML = '';
    for (const s of SKILLS) {
        const wrap = document.createElement('label');
        wrap.className = 'skill-item';

        const cb = document.createElement('input');
        cb.type = 'checkbox';
        cb.setAttribute('data-skill', s.name);
        cb.checked = selectedNames.includes(s.name);

        const name = document.createElement('div');
        name.textContent = s.name;

        const meta = document.createElement('div');
        meta.className = 'meta';
        meta.textContent = (s.version ? `v${s.version}` : '');

        wrap.appendChild(cb);
        wrap.appendChild(name);
        wrap.appendChild(meta);
        pickerEl.appendChild(wrap);
    }
}

async function loadPrompts() {
    const data = await apiFetch('/api/prompts');
    const sel = document.getElementById('promptTemplate');
    sel.innerHTML = '';
    (data.templates || []).forEach(t => {
        const opt = document.createElement('option');
        opt.value = t;
        opt.textContent = t;
        sel.appendChild(opt);
    });
}

async function loadAgentSettings() {
    const data = await apiFetch('/api/agent/settings');
    AGENT_SETTINGS = data.settings || {};
    return AGENT_SETTINGS;
}

function fillAgentSettingsToUI() {
    const rag = AGENT_SETTINGS.rag || {};
    const ragSources = rag.sources || {};
    const call = rag.call_chain || {};
    const prompt = AGENT_SETTINGS.prompt || {};

    document.getElementById('ragEnabled').checked = !!rag.enabled;
    document.getElementById('ragSourceCode').checked = (ragSources.code !== false);
    document.getElementById('ragSourceDocs').checked = !!ragSources.docs;
    document.getElementById('ragSourceDeps').checked = !!ragSources.deps;

    document.getElementById('callChainEnabled').checked = !!call.enabled;
    document.getElementById('callChainDepth').value = call.max_depth || 3;
    document.getElementById('callChainCrossFile').checked = !!call.cross_file;
    document.getElementById('callChainParser').value = call.parser || 'python';

    document.getElementById('promptInjectSkillNames').checked = prompt.inject_skill_names !== false;
    document.getElementById('promptOnDemandSkillRead').checked = prompt.skill_doc_mode !== 'always';

    if (prompt.template) document.getElementById('promptTemplate').value = prompt.template;
}

async function saveAgentSettingsFromUI() {
    const picker = document.getElementById('skillPicker');
    const skillsEnabled = selectedSkillNames(picker);

    const payload = {
        skills_enabled: skillsEnabled,
        rag: {
            enabled: document.getElementById('ragEnabled').checked,
            sources: {
                code: document.getElementById('ragSourceCode').checked,
                docs: document.getElementById('ragSourceDocs').checked,
                deps: document.getElementById('ragSourceDeps').checked,
            },
            call_chain: {
                enabled: document.getElementById('callChainEnabled').checked,
                max_depth: Number(document.getElementById('callChainDepth').value || 3),
                cross_file: document.getElementById('callChainCrossFile').checked,
                parser: document.getElementById('callChainParser').value,
            }
        },
        prompt: {
            template: document.getElementById('promptTemplate').value || '',
            inject_skill_names: document.getElementById('promptInjectSkillNames').checked,
            skill_doc_mode: document.getElementById('promptOnDemandSkillRead').checked ? 'on_demand' : 'always',
        }
    };
    const data = await apiFetch('/api/agent/settings', { method: 'POST', body: JSON.stringify(payload) });
    AGENT_SETTINGS = data.settings || {};
    showStatus('已保存 Agent 设置');
}

function addAgentChat(role, text) {
    const box = document.getElementById('agentChatMessages');
    const row = document.createElement('div');
    row.className = 'chat-msg ' + role;
    const r = document.createElement('div');
    r.className = 'role';
    r.textContent = role === 'user' ? 'You' : 'Agent';
    const b = document.createElement('div');
    b.className = 'bubble';
    b.textContent = text || '';
    row.appendChild(r);
    row.appendChild(b);
    box.appendChild(row);
    box.scrollTop = box.scrollHeight;
}

async function sendAgentChat() {
    const input = document.getElementById('agentChatInput');
    const msg = (input.value || '').trim();
    if (!msg) return;
    input.value = '';
    addAgentChat('user', msg);
    try {
        const data = await apiFetch('/api/agent/chat', { method: 'POST', body: JSON.stringify({ message: msg }) });
        addAgentChat('assistant', data.reply || '');
    } catch (e) {
        addAgentChat('assistant', `请求失败：${e.message}`);
    }
}

function switchPage(page) {
    document.querySelectorAll('.nav-item').forEach(b => b.classList.toggle('active', b.getAttribute('data-page') === page));
    document.querySelectorAll('.page').forEach(p => p.classList.toggle('active', p.getAttribute('data-page') === page));
}

async function loadReviews() {
    const data = await apiFetch('/api/reviews/list?include_stats=1');
    const items = data.reviews || [];
    window.__REVIEWS = items;
    renderReviewsTable();
}

function reviewRowTagList(skillHits, riskLevel, ragSources) {
    const out = [];
    (skillHits || []).slice(0, 3).forEach(s => out.push(s));
    if (riskLevel) out.unshift(riskLevel);
    if (ragSources && ragSources.length) out.push(...ragSources.slice(0, 2));
    return out;
}

function renderReviewsTable() {
    const tbody = document.querySelector('#reviewsTable tbody');
    tbody.innerHTML = '';

    const q = (document.getElementById('reviewSearch').value || '').toLowerCase().trim();
    const risk = document.getElementById('filterRisk').value;
    const skill = document.getElementById('filterSkill').value;
    const rag = document.getElementById('filterRag').value;

    const items = (window.__REVIEWS || []).filter(rw => {
        if (risk && (rw.risk_level || '') !== risk) return false;
        if (skill && !(rw.skill_hits || []).includes(skill)) return false;
        if (rag) {
            const list = rw.rag_sources || [];
            if (!list.includes(rag)) return false;
        }
        if (!q) return true;
        const blob = [
            rw.display_name, rw.identifier, rw.pr_mr_id, rw.vcs_type,
            ...(rw.files || []),
            ...(rw.skill_hits || [])
        ].filter(Boolean).join(' ').toLowerCase();
        return blob.includes(q);
    });

    for (const rw of items) {
        const tr = document.createElement('tr');
        tr.style.cursor = 'pointer';
        tr.addEventListener('click', () => openReviewDetail(rw.vcs_type, rw.identifier, String(rw.pr_mr_id || '')));

        const files = (rw.files || []).slice(0, 3).join('\n');
        const fileMore = (rw.files || []).length > 3 ? `\n... +${(rw.files || []).length - 3}` : '';

        const td0 = document.createElement('td');
        td0.textContent = `${rw.vcs_type}:${rw.pr_mr_id}`;
        const td1 = document.createElement('td');
        td1.textContent = rw.display_name || rw.identifier;
        const td2 = document.createElement('td');
        td2.textContent = rw.risk_level || 'UNKNOWN';
        const td3 = document.createElement('td');
        td3.textContent = files + fileMore;
        const td4 = document.createElement('td');
        td4.textContent = (rw.skill_hits || []).join(', ');
        const td5 = document.createElement('td');
        td5.textContent = (rw.rag_sources || []).join(', ') || 'code_context';
        const td6 = document.createElement('td');
        td6.textContent = rw.created_at || '';

        tr.appendChild(td0);
        tr.appendChild(td1);
        tr.appendChild(td2);
        tr.appendChild(td3);
        tr.appendChild(td4);
        tr.appendChild(td5);
        tr.appendChild(td6);
        tbody.appendChild(tr);
    }
}

async function loadProjects() {
    const data = await apiFetch('/api/projects');
    window.__PROJECTS = data.projects || [];
    renderProjectsTable();
}

async function loadMembers() {
    const data = await apiFetch('/api/users');
    window.__USERS = data.users || [];
    renderMembersTable();
}

function renderMembersTable() {
    const tbody = document.querySelector('#membersTable tbody');
    if (!tbody) return;
    tbody.innerHTML = '';
    for (const u of (window.__USERS || [])) {
        const tr = document.createElement('tr');
        tr.innerHTML = `
            <td>${u.id || ''}</td>
            <td>${u.username || ''}</td>
            <td>${u.nickname || ''}</td>
            <td>${u.llm_type || ''}</td>
            <td>${u.llm_url || ''}</td>
            <td>${u.created_at || ''}</td>
            <td>${u.updated_at || ''}</td>
        `;
        tbody.appendChild(tr);
    }
}

function renderProjectsTable() {
    const tbody = document.querySelector('#projectsTable tbody');
    tbody.innerHTML = "";
    for (const p of (window.__PROJECTS || [])) {
        const tr = document.createElement('tr');
        tr.innerHTML = `
            <td>${p.name || ""}</td>
            <td>${p.platform || ""}</td>
            <td>${p.repo_url || ""}</td>
            <td>${p.project_key || ""}</td>
            <td>${p.is_active ? "yes" : "no"}</td>
            <td>${p.created_at || ""}</td>
        `;
        tbody.appendChild(tr);
    }
}
async function openReviewDetail(vcsType, identifier, prMrId) {
    CURRENT_REVIEW_KEY = { vcs_type: vcsType, identifier, pr_mr_id: prMrId };
    document.getElementById('reviewModalTitle').textContent = `审查详情：${vcsType}:${identifier}#${prMrId}`;
    document.getElementById('callGraphPre').textContent = '加载中...';
    document.getElementById('reviewRawPre').textContent = '';
    document.getElementById('skillHitsBox').innerHTML = '';
    openModal('reviewBackdrop', 'reviewModal', { closeOthers: true });

    const detail = await apiFetch(`/api/reviews/${encodeURIComponent(vcsType)}/${encodeURIComponent(identifier)}/${encodeURIComponent(prMrId)}`);
    document.getElementById('reviewRawPre').textContent = JSON.stringify(detail.reviews_by_commit || {}, null, 2);

    const hits = detail.skill_hits || [];
    const box = document.getElementById('skillHitsBox');
    box.innerHTML = '';
    hits.forEach(name => {
        const t = document.createElement('span');
        t.className = 'tag accent';
        t.textContent = name;
        t.style.cursor = 'pointer';
        t.title = '点击查看 Skill 文档';
        t.addEventListener('click', async (e) => {
            e.stopPropagation();
            try {
                const data = await apiFetch(`/api/skills/${encodeURIComponent(name)}`);
                document.getElementById('skillModalTitle').textContent = name;
                document.getElementById('skillDoc').textContent = data.doc || '';
                openModal('skillBackdrop', 'skillModal');
            } catch (err) {
                showStatus(`读取 Skill 失败：${err.message}`, true);
            }
        });
        box.appendChild(t);
    });

    await rebuildCallGraph();
}

async function rebuildCallGraph() {
    if (!CURRENT_REVIEW_KEY) return;
    const pre = document.getElementById('callGraphPre');
    pre.textContent = '构建中...';

    const options = (AGENT_SETTINGS.rag && AGENT_SETTINGS.rag.call_chain) ? AGENT_SETTINGS.rag.call_chain : {};
    const payload = {
        vcs_type: CURRENT_REVIEW_KEY.vcs_type,
        identifier: CURRENT_REVIEW_KEY.identifier,
        pr_mr_id: CURRENT_REVIEW_KEY.pr_mr_id,
        options: {
            max_depth: options.max_depth || 3,
            cross_file: !!options.cross_file,
            parser: options.parser || 'python',
        }
    };

    try {
        const data = await apiFetch('/api/rag/call_graph', { method: 'POST', body: JSON.stringify(payload) });
        const graph = data.graph || {};
        pre.textContent = toMermaid(graph) + '\n\n' + (graph.note || '');
    } catch (e) {
        pre.textContent = `调用链构建失败：${e.message}`;
    }
}

async function loadLogs() {
    const data = await apiFetch('/api/logs?limit=200');
    const tbody = document.querySelector('#logsTable tbody');
    tbody.innerHTML = '';
    for (const ev of (data.events || [])) {
        const tr = document.createElement('tr');
        tr.innerHTML = `
            <td>${ev.ts || ''}</td>
            <td>${ev.level || ''}</td>
            <td>${ev.type || ''}</td>
            <td>${(ev.message || '').toString()}</td>
            <td><pre style="margin:0;white-space:pre-wrap">${JSON.stringify(ev.meta || {}, null, 2)}</pre></td>
        `;
        tbody.appendChild(tr);
    }
}

async function loadGlobalSettingsIntoUI() {
    const cfg = await apiFetch('/config/global_settings');
    document.getElementById('cfgOpenaiBaseUrl').value = cfg.OPENAI_API_BASE_URL || '';
    document.getElementById('cfgOpenaiModel').value = cfg.OPENAI_MODEL || '';
    document.getElementById('cfgTemp').value = cfg.LLM_TEMPERATURE ?? '';
    document.getElementById('cfgMaxCtx').value = cfg.LLM_MAX_CONTEXT_TOKENS ?? '';
    document.getElementById('cfgToolPolicy').value = cfg.TOOL_CALL_POLICY || 'auto';
    document.getElementById('cfgRagPolicy').value = cfg.RAG_TRIGGER_POLICY || 'on_demand';
    document.getElementById('cfgSkillPolicy').value = cfg.SKILL_READ_POLICY || 'on_demand';

    document.getElementById('cfgWecomUrl').value = cfg.WECOM_BOT_WEBHOOK_URL || '';
    document.getElementById('cfgCustomWebhookUrl').value = cfg.CUSTOM_WEBHOOK_URL || '';
    document.getElementById('cfgNotifyTemplate').value = cfg.NOTIFY_TEMPLATE || '';
}

async function saveGlobalSettingsFromUI() {
    const payload = {
        OPENAI_API_BASE_URL: document.getElementById('cfgOpenaiBaseUrl').value,
        OPENAI_MODEL: document.getElementById('cfgOpenaiModel').value,
        LLM_TEMPERATURE: document.getElementById('cfgTemp').value,
        LLM_MAX_CONTEXT_TOKENS: document.getElementById('cfgMaxCtx').value,
        TOOL_CALL_POLICY: document.getElementById('cfgToolPolicy').value,
        RAG_TRIGGER_POLICY: document.getElementById('cfgRagPolicy').value,
        SKILL_READ_POLICY: document.getElementById('cfgSkillPolicy').value,
        WECOM_BOT_WEBHOOK_URL: document.getElementById('cfgWecomUrl').value,
        CUSTOM_WEBHOOK_URL: document.getElementById('cfgCustomWebhookUrl').value,
        NOTIFY_TEMPLATE: document.getElementById('cfgNotifyTemplate').value,
    };
    await apiFetch('/config/global_settings', { method: 'POST', body: JSON.stringify(payload) });
    showStatus('已保存全局配置');
}

async function ensureAdminKey() {
    if (apiKey()) return true;
    openModal('keyBackdrop', 'keyModal', { closeOthers: true });
    return false;
}

async function init() {
    // Nav
    document.querySelectorAll('.nav-item').forEach(btn => {
        btn.addEventListener('click', async () => {
            const page = btn.getAttribute('data-page');
            switchPage(page);
            // Lazy load per page.
            if (page === 'reviews') await loadReviews();
            if (page === 'projects') await loadProjects();
            if (page === 'members') await loadMembers();
            if (page === 'logs') await loadLogs();
            if (page === 'llm' || page === 'notify') await loadGlobalSettingsIntoUI();
        });
    });

    // Modals: Admin key
    document.getElementById('btnSetKey').addEventListener('click', () => openModal('keyBackdrop', 'keyModal', { closeOthers: true }));
    document.getElementById('btnCloseKey').addEventListener('click', () => closeModal('keyBackdrop', 'keyModal'));
    document.getElementById('keyBackdrop').addEventListener('click', () => closeModal('keyBackdrop', 'keyModal'));
    document.getElementById('btnSaveKey').addEventListener('click', () => {
        const v = (document.getElementById('adminKeyInput').value || '').trim();
        if (!v) return;
        setCookie('ADMIN_API_KEY', v, 7);
        closeModal('keyBackdrop', 'keyModal');
        showStatus('已保存 Admin Key');
    });
    document.getElementById('btnClearKey').addEventListener('click', () => {
        setCookie('ADMIN_API_KEY', '', -1);
        document.getElementById('adminKeyInput').value = '';
        showStatus('已清除 Admin Key');
    });

    // Skill modal
    document.getElementById('btnCloseSkill').addEventListener('click', () => closeModal('skillBackdrop', 'skillModal'));
    document.getElementById('skillBackdrop').addEventListener('click', () => closeModal('skillBackdrop', 'skillModal'));

    // Project modal

    // Review modal
    document.getElementById('btnCloseReview').addEventListener('click', () => closeModal('reviewBackdrop', 'reviewModal'));
    document.getElementById('reviewBackdrop').addEventListener('click', () => closeModal('reviewBackdrop', 'reviewModal'));
    document.getElementById('btnRebuildCallGraph').addEventListener('click', rebuildCallGraph);

    // Dashboard actions
    document.getElementById('btnAgentChatSend').addEventListener('click', sendAgentChat);
    document.getElementById('agentChatInput').addEventListener('keydown', (e) => {
        if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); sendAgentChat(); }
    });
    document.getElementById('btnSaveAgentSettings').addEventListener('click', saveAgentSettingsFromUI);
    document.getElementById('btnSkillsRefresh').addEventListener('click', async () => {
        await loadSkills();
        renderSkillPicker(document.getElementById('skillPicker'), (AGENT_SETTINGS.skills_enabled || []));
        showStatus('已刷新 Skills');
        fillSkillFilterOptions();
    });
    document.getElementById('btnSkillRead').addEventListener('click', async () => {
        const picker = document.getElementById('skillPicker');
        const names = selectedSkillNames(picker);
        if (!names.length) return showStatus('请选择一个 Skill', true);
        const name = names[0];
        const data = await apiFetch(`/api/skills/${encodeURIComponent(name)}`);
        document.getElementById('skillModalTitle').textContent = name;
        document.getElementById('skillDoc').textContent = data.doc || '';
        openModal('skillBackdrop', 'skillModal');
    });
    document.getElementById('btnPromptsRefresh').addEventListener('click', async () => {
        await loadPrompts();
        showStatus('已刷新模板列表');
    });
    document.getElementById('btnReloadDashboard').addEventListener('click', async () => {
        await bootstrapDashboard();
        showStatus('Dashboard 已刷新');
    });

    // Reviews
    document.getElementById('btnReloadReviews').addEventListener('click', loadReviews);
    document.getElementById('reviewSearch').addEventListener('input', renderReviewsTable);
    document.getElementById('filterRisk').addEventListener('change', renderReviewsTable);
    document.getElementById('filterSkill').addEventListener('change', renderReviewsTable);
    document.getElementById('filterRag').addEventListener('change', renderReviewsTable);

    // Projects
    document.getElementById('btnReloadProjects').addEventListener('click', loadProjects);

    // Members
    document.getElementById('btnReloadMembers').addEventListener('click', loadMembers);

    // LLM / Notify
    document.getElementById('btnReloadLlm').addEventListener('click', loadGlobalSettingsIntoUI);
    document.getElementById('btnSaveLlm').addEventListener('click', saveGlobalSettingsFromUI);
    document.getElementById('btnReloadNotify').addEventListener('click', loadGlobalSettingsIntoUI);
    document.getElementById('btnSaveNotify').addEventListener('click', saveGlobalSettingsFromUI);

    // Logs
    document.getElementById('btnReloadLogs').addEventListener('click', loadLogs);
    document.getElementById('btnClearLogs').addEventListener('click', async () => {
        await apiFetch('/api/logs/clear', { method: 'POST', body: '{}' });
        await loadLogs();
        showStatus('已清空日志');
    });

    await ensureAdminKey();
    await bootstrapDashboard();
}

function fillSkillFilterOptions() {
    const sel = document.getElementById('filterSkill');
    const existing = new Set();
    Array.from(sel.options).forEach(o => existing.add(o.value));
    for (const s of SKILLS) {
        if (existing.has(s.name)) continue;
        const opt = document.createElement('option');
        opt.value = s.name;
        opt.textContent = s.name;
        sel.appendChild(opt);
    }
}

async function bootstrapDashboard() {
    try {
        await loadSkills();
        await loadPrompts();
        await loadAgentSettings();
        renderSkillPicker(document.getElementById('skillPicker'), AGENT_SETTINGS.skills_enabled || []);
        fillAgentSettingsToUI();
        fillSkillFilterOptions();
    } catch (e) {
        showStatus(`加载失败：${e.message}`, true);
    }
}

document.addEventListener('DOMContentLoaded', init);

document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') {
        closeTopModal();
    }
});
