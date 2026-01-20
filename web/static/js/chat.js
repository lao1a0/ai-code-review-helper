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
    document.cookie = `${name}=${encodeURIComponent(value)};${expires};path=/`;
}

function escapeHtml(s) {
    return s
        .replaceAll('&', '&amp;')
        .replaceAll('<', '&lt;')
        .replaceAll('>', '&gt;')
        .replaceAll('"', '&quot;')
        .replaceAll("'", '&#039;');
}

function addMessage(role, text) {
    const messages = document.getElementById('messages');
    const row = document.createElement('div');
    row.className = `msg-row ${role}`;
    const bubble = document.createElement('div');
    bubble.className = 'bubble';
    bubble.innerHTML = escapeHtml(text || '');
    row.appendChild(bubble);
    messages.appendChild(row);
    messages.scrollTop = messages.scrollHeight;
}

function autoResize(textarea) {
    textarea.style.height = 'auto';
    textarea.style.height = Math.min(textarea.scrollHeight, 180) + 'px';
}

function openModal() {
    document.getElementById('modalBackdrop').hidden = false;
    document.getElementById('modal').hidden = false;
    const v = getCookie('ADMIN_API_KEY') || '';
    const input = document.getElementById('adminKey');
    input.value = v;
    input.focus();
}

function closeModal() {
    document.getElementById('modalBackdrop').hidden = true;
    document.getElementById('modal').hidden = true;
}

async function sendMessage() {
    const input = document.getElementById('input');
    const text = (input.value || '').trim();
    if (!text) return;

    addMessage('user', text);
    input.value = '';
    autoResize(input);

    try {
        const resp = await fetch('/api/agent/chat', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ message: text }),
        });

        if (resp.status === 401) {
            addMessage('assistant', '需要 Admin API Key 才能操作配置。点击右上角“设置”填写后再试。');
            return;
        }

        const data = await resp.json();
        if (!resp.ok) {
            addMessage('assistant', data && data.error ? String(data.error) : `请求失败 (${resp.status})`);
            return;
        }
        addMessage('assistant', data.reply || '');
    } catch (e) {
        addMessage('assistant', '网络或服务异常，请检查服务是否启动。');
    }
}

document.addEventListener('DOMContentLoaded', () => {
    const input = document.getElementById('input');
    const send = document.getElementById('send');

    addMessage('assistant',
        '我可以用对话帮你配置 GitHub / GitLab 仓库。\n\n' +
        '你可以直接输入：\n' +
        '- 列出 GitHub 仓库\n' +
        '- 添加 GitHub：owner/repo secret=xxx token=yyy\n' +
        '- 删除 GitHub：owner/repo\n' +
        '- 列出 GitLab 项目\n' +
        '- 添加 GitLab：project_id=123 secret=xxx token=yyy (instance_url 可选)\n' +
        '- 删除 GitLab：project_id=123\n\n' +
        '也可以发送 JSON（更稳定）：\n' +
        '{\"action\":\"github_add\",\"repo_full_name\":\"owner/repo\",\"secret\":\"xxx\",\"token\":\"yyy\"}'
    );

    input.addEventListener('input', () => autoResize(input));
    autoResize(input);

    input.addEventListener('keydown', (e) => {
        if (e.key === 'Enter' && !e.shiftKey) {
            e.preventDefault();
            sendMessage();
        }
    });
    send.addEventListener('click', sendMessage);

    document.getElementById('chips').addEventListener('click', (e) => {
        const btn = e.target.closest('button[data-fill]');
        if (!btn) return;
        input.value = btn.getAttribute('data-fill') || '';
        input.focus();
        autoResize(input);
    });

    document.getElementById('btnSettings').addEventListener('click', openModal);
    document.getElementById('btnClose').addEventListener('click', closeModal);
    document.getElementById('modalBackdrop').addEventListener('click', closeModal);

    document.getElementById('btnSaveKey').addEventListener('click', () => {
        const v = (document.getElementById('adminKey').value || '').trim();
        if (!v) return;
        setCookie('ADMIN_API_KEY', v, 7);
        closeModal();
        addMessage('assistant', '已保存 Admin API Key。你现在可以开始配置。');
    });

    document.getElementById('btnClearKey').addEventListener('click', () => {
        setCookie('ADMIN_API_KEY', '', -1);
        document.getElementById('adminKey').value = '';
        addMessage('assistant', '已清除 Admin API Key。');
    });

    // Prompt once if key not set.
    if (!getCookie('ADMIN_API_KEY')) openModal();
});

