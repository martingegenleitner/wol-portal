(() => {
  const POLL_MS = 3000;
  const LABELS = {
    on: 'Online',
    off: 'Offline',
    pending_start: 'Starting…',
    pending_stop: 'Shutting down…',
  };

  const list = document.getElementById('hosts');
  const banner = document.getElementById('banner');
  const userEl = document.getElementById('user');
  let csrf = '';

  function showBanner(msg) {
    banner.textContent = msg || '';
    banner.hidden = !msg;
  }

  async function api(path, opts = {}) {
    const res = await fetch(path, {
      credentials: 'same-origin',
      ...opts,
      headers: { 'X-CSRF-Token': csrf, ...(opts.headers || {}) },
    });
    if (res.status === 401) {
      location.href = '/login';
      throw new Error('not logged in');
    }
    return res;
  }

  function row(h) {
    const li = document.createElement('li');
    li.className = 'host';

    const info = document.createElement('div');
    const name = document.createElement('strong');
    name.textContent = h.name;
    const ip = document.createElement('span');
    ip.className = 'ip';
    ip.textContent = h.ip;
    info.append(name, ip);
    if (h.error) {
      const err = document.createElement('div');
      err.className = 'error';
      err.textContent = h.error;
      info.append(err);
    }

    const badge = document.createElement('span');
    badge.className = 'badge ' + h.state;
    badge.textContent = LABELS[h.state] || h.state;

    const btn = document.createElement('button');
    btn.type = 'button';
    if (h.state === 'off') {
      btn.textContent = 'Power on';
      btn.disabled = !h.can_control;
      btn.onclick = () => act(h, 'start');
    } else if (h.state === 'on') {
      btn.textContent = 'Shut down';
      btn.className = 'danger';
      btn.disabled = !h.can_control;
      btn.onclick = () => {
        if (confirm(`Shut down ${h.name}?`)) act(h, 'stop');
      };
    } else {
      btn.textContent = LABELS[h.state];
      btn.disabled = true;
    }
    if (!h.can_control) btn.title = 'You are not allowed to control this host';

    li.append(info, badge, btn);
    return li;
  }

  async function act(h, action) {
    showBanner('');
    try {
      const res = await api(`/api/hosts/${encodeURIComponent(h.id)}/${action}`, { method: 'POST' });
      if (!res.ok) {
        const body = await res.json().catch(() => ({}));
        showBanner(body.error || `Request failed (${res.status})`);
      }
    } catch (e) {
      showBanner(String(e.message || e));
    }
    refresh();
  }

  async function refresh() {
    try {
      const res = await api('/api/hosts');
      if (!res.ok) throw new Error(`Request failed (${res.status})`);
      const data = await res.json();
      csrf = data.user.csrf;
      userEl.textContent = data.user.name;
      list.replaceChildren(...data.hosts.map(row));
    } catch (e) {
      showBanner(String(e.message || e));
    }
  }

  document.getElementById('logout').onclick = async () => {
    await api('/logout', { method: 'POST' }).catch(() => {});
    location.href = '/logged-out';
  };

  refresh();
  setInterval(refresh, POLL_MS);
})();
