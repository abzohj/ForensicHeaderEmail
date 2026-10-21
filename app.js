/* app.js — Email Forensics Analyzer frontend */

// ─── RELOJ ────────────────────────────────────────────────────
function updateClock() {
  const el = document.getElementById('clock');
  if (el) el.textContent = new Date().toLocaleTimeString('es-ES', {hour12: false});
}
setInterval(updateClock, 1000);
updateClock();

// ─── TABS ─────────────────────────────────────────────────────
document.querySelectorAll('.tab').forEach(tab => {
  tab.addEventListener('click', () => {
    document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
    document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
    tab.classList.add('active');
    document.getElementById('tab-' + tab.dataset.tab).classList.add('active');
  });
});

// ─── DROP ZONE ────────────────────────────────────────────────
const dropZone  = document.getElementById('dropZone');
const fileInput = document.getElementById('fileInput');
const fileNameEl = document.getElementById('file-name');
let selectedFile = null;

dropZone.addEventListener('click', () => fileInput.click());

fileInput.addEventListener('change', () => {
  if (fileInput.files[0]) setFile(fileInput.files[0]);
});

dropZone.addEventListener('dragover', e => {
  e.preventDefault();
  dropZone.classList.add('dragover');
});

dropZone.addEventListener('dragleave', () => dropZone.classList.remove('dragover'));

dropZone.addEventListener('drop', e => {
  e.preventDefault();
  dropZone.classList.remove('dragover');
  if (e.dataTransfer.files[0]) setFile(e.dataTransfer.files[0]);
});

function setFile(file) {
  selectedFile = file;
  fileNameEl.textContent = `✓ ${file.name}  (${(file.size/1024).toFixed(1)} KB)`;
}

// ─── ANALYZE BUTTON ───────────────────────────────────────────
document.getElementById('analyzeBtn').addEventListener('click', async () => {
  const btn    = document.getElementById('analyzeBtn');
  const btnTxt = btn.querySelector('.btn-text');
  const loader = btn.querySelector('.btn-loader');
  const errBox = document.getElementById('error-box');

  errBox.classList.add('hidden');

  const formData = new FormData();
  const activeTab = document.querySelector('.tab.active').dataset.tab;

  if (activeTab === 'file') {
    if (!selectedFile) { showError('Selecciona un archivo .txt primero.'); return; }
    formData.append('file', selectedFile);
  } else {
    const text = document.getElementById('pasteArea').value.trim();
    if (!text) { showError('Pega la cabecera del correo primero.'); return; }
    formData.append('header_text', text);
  }

  btn.disabled = true;
  btnTxt.hidden = true;
  loader.hidden = false;

  try {
    const resp = await fetch('/analyze', { method: 'POST', body: formData });
    const data = await resp.json();

    if (!resp.ok || data.error) {
      showError(data.error || 'Error desconocido en el servidor.');
      return;
    }

    renderResults(data);

  } catch (e) {
    showError('No se pudo conectar con el servidor Flask. ¿Está ejecutándose?');
  } finally {
    btn.disabled = false;
    btnTxt.hidden = false;
    loader.hidden = true;
  }
});

function showError(msg) {
  const el = document.getElementById('error-box');
  el.textContent = '⚠ ERROR: ' + msg;
  el.classList.remove('hidden');
}

// ─── RENDER RESULTS ───────────────────────────────────────────
function renderResults(d) {
  document.getElementById('results').classList.remove('hidden');
  document.getElementById('results').scrollIntoView({ behavior: 'smooth', block: 'start' });

  renderSpamBanner(d.spam);
  renderBasic(d.basic);
  renderSpam(d.spam);
  renderMTA(d.mta_global);
  renderHops(d.hops);
  renderMap(d.hops);
  renderTimes(d.delivery_times, d.total_transit_human);
  renderRecipient(d.recipient_ip, d.hops);
}

// ── Spam Banner ───────────────────────────────────────────────
function renderSpamBanner(spam) {
  const el = document.getElementById('spam-banner');
  const icons = { danger: '🚨', warning: '⚠️', ok: '✅' };
  el.className = `spam-banner ${spam.verdict_level}`;
  el.textContent = `${icons[spam.verdict_level]}  ${spam.verdict}  —  Puntuación de riesgo: ${spam.score}/100`;
}

// ── Información básica ────────────────────────────────────────
function renderBasic(b) {
  const fields = [
    ['ORIGEN (FROM)',    b.from,        'accent'],
    ['DESTINO (TO)',     b.to,          'accent2'],
    ['ASUNTO',          b.subject,     ''],
    ['FECHA ENVÍO',     b.date,        ''],
    ['MESSAGE-ID',      b.message_id,  'accent'],
    ['RETURN-PATH',     b.return_path, ''],
    ['REPLY-TO',        b.reply_to,    ''],
    ['X-ORIGINATING-IP',b.x_orig_ip,  'warning'],
    ['MAILER / UA',     b.x_mailer,    ''],
  ];

  document.getElementById('basic-content').innerHTML = fields
    .filter(([,v]) => v)
    .map(([l, v, cls]) => `
      <div class="field-row">
        <span class="field-label">${l}</span>
        <span class="field-value ${cls}">${esc(v)}</span>
      </div>`).join('');
}

// ── Spam analysis ─────────────────────────────────────────────
function renderSpam(spam) {
  const fillClass = spam.verdict_level;
  const flagsHtml = spam.flags.length
    ? spam.flags.map(f => `
        <div class="flag-item ${f.severity}">
          <span class="flag-severity">${f.severity.toUpperCase()}</span>
          <div>
            <div class="flag-label">${esc(f.label)}</div>
            <div class="flag-detail">${esc(f.detail)}</div>
          </div>
        </div>`).join('')
    : '<p style="color:var(--text-dim);font-family:var(--font-mono);font-size:.8rem">No se detectaron indicadores de spam.</p>';

  document.getElementById('spam-content').innerHTML = `
    <div style="display:flex;justify-content:space-between;font-family:var(--font-mono);font-size:.75rem;margin-bottom:.4rem;">
      <span style="color:var(--text-dim)">PUNTUACIÓN DE RIESGO</span>
      <span style="color:var(--warning)">${spam.score}/100</span>
    </div>
    <div class="spam-score-bar">
      <div class="spam-score-fill ${fillClass}" style="width:${spam.score}%"></div>
    </div>
    ${flagsHtml}
  `;
}

// ── MTA Global ────────────────────────────────────────────────
function renderMTA(mta) {
  const oGeo = mta.origin_geo;
  const dGeo = mta.dest_geo;

  function nodeHtml(label, ip, geo) {
    if (!ip) return `<div class="mta-node"><div class="mta-node-label">${label}</div><div style="color:var(--text-dim);font-family:var(--font-mono);font-size:.8rem">No detectada</div></div>`;
    const flag = geo.countryCode ? countryFlag(geo.countryCode) : '🌐';
    return `
      <div class="mta-node">
        <div class="mta-node-label">${label}</div>
        <div class="mta-node-ip">${esc(ip)}</div>
        <div class="mta-node-country">${flag} ${esc(geo.country || 'Desconocido')}</div>
        <div class="mta-node-info">${esc(geo.city || '')}${geo.city && geo.org ? ' · ' : ''}${esc(geo.org || '')}</div>
        <div class="mta-node-info" style="margin-top:.3rem">${esc(geo.as || '')}</div>
      </div>`;
  }

  document.getElementById('mta-content').innerHTML = `
    <div class="mta-global">
      ${nodeHtml('SERVIDOR ORIGEN', mta.origin_ip, oGeo)}
      <div class="mta-arrow">⟶</div>
      ${nodeHtml('SERVIDOR DESTINO', mta.dest_ip, dGeo)}
    </div>`;
}

// ── Hops table ────────────────────────────────────────────────
function renderHops(hops) {
  if (!hops || !hops.length) {
    document.getElementById('hops-content').innerHTML = '<p style="color:var(--text-dim)">No se detectaron saltos Received.</p>';
    return;
  }

  const rows = hops.map(hop => {
    const ipList = hop.ips.map(i =>
      `<div class="hop-ip">${esc(i.ip)}</div>
       <div style="font-size:.72rem;color:var(--text-dim)">${countryFlag(i.country_code)} ${esc(i.country)} ${i.city ? '· '+esc(i.city) : ''}</div>
       <div style="font-size:.68rem;color:var(--text-dim)">${esc(i.org || '')}</div>`
    ).join('<hr style="border-color:var(--border);margin:.4rem 0">') || '<span style="color:var(--text-dim)">—</span>';

    const tagHtml = hop.index === 1 ? '<span class="tag origin">ORIGEN</span>'
                  : hop.index === hops.length ? '<span class="tag dest">DESTINO</span>' : '';

    const distHtml = hop.distance_km != null
      ? `<span class="hop-dist">~${hop.distance_km.toLocaleString()} km</span>` : '—';

    return `<tr>
      <td><span class="hop-index">${hop.index}</span>${tagHtml}</td>
      <td style="font-family:var(--font-mono);font-size:.78rem;color:var(--text-dim)">${esc(hop.from_host||'—')}</td>
      <td style="font-family:var(--font-mono);font-size:.78rem;color:var(--text-dim)">${esc(hop.by_host||'—')}</td>
      <td>${ipList}</td>
      <td style="font-family:var(--font-mono);font-size:.72rem;color:var(--text-dim)">${esc(hop.timestamp||'—')}</td>
      <td>${distHtml}</td>
    </tr>`;
  }).join('');

  document.getElementById('hops-content').innerHTML = `
    <table class="hops-table">
      <thead><tr>
        <th>#</th><th>FROM HOST</th><th>BY HOST</th><th>IPs / GEO</th><th>TIMESTAMP</th><th>DISTANCIA</th>
      </tr></thead>
      <tbody>${rows}</tbody>
    </table>`;
}

// ── SVG World Map ─────────────────────────────────────────────
function renderMap(hops) {
  // Collect all geolocated points
  const points = [];
  hops.forEach(hop => {
    hop.ips.forEach(ip => {
      if (ip.lat && ip.lon) {
        points.push({
          lat: ip.lat, lon: ip.lon,
          label: ip.ip,
          country: ip.country,
          city: ip.city || '',
          index: hop.index
        });
      }
    });
  });

  const container = document.getElementById('map-content');

  if (points.length < 1) {
    container.innerHTML = '<p style="color:var(--text-dim);font-family:var(--font-mono);padding:1rem">No hay suficientes IPs geolocalizadas para trazar el mapa.</p>';
    return;
  }

  // Equirectangular projection helpers
  const W = 1000, H = 500;
  function project(lat, lon) {
    const x = (lon + 180) * (W / 360);
    const y = (90 - lat) * (H / 180);
    return [x, y];
  }

  // Build SVG path lines between consecutive points
  let pathLines = '';
  for (let i = 1; i < points.length; i++) {
    const [x1, y1] = project(points[i-1].lat, points[i-1].lon);
    const [x2, y2] = project(points[i].lat, points[i].lon);
    // Control point for curve
    const cx = (x1 + x2) / 2;
    const cy = Math.min(y1, y2) - 60;
    const id = `path-${i}`;
    pathLines += `
      <path id="${id}" d="M${x1},${y1} Q${cx},${cy} ${x2},${y2}"
        fill="none" stroke="url(#lineGrad)" stroke-width="1.5" stroke-dasharray="6 3" opacity="0.7">
        <animate attributeName="stroke-dashoffset" from="0" to="-100" dur="3s" repeatCount="indefinite"/>
      </path>`;
  }

  // Build markers
  let markers = '';
  const colors = ['#00ff9d', '#00d4ff', '#ffcc00', '#ff6b35', '#ff2d55'];
  points.forEach((p, i) => {
    const [x, y] = project(p.lat, p.lon);
    const color = colors[i % colors.length];
    const isFirst = i === 0;
    const isLast  = i === points.length - 1;
    const r = (isFirst || isLast) ? 7 : 5;
    markers += `
      <g class="map-marker" data-ip="${esc(p.label)}" data-country="${esc(p.country)}" data-city="${esc(p.city)}" data-index="${p.index}">
        <circle cx="${x}" cy="${y}" r="${r+6}" fill="${color}" opacity="0.15">
          <animate attributeName="r" values="${r+6};${r+14};${r+6}" dur="2.5s" repeatCount="indefinite"/>
          <animate attributeName="opacity" values="0.15;0.05;0.15" dur="2.5s" repeatCount="indefinite"/>
        </circle>
        <circle cx="${x}" cy="${y}" r="${r}" fill="${color}" stroke="#080c10" stroke-width="1.5" opacity="0.9"/>
        <text x="${x}" y="${y - r - 5}" text-anchor="middle" font-family="Share Tech Mono,monospace"
          font-size="9" fill="${color}" opacity="0.9">${p.index}</text>
      </g>`;
  });

  container.innerHTML = `
    <div id="map-svg-container">
      <div class="map-tooltip" id="mapTooltip"></div>
      <svg viewBox="0 0 ${W} ${H}" xmlns="http://www.w3.org/2000/svg" style="background:#0a1218">
        <defs>
          <linearGradient id="lineGrad" x1="0%" y1="0%" x2="100%" y2="0%">
            <stop offset="0%"   stop-color="#00ff9d"/>
            <stop offset="100%" stop-color="#00d4ff"/>
          </linearGradient>
        </defs>

        <!-- Simplified world grid -->
        ${buildGrid(W, H)}

        <!-- Continents outline (simplified) -->
        ${buildContinents()}

        <!-- Route lines -->
        ${pathLines}

        <!-- Markers -->
        ${markers}
      </svg>
    </div>`;

  // Tooltip
  const tooltip = document.getElementById('mapTooltip');
  document.querySelectorAll('.map-marker').forEach(el => {
    el.style.cursor = 'pointer';
    el.addEventListener('mouseenter', e => {
      const r = el.getBoundingClientRect();
      const cr = container.getBoundingClientRect();
      tooltip.innerHTML = `<strong>${el.dataset.ip}</strong><br>Salto: ${el.dataset.index}<br>${el.dataset.country}${el.dataset.city ? ' · '+el.dataset.city : ''}`;
      tooltip.style.display = 'block';
      tooltip.style.left = (r.left - cr.left + 10) + 'px';
      tooltip.style.top  = (r.top  - cr.top  - 60) + 'px';
    });
    el.addEventListener('mouseleave', () => { tooltip.style.display = 'none'; });
  });
}

function buildGrid(W, H) {
  let lines = '';
  // Longitudes
  for (let lon = -180; lon <= 180; lon += 30) {
    const x = (lon + 180) * (W / 360);
    lines += `<line x1="${x}" y1="0" x2="${x}" y2="${H}" stroke="#1e3a4a" stroke-width="0.5" opacity="0.5"/>`;
  }
  // Latitudes
  for (let lat = -90; lat <= 90; lat += 30) {
    const y = (90 - lat) * (H / 180);
    lines += `<line x1="0" y1="${y}" x2="${W}" y2="${y}" stroke="#1e3a4a" stroke-width="0.5" opacity="0.5"/>`;
  }
  // Ecuador y meridiano 0 más marcados
  const eqY = (90) * (H / 180);
  const pm = (180) * (W / 360);
  lines += `<line x1="0" y1="${eqY}" x2="${W}" y2="${eqY}" stroke="#1e3a4a" stroke-width="1" opacity="0.8"/>`;
  lines += `<line x1="${pm}" y1="0" x2="${pm}" y2="${H}" stroke="#1e3a4a" stroke-width="1" opacity="0.8"/>`;
  return lines;
}

function buildContinents() {
  // Simplified continent polygons (equirectangular)
  function ll(lat, lon) {
    const W = 1000, H = 500;
    return `${(lon+180)*(W/360)},${(90-lat)*(H/180)}`;
  }

  const continents = [
    // North America
    `M${ll(70,-140)} L${ll(70,-55)} L${ll(25,-55)} L${ll(15,-85)} L${ll(10,-75)} L${ll(20,-105)} L${ll(30,-110)} L${ll(50,-125)} Z`,
    // South America
    `M${ll(12,-73)} L${ll(12,-50)} L${ll(-55,-65)} L${ll(-55,-75)} L${ll(0,-80)} Z`,
    // Europe
    `M${ll(72,30)} L${ll(72,-10)} L${ll(35,-10)} L${ll(35,40)} Z`,
    // Africa
    `M${ll(37,-5)} L${ll(37,50)} L${ll(-35,35)} L${ll(-35,15)} L${ll(5,-5)} Z`,
    // Asia
    `M${ll(72,30)} L${ll(72,180)} L${ll(10,100)} L${ll(10,60)} L${ll(35,40)} Z`,
    // Australia
    `M${ll(-15,114)} L${ll(-15,155)} L${ll(-44,148)} L${ll(-35,114)} Z`,
  ];

  return continents.map(d =>
    `<path d="${d}" fill="#0f2535" stroke="#1e3a4a" stroke-width="0.8" opacity="0.8"/>`
  ).join('\n');
}

// ── Delivery Times ────────────────────────────────────────────
function renderTimes(times, total) {
  if (!times || !times.length) {
    document.getElementById('times-content').innerHTML = '<p style="color:var(--text-dim);font-family:var(--font-mono);font-size:.8rem">No se pudieron calcular tiempos (faltan timestamps).</p>';
    return;
  }

  const maxSec = Math.max(...times.map(t => t.seconds || 0), 1);

  const bars = times.map(t => {
    const pct = t.seconds != null ? Math.min((t.seconds / maxSec) * 100, 100) : 0;
    return `
      <div class="time-bar-container">
        <div class="time-bar-label">
          <span>SALTO ${t.hop}</span>
          <span class="time-val">${t.human}</span>
        </div>
        <div class="time-bar-track">
          <div class="time-bar-fill" style="width:${pct}%"></div>
        </div>
      </div>`;
  }).join('');

  document.getElementById('times-content').innerHTML = `
    ${bars}
    <div class="time-total">
      <span class="time-total-label">TRÁNSITO TOTAL</span>
      <span class="time-total-val">${total}</span>
    </div>`;
}

// ── Recipient IP ──────────────────────────────────────────────
function renderRecipient(ip, hops) {
  if (!ip) {
    document.getElementById('recipient-content').innerHTML = '<p style="color:var(--text-dim);font-family:var(--font-mono);font-size:.8rem">No detectada.</p>';
    return;
  }

  // Find geo from hops
  let geo = null;
  for (const hop of [...hops].reverse()) {
    for (const i of hop.ips) {
      if (i.ip === ip) { geo = i; break; }
    }
    if (geo) break;
  }

  const flag = geo && geo.country_code ? countryFlag(geo.country_code) : '🌐';

  document.getElementById('recipient-content').innerHTML = `
    <div class="big-ip">${esc(ip)}</div>
    ${geo ? `
      <div class="field-row">
        <span class="field-label">PAÍS</span>
        <span class="field-value">${flag} ${esc(geo.country)}</span>
      </div>
      <div class="field-row">
        <span class="field-label">CIUDAD</span>
        <span class="field-value">${esc(geo.city||'—')}</span>
      </div>
      <div class="field-row">
        <span class="field-label">ORG / ISP</span>
        <span class="field-value">${esc(geo.org||'—')}</span>
      </div>
      <div class="field-row">
        <span class="field-label">AS</span>
        <span class="field-value">${esc(geo.as||'—')}</span>
      </div>` : ''}
  `;
}

// ─── HELPERS ──────────────────────────────────────────────────
function esc(str) {
  if (!str) return '';
  return String(str)
    .replace(/&/g,'&amp;')
    .replace(/</g,'&lt;')
    .replace(/>/g,'&gt;')
    .replace(/"/g,'&quot;');
}

function countryFlag(code) {
  if (!code || code.length !== 2) return '🌐';
  const offset = 127397;
  return String.fromCodePoint(...[...code.toUpperCase()].map(c => c.charCodeAt(0) + offset));
}


// ═══════════════════════════════════════════════════════════════
//   IP GEOLOCATOR TOOL
// ═══════════════════════════════════════════════════════════════

// ─── Dynamic IP rows ──────────────────────────────────────────
function updateRowIndices() {
  document.querySelectorAll('.geo-ip-row').forEach((row, i) => {
    row.querySelector('.geo-ip-index').textContent = String(i + 1).padStart(2, '0');
  });
}

function addRemoveListener(row) {
  row.querySelector('.geo-ip-remove').addEventListener('click', () => {
    if (document.querySelectorAll('.geo-ip-row').length > 1) {
      row.remove();
      updateRowIndices();
    }
  });
}

// Init existing rows
document.querySelectorAll('.geo-ip-row').forEach(addRemoveListener);

document.getElementById('geoAddBtn').addEventListener('click', () => {
  const rows = document.querySelectorAll('.geo-ip-row');
  if (rows.length >= 10) return;

  const newRow = document.createElement('div');
  newRow.className = 'geo-ip-row';
  newRow.innerHTML = `
    <span class="geo-ip-index">${String(rows.length + 1).padStart(2,'0')}</span>
    <input class="geo-ip-input" type="text" placeholder="x.x.x.x" maxlength="45">
    <button class="geo-ip-remove" title="Eliminar">✕</button>
  `;
  document.getElementById('geoInputs').appendChild(newRow);
  addRemoveListener(newRow);
  newRow.querySelector('input').focus();
});

// ─── Lookup button ────────────────────────────────────────────
document.getElementById('geoLookupBtn').addEventListener('click', async () => {
  const btn    = document.getElementById('geoLookupBtn');
  const btnTxt = btn.querySelector('.btn-text');
  const loader = btn.querySelector('.btn-loader');
  const errBox = document.getElementById('geo-error-box');

  errBox.classList.add('hidden');

  // Collect IPs
  const inputs = [...document.querySelectorAll('.geo-ip-input')];
  const ips = inputs.map(i => i.value.trim()).filter(Boolean);

  // Simple validation
  let hasError = false;
  inputs.forEach(i => {
    i.classList.remove('error');
    if (i.value.trim() && !isValidIP(i.value.trim())) {
      i.classList.add('error');
      hasError = true;
    }
  });

  if (!ips.length) {
    showGeoError('Introduce al menos una dirección IP.');
    return;
  }
  if (hasError) {
    showGeoError('Alguna IP no tiene formato válido (ej: 192.168.1.1).');
    return;
  }

  btn.disabled = true;
  btnTxt.hidden = true;
  loader.hidden = false;

  try {
    const resp = await fetch('/geoip', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ips })
    });
    const data = await resp.json();

    if (!resp.ok || data.error) {
      showGeoError(data.error || 'Error en el servidor.');
      return;
    }

    renderGeoResults(data);

  } catch (e) {
    showGeoError('No se pudo conectar con el servidor Flask.');
  } finally {
    btn.disabled = false;
    btnTxt.hidden = false;
    loader.hidden = true;
  }
});

// ─── Render geo results ───────────────────────────────────────
function renderGeoResults(data) {
  const section = document.getElementById('geo-results');
  section.classList.remove('hidden');
  section.scrollIntoView({ behavior: 'smooth', block: 'start' });

  renderGeoCards(data.results);
  renderGeoDistances(data.distances);
  renderGeoMap(data.results);
}

function renderGeoCards(results) {
  const html = `<div class="geo-cards-grid">
    ${results.map(r => {
      if (!r.ok) return `
        <div class="geo-card error-card">
          <div class="geo-card-ip">${esc(r.ip)}</div>
          <div style="color:var(--danger);font-family:var(--font-mono);font-size:.8rem">
            ✕ ${esc(r.error || 'Error de geolocalización')}
          </div>
        </div>`;

      const flag = r.country_code ? countryFlag(r.country_code) : '🌐';
      return `
        <div class="geo-card">
          <div class="geo-card-ip">${esc(r.ip)}</div>
          <div class="geo-card-flag">${flag}</div>
          <div class="geo-card-country">${esc(r.country)}</div>
          <div class="geo-card-city">${esc(r.city || '—')}</div>
          <div class="geo-card-detail">
            <div>ISP: ${esc(r.isp || '—')}</div>
            <div>ORG: ${esc(r.org || '—')}</div>
            <div>AS:  ${esc(r.as  || '—')}</div>
          </div>
          ${r.lat ? `<div class="geo-card-coords">📍 ${r.lat.toFixed(4)}, ${r.lon.toFixed(4)}</div>` : ''}
        </div>`;
    }).join('')}
  </div>`;

  document.getElementById('geo-cards-content').innerHTML = html;
}

function renderGeoDistances(distances) {
  const card = document.getElementById('geo-dist-card');

  if (!distances || !distances.length) {
    card.classList.add('hidden');
    return;
  }

  card.classList.remove('hidden');

  const maxKm = Math.max(...distances.map(d => d.km), 1);

  const rows = distances.map(d => {
    const pct = Math.min((d.km / maxKm) * 100, 100);
    return `<tr>
      <td style="font-family:var(--font-mono);color:var(--accent)">${esc(d.from_ip)}</td>
      <td style="color:var(--text-dim);font-size:1rem">→</td>
      <td style="font-family:var(--font-mono);color:var(--accent2)">${esc(d.to_ip)}</td>
      <td>
        <div class="dist-km">${d.km.toLocaleString()} km</div>
        <div class="dist-bar-wrap">
          <div class="dist-bar" style="width:${pct}%"></div>
        </div>
      </td>
    </tr>`;
  }).join('');

  document.getElementById('geo-dist-content').innerHTML = `
    <table class="dist-table">
      <thead><tr>
        <th>IP ORIGEN</th><th></th><th>IP DESTINO</th><th>DISTANCIA</th>
      </tr></thead>
      <tbody>${rows}</tbody>
    </table>`;
}

function renderGeoMap(results) {
  const geolocated = results.filter(r => r.ok && r.lat && r.lon);
  const container = document.getElementById('geo-map-content');

  if (!geolocated.length) {
    container.innerHTML = '<p style="color:var(--text-dim);font-family:var(--font-mono);padding:1rem">No hay IPs geolocalizadas para mostrar en el mapa.</p>';
    return;
  }

  const W = 1000, H = 500;
  function project(lat, lon) {
    return [(lon + 180) * (W / 360), (90 - lat) * (H / 180)];
  }

  // Lines between consecutive geolocated IPs
  let lines = '';
  for (let i = 1; i < geolocated.length; i++) {
    const [x1, y1] = project(geolocated[i-1].lat, geolocated[i-1].lon);
    const [x2, y2] = project(geolocated[i].lat,   geolocated[i].lon);
    const cx = (x1 + x2) / 2;
    const cy = Math.min(y1, y2) - 55;
    lines += `
      <path d="M${x1},${y1} Q${cx},${cy} ${x2},${y2}"
        fill="none" stroke="url(#geoLineGrad)" stroke-width="1.8"
        stroke-dasharray="6 3" opacity="0.75">
        <animate attributeName="stroke-dashoffset" from="0" to="-100" dur="3s" repeatCount="indefinite"/>
      </path>`;
  }

  // Distance labels on lines
  let distLabels = '';
  for (let i = 1; i < geolocated.length; i++) {
    const a = geolocated[i-1], b = geolocated[i];
    const [x1, y1] = project(a.lat, a.lon);
    const [x2, y2] = project(b.lat, b.lon);
    const mx = (x1 + x2) / 2;
    const my = Math.min(y1, y2) - 70;
    const km = haversineJS(a.lat, a.lon, b.lat, b.lon);
    distLabels += `
      <text x="${mx}" y="${my}" text-anchor="middle"
        font-family="Share Tech Mono,monospace" font-size="9"
        fill="#ff6b35" opacity="0.9">~${Math.round(km).toLocaleString()} km</text>`;
  }

  // Markers
  const colors = ['#00ff9d','#00d4ff','#ffcc00','#ff6b35','#ff2d55',
                   '#c084fc','#38bdf8','#fb923c','#a3e635','#f472b6'];
  let markers = '';
  geolocated.forEach((r, i) => {
    const [x, y] = project(r.lat, r.lon);
    const color = colors[i % colors.length];
    markers += `
      <g class="geo-marker"
         data-ip="${esc(r.ip)}"
         data-country="${esc(r.country)}"
         data-city="${esc(r.city||'')}">
        <circle cx="${x}" cy="${y}" r="13" fill="${color}" opacity="0.12">
          <animate attributeName="r" values="13;20;13" dur="2.5s" repeatCount="indefinite"/>
          <animate attributeName="opacity" values="0.12;0.04;0.12" dur="2.5s" repeatCount="indefinite"/>
        </circle>
        <circle cx="${x}" cy="${y}" r="6" fill="${color}" stroke="#080c10" stroke-width="1.5" opacity="0.95"/>
        <text x="${x+9}" y="${y+4}" font-family="Share Tech Mono,monospace"
          font-size="8" fill="${color}" opacity="0.9">${esc(r.ip)}</text>
      </g>`;
  });

  container.innerHTML = `
    <div id="map-svg-container">
      <div class="map-tooltip" id="geoMapTooltip"></div>
      <svg viewBox="0 0 ${W} ${H}" xmlns="http://www.w3.org/2000/svg" style="background:#0a1218">
        <defs>
          <linearGradient id="geoLineGrad" x1="0%" y1="0%" x2="100%" y2="0%">
            <stop offset="0%" stop-color="#00ff9d"/>
            <stop offset="100%" stop-color="#ff6b35"/>
          </linearGradient>
        </defs>
        ${buildGrid(W, H)}
        ${buildContinents()}
        ${lines}
        ${distLabels}
        ${markers}
      </svg>
    </div>`;

  // Tooltips
  const tooltip = document.getElementById('geoMapTooltip');
  document.querySelectorAll('.geo-marker').forEach(el => {
    el.style.cursor = 'default';
    el.addEventListener('mouseenter', e => {
      const r  = el.getBoundingClientRect();
      const cr = container.getBoundingClientRect();
      tooltip.innerHTML = `<strong>${el.dataset.ip}</strong><br>${el.dataset.country}${el.dataset.city ? ' · '+el.dataset.city : ''}`;
      tooltip.style.display = 'block';
      tooltip.style.left = (r.left - cr.left + 10) + 'px';
      tooltip.style.top  = (r.top  - cr.top  - 55) + 'px';
    });
    el.addEventListener('mouseleave', () => { tooltip.style.display = 'none'; });
  });
}

// ─── Helpers geo tool ─────────────────────────────────────────
function showGeoError(msg) {
  const el = document.getElementById('geo-error-box');
  el.textContent = '⚠ ' + msg;
  el.classList.remove('hidden');
}

function isValidIP(str) {
  const parts = str.split('.');
  if (parts.length !== 4) return false;
  return parts.every(p => {
    const n = parseInt(p, 10);
    return !isNaN(n) && n >= 0 && n <= 255 && String(n) === p;
  });
}

function haversineJS(lat1, lon1, lat2, lon2) {
  const R = 6371;
  const toRad = x => x * Math.PI / 180;
  const dLat = toRad(lat2 - lat1);
  const dLon = toRad(lon2 - lon1);
  const a = Math.sin(dLat/2)**2 +
            Math.cos(toRad(lat1)) * Math.cos(toRad(lat2)) * Math.sin(dLon/2)**2;
  return R * 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
}
