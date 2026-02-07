export function page(title: string, body: string, scripts: string = "") {
  return `<!doctype html>
<html lang="en" data-theme="dark">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>${escapeHtml(title)}</title>
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/@picocss/pico@2/css/pico.min.css" />
    <style>
      :root {
        --pico-font-size: 100%;
        --pico-header-height: 3.5rem;
      }
      body > header {
        padding: 1rem 0;
        border-bottom: 1px solid var(--pico-muted-border-color);
        margin-bottom: 2rem;
      }
      .container { max-width: 960px; }
      .status-dot {
        display: inline-block;
        width: 10px;
        height: 10px;
        border-radius: 50%;
        background-color: var(--pico-muted-color);
        margin-right: 6px;
      }
      .status-dot.running { background-color: var(--pico-ins-color); box-shadow: 0 0 8px var(--pico-ins-color); }
      .status-dot.stopped { background-color: var(--pico-del-color); }
      .status-dot.starting { background-color: var(--pico-primary-color); animation: pulse 1.5s infinite; }

      .status-badge {
        display: inline-block;
        padding: 0.15rem 0.5rem;
        border-radius: 0.25rem;
        font-size: 0.75rem;
        font-weight: 600;
        text-transform: uppercase;
      }
      .status-badge.status-running {
        background-color: color-mix(in srgb, var(--pico-ins-color) 20%, transparent);
        color: var(--pico-ins-color);
        border: 1px solid var(--pico-ins-color);
      }
      .status-badge.status-stopped {
        background-color: color-mix(in srgb, var(--pico-del-color) 20%, transparent);
        color: var(--pico-del-color);
        border: 1px solid var(--pico-del-color);
      }
      
      @keyframes pulse { 0% { opacity: 0.5; } 50% { opacity: 1; } 100% { opacity: 0.5; } }

      .card-header-actions { display: flex; justify-content: space-between; align-items: center; margin-bottom: 1rem; }
      .secret-input-group { display: flex; gap: 0.5rem; }
      .secret-input-group input { flex-grow: 1; }
      
      /* Toast notifications */
      #toast-container { position: fixed; bottom: 20px; right: 20px; z-index: 1000; }
      .toast { 
        padding: 1rem; 
        border-radius: var(--pico-border-radius); 
        background: var(--pico-card-background-color); 
        border: 1px solid var(--pico-card-border-color);
        box-shadow: var(--pico-card-box-shadow);
        margin-top: 0.5rem;
        animation: slideIn 0.3s ease-out;
      }
      @keyframes slideIn { from { transform: translateY(100%); opacity: 0; } to { transform: translateY(0); opacity: 1; } }

      .mono { font-family: monospace; }
      .muted-text { color: var(--pico-muted-color); font-size: 0.875rem; }
      
      img.qr { 
        width: 250px; 
        height: 250px; 
        image-rendering: pixelated; 
        border: 4px solid white; 
        border-radius: 8px;
        display: block;
        margin: 1rem auto;
      }
    </style>
  </head>
  <body>
    <header>
      <div class="container">
        <nav>
          <ul>
            <li><strong>🦞 OpenClaw Manager</strong></li>
          </ul>
          <ul>
            <li><a href="/instances">Instances</a></li>
            <li><form method="post" action="/logout" style="margin:0"><button type="submit" class="outline contrast" style="padding: 0.25rem 0.75rem; font-size: 0.875rem;">Logout</button></form></li>
          </ul>
        </nav>
      </div>
    </header>
    
    <main class="container">
      ${body}
    </main>
    
    <div id="toast-container"></div>

    <script>
      function showToast(message, type = 'info') {
        const container = document.getElementById('toast-container');
        const toast = document.createElement('div');
        toast.className = 'toast';
        toast.textContent = message;
        if (type === 'error') toast.style.borderColor = 'var(--pico-del-color)';
        if (type === 'success') toast.style.borderColor = 'var(--pico-ins-color)';
        container.appendChild(toast);
        setTimeout(() => {
          toast.style.opacity = '0';
          setTimeout(() => toast.remove(), 300);
        }, 3000);
      }
      ${scripts}
    </script>
  </body>
</html>`;
}

export function escapeHtml(s: string) {
  return s
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}
