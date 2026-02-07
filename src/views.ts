export function page(title: string, body: string) {
  return `<!doctype html>
<html>
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>${escapeHtml(title)}</title>
    <style>
      body { font-family: ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, Helvetica, Arial; max-width: 900px; margin: 24px auto; padding: 0 16px; }
      .row { display:flex; gap: 16px; align-items: center; flex-wrap: wrap; }
      input, select { padding: 8px; min-width: 320px; }
      button { padding: 8px 12px; }
      code { background: #f2f2f2; padding: 2px 6px; border-radius: 4px; }
      .card { border: 1px solid #ddd; border-radius: 8px; padding: 12px; margin: 12px 0; }
      .muted { color: #666; }
      img.qr { width: 280px; height: 280px; image-rendering: pixelated; border: 1px solid #eee; }
      a { color: #0b5; }
    </style>
  </head>
  <body>
    ${body}
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

