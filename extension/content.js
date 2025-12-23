(() => {
  const api = 'http://127.0.0.1:8002/api/media-risk';
  const u = location.href;
  const key = '__payguard_banner__';
  if (document.body && !document.body.dataset[key]) {
    document.body.dataset[key] = '1';
    fetch(api + '?url=' + encodeURIComponent(u))
      .then(r => r.json())
      .then(j => {
        const color = j.media_color;
        const score = j.media_score;
        const prob = j.image_fake_prob;
        const msg = prob != null && prob >= 80 ? 'AI image likely' : 'Scanning images';
        const bg = color === 'high' ? '#ffebe9' : color === 'medium' ? '#fff3cd' : '#e6ffed';
        const fg = color === 'high' ? '#d1242f' : color === 'medium' ? '#8a6d3b' : '#0969da';
        const bar = document.createElement('div');
        bar.style.position = 'fixed';
        bar.style.top = '0';
        bar.style.left = '0';
        bar.style.right = '0';
        bar.style.zIndex = '2147483647';
        bar.style.background = bg;
        bar.style.color = fg;
        bar.style.fontFamily = 'system-ui, -apple-system, Segoe UI, Roboto, Ubuntu, Cantarell, Noto Sans, sans-serif';
        bar.style.fontSize = '14px';
        bar.style.padding = '10px 12px';
        bar.style.borderBottom = '1px solid rgba(0,0,0,0.15)';
        bar.style.display = 'flex';
        bar.style.alignItems = 'center';
        bar.style.gap = '12px';
        const text = document.createElement('div');
        text.textContent = 'PayGuard • Media risk: ' + score + ' • ' + msg;
        const close = document.createElement('button');
        close.textContent = 'Dismiss';
        close.style.marginLeft = 'auto';
        close.style.border = '1px solid rgba(0,0,0,0.2)';
        close.style.borderRadius = '6px';
        close.style.padding = '6px 10px';
        close.style.background = 'white';
        close.style.cursor = 'pointer';
        close.onclick = () => bar.remove();
        bar.appendChild(text);
        bar.appendChild(close);
        document.body.appendChild(bar);
      })
      .catch(() => {});
  }
})();
