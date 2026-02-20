(() => {
  const api = 'http://127.0.0.1:8002/api';
  const u = location.href;
  const key = '__payguard_banner__';
  
  // Main page scan
  if (document.body && !document.body.dataset[key]) {
    document.body.dataset[key] = '1';
    fetch(api + '/media-risk?url=' + encodeURIComponent(u))
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

  // AI Image Detection for individual images on page
  const imageKey = '__payguard_ai_checked__';
  const minSize = 128; // Minimum dimension for analysis
  
  async function analyzeImage(img) {
    if (img.dataset[imageKey]) return;
    img.dataset[imageKey] = 'checking';
    
    try {
      // Get image dimensions
      const w = img.naturalWidth || img.width;
      const h = img.naturalHeight || img.height;
      
      if (w < minSize || h < minSize) {
        img.dataset[imageKey] = 'too-small';
        return;
      }
      
      // Fetch and analyze image
      const imgUrl = img.src;
      if (!imgUrl || imgUrl.startsWith('data:')) {
        img.dataset[imageKey] = 'skipped';
        return;
      }
      
      // Fetch image as blob
      const response = await fetch(imgUrl);
      if (!response.ok) {
        img.dataset[imageKey] = 'fetch-error';
        return;
      }
      
      const blob = await response.blob();
      if (blob.size > 10 * 1024 * 1024) { // Skip if > 10MB
        img.dataset[imageKey] = 'too-large';
        return;
      }
      
      // Convert to base64
      const reader = new FileReader();
      const base64Promise = new Promise((resolve) => {
        reader.onloadend = () => resolve(reader.result.split(',')[1]);
        reader.readAsDataURL(blob);
      });
      const base64 = await base64Promise;
      
      // Send to backend
      const apiResponse = await fetch(api + '/media-risk/bytes', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-API-Key': 'demo_key'
        },
        body: JSON.stringify({
          url: imgUrl,
          content: base64,
          metadata: { source: 'browser-extension' }
        })
      });
      
      if (apiResponse.ok) {
        const result = await apiResponse.json();
        const fakeProb = result.image_fake_prob || 0;
        
        img.dataset[imageKey] = 'checked';
        img.dataset.payguardAiScore = fakeProb;
        
        // If AI-generated (>=70% probability), add warning overlay
        if (fakeProb >= 70) {
          addAiWarning(img, fakeProb);
        }
      } else {
        img.dataset[imageKey] = 'api-error';
      }
    } catch (e) {
      img.dataset[imageKey] = 'error';
    }
  }
  
  function addAiWarning(img, score) {
    // Create warning overlay
    const wrapper = document.createElement('div');
    wrapper.style.position = 'relative';
    wrapper.style.display = 'inline-block';
    
    const warning = document.createElement('div');
    warning.textContent = `⚠️ AI Image (${Math.round(score)}%)`;
    warning.style.position = 'absolute';
    warning.style.top = '5px';
    warning.style.left = '5px';
    warning.style.background = 'rgba(255, 0, 0, 0.85)';
    warning.style.color = 'white';
    warning.style.padding = '4px 8px';
    warning.style.borderRadius = '4px';
    warning.style.fontSize = '12px';
    warning.style.fontWeight = 'bold';
    warning.style.zIndex = '10000';
    warning.style.pointerEvents = 'none';
    
    // Red border on image
    img.style.border = '3px solid red';
    img.style.boxSizing = 'border-box';
    
    // Insert wrapper
    img.parentNode.insertBefore(wrapper, img);
    wrapper.appendChild(img);
    wrapper.appendChild(warning);
  }
  
  // Scan all images on page
  function scanImages() {
    const images = document.querySelectorAll('img');
    images.forEach(img => {
      if (!img.dataset[imageKey] && img.src) {
        analyzeImage(img);
      }
    });
  }
  
  // Initial scan after page load
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', scanImages);
  } else {
    scanImages();
  }
  
  // Watch for new images added dynamically
  const observer = new MutationObserver((mutations) => {
    mutations.forEach((mutation) => {
      mutation.addedNodes.forEach((node) => {
        if (node.nodeName === 'IMG') {
          analyzeImage(node);
        } else if (node.querySelectorAll) {
          node.querySelectorAll('img').forEach(analyzeImage);
        }
      });
    });
  });
  
  observer.observe(document.body, {
    childList: true,
    subtree: true
  });
})();