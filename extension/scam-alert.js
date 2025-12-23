// PayGuard Scam Alert Overlay - Senior-friendly scam warning display
// Injected into pages to show large, clear warnings when scams are detected

(function () {
    'use strict';

    // Listen for scam alert messages from background script
    chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
        if (request.action === 'showScamAlert') {
            showScamAlertOverlay(request.scamAlert);
            sendResponse({ success: true });
        }
        return true;
    });

    function showScamAlertOverlay(scamAlert) {
        // Remove any existing overlay first
        const existing = document.getElementById('payguard-scam-overlay');
        if (existing) {
            existing.remove();
        }

        // Create full-screen overlay
        const overlay = document.createElement('div');
        overlay.id = 'payguard-scam-overlay';
        overlay.className = 'payguard-scam-overlay';

        // Build overlay content
        overlay.innerHTML = `
      <div class="payguard-scam-content">
        <div class="payguard-scam-icon">🛡️</div>
        <h1 class="payguard-scam-title">STOP! This is a SCAM!</h1>
        
        <div class="payguard-scam-message">
          <p class="payguard-main-message">${escapeHtml(scamAlert.senior_message)}</p>
        </div>

        <div class="payguard-scam-advice">
          ${formatActionAdvice(scamAlert.action_advice)}
        </div>

        <div class="payguard-scam-confidence">
          Confidence: ${Math.round(scamAlert.confidence)}%
        </div>

        <button class="payguard-close-button" id="payguard-close-scam">
          I Understand - Close This Warning
        </button>

        <div class="payguard-help-text">
          Need help? Call a trusted family member or friend.
        </div>
      </div>
    `;

        // Add to page
        document.body.appendChild(overlay);

        // Add close button listener
        document.getElementById('payguard-close-scam').addEventListener('click', () => {
            overlay.remove();
        });

        // Also close on Escape key
        const closeOnEscape = (e) => {
            if (e.key === 'Escape') {
                overlay.remove();
                document.removeEventListener('keydown', closeOnEscape);
            }
        };
        document.addEventListener('keydown', closeOnEscape);
    }

    function formatActionAdvice(advice) {
        // Split advice by | delimiter and create list
        const items = advice.split('|').map(item => item.trim());
        return `
      <ul class="payguard-advice-list">
        ${items.map(item => `<li>${escapeHtml(item)}</li>`).join('')}
      </ul>
    `;
    }

    function escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }

})();
