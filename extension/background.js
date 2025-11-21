// PayGuard Background Service Worker

const API_BASE_URL = 'http://localhost:8001/api';
const CACHE_DURATION = 5 * 60 * 1000; // 5 minutes

// Cache for risk scores
const riskCache = new Map();

// Listen for tab updates
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status === 'complete' && tab.url) {
    checkUrlRisk(tab.url, tabId);
  }
});

// Listen for tab activation
chrome.tabs.onActivated.addListener((activeInfo) => {
  chrome.tabs.get(activeInfo.tabId, (tab) => {
    if (tab.url) {
      checkUrlRisk(tab.url, activeInfo.tabId);
    }
  });
});

// Check URL risk
async function checkUrlRisk(url, tabId) {
  try {
    // Skip chrome:// and other internal URLs
    if (!url.startsWith('http://') && !url.startsWith('https://')) {
      updateBadge(tabId, 'neutral', '?');
      return;
    }

    // Check cache first
    const cached = getCachedRisk(url);
    if (cached) {
      updateBadge(tabId, cached.risk_level, cached.trust_score);
      return;
    }

    // Fetch risk score from API
    const response = await fetch(`${API_BASE_URL}/risk?url=${encodeURIComponent(url)}`, {
      method: 'GET',
      headers: {
        'Content-Type': 'application/json'
      }
    });

    if (!response.ok) {
      throw new Error(`API error: ${response.status}`);
    }

    const riskData = await response.json();
    
    // Cache the result
    cacheRiskScore(url, riskData);
    
    // Update badge
    updateBadge(tabId, riskData.risk_level, riskData.trust_score);
    
    // Store for popup
    await chrome.storage.local.set({ [`risk_${tabId}`]: riskData });
    
  } catch (error) {
    console.error('Error checking URL risk:', error);
    updateBadge(tabId, 'error', '!');
    
    // Store error for popup
    await chrome.storage.local.set({ 
      [`risk_${tabId}`]: { 
        error: true, 
        message: 'Unable to connect to PayGuard API' 
      } 
    });
  }
}

// Update badge based on risk level
function updateBadge(tabId, riskLevel, score) {
  const colors = {
    'low': '#10b981',      // Green
    'medium': '#f59e0b',   // Yellow/Orange
    'high': '#ef4444',     // Red
    'error': '#6b7280',    // Gray
    'neutral': '#6b7280'   // Gray
  };

  const text = typeof score === 'number' ? Math.round(score).toString() : score;
  
  chrome.action.setBadgeBackgroundColor({ 
    color: colors[riskLevel] || colors.neutral,
    tabId: tabId 
  });
  
  chrome.action.setBadgeText({ 
    text: text,
    tabId: tabId 
  });
}

// Cache management
function cacheRiskScore(url, riskData) {
  riskCache.set(url, {
    data: riskData,
    timestamp: Date.now()
  });
}

function getCachedRisk(url) {
  const cached = riskCache.get(url);
  if (cached && (Date.now() - cached.timestamp) < CACHE_DURATION) {
    return cached.data;
  }
  riskCache.delete(url);
  return null;
}

// Listen for messages from popup
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === 'refreshRisk') {
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      if (tabs[0]) {
        checkUrlRisk(tabs[0].url, tabs[0].id);
        sendResponse({ success: true });
      }
    });
    return true;
  }
});