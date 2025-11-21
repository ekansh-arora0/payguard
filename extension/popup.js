// PayGuard Popup Script

const API_BASE_URL = 'http://localhost:8001/api';

// DOM Elements
const loadingState = document.getElementById('loadingState');
const errorState = document.getElementById('errorState');
const mainContent = document.getElementById('mainContent');
const trustScore = document.getElementById('trustScore');
const riskLevel = document.getElementById('riskLevel');
const riskBadge = document.getElementById('riskBadge');
const progressRing = document.getElementById('progressRing');
const websiteDomain = document.getElementById('websiteDomain');
const sslStatus = document.getElementById('sslStatus');
const riskFactorsList = document.getElementById('riskFactorsList');
const safetyList = document.getElementById('safetyList');
const educationMessage = document.getElementById('educationMessage');
const educationIcon = document.getElementById('educationIcon');
const riskFactorsSection = document.getElementById('riskFactorsSection');
const safetySection = document.getElementById('safetySection');
const errorTitle = document.getElementById('errorTitle');
const errorMessage = document.getElementById('errorMessage');
const refreshBtn = document.getElementById('refreshBtn');
const retryBtn = document.getElementById('retryBtn');

// Initialize popup
async function init() {
  showLoading();
  
  try {
    const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
    const currentTab = tabs[0];
    
    if (!currentTab || !currentTab.id) {
      showError('No Active Tab', 'Unable to detect current tab');
      return;
    }

    // Get risk data from storage (set by background script)
    const storageKey = `risk_${currentTab.id}`;
    const result = await chrome.storage.local.get(storageKey);
    const riskData = result[storageKey];

    if (!riskData) {
      // No data yet, wait a bit and try again
      setTimeout(async () => {
        const retryResult = await chrome.storage.local.get(storageKey);
        if (retryResult[storageKey]) {
          displayRiskData(retryResult[storageKey]);
        } else {
          showError('Analysis Pending', 'Analyzing website, please wait...');
        }
      }, 1000);
      return;
    }

    displayRiskData(riskData);
    
  } catch (error) {
    console.error('Error initializing popup:', error);
    showError('Initialization Error', error.message);
  }
}

// Display risk data
function displayRiskData(data) {
  if (data.error) {
    showError('Connection Error', data.message || 'Unable to connect to PayGuard API');
    return;
  }

  // Update trust score
  const score = Math.round(data.trust_score);
  trustScore.textContent = score;
  
  // Update progress ring
  updateProgressRing(score);
  
  // Update risk level badge
  const levelText = {
    'low': 'Safe',
    'medium': 'Caution',
    'high': 'High Risk'
  }[data.risk_level] || 'Unknown';
  
  riskLevel.textContent = levelText;
  riskBadge.className = `risk-badge ${data.risk_level}`;
  
  // Update website info
  websiteDomain.textContent = data.domain || 'Unknown';
  sslStatus.textContent = data.ssl_valid ? 'SSL Secured' : 'No SSL';
  sslStatus.style.color = data.ssl_valid ? '#10b981' : '#ef4444';
  
  // Update risk factors (show top 3)
  if (data.risk_factors && data.risk_factors.length > 0) {
    riskFactorsSection.classList.remove('hidden');
    riskFactorsList.innerHTML = '';
    data.risk_factors.slice(0, 3).forEach(factor => {
      const li = document.createElement('li');
      li.textContent = factor;
      riskFactorsList.appendChild(li);
    });
  } else {
    riskFactorsSection.classList.add('hidden');
  }
  
  // Update safety indicators (show top 3)
  if (data.safety_indicators && data.safety_indicators.length > 0) {
    safetySection.classList.remove('hidden');
    safetyList.innerHTML = '';
    data.safety_indicators.slice(0, 3).forEach(indicator => {
      const li = document.createElement('li');
      li.textContent = indicator;
      safetyList.appendChild(li);
    });
  } else {
    safetySection.classList.add('hidden');
  }
  
  // Update education message
  educationMessage.textContent = data.education_message || 'No additional information available.';
  
  // Update education icon based on risk level
  const icons = {
    'low': '✅',
    'medium': '⚠️',
    'high': '🚨'
  };
  educationIcon.textContent = icons[data.risk_level] || 'ℹ️';
  
  // Show main content
  showMain();
}

// Update progress ring
function updateProgressRing(score) {
  const circumference = 326.73; // 2 * PI * radius (52)
  const offset = circumference - (score / 100) * circumference;
  
  progressRing.style.strokeDashoffset = offset;
  
  // Update color based on score
  if (score >= 70) {
    progressRing.style.stroke = '#10b981'; // Green
  } else if (score >= 40) {
    progressRing.style.stroke = '#f59e0b'; // Orange
  } else {
    progressRing.style.stroke = '#ef4444'; // Red
  }
}

// Show loading state
function showLoading() {
  loadingState.classList.remove('hidden');
  errorState.classList.add('hidden');
  mainContent.classList.add('hidden');
}

// Show error state
function showError(title, message) {
  errorTitle.textContent = title;
  errorMessage.textContent = message;
  errorState.classList.remove('hidden');
  loadingState.classList.add('hidden');
  mainContent.classList.add('hidden');
}

// Show main content
function showMain() {
  mainContent.classList.remove('hidden');
  loadingState.classList.add('hidden');
  errorState.classList.add('hidden');
}

// Refresh button handler
refreshBtn.addEventListener('click', () => {
  chrome.runtime.sendMessage({ action: 'refreshRisk' }, (response) => {
    if (response && response.success) {
      setTimeout(() => {
        init();
      }, 500);
    }
  });
});

// Retry button handler
retryBtn.addEventListener('click', () => {
  init();
});

// Initialize when popup opens
init();