// PayGuard Scam Monitor - Periodic screen checking for scam pop-ups
// Runs in background and triggers alerts when scams are detected

const SCAM_MONITOR_CONFIG = {
    CHECK_INTERVAL: 30000, // 30 seconds
    IDLE_THRESHOLD: 300000, // 5 minutes - pause monitoring when idle
    API_URL: 'http://localhost:8001/api/media-risk-screen',
    MIN_CONFIDENCE: 80 // Only alert on high-confidence detections
};

class ScamMonitor {
    constructor() {
        this.isMonitoring = false;
        this.lastActivity = Date.now();
        this.lastScamAlert = null;
        this.alertDebounce = 60000; // Don't show same alert within 1 minute
    }

    // Start monitoring
    start() {
        if (this.isMonitoring) return;
        this.isMonitoring = true;
        console.log('[PayGuard] Scam monitor started');

        // Set up periodic check
        this.checkInterval = setInterval(() => {
            this.performCheck();
        }, SCAM_MONITOR_CONFIG.CHECK_INTERVAL);

        // Monitor user activity
        this.setupActivityTracking();
    }

    // St op monitoring
    stop() {
        this.isMonitoring = false;
        if (this.checkInterval) {
            clearInterval(this.checkInterval);
        }
        console.log('[PayGuard] Scam monitor stopped');
    }

    // Set up activity tracking to pause when idle
    setupActivityTracking() {
        // Chrome idle detection
        if (chrome.idle) {
            chrome.idle.setDetectionInterval(300); // 5 minutes
            chrome.idle.onStateChanged.addListener((state) => {
                if (state === 'active') {
                    this.lastActivity = Date.now();
                }
            });
        }
    }

    // Check if user is active
    isUserActive() {
        const timeSinceActivity = Date.now() - this.lastActivity;
        return timeSinceActivity < SCAM_MONITOR_CONFIG.IDLE_THRESHOLD;
    }

    // Perform scam check
    async performCheck() {
        // Skip if not monitoring or user is idle
        if (!this.isMonitoring || !this.isUserActive()) {
            return;
        }

        try {
            const response = await fetch(SCAM_MONITOR_CONFIG.API_URL, {
                method: 'GET',
                headers: {
                    'Content-Type': 'application/json'
                }
            });

            if (!response.ok) {
                console.error('[PayGuard] API error:', response.status);
                return;
            }

            const data = await response.json();

            // Check if scam was detected
            if (data.scam_alert && data.scam_alert.is_scam) {
                const scamAlert = data.scam_alert;

                // Only alert if confidence meets threshold
                if (scamAlert.confidence >= SCAM_MONITOR_CONFIG.MIN_CONFIDENCE) {
                    // Debounce to avoid repeated alerts
                    if (this.shouldShowAlert(scamAlert)) {
                        this.showScamAlert(scamAlert);
                        this.lastScamAlert = {
                            timestamp: Date.now(),
                            patterns: scamAlert.detected_patterns
                        };
                    }
                }
            }

        } catch (error) {
            console.error('[PayGuard] Scam check error:', error);
        }
    }

    // Check if should show alert (debouncing logic)
    shouldShowAlert(scamAlert) {
        if (!this.lastScamAlert) return true;

        const timeSinceLastAlert = Date.now() - this.lastScamAlert.timestamp;
        if (timeSinceLastAlert < this.alertDebounce) {
            // Check if it's the same scam pattern
            const samePatterns = this.lastScamAlert.patterns.some(p => scamAlert.detected_patterns.includes(p));
            if (samePatterns) {
                return false; // Skip duplicate alert
            }
        }

        return true;
    }

    // Show scam alert overlay
    async showScamAlert(scamAlert) {
        // Get active tab
        const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
        if (!tabs || tabs.length === 0) return;

        const tabId = tabs[0].id;

        // Send message to content script to show overlay
        try {
            await chrome.tabs.sendMessage(tabId, {
                action: 'showScamAlert',
                scamAlert: scamAlert
            });
        } catch (error) {
            console.error('[PayGuard] Error showing alert:', error);
        }

        // Optionally show browser notification as backup
        if (chrome.notifications) {
            chrome.notifications.create({
                type: 'basic',
                iconUrl: chrome.runtime.getURL('icons/icon48.png'),
                title: '🛡️ PayGuard: SCAM DETECTED!',
                message: scamAlert.senior_message,
                priority: 2,
                requireInteraction: true
            });
        }
    }
}

// Initialize scam monitor
const scamMonitor = new ScamMonitor();

// Start monitoring when extension loads
chrome.runtime.onStartup.addListener(() => {
    scamMonitor.start();
});

// Also start on install
chrome.runtime.onInstalled.addListener(() => {
    scamMonitor.start();
});

// Start immediately
scamMonitor.start();

// Listen for messages from popup or content scripts
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.action === 'getMonitorStatus') {
        sendResponse({ isMonitoring: scamMonitor.isMonitoring });
    } else if (request.action === 'toggleMonitor') {
        if (scamMonitor.isMonitoring) {
            scamMonitor.stop();
        } else {
            scamMonitor.start();
        }
        sendResponse({ isMonitoring: scamMonitor.isMonitoring });
    }
    return true;
});
