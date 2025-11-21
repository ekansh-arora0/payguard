# PayGuard Browser Extension

## Overview
PayGuard is a Chrome extension that provides real-time website and merchant risk scoring to protect you from online financial scams. It automatically checks every website you visit and displays a trust score with detailed safety information.

## Features

### Core Functionality
- ✅ **Real-time Risk Assessment**: Automatically scans every page you visit
- ✅ **Trust Score (0-100)**: Clear numerical rating of website safety
- ✅ **Color-Coded Badges**: Red/Yellow/Green indicators in browser
- ✅ **Risk Factors**: Up to 3 top reasons for concern
- ✅ **Safety Indicators**: Positive security features detected
- ✅ **Educational Messages**: Learn why sites are risky or safe
- ✅ **SSL Detection**: Shows if site has valid certificate
- ✅ **Offline Handling**: Graceful error states

### UI Features
- Modern, clean popup dashboard
- Real-time progress ring for trust score
- Detailed risk breakdown
- One-click refresh
- Responsive error handling

## Installation Instructions

### Step 1: Ensure Backend is Running
Make sure the PayGuard backend API is running on `http://localhost:8001`:

```bash
cd /app/backend
sudo supervisorctl status backend
# Should show: backend RUNNING
```

Test the API:
```bash
curl http://localhost:8001/api/health
```

### Step 2: Load Extension in Chrome

1. **Open Chrome Extensions Page**:
   - Navigate to `chrome://extensions/` in your browser
   - OR click the three dots menu → Extensions → Manage Extensions

2. **Enable Developer Mode**:
   - Toggle the "Developer mode" switch in the top right corner

3. **Load Unpacked Extension**:
   - Click "Load unpacked" button
   - Navigate to `/app/extension` directory
   - Click "Select Folder"

4. **Verify Installation**:
   - You should see "PayGuard" in your extensions list
   - The extension should show as "Enabled"

5. **Pin Extension (Optional)**:
   - Click the puzzle piece icon in Chrome toolbar
   - Find PayGuard and click the pin icon
   - Extension icon will appear in toolbar

### Step 3: Test the Extension

1. **Visit a Website**:
   - Navigate to any HTTPS website (e.g., https://google.com)
   - The extension will automatically scan the URL

2. **Check the Badge**:
   - Look at the extension icon in your toolbar
   - You should see a colored badge with a trust score number

3. **Open the Popup**:
   - Click the PayGuard icon in toolbar
   - View detailed risk assessment:
     * Trust score with progress ring
     * Risk level (Safe/Caution/High Risk)
     * Domain and SSL status
     * Risk factors (if any)
     * Safety indicators
     * Educational message

4. **Test Different Sites**:
   - Try safe sites: amazon.com, google.com, stripe.com
   - Try suspicious patterns: URLs with "verify-account" or IP addresses
   - Watch how badges and scores change

## How It Works

### Architecture

```
┌─────────────────┐
│   Background    │
│  Service Worker │
│ (background.js) │
└────────┬────────┘
         │
         ├─ Monitors tab updates
         ├─ Calls API: GET /api/risk?url={url}
         ├─ Caches results (5 min)
         └─ Updates badge color & text
              │
              v
    ┌─────────────────┐
    │  Popup UI       │
    │ (popup.html/js) │
    └─────────────────┘
         │
         ├─ Displays trust score
         ├─ Shows risk factors
         ├─ Educational messages
         └─ Refresh button
```

### Badge Colors
- 🟢 **Green (70-100)**: Safe website, low risk
- 🟡 **Yellow (40-69)**: Exercise caution
- 🔴 **Red (0-39)**: High risk, avoid transactions
- ⚪ **Gray**: Error or non-HTTP page

### Risk Scoring
The extension displays risk scores calculated by the backend API:
- **SSL Validation**: +15 points for valid certificate
- **Domain Age**: +15 for established domains (>1 year)
- **Payment Gateways**: +10 for trusted gateways
- **Suspicious Patterns**: -25 for phishing indicators
- **Fraud Reports**: -20 for high fraud rates
- **Blacklist**: -30 if flagged in database

## Configuration

### Backend URL
Default: `http://localhost:8001/api`

To change the backend URL (for production deployment):

1. Edit `background.js`:
   ```javascript
   const API_BASE_URL = 'https://your-api-domain.com/api';
   ```

2. Edit `popup.js`:
   ```javascript
   const API_BASE_URL = 'https://your-api-domain.com/api';
   ```

3. Reload the extension in Chrome

### Cache Duration
Default: 5 minutes

To change caching behavior, edit `background.js`:
```javascript
const CACHE_DURATION = 5 * 60 * 1000; // milliseconds
```

## Custom Icons

The extension includes placeholder icons. For production:

1. Replace the following files in `icons/` directory:
   - `icon16.png` (16x16 pixels)
   - `icon48.png` (48x48 pixels)
   - `icon128.png` (128x128 pixels)

2. Use your custom PayGuard branding
3. Reload the extension to see new icons

## Troubleshooting

### Extension not loading
- **Issue**: "Manifest file is missing or unreadable"
- **Fix**: Ensure you're selecting the `/app/extension` folder, not a parent directory

### No badge appearing
- **Issue**: Extension icon shows no colored badge
- **Fix**: 
  1. Check backend is running: `curl http://localhost:8001/api/health`
  2. Check browser console for errors
  3. Try refreshing the page

### "Connection Error" in popup
- **Issue**: Popup shows connection error
- **Fix**:
  1. Verify backend is running on port 8001
  2. Check CORS is enabled in backend (already configured)
  3. Ensure URL in extension matches backend URL

### Badge shows "?"
- **Issue**: Badge displays question mark
- **Fix**: This is normal for non-HTTP pages (chrome://, file://, etc.)

### Scores seem incorrect
- **Issue**: Risk scores don't match expectations
- **Fix**: 
  1. This is the rule-based system - train your ML model for better accuracy
  2. Check backend logs: `tail -f /var/log/supervisor/backend.out.log`
  3. Test API directly: `curl http://localhost:8001/api/risk?url=https://example.com`

### Extension not updating
- **Issue**: Changes not appearing after code edits
- **Fix**:
  1. Go to `chrome://extensions/`
  2. Click the refresh icon on PayGuard extension
  3. Reload any open tabs

## Development Tips

### Debugging Background Script
```bash
# In Chrome, go to:
chrome://extensions/
# Click "Inspect views: background page" under PayGuard
# Opens DevTools for background service worker
```

### Debugging Popup
```bash
# Right-click the extension icon → Inspect popup
# Opens DevTools for popup.html
```

### Testing Error States

1. **Offline Mode**:
   - Stop backend: `sudo supervisorctl stop backend`
   - Refresh page, open popup
   - Should show "Connection Error"

2. **Invalid URL**:
   - Navigate to `chrome://extensions/`
   - Should show gray "?" badge

3. **High Risk Site**:
   - Test with: `http://verify-account-urgent.com/payment`
   - Should show red badge and high risk warning

## API Integration

The extension makes GET requests to:
```
GET http://localhost:8001/api/risk?url={encoded_url}
```

Expected response format:
```json
{
  "url": "https://example.com",
  "domain": "example.com",
  "trust_score": 85.0,
  "risk_level": "low",
  "ssl_valid": true,
  "risk_factors": ["Recently registered domain"],
  "safety_indicators": ["Valid SSL certificate", "Uses Stripe"],
  "education_message": "✅ This website appears safe...",
  "checked_at": "2025-01-15T10:30:00"
}
```

## Performance

- **Request Caching**: 5-minute cache to reduce API calls
- **Badge Updates**: Real-time on tab switch/load
- **Response Time**: < 500ms per check (backend requirement)
- **Memory Usage**: ~10MB per tab (minimal overhead)

## Security Notes

1. **Local Development**: Extension connects to localhost:8001
2. **Production**: Update URLs to HTTPS endpoints
3. **API Keys**: Not required for public endpoints (add if needed)
4. **CORS**: Backend configured for all origins (restrict in production)

## Next Steps

1. ✅ **Extension is ready for testing**
2. 🔄 **Train your ML model** using backend data
3. 🔄 **Replace placeholder icons** with custom branding
4. 🔄 **Deploy backend** to production server
5. 🔄 **Update extension** with production URL
6. 🔄 **Submit to Chrome Web Store** (when ready)

## File Structure

```
/app/extension/
├── manifest.json       # Extension configuration (Manifest V3)
├── background.js       # Service worker - monitors tabs, calls API
├── popup.html          # Popup dashboard HTML
├── popup.js            # Popup logic and UI updates
├── popup.css           # Popup styling
├── icons/              # Extension icons
│   ├── icon16.png
│   ├── icon48.png
│   ├── icon128.png
│   └── icon.svg        # SVG source
├── ICON_NOTE.txt       # Note about placeholder icons
└── README.md           # This file
```

## Version History

- **v1.0.0** (Current)
  - Initial release
  - Real-time risk scoring
  - Color-coded badges
  - Detailed popup dashboard
  - Error handling
  - Caching system

## Support

For issues or questions:
1. Check backend logs: `/var/log/supervisor/backend.*.log`
2. Check browser console for extension errors
3. Test API directly with curl
4. Review `/app/backend/README.md` for API documentation
