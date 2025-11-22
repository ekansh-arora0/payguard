# PayGuard Extension - Quick Installation Guide

## Prerequisites
✅ Chrome browser installed  
✅ PayGuard backend running on http://localhost:8001  

## Installation Steps (5 minutes)

### 1. Verify Backend is Running

```bash
# Check backend status
sudo supervisorctl status backend

# Test API endpoint
curl http://localhost:8001/api/health
```

Expected response:
```json
{"status": "healthy", "timestamp": "..."}
```

### 2. Load Extension in Chrome

**Method 1: Direct Navigation**
1. Copy this URL: `chrome://extensions/`
2. Paste in Chrome address bar
3. Press Enter

**Method 2: Menu Navigation**
1. Click three dots (⋮) in Chrome
2. Go to: Extensions → Manage Extensions

### 3. Enable Developer Mode
- Look for "Developer mode" toggle in top-right
- Turn it ON (should be blue)

### 4. Load the Extension
1. Click **"Load unpacked"** button
2. Navigate to: `/app/extension`
3. Click **"Select Folder"**

### 5. Verify Installation
You should see:
- ✅ PayGuard listed in extensions
- ✅ Status: Enabled
- ✅ No errors shown

### 6. Pin to Toolbar (Optional)
1. Click puzzle icon (🧩) in Chrome toolbar
2. Find "PayGuard"
3. Click pin icon (📌)
4. Extension icon appears in toolbar

## Test the Extension

### Quick Test (1 minute)

1. **Navigate to a safe site:**
   ```
   https://google.com
   ```
   - Check toolbar: Should show GREEN badge with score (e.g., "85")
   - Click PayGuard icon
   - Popup shows: Trust Score, "Safe" badge, details

2. **Try different sites:**
   - https://amazon.com (should be green/safe)
   - https://stripe.com (should be green/safe)

3. **Test refresh:**
   - Click refresh icon in popup
   - Score should reload

## Visual Guide

```
Chrome Browser
┌─────────────────────────────────────┐
│ [Address Bar]              [🧩 🔔 👤]│
│                                      │
│ Click PayGuard icon →                │
│                                      │
│  ┌──────────────────────┐           │
│  │ PayGuard    🔄       │           │
│  ├──────────────────────┤           │
│  │                      │           │
│  │       ⭕ 85          │           │
│  │    Trust Score       │           │
│  │      [Safe]          │           │
│  │                      │           │
│  │  🌐 google.com       │           │
│  │  🔒 SSL Secured      │           │
│  │                      │           │
│  │  Safety Indicators   │           │
│  │  • Valid SSL cert    │           │
│  │  • Established domain│           │
│  │                      │           │
│  └──────────────────────┘           │
└─────────────────────────────────────┘
```

## Badge Colors Explained

| Badge | Score | Meaning |
|-------|-------|---------|
| 🟢 Green | 70-100 | ✅ Safe for transactions |
| 🟡 Yellow | 40-69 | ⚠️ Exercise caution |
| 🔴 Red | 0-39 | 🚨 High risk - avoid |
| ⚪ Gray | - | Internal/non-HTTP page |

## Troubleshooting

### ❌ "Manifest file is missing"
**Fix:** Select the `/app/extension` folder, not its parent

### ❌ No badge showing
**Fix:** 
```bash
# Restart backend
sudo supervisorctl restart backend

# Reload extension
Go to chrome://extensions/ → Click refresh icon
```

### ❌ "Connection Error" in popup
**Fix:**
```bash
# Check backend is listening
netstat -tlnp | grep 8001

# Check backend logs
tail -n 50 /var/log/supervisor/backend.out.log
```

### ❌ Badge shows "?"
**Normal:** This happens on chrome://, file://, and other non-HTTP pages

## Updating After Code Changes

1. Edit extension files (background.js, popup.js, etc.)
2. Go to: `chrome://extensions/`
3. Click refresh icon (🔄) on PayGuard
4. Reload any open tabs
5. Test changes

## Uninstall

1. Go to: `chrome://extensions/`
2. Find PayGuard
3. Click "Remove"
4. Confirm deletion

## Configuration

### Change Backend URL

Edit both files:

**File: background.js** (Line 3)
```javascript
const API_BASE_URL = 'http://localhost:8001/api';
// Change to: 'https://your-domain.com/api'
```

**File: popup.js** (Line 3)
```javascript
const API_BASE_URL = 'http://localhost:8001/api';
// Change to: 'https://your-domain.com/api'
```

Then reload extension.

## Next Steps

1. ✅ Extension installed and working
2. 🔄 Test with various websites
3. 🔄 Replace placeholder icons (icons/*.png)
4. 🔄 Train ML model and update backend
5. 🔄 Deploy backend to production
6. 🔄 Update extension URLs
7. 🔄 Publish to Chrome Web Store

## Support

**Backend not responding?**
```bash
sudo supervisorctl restart backend
```

**Extension not updating?**
```bash
# In Chrome: chrome://extensions/ → Refresh PayGuard
```

**Need API documentation?**
See: `/app/backend/README.md`

---

**Ready to Test!** 🚀  
Navigate to any website and click the PayGuard icon.
