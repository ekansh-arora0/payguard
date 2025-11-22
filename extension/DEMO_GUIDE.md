# PayGuard Extension Demo Guide

## What You'll See

### Safe Website (Green Badge)
Navigate to: `https://google.com` or `https://amazon.com`

**Badge Display:**
```
[🛡️ 85] ← Green badge with score
```

**Popup Shows:**
```
╔════════════════════════════╗
║    PayGuard         🔄     ║
╠════════════════════════════╣
║                            ║
║         ⭕ 85              ║
║       Trust Score          ║
║         [Safe]             ║
║                            ║
║   🌐 google.com            ║
║   🔒 SSL Secured           ║
║                            ║
║   ✅ Safety Indicators     ║
║   • Valid SSL certificate  ║
║   • Domain age: 2 years    ║
║   • Uses trusted gateway   ║
║                            ║
║   ℹ️ This website appears  ║
║   safe for transactions.   ║
║   It has valid security    ║
║   measures and no red      ║
║   flags.                   ║
║                            ║
╚════════════════════════════╝
```

### Caution Website (Yellow Badge)
Test URL: Any site with medium score (40-69)

**Badge Display:**
```
[🛡️ 55] ← Yellow/Orange badge
```

**Popup Shows:**
```
╔════════════════════════════╗
║    PayGuard         🔄     ║
╠════════════════════════════╣
║                            ║
║         ⭕ 55              ║
║       Trust Score          ║
║       [Caution]            ║
║                            ║
║   ⚠️ Risk Factors          ║
║   • Recently registered    ║
║   • No payment gateway     ║
║                            ║
║   ⚠️ Exercise caution      ║
║   with this website.       ║
║   Verify merchant before   ║
║   making payments.         ║
║                            ║
╚════════════════════════════╝
```

### High Risk Website (Red Badge)
Test URL: `http://verify-account-urgent-update.com/payment`

**Badge Display:**
```
[🛡️ 15] ← Red badge with low score
```

**Popup Shows:**
```
╔════════════════════════════╗
║    PayGuard         🔄     ║
╠════════════════════════════╣
║                            ║
║         ⭕ 15              ║
║       Trust Score          ║
║      [High Risk]           ║
║                            ║
║   🚨 Risk Factors          ║
║   • No valid SSL cert      ║
║   • New domain (<3 months) ║
║   • Suspicious patterns    ║
║                            ║
║   🚨 HIGH RISK - We        ║
║   strongly recommend       ║
║   avoiding transactions    ║
║   on this website. This    ║
║   site may be a scam.      ║
║                            ║
╚════════════════════════════╝
```

### Internal Page (Gray Badge)
Navigate to: `chrome://extensions/`

**Badge Display:**
```
[🛡️ ?] ← Gray badge with "?"
```

**Popup Shows:**
```
╔════════════════════════════╗
║    PayGuard         🔄     ║
╠════════════════════════════╣
║                            ║
║      [Analysis             ║
║       Pending]             ║
║                            ║
║   Internal or non-HTTP     ║
║   page detected. PayGuard  ║
║   only analyzes standard   ║
║   websites.                ║
║                            ║
╚════════════════════════════╝
```

### Offline/Error (Gray Badge)
Backend not running or network issue

**Badge Display:**
```
[🛡️ !] ← Gray badge with "!"
```

**Popup Shows:**
```
╔════════════════════════════╗
║    PayGuard         🔄     ║
╠════════════════════════════╣
║                            ║
║         ⚠️                 ║
║                            ║
║   Connection Error         ║
║                            ║
║   Unable to connect to     ║
║   PayGuard API. Please     ║
║   check your connection    ║
║   and try again.           ║
║                            ║
║      [Try Again]           ║
║                            ║
╚════════════════════════════╝
```

## Test Sequence (5 minutes)

### Step 1: Install Extension
Follow INSTALLATION.md

### Step 2: Test Safe Site
```
1. Navigate to: https://google.com
2. Check badge: Should be GREEN with high score (70-100)
3. Click extension icon
4. Verify:
   ✓ Trust score displayed
   ✓ "Safe" badge shown
   ✓ Safety indicators listed
   ✓ Green color scheme
   ✓ Positive education message
```

### Step 3: Test Suspicious Site
```
1. Create test: http://verify-account.com
2. Check badge: Should be RED or YELLOW
3. Click extension icon
4. Verify:
   ✓ Low trust score (0-40)
   ✓ "High Risk" badge shown
   ✓ Risk factors listed
   ✓ Red color scheme
   ✓ Warning education message
```

### Step 4: Test Refresh
```
1. On any website
2. Click refresh button (🔄) in popup
3. Verify:
   ✓ Shows loading spinner
   ✓ Score refreshes
   ✓ UI updates
```

### Step 5: Test Error Handling
```
1. Stop backend: sudo supervisorctl stop backend
2. Navigate to any site
3. Check badge: Should show "!"
4. Click extension icon
5. Verify:
   ✓ "Connection Error" shown
   ✓ Error message displayed
   ✓ "Try Again" button available
6. Restart backend: sudo supervisorctl start backend
7. Click "Try Again"
8. Verify: Score loads successfully
```

## Real-World Test Sites

### Expected Safe (Green)
- https://google.com (85-95)
- https://amazon.com (80-90)
- https://stripe.com (90-100)
- https://github.com (85-95)
- https://microsoft.com (80-90)

### Expected Caution (Yellow)
- New startups with SSL
- Sites without payment gateways
- Recently launched domains
- Personal websites

### Expected High Risk (Red)
- No SSL certificate (HTTP only)
- Suspicious URL patterns (verify-*, urgent-*, etc.)
- IP addresses in URL
- Very new domains (<90 days)
- High fraud report count

## Features Demo

### 1. Auto-Scanning
```
✓ Switch tabs → Badge updates automatically
✓ Load new page → Badge updates in real-time
✓ No manual action needed
```

### 2. Caching
```
✓ Visit same site twice → Second load is instant
✓ Cache expires after 5 minutes
✓ Click refresh to bypass cache
```

### 3. Progressive Details
```
✓ Badge: Quick color glance
✓ Popup: Full risk breakdown
✓ Education: Learn why it's safe/risky
```

### 4. Error Recovery
```
✓ API down → Shows error, not crash
✓ Invalid response → Handles gracefully
✓ Network timeout → Retry available
```

## API Calls You'll See

The extension makes these calls:

```bash
# When you visit google.com
GET http://localhost:8001/api/risk?url=https%3A%2F%2Fgoogle.com

# Backend responds with:
{
  "trust_score": 85,
  "risk_level": "low",
  "risk_factors": [],
  "safety_indicators": ["Valid SSL", "Established domain"],
  "education_message": "✅ Safe for transactions..."
}

# Extension displays:
- Badge: Green "85"
- Popup: Full details
```

## Performance Expectations

| Action | Expected Time |
|--------|---------------|
| Page load → Badge update | < 1 second |
| Badge update → API call | < 500ms |
| Click icon → Popup open | Instant |
| Click refresh → New score | < 1 second |

## Visual States

### Score Circle Colors
```
 0-39:  🔴 Red ring
40-69:  🟡 Orange ring
70-100: 🟢 Green ring
```

### Badge States
```
[85] Green  ← Safe
[55] Yellow ← Caution
[15] Red    ← High Risk
[?]  Gray   ← Non-HTTP
[!]  Gray   ← Error
```

## Developer Console

### View Background Logs
```
1. chrome://extensions/
2. Click "Inspect views: service worker"
3. See console logs:
   - "Checking risk for URL: ..."
   - "Error checking URL risk: ..."
```

### View Popup Logs
```
1. Right-click extension icon
2. Click "Inspect popup"
3. See console logs:
   - Risk data received
   - UI update events
```

## Known Behaviors

✅ **Expected:**
- Gray badge on chrome:// pages
- ? badge on file:// pages
- Instant updates on tab switch
- 5-min cached results

❌ **Not Bugs:**
- No badge on browser UI pages
- Different scores on reload (backend logic)
- Gray badge when offline

## Success Criteria

Extension is working if:
- ✅ Badge appears on all HTTP/HTTPS sites
- ✅ Colors match risk levels (red/yellow/green)
- ✅ Popup shows detailed information
- ✅ Refresh button works
- ✅ Error states are handled gracefully
- ✅ No console errors in normal operation

## Next: Production Checklist

Before deploying:
- [ ] Replace placeholder icons
- [ ] Update API URL to production
- [ ] Test on various sites
- [ ] Add API key if needed
- [ ] Enable error tracking
- [ ] Submit to Chrome Web Store

---

**Ready to demo!** Install the extension and start browsing! 🚀
