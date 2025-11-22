# PayGuard Extension - Verification Checklist

## Before Testing
- [ ] Backend is running: `sudo supervisorctl status backend`
- [ ] Backend responds: `curl http://localhost:8001/api/health`
- [ ] Chrome browser is installed
- [ ] Developer mode is enabled in Chrome

## Installation Verification
- [ ] Extension loaded without errors in `chrome://extensions/`
- [ ] PayGuard shows in extensions list
- [ ] Extension is enabled (toggle is ON)
- [ ] No red error messages displayed
- [ ] Service worker is active

## Basic Functionality
- [ ] Navigate to https://google.com
- [ ] Badge appears in toolbar
- [ ] Badge shows a number (score)
- [ ] Badge has color (should be green for Google)
- [ ] Click badge → popup opens
- [ ] Popup shows trust score
- [ ] Popup shows risk level badge
- [ ] Popup shows domain name
- [ ] Popup shows SSL status

## Score Display Tests

### High Score (Safe - Green)
Test URLs: https://google.com, https://amazon.com, https://stripe.com

Expected:
- [ ] Badge color: Green
- [ ] Score: 70-100
- [ ] Risk badge: "Safe"
- [ ] Progress ring: Green
- [ ] Safety indicators shown
- [ ] No risk factors (or minimal)
- [ ] Education message: Positive tone

### Medium Score (Caution - Yellow)
Test URLs: Sites with some issues but not completely unsafe

Expected:
- [ ] Badge color: Yellow/Orange
- [ ] Score: 40-69
- [ ] Risk badge: "Caution"
- [ ] Progress ring: Orange
- [ ] Both risk factors AND safety indicators may show
- [ ] Education message: Warning tone

### Low Score (High Risk - Red)
Test URL: http://verify-account-urgent-update.com/payment

Expected:
- [ ] Badge color: Red
- [ ] Score: 0-39
- [ ] Risk badge: "High Risk"
- [ ] Progress ring: Red
- [ ] Risk factors shown (multiple)
- [ ] Few or no safety indicators
- [ ] Education message: Strong warning

### Non-HTTP Pages (Gray)
Test URLs: chrome://extensions/, about:blank, file:///

Expected:
- [ ] Badge color: Gray
- [ ] Badge text: "?"
- [ ] Popup: Shows pending/neutral state

## Interactive Features

### Refresh Button
- [ ] Refresh button visible in popup header
- [ ] Click refresh button
- [ ] Loading state appears briefly
- [ ] Score reloads
- [ ] UI updates with new data

### Tab Switching
- [ ] Open multiple tabs with different sites
- [ ] Switch between tabs
- [ ] Badge updates for each tab
- [ ] Each tab has independent score
- [ ] Popup shows correct data for active tab

### Page Navigation
- [ ] Navigate to new page in same tab
- [ ] Badge updates automatically
- [ ] No manual refresh needed
- [ ] New score appears within 1-2 seconds

## Error Handling

### Backend Offline
- [ ] Stop backend: `sudo supervisorctl stop backend`
- [ ] Navigate to any site
- [ ] Badge shows "!" (error indicator)
- [ ] Badge color: Gray
- [ ] Open popup
- [ ] Error message displayed clearly
- [ ] "Try Again" button appears
- [ ] Restart backend: `sudo supervisorctl start backend`
- [ ] Click "Try Again"
- [ ] Score loads successfully

### Invalid Response
- [ ] Backend returns error (test by modifying API)
- [ ] Extension handles gracefully
- [ ] No crash or freeze
- [ ] Error message shown to user

### Network Timeout
- [ ] Slow network simulation (if possible)
- [ ] Extension shows loading state
- [ ] Timeout handled gracefully
- [ ] User can retry

## UI/UX Quality

### Visual Design
- [ ] Colors are vibrant and clear
- [ ] Text is readable (good contrast)
- [ ] Icons render correctly
- [ ] Progress ring animates smoothly
- [ ] No visual glitches or overlaps
- [ ] Spacing looks balanced
- [ ] Gradients render properly

### Responsive Behavior
- [ ] Popup width: 380px (fixed)
- [ ] Content fits without horizontal scroll
- [ ] Vertical scroll appears if needed
- [ ] All elements visible
- [ ] No cutoff text or buttons

### Typography
- [ ] All text is legible
- [ ] Font sizes are appropriate
- [ ] No text overflow
- [ ] Line heights comfortable
- [ ] Headers stand out from body text

### Animations
- [ ] Progress ring animates on load
- [ ] Refresh button rotates on click
- [ ] Smooth transitions between states
- [ ] No janky animations
- [ ] Performance is smooth (60fps)

## Data Accuracy

### Risk Factors
- [ ] Risk factors match URL characteristics
- [ ] Maximum 3 factors shown
- [ ] Factors are relevant and specific
- [ ] Text is clear and understandable

### Safety Indicators
- [ ] Safety indicators are accurate
- [ ] Maximum 3 indicators shown
- [ ] Indicators are positive signals
- [ ] Text is encouraging when present

### Education Messages
- [ ] Message matches risk level
- [ ] Message is helpful and informative
- [ ] Message explains WHY site is safe/risky
- [ ] Message uses appropriate emoji
- [ ] Message tone is professional

## Performance

### Speed
- [ ] Badge update: < 1 second
- [ ] API response: < 500ms
- [ ] Popup open: Instant (< 100ms)
- [ ] Refresh: < 1 second
- [ ] No lag or stuttering

### Caching
- [ ] Visit same site twice
- [ ] Second load is faster (cached)
- [ ] Wait 5+ minutes
- [ ] Cache expires (new API call)
- [ ] Fresh data retrieved

### Memory Usage
- [ ] Open 10+ tabs with extension
- [ ] Chrome doesn't slow down significantly
- [ ] Extension uses < 100MB total
- [ ] No memory leaks over time

## Developer Tools

### Background Script Console
- [ ] Open: chrome://extensions/ → Inspect views: service worker
- [ ] Console shows API calls
- [ ] No unexpected errors
- [ ] Logs are informative

### Popup Console
- [ ] Right-click badge → Inspect popup
- [ ] Console opens for popup.html
- [ ] No errors on load
- [ ] State updates logged correctly

### Network Tab
- [ ] Check background script network tab
- [ ] API calls to localhost:8001 visible
- [ ] Responses are 200 OK
- [ ] Response time < 500ms
- [ ] Proper error codes on failures

## Edge Cases

### Special URLs
- [ ] HTTPS sites: Work correctly
- [ ] HTTP sites: Work correctly (show SSL warning)
- [ ] Subdomains: Handle correctly
- [ ] URLs with paths: Extract domain properly
- [ ] URLs with query params: Work correctly
- [ ] Internationalized domains: Handle gracefully

### Rapid Navigation
- [ ] Navigate quickly between sites
- [ ] Badge updates keep up
- [ ] No race conditions
- [ ] Correct score shows for current site
- [ ] No stale data displayed

### Long Running
- [ ] Keep browser open for 30+ minutes
- [ ] Extension continues working
- [ ] No degradation over time
- [ ] Service worker stays active
- [ ] No accumulation of errors

## API Integration

### Request Format
- [ ] GET /api/risk?url=... is called
- [ ] URL is properly encoded
- [ ] Headers are correct
- [ ] Method is GET (not POST)

### Response Handling
- [ ] trust_score parsed correctly (0-100)
- [ ] risk_level mapped correctly (low/medium/high)
- [ ] risk_factors array displayed
- [ ] safety_indicators array displayed
- [ ] ssl_valid boolean checked
- [ ] education_message shown
- [ ] All fields handled gracefully

### Error Responses
- [ ] 404: Handles gracefully
- [ ] 500: Shows error message
- [ ] Network error: Shows offline message
- [ ] Timeout: Shows retry option
- [ ] Invalid JSON: Doesn't crash

## Security

### Content Security Policy
- [ ] No CSP violations in console
- [ ] Inline scripts avoided
- [ ] External resources loaded correctly

### Permissions
- [ ] Extension has necessary permissions
- [ ] No excessive permissions requested
- [ ] activeTab, tabs, storage only

### Data Handling
- [ ] No sensitive data stored locally
- [ ] API keys not exposed (if used)
- [ ] URLs sent to API only (not third parties)

## Cross-Browser (Future)
- [ ] Chrome: Fully supported ✅
- [ ] Edge: (Chromium-based, should work)
- [ ] Firefox: (Needs Manifest V2 adaptation)
- [ ] Safari: (Needs conversion)

## Final Checks

### User Experience
- [ ] First-time user can understand immediately
- [ ] Color coding is intuitive (red=bad, green=good)
- [ ] Messages are helpful, not technical
- [ ] Extension adds value without being intrusive
- [ ] Trust score makes sense for various sites

### Production Readiness
- [ ] All features working
- [ ] No console errors
- [ ] Performance is acceptable
- [ ] Error handling is robust
- [ ] Documentation is complete

### Known Limitations (Expected)
- [ ] Placeholder icons (user will replace)
- [ ] Localhost backend URL (will update for production)
- [ ] Rule-based scoring (will replace with ML)

## Issue Tracking

Found issues:
```
Issue 1: _________________________
Status: _________________________
Priority: _______________________

Issue 2: _________________________
Status: _________________________
Priority: _______________________
```

## Sign-off

- [ ] All critical features tested
- [ ] All tests passed or issues documented
- [ ] Extension is ready for next phase (ML model)
- [ ] Extension is ready for production URL update
- [ ] Extension is ready for custom icons

---

**Tested by:** ____________________
**Date:** ____________________
**Version:** 1.0.0
**Status:** ☐ Pass  ☐ Pass with Issues  ☐ Fail

**Notes:**
_______________________________________________________________________________
_______________________________________________________________________________
_______________________________________________________________________________
