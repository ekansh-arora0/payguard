# PayGuard - Quick Start Guide (2 Minutes)

## What You Have
✅ Backend API running on http://localhost:8001  
✅ Chrome extension ready to install at `/app/extension`  

## Install Extension (30 seconds)

1. **Open Chrome and navigate to:**
   ```
   chrome://extensions/
   ```

2. **Enable Developer Mode** (top-right toggle)

3. **Click "Load unpacked"** → Select `/app/extension` folder

4. **Done!** You should see PayGuard in your extensions list

## Test It (30 seconds)

1. **Navigate to any website:**
   ```
   https://google.com
   ```

2. **Check toolbar** - You should see a green badge with a number (like "85")

3. **Click the PayGuard icon** - A popup appears showing:
   - Trust Score circle
   - Risk level badge (Safe/Caution/High Risk)
   - Website details
   - Risk factors or safety indicators
   - Educational message

4. **Try a suspicious URL:**
   ```
   http://verify-account-urgent.com/payment
   ```
   - Badge should turn RED
   - Score should be low (0-40)
   - Popup shows warnings

## That's It! 🎉

The extension is now protecting you from scam websites in real-time.

## Next Steps

1. **Read Full Documentation:**
   - Extension guide: `/app/extension/README.md`
   - Installation: `/app/extension/INSTALLATION.md`
   - Demo scenarios: `/app/extension/DEMO_GUIDE.md`
   - Backend API: `/app/backend/README.md`

2. **Replace Icons:**
   - Add custom icons to `/app/extension/icons/`
   - Reload extension in Chrome

3. **Train Your ML Model:**
   - Use data from MongoDB `risk_checks` collection
   - Replace `calculate_risk()` in `/app/backend/risk_engine.py`
   - Test predictions

4. **Deploy to Production:**
   - Deploy backend to your server
   - Update extension URLs
   - Submit to Chrome Web Store

## Troubleshooting

**Badge not showing?**
```bash
# Check backend
curl http://localhost:8001/api/health

# Restart if needed
sudo supervisorctl restart backend
```

**Extension error?**
- Go to `chrome://extensions/`
- Click refresh icon on PayGuard
- Check for error messages

**Need help?**
- Check documentation in `/app/extension/`
- Review test results in `/app/test_result.md`
- See complete guide in `/app/PAYGUARD_COMPLETE_GUIDE.md`

---

**You're all set!** Browse the web with PayGuard protection. 🛡️
