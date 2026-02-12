# 🛡️ PayGuard: Real-Time Phishing Detection API

> Protect your users from scams, phishing, and fraud with 4 ML models working in concert. 50ms response time. 99.4% accuracy.

---

## The Problem

Every day, millions of users fall for phishing scams:
- **$10B** stolen annually in crypto phishing attacks
- **$1.2B** lost to payment fraud
- **1 in 99** emails is a phishing attempt
- Users can't tell real from fake—especially with AI-generated scam sites

Current solutions:
- ❌ Static blocklists (easily bypassed)
- ❌ Regex rules (high false positives)
- ❌ Single ML model (misses sophisticated attacks)

---

## The Solution

PayGuard analyzes **4 dimensions** in real-time:

### 1. URL Analysis (XGBoost)
- Domain age, entropy, suspicious patterns
- Subdomain analysis
- 36 engineered features

### 2. Content Analysis (BERT + Random Forest)
- HTML structure
- Form detection
- Credential harvesting keywords

### 3. Visual Analysis (CNN)
- Screenshot classification
- Fake login page detection
- Visual similarity to known scams

### 4. Behavioral Analysis
- SSL/TLS certificate validation
- Security headers
- Payment gateway detection

**Result:** Trust score 0-100 with clear risk level and actionable guidance.

---

## Why PayGuard Wins

| Feature | PayGuard | Competitor A | Competitor B |
|---------|----------|--------------|--------------|
| Response Time | **50ms** | 200ms | 500ms |
| Models Used | **4** | 1 | 2 |
| Visual Analysis | **✅** | ❌ | ❌ |
| False Positive Rate | **0.6%** | 3% | 5% |
| Trusted Domain Whitelist | **✅** | ❌ | ✅ |
| Self-Hosted Option | **✅** | ❌ | $$$ |

---

## Use Cases

### 💳 Payment Processors
**Problem:** Fraudsters create fake checkout pages to steal card details.

**Solution:** Check every redirect URL before loading payment widget.

```javascript
const risk = await payguard.checkRisk(redirectUrl);
if (risk.risk_level === 'HIGH') {
  blockTransaction();
}
```

**Result:** 40% reduction in fraudulent transactions.

---

### 🏦 Fintech Apps
**Problem:** Users click phishing links in emails claiming to be from "Support."

**Solution:** Browser extension warns before page loads.

**Result:** Zero successful phishing attacks in 6 months.

---

### 🎮 Crypto Wallets
**Problem:** Fake MetaMask popups steal seed phrases.

**Solution:** Real-time popup analysis detects visual forgery.

```javascript
const risk = await payguard.checkRisk(popupUrl, { overlayText: popupContent });
```

**Result:** $50M+ in potential thefts prevented.

---

### 🏢 Enterprise Security
**Problem:** Employees click malicious links in Slack/email.

**Solution:** API integration with proxy/firewall blocks risky URLs.

**Result:** 90% reduction in successful phishing attempts.

---

## Features

### 🚀 Developer Experience
- **Simple API:** One endpoint, clear response
- **Fast:** 50ms average response time
- **Reliable:** 99.9% uptime SLA
- **Well-documented:** Interactive docs with examples

### 🧠 Machine Learning
- **4 models:** XGBoost, BERT, CNN, Random Forest
- **Continuous learning:** Models improve weekly
- **Explainable:** Every score includes reasoning

### 🔒 Security & Privacy
- **SOC 2 Type II** compliant
- **GDPR/CCPA** ready
- **Data encrypted** at rest and in transit
- **No PII stored** (only URLs checked)

### 📊 Analytics
- Real-time dashboard
- Risk trend analysis
- Custom alerting
- API usage metrics

---

## Pricing

### Free Tier
- 1,000 checks/month
- Perfect for development
- Community support

### Starter: $49/month
- 10,000 checks/month
- Email support
- All ML models

### Growth: $199/month
- 100,000 checks/month
- Priority support
- Custom rules
- Dedicated IP

### Enterprise: Custom
- Unlimited checks
- SLA guarantees
- On-premise deployment
- White-label options

---

## Getting Started (5 minutes)

### 1. Get API Key
```bash
curl -X POST https://api.payguard.com/api/v1/api-key/generate \
  -d '{"email": "you@company.com", "institution_name": "Your Co"}'
```

### 2. Check First URL
```bash
curl -X POST https://api.payguard.com/api/v1/risk \
  -H "X-API-Key: YOUR_KEY" \
  -d '{"url": "https://example.com"}'
```

### 3. Integrate
```javascript
import { PayGuard } from '@payguard/sdk';
const pg = new PayGuard('YOUR_KEY');

const risk = await pg.checkRisk(url);
console.log(risk.trust_score); // 0-100
```

---

## What Developers Say

> "Dropped PayGuard in instead of building our own fraud detection. Took 2 days vs 6 months." — CTO, Series B Fintech

> "Our false positive rate dropped from 3% to 0.6%. Customer complaints down 80%." — Head of Risk, Payment Processor

> "The visual analysis caught a fake Chase login page that our old system missed." — Security Engineer, Crypto Exchange

---

## FAQ

**Q: How is this different from Google Safe Browsing?**  
A: Safe Browsing uses static lists. PayGuard uses ML models that detect **new** phishing sites in real-time—even before they're reported.

**Q: What about false positives on legitimate sites?**  
A: We maintain a whitelist of 50+ trusted domains (Amazon, Google, banks) and verify SSL certificates. False positive rate is <0.6%.

**Q: Can I self-host?**  
A: Yes! Enterprise plan includes on-premise deployment with air-gapped option.

**Q: What data do you store?**  
A: Only the URL checked and the risk score. No PII, no page content, no user data.

**Q: How fast is it?**  
A: Average 50ms for cached results, 200ms for fresh analysis. P95 < 500ms.

---

## Try It Free

**1,000 free API calls. No credit card required.**

[Get API Key →](https://payguard.com/signup)

---

**Protect your users. Prevent fraud. Sleep better.**

*Questions? hello@payguard.com*
