/**
 * PayGuard V2 - Extension Core
 * 
 * Main entry point for the PayGuard browser extension.
 */

// Types
export * from './types/consent';
export * from './types/storage';
export * from './types/audit';
export * from './types/privacy';

// Consent Management
export { ConsentManager } from './consent/ConsentManager';
export type { ConsentChangeCallback, CapabilityStopCallback } from './consent/ConsentManager';
export { ConsentUI } from './consent/ConsentUI';
export type { 
  ConsentRequestOptions, 
  ConsentDialogResult, 
  ConsentScreenData, 
  CapabilityInfo 
} from './consent/ConsentUI';

// Privacy
export { PrivacyController } from './privacy/PrivacyController';
export type { ConsentChecker } from './privacy/PrivacyController';
export { NetworkInterceptor } from './privacy/NetworkInterceptor';
export type { InterceptionResult, RequestInfo } from './privacy/NetworkInterceptor';
export { SignalExtractor } from './privacy/SignalExtractor';
export type { ContentInput, ExtractedSignals } from './privacy/SignalExtractor';
export { NetworkActivityLogger } from './privacy/NetworkActivityLogger';
export type { NetworkActivityFilter, NetworkActivityStats } from './privacy/NetworkActivityLogger';

// Storage
export { BrowserSecureStorage, secureStorage } from './storage/SecureStorage';
export { RAMEphemeralStorage, createEphemeralStorage } from './storage/EphemeralStorage';

// Audit
export { BasicAuditLogger } from './audit/AuditLogger';

// Detection
export * from './types/fingerprint';
export { VisualFingerprintAnalyzer, getDefaultBrandFingerprints } from './detection/VisualFingerprintAnalyzer';
export { 
  getAllBrandFingerprints, 
  getBrandsByCategory, 
  getBrandsByPriority, 
  searchBrands,
  getBrandCount
} from './detection/BrandDatabase';
export type { BrandCategory, CategorizedBrandFingerprint } from './detection/BrandDatabase';
