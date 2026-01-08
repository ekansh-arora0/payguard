/**
 * PayGuard V2 - ML Pipeline Types
 * 
 * Interfaces for the ML Pipeline that provides on-device inference
 * for threat detection using ONNX runtime.
 * Implements Requirements 6.1, 6.2, 6.3, 6.6, 6.7
 */

/**
 * URL features extracted for ML inference.
 */
export interface URLFeatures {
  /** Total URL length */
  length: number;
  /** Number of dots in URL */
  dotCount: number;
  /** Number of hyphens in URL */
  hyphenCount: number;
  /** Number of underscores in URL */
  underscoreCount: number;
  /** Number of slashes in URL */
  slashCount: number;
  /** Number of digits in URL */
  digitCount: number;
  /** Number of special characters */
  specialCharCount: number;
  /** Whether URL uses HTTPS */
  isHttps: boolean;
  /** Whether URL contains IP address */
  hasIPAddress: boolean;
  /** Domain length */
  domainLength: number;
  /** Path length */
  pathLength: number;
  /** Query string length */
  queryLength: number;
  /** Number of subdomains */
  subdomainCount: number;
  /** Whether domain uses suspicious TLD */
  hasSuspiciousTLD: boolean;
  /** Entropy of the URL */
  entropy: number;
  /** Whether URL contains @ symbol */
  hasAtSymbol: boolean;
  /** Whether URL contains double slashes in path */
  hasDoubleSlash: boolean;
  /** Whether URL contains port number */
  hasPort: boolean;
  /** Ratio of digits to total characters */
  digitRatio: number;
  /** Ratio of letters to total characters */
  letterRatio: number;
}

/**
 * Content features extracted for ML inference.
 */
export interface ContentFeatures {
  /** Number of forms in the page */
  formCount: number;
  /** Number of input fields */
  inputCount: number;
  /** Number of password fields */
  passwordFieldCount: number;
  /** Number of external links */
  externalLinkCount: number;
  /** Number of internal links */
  internalLinkCount: number;
  /** Number of images */
  imageCount: number;
  /** Number of scripts */
  scriptCount: number;
  /** Number of iframes */
  iframeCount: number;
  /** Whether page has favicon */
  hasFavicon: boolean;
  /** Whether page title matches domain */
  titleMatchesDomain: boolean;
  /** Number of hidden elements */
  hiddenElementCount: number;
  /** Whether page has login form */
  hasLoginForm: boolean;
  /** Whether page requests sensitive data */
  requestsSensitiveData: boolean;
  /** Text to HTML ratio */
  textToHtmlRatio: number;
  /** Number of suspicious keywords */
  suspiciousKeywordCount: number;
  /** Number of urgency keywords */
  urgencyKeywordCount: number;
  /** Whether page has copyright notice */
  hasCopyright: boolean;
  /** Whether page has privacy policy link */
  hasPrivacyPolicy: boolean;
  /** Whether page has terms of service link */
  hasTermsOfService: boolean;
}

/**
 * ML model prediction result.
 */
export interface MLPrediction {
  /** Predicted label */
  label: 'safe' | 'suspicious' | 'malicious';
  /** Confidence score (0-1) */
  confidence: number;
  /** Probability distribution across labels */
  probabilities: Map<string, number>;
  /** Feature importance scores */
  features: FeatureImportance[];
  /** Model version used */
  modelVersion: string;
  /** Inference time in milliseconds */
  inferenceTimeMs: number;
}

/**
 * Feature importance for explainability.
 */
export interface FeatureImportance {
  /** Feature name */
  name: string;
  /** Importance score */
  importance: number;
  /** Feature value */
  value: number | boolean | string;
}

/**
 * Information about a loaded ML model.
 */
export interface ModelInfo {
  /** Model identifier */
  id: string;
  /** Model version */
  version: string;
  /** Model type */
  type: 'url_classifier' | 'content_classifier' | 'visual_classifier';
  /** Model format */
  format: 'onnx' | 'tflite' | 'coreml';
  /** Model size in bytes */
  sizeBytes: number;
  /** Last update timestamp */
  lastUpdated: Date;
  /** Cryptographic signature for integrity verification */
  signature: string;
  /** Model description */
  description?: string;
  /** Input feature names */
  inputFeatures: string[];
  /** Output labels */
  outputLabels: string[];
}

/**
 * Model health status.
 */
export interface ModelHealth {
  /** Whether model is loaded */
  loaded: boolean;
  /** Whether model is healthy */
  healthy: boolean;
  /** Last inference timestamp */
  lastInference: Date | null;
  /** Average inference time in milliseconds */
  avgInferenceMs: number;
  /** Error rate (0-1) */
  errorRate: number;
  /** Number of inferences performed */
  inferenceCount: number;
  /** Number of errors */
  errorCount: number;
}

/**
 * Model signature verification result.
 */
export interface SignatureVerificationResult {
  /** Whether signature is valid */
  valid: boolean;
  /** Signer identity (if valid) */
  signer?: string;
  /** Verification timestamp */
  verifiedAt: Date;
  /** Error message (if invalid) */
  error?: string;
}

/**
 * Configuration for the ML Pipeline.
 */
export interface MLPipelineConfig {
  /** Maximum inference time in milliseconds */
  maxInferenceTimeMs: number;
  /** Whether to enable model signature verification */
  enableSignatureVerification: boolean;
  /** Whether to enable fallback to rule-based detection */
  enableFallback: boolean;
  /** Confidence threshold for predictions */
  confidenceThreshold: number;
  /** Model cache directory */
  modelCacheDir?: string;
  /** Whether to use GPU acceleration if available */
  useGPU: boolean;
  /** Number of threads for inference */
  numThreads: number;
}

/**
 * Default ML Pipeline configuration.
 */
export const DEFAULT_ML_CONFIG: MLPipelineConfig = {
  maxInferenceTimeMs: 200,
  enableSignatureVerification: true,
  enableFallback: true,
  confidenceThreshold: 0.7,
  useGPU: false,
  numThreads: 2
};

/**
 * Rule-based detection result (fallback).
 */
export interface RuleBasedResult {
  /** Risk level */
  riskLevel: 'low' | 'medium' | 'high';
  /** Confidence score */
  confidence: number;
  /** Rules that triggered */
  triggeredRules: TriggeredRule[];
  /** Processing time in milliseconds */
  processingTimeMs: number;
}

/**
 * A rule that was triggered during rule-based detection.
 */
export interface TriggeredRule {
  /** Rule identifier */
  id: string;
  /** Rule name */
  name: string;
  /** Rule description */
  description: string;
  /** Severity level */
  severity: 'low' | 'medium' | 'high' | 'critical';
  /** Evidence that triggered the rule */
  evidence: string;
}

/**
 * Interface for the ML Pipeline.
 */
export interface IMLPipeline {
  /** Run inference on URL features */
  predictUrl(features: URLFeatures): Promise<MLPrediction>;
  
  /** Run inference on page content */
  predictContent(features: ContentFeatures): Promise<MLPrediction>;
  
  /** Load a model */
  loadModel(modelId: string): Promise<void>;
  
  /** Unload a model */
  unloadModel(modelId: string): Promise<void>;
  
  /** Get model info */
  getModelInfo(modelId?: string): ModelInfo | null;
  
  /** Check model health */
  healthCheck(): Promise<ModelHealth>;
  
  /** Verify model signature */
  verifyModelSignature(modelData: Uint8Array, signature: string): Promise<SignatureVerificationResult>;
  
  /** Get current configuration */
  getConfig(): MLPipelineConfig;
  
  /** Update configuration */
  updateConfig(config: Partial<MLPipelineConfig>): void;
  
  /** Get available models */
  getAvailableModels(): ModelInfo[];
  
  /** Fall back to rule-based detection */
  fallbackDetection(urlFeatures?: URLFeatures, contentFeatures?: ContentFeatures): Promise<RuleBasedResult>;
}

/**
 * ML Pipeline error codes.
 */
export enum MLPipelineErrorCode {
  MODEL_NOT_FOUND = 'MODEL_NOT_FOUND',
  MODEL_LOAD_FAILED = 'MODEL_LOAD_FAILED',
  INFERENCE_FAILED = 'INFERENCE_FAILED',
  INFERENCE_TIMEOUT = 'INFERENCE_TIMEOUT',
  SIGNATURE_INVALID = 'SIGNATURE_INVALID',
  SIGNATURE_MISSING = 'SIGNATURE_MISSING',
  FEATURE_EXTRACTION_FAILED = 'FEATURE_EXTRACTION_FAILED',
  RUNTIME_NOT_AVAILABLE = 'RUNTIME_NOT_AVAILABLE'
}

/**
 * ML Pipeline error.
 */
export class MLPipelineError extends Error {
  constructor(
    message: string,
    public code: MLPipelineErrorCode,
    public recoverable: boolean = true
  ) {
    super(message);
    this.name = 'MLPipelineError';
  }
}
