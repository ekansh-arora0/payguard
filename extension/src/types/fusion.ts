/**
 * PayGuard V2 - Signal Fusion Types
 * 
 * Interfaces for the Signal Fusion Engine that combines signals
 * from all detection layers using weighted scoring.
 * Implements Requirements 11.6, 11.7, 11.8
 */

/**
 * Source of a detection signal.
 */
export type SignalSource = 
  | 'url_reputation'
  | 'visual_fingerprint'
  | 'behavioral'
  | 'ml_model';

/**
 * A detection signal from one of the detection layers.
 */
export interface DetectionSignal {
  /** Source layer that generated this signal */
  source: SignalSource;
  /** Name/identifier of the signal */
  name: string;
  /** Score from this signal (0-1) */
  score: number;
  /** Weight assigned to this signal type */
  weight: number;
  /** Additional details about the signal */
  details: Record<string, unknown>;
  /** Confidence of this specific signal (0-1) */
  confidence?: number;
  /** Timestamp when signal was generated */
  timestamp?: Date;
}

/**
 * Risk level classification.
 */
export type RiskLevel = 'low' | 'medium' | 'high';

/**
 * A signal with its contribution to the final score.
 */
export interface RankedSignal {
  /** The original signal */
  signal: DetectionSignal;
  /** How much this signal contributed to the final score (0-1) */
  contribution: number;
  /** Rank among all signals (1 = highest contribution) */
  rank: number;
}

/**
 * Result of signal fusion.
 */
export interface FusionResult {
  /** Final risk level classification */
  riskLevel: RiskLevel;
  /** Overall confidence score (0-100) */
  confidence: number;
  /** Signals ranked by their contribution */
  contributingSignals: RankedSignal[];
  /** Human-readable explanation of the verdict */
  explanation: string;
  /** Raw fused score before classification (0-1) */
  rawScore: number;
  /** Per-layer confidence scores */
  layerConfidences: Map<SignalSource, number>;
  /** Processing time in milliseconds */
  processingTimeMs: number;
  /** Timestamp of fusion */
  fusedAt: Date;
}

/**
 * Default weights for each signal source.
 */
export const DEFAULT_SIGNAL_WEIGHTS: Record<SignalSource, number> = {
  url_reputation: 0.30,
  visual_fingerprint: 0.25,
  behavioral: 0.25,
  ml_model: 0.20
};

/**
 * Thresholds for risk level classification.
 */
export interface RiskThresholds {
  /** Score above this is HIGH risk */
  high: number;
  /** Score above this (but below high) is MEDIUM risk */
  medium: number;
  /** Score below medium threshold is LOW risk */
}

/**
 * Default risk thresholds.
 */
export const DEFAULT_RISK_THRESHOLDS: RiskThresholds = {
  high: 0.7,
  medium: 0.4
};

/**
 * Configuration for the Signal Fusion Engine.
 */
export interface SignalFusionConfig {
  /** Weights for each signal source */
  weights: Record<SignalSource, number>;
  /** Risk level thresholds */
  thresholds: RiskThresholds;
  /** Minimum number of signals required for high confidence */
  minSignalsForHighConfidence: number;
  /** Whether to normalize weights automatically */
  normalizeWeights: boolean;
  /** Minimum confidence to include a signal */
  minSignalConfidence: number;
}

/**
 * Default Signal Fusion configuration.
 */
export const DEFAULT_FUSION_CONFIG: SignalFusionConfig = {
  weights: { ...DEFAULT_SIGNAL_WEIGHTS },
  thresholds: { ...DEFAULT_RISK_THRESHOLDS },
  minSignalsForHighConfidence: 3,
  normalizeWeights: true,
  minSignalConfidence: 0.1
};

/**
 * Interface for the Signal Fusion Engine.
 */
export interface ISignalFusionEngine {
  /** Fuse signals into a final verdict */
  fuseSignals(signals: DetectionSignal[]): FusionResult;
  
  /** Get current weights for all signal sources */
  getWeights(): Map<SignalSource, number>;
  
  /** Update weights (enterprise feature) */
  updateWeights(weights: Map<SignalSource, number>): void;
  
  /** Get current configuration */
  getConfig(): SignalFusionConfig;
  
  /** Update configuration */
  updateConfig(config: Partial<SignalFusionConfig>): void;
  
  /** Calculate per-layer confidence scores */
  calculateLayerConfidences(signals: DetectionSignal[]): Map<SignalSource, number>;
  
  /** Reset to default configuration */
  resetToDefaults(): void;
}

/**
 * Statistics about fusion operations.
 */
export interface FusionStats {
  /** Total number of fusions performed */
  totalFusions: number;
  /** Average number of signals per fusion */
  avgSignalsPerFusion: number;
  /** Distribution of risk levels */
  riskLevelDistribution: Record<RiskLevel, number>;
  /** Average processing time in milliseconds */
  avgProcessingTimeMs: number;
  /** Most common contributing signal sources */
  topContributingSources: SignalSource[];
}
