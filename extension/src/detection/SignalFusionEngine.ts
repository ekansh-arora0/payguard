/**
 * PayGuard V2 - Signal Fusion Engine
 * 
 * Combines signals from all detection layers (URL reputation, visual fingerprint,
 * behavioral analysis, ML models) using weighted scoring to produce a final
 * threat verdict with confidence scores.
 * 
 * Implements Requirements 11.6, 11.7, 11.8
 */

import {
  DetectionSignal,
  FusionResult,
  RankedSignal,
  RiskLevel,
  SignalSource,
  SignalFusionConfig,
  ISignalFusionEngine,
  DEFAULT_FUSION_CONFIG,
  DEFAULT_SIGNAL_WEIGHTS
} from '../types/fusion';

/**
 * Signal Fusion Engine implementation.
 * 
 * Combines detection signals from multiple layers using weighted scoring
 * to produce a unified threat assessment.
 */
export class SignalFusionEngine implements ISignalFusionEngine {
  private config: SignalFusionConfig;

  constructor(config: Partial<SignalFusionConfig> = {}) {
    this.config = {
      ...DEFAULT_FUSION_CONFIG,
      ...config,
      weights: { ...DEFAULT_FUSION_CONFIG.weights, ...config.weights },
      thresholds: { ...DEFAULT_FUSION_CONFIG.thresholds, ...config.thresholds }
    };

    // Normalize weights if configured
    if (this.config.normalizeWeights) {
      this.normalizeWeights();
    }
  }

  /**
   * Fuse signals from all detection layers into a final verdict.
   * 
   * @param signals - Array of detection signals from various layers
   * @returns FusionResult with risk level, confidence, and contributing signals
   */
  fuseSignals(signals: DetectionSignal[]): FusionResult {
    const startTime = performance.now();

    // Filter signals below minimum confidence threshold
    const validSignals = signals.filter(
      s => (s.confidence ?? 1) >= this.config.minSignalConfidence
    );

    // Calculate weighted score
    const { rawScore, rankedSignals } = this.calculateWeightedScore(validSignals);

    // Determine risk level from raw score
    const riskLevel = this.classifyRiskLevel(rawScore);

    // Calculate overall confidence
    const confidence = this.calculateOverallConfidence(validSignals, rawScore);

    // Calculate per-layer confidences
    const layerConfidences = this.calculateLayerConfidences(validSignals);

    // Generate explanation
    const explanation = this.generateExplanation(riskLevel, rankedSignals, confidence);

    const processingTimeMs = performance.now() - startTime;

    return {
      riskLevel,
      confidence,
      contributingSignals: rankedSignals,
      explanation,
      rawScore,
      layerConfidences,
      processingTimeMs,
      fusedAt: new Date()
    };
  }

  /**
   * Get current weights for all signal sources.
   */
  getWeights(): Map<SignalSource, number> {
    return new Map(Object.entries(this.config.weights) as [SignalSource, number][]);
  }

  /**
   * Update weights for signal sources (enterprise feature).
   * 
   * @param weights - New weights to apply
   */
  updateWeights(weights: Map<SignalSource, number>): void {
    weights.forEach((weight, source) => {
      if (source in this.config.weights) {
        this.config.weights[source] = Math.max(0, Math.min(1, weight));
      }
    });

    if (this.config.normalizeWeights) {
      this.normalizeWeights();
    }
  }

  /**
   * Get current configuration.
   */
  getConfig(): SignalFusionConfig {
    return { ...this.config };
  }

  /**
   * Update configuration.
   */
  updateConfig(config: Partial<SignalFusionConfig>): void {
    if (config.weights) {
      this.config.weights = { ...this.config.weights, ...config.weights };
    }
    if (config.thresholds) {
      this.config.thresholds = { ...this.config.thresholds, ...config.thresholds };
    }
    if (config.minSignalsForHighConfidence !== undefined) {
      this.config.minSignalsForHighConfidence = config.minSignalsForHighConfidence;
    }
    if (config.normalizeWeights !== undefined) {
      this.config.normalizeWeights = config.normalizeWeights;
    }
    if (config.minSignalConfidence !== undefined) {
      this.config.minSignalConfidence = config.minSignalConfidence;
    }

    if (this.config.normalizeWeights) {
      this.normalizeWeights();
    }
  }

  /**
   * Calculate per-layer confidence scores.
   * 
   * @param signals - Detection signals to analyze
   * @returns Map of signal source to confidence score
   */
  calculateLayerConfidences(signals: DetectionSignal[]): Map<SignalSource, number> {
    const layerConfidences = new Map<SignalSource, number>();
    const layerSignals = new Map<SignalSource, DetectionSignal[]>();

    // Group signals by source
    for (const signal of signals) {
      const existing = layerSignals.get(signal.source) || [];
      existing.push(signal);
      layerSignals.set(signal.source, existing);
    }

    // Calculate confidence for each layer
    for (const [source, sourceSignals] of layerSignals) {
      if (sourceSignals.length === 0) {
        layerConfidences.set(source, 0);
        continue;
      }

      // Average confidence of signals from this layer
      const avgConfidence = sourceSignals.reduce(
        (sum, s) => sum + (s.confidence ?? s.score),
        0
      ) / sourceSignals.length;

      // Boost confidence if multiple signals from same layer agree
      const agreementBoost = Math.min(0.2, (sourceSignals.length - 1) * 0.05);
      
      const finalConfidence = Math.min(1, avgConfidence + agreementBoost);
      layerConfidences.set(source, finalConfidence);
    }

    return layerConfidences;
  }

  /**
   * Reset to default configuration.
   */
  resetToDefaults(): void {
    this.config = { ...DEFAULT_FUSION_CONFIG };
  }

  /**
   * Calculate weighted score from signals.
   */
  private calculateWeightedScore(signals: DetectionSignal[]): {
    rawScore: number;
    rankedSignals: RankedSignal[];
  } {
    if (signals.length === 0) {
      return { rawScore: 0, rankedSignals: [] };
    }

    // Group signals by source and take the max score per source
    const sourceScores = new Map<SignalSource, { score: number; signal: DetectionSignal }>();
    
    for (const signal of signals) {
      const existing = sourceScores.get(signal.source);
      if (!existing || signal.score > existing.score) {
        sourceScores.set(signal.source, { score: signal.score, signal });
      }
    }

    // Calculate weighted sum
    let totalWeight = 0;
    let weightedSum = 0;
    const contributions: { signal: DetectionSignal; contribution: number }[] = [];

    for (const [source, { score, signal }] of sourceScores) {
      const weight = this.config.weights[source] ?? DEFAULT_SIGNAL_WEIGHTS[source] ?? 0.1;
      const contribution = score * weight;
      
      weightedSum += contribution;
      totalWeight += weight;
      
      contributions.push({ signal, contribution });
    }

    // Normalize by total weight
    const rawScore = totalWeight > 0 ? weightedSum / totalWeight : 0;

    // Rank signals by contribution
    contributions.sort((a, b) => b.contribution - a.contribution);
    
    const rankedSignals: RankedSignal[] = contributions.map((c, index) => ({
      signal: c.signal,
      contribution: c.contribution,
      rank: index + 1
    }));

    return { rawScore, rankedSignals };
  }

  /**
   * Classify risk level based on raw score.
   */
  private classifyRiskLevel(rawScore: number): RiskLevel {
    if (rawScore >= this.config.thresholds.high) {
      return 'high';
    }
    if (rawScore >= this.config.thresholds.medium) {
      return 'medium';
    }
    return 'low';
  }

  /**
   * Calculate overall confidence in the verdict.
   */
  private calculateOverallConfidence(signals: DetectionSignal[], rawScore: number): number {
    if (signals.length === 0) {
      return 0;
    }

    // Base confidence from number of signals
    const signalCountFactor = Math.min(1, signals.length / this.config.minSignalsForHighConfidence);

    // Confidence from signal agreement (variance)
    const scores = signals.map(s => s.score);
    const avgScore = scores.reduce((a, b) => a + b, 0) / scores.length;
    const variance = scores.reduce((sum, s) => sum + Math.pow(s - avgScore, 2), 0) / scores.length;
    const agreementFactor = 1 - Math.min(1, variance * 4); // Lower variance = higher agreement

    // Confidence from individual signal confidences
    const avgSignalConfidence = signals.reduce(
      (sum, s) => sum + (s.confidence ?? s.score),
      0
    ) / signals.length;

    // Combine factors
    const rawConfidence = (
      signalCountFactor * 0.3 +
      agreementFactor * 0.3 +
      avgSignalConfidence * 0.4
    );

    // Scale to 0-100
    return Math.round(rawConfidence * 100);
  }

  /**
   * Generate human-readable explanation of the verdict.
   */
  private generateExplanation(
    riskLevel: RiskLevel,
    rankedSignals: RankedSignal[],
    confidence: number
  ): string {
    if (rankedSignals.length === 0) {
      return 'No detection signals available for analysis.';
    }

    const riskDescriptions: Record<RiskLevel, string> = {
      high: 'This page shows strong indicators of being malicious',
      medium: 'This page shows some suspicious characteristics',
      low: 'This page appears to be safe'
    };

    const topSignals = rankedSignals.slice(0, 3);
    const signalDescriptions = topSignals.map(rs => {
      const sourceNames: Record<SignalSource, string> = {
        url_reputation: 'URL reputation check',
        visual_fingerprint: 'visual similarity analysis',
        behavioral: 'behavioral analysis',
        ml_model: 'machine learning analysis'
      };
      return sourceNames[rs.signal.source] || rs.signal.source;
    });

    let explanation = `${riskDescriptions[riskLevel]} (${confidence}% confidence). `;
    
    if (riskLevel !== 'low') {
      explanation += `Key factors: ${signalDescriptions.join(', ')}.`;
    } else {
      explanation += `Analysis based on ${signalDescriptions.join(', ')}.`;
    }

    return explanation;
  }

  /**
   * Normalize weights to sum to 1.
   */
  private normalizeWeights(): void {
    const sources = Object.keys(this.config.weights) as SignalSource[];
    const totalWeight = sources.reduce((sum, source) => sum + this.config.weights[source], 0);
    
    if (totalWeight > 0 && totalWeight !== 1) {
      for (const source of sources) {
        this.config.weights[source] /= totalWeight;
      }
    }
  }
}
