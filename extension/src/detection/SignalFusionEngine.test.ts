/**
 * PayGuard V2 - Signal Fusion Engine Tests
 * 
 * Tests for the Signal Fusion Engine that combines signals from
 * all detection layers using weighted scoring.
 */

import { SignalFusionEngine } from './SignalFusionEngine';
import {
  DetectionSignal,
  SignalSource,
  DEFAULT_SIGNAL_WEIGHTS,
  DEFAULT_RISK_THRESHOLDS
} from '../types/fusion';

describe('SignalFusionEngine', () => {
  let engine: SignalFusionEngine;

  beforeEach(() => {
    engine = new SignalFusionEngine();
  });

  describe('constructor', () => {
    it('should initialize with default configuration', () => {
      const config = engine.getConfig();
      expect(config.weights).toEqual(expect.objectContaining(DEFAULT_SIGNAL_WEIGHTS));
      expect(config.thresholds).toEqual(DEFAULT_RISK_THRESHOLDS);
    });

    it('should accept custom configuration', () => {
      const customEngine = new SignalFusionEngine({
        thresholds: { high: 0.8, medium: 0.5 }
      });
      const config = customEngine.getConfig();
      expect(config.thresholds.high).toBe(0.8);
      expect(config.thresholds.medium).toBe(0.5);
    });
  });

  describe('fuseSignals', () => {
    it('should return low risk for empty signals', () => {
      const result = engine.fuseSignals([]);
      expect(result.riskLevel).toBe('low');
      expect(result.confidence).toBe(0);
      expect(result.contributingSignals).toHaveLength(0);
    });

    it('should classify high risk correctly', () => {
      const signals: DetectionSignal[] = [
        createSignal('url_reputation', 0.9),
        createSignal('behavioral', 0.85),
        createSignal('ml_model', 0.8)
      ];

      const result = engine.fuseSignals(signals);
      expect(result.riskLevel).toBe('high');
      expect(result.rawScore).toBeGreaterThanOrEqual(0.7);
    });

    it('should classify medium risk correctly', () => {
      const signals: DetectionSignal[] = [
        createSignal('url_reputation', 0.5),
        createSignal('behavioral', 0.5)
      ];

      const result = engine.fuseSignals(signals);
      expect(result.riskLevel).toBe('medium');
      expect(result.rawScore).toBeGreaterThanOrEqual(0.4);
      expect(result.rawScore).toBeLessThan(0.7);
    });

    it('should classify low risk correctly', () => {
      const signals: DetectionSignal[] = [
        createSignal('url_reputation', 0.1),
        createSignal('behavioral', 0.2)
      ];

      const result = engine.fuseSignals(signals);
      expect(result.riskLevel).toBe('low');
      expect(result.rawScore).toBeLessThan(0.4);
    });

    it('should rank signals by contribution', () => {
      const signals: DetectionSignal[] = [
        createSignal('url_reputation', 0.9),
        createSignal('behavioral', 0.3),
        createSignal('ml_model', 0.6)
      ];

      const result = engine.fuseSignals(signals);
      expect(result.contributingSignals[0].rank).toBe(1);
      expect(result.contributingSignals[0].signal.source).toBe('url_reputation');
    });

    it('should calculate per-layer confidences', () => {
      const signals: DetectionSignal[] = [
        createSignal('url_reputation', 0.8, 0.9),
        createSignal('behavioral', 0.6, 0.7)
      ];

      const result = engine.fuseSignals(signals);
      expect(result.layerConfidences.get('url_reputation')).toBeGreaterThan(0);
      expect(result.layerConfidences.get('behavioral')).toBeGreaterThan(0);
    });

    it('should generate explanation', () => {
      const signals: DetectionSignal[] = [
        createSignal('url_reputation', 0.9)
      ];

      const result = engine.fuseSignals(signals);
      expect(result.explanation).toBeTruthy();
      expect(result.explanation.length).toBeGreaterThan(0);
    });

    it('should filter signals below minimum confidence', () => {
      const customEngine = new SignalFusionEngine({ minSignalConfidence: 0.5 });
      const signals: DetectionSignal[] = [
        createSignal('url_reputation', 0.9, 0.6),
        createSignal('behavioral', 0.9, 0.3) // Below threshold
      ];

      const result = customEngine.fuseSignals(signals);
      expect(result.contributingSignals).toHaveLength(1);
      expect(result.contributingSignals[0].signal.source).toBe('url_reputation');
    });

    it('should include processing time', () => {
      const signals: DetectionSignal[] = [createSignal('url_reputation', 0.5)];
      const result = engine.fuseSignals(signals);
      expect(result.processingTimeMs).toBeGreaterThanOrEqual(0);
    });

    it('should include fusion timestamp', () => {
      const signals: DetectionSignal[] = [createSignal('url_reputation', 0.5)];
      const result = engine.fuseSignals(signals);
      expect(result.fusedAt).toBeInstanceOf(Date);
    });
  });

  describe('getWeights', () => {
    it('should return weights as a Map', () => {
      const weights = engine.getWeights();
      expect(weights).toBeInstanceOf(Map);
      expect(weights.get('url_reputation')).toBeDefined();
    });

    it('should return all signal source weights', () => {
      const weights = engine.getWeights();
      expect(weights.size).toBe(4);
      expect(weights.has('url_reputation')).toBe(true);
      expect(weights.has('visual_fingerprint')).toBe(true);
      expect(weights.has('behavioral')).toBe(true);
      expect(weights.has('ml_model')).toBe(true);
    });
  });

  describe('updateWeights', () => {
    it('should update weights', () => {
      const newWeights = new Map<SignalSource, number>([
        ['url_reputation', 0.5]
      ]);

      engine.updateWeights(newWeights);
      const weights = engine.getWeights();
      
      // Weights are normalized, so check relative increase
      expect(weights.get('url_reputation')).toBeGreaterThan(weights.get('ml_model')!);
    });

    it('should clamp weights to valid range', () => {
      const newWeights = new Map<SignalSource, number>([
        ['url_reputation', 1.5],
        ['behavioral', -0.5]
      ]);

      engine.updateWeights(newWeights);
      const weights = engine.getWeights();
      
      // All weights should be between 0 and 1
      for (const [, weight] of weights) {
        expect(weight).toBeGreaterThanOrEqual(0);
        expect(weight).toBeLessThanOrEqual(1);
      }
    });
  });

  describe('updateConfig', () => {
    it('should update thresholds', () => {
      engine.updateConfig({ thresholds: { high: 0.9, medium: 0.6 } });
      const config = engine.getConfig();
      expect(config.thresholds.high).toBe(0.9);
      expect(config.thresholds.medium).toBe(0.6);
    });

    it('should update minSignalsForHighConfidence', () => {
      engine.updateConfig({ minSignalsForHighConfidence: 5 });
      const config = engine.getConfig();
      expect(config.minSignalsForHighConfidence).toBe(5);
    });
  });

  describe('calculateLayerConfidences', () => {
    it('should calculate confidence for each layer', () => {
      const signals: DetectionSignal[] = [
        createSignal('url_reputation', 0.8, 0.9),
        createSignal('behavioral', 0.6, 0.7),
        createSignal('ml_model', 0.5, 0.6)
      ];

      const confidences = engine.calculateLayerConfidences(signals);
      
      expect(confidences.get('url_reputation')).toBeCloseTo(0.9, 1);
      expect(confidences.get('behavioral')).toBeCloseTo(0.7, 1);
      expect(confidences.get('ml_model')).toBeCloseTo(0.6, 1);
    });

    it('should boost confidence for multiple agreeing signals', () => {
      const signals: DetectionSignal[] = [
        createSignal('url_reputation', 0.8, 0.7),
        { ...createSignal('url_reputation', 0.75, 0.7), name: 'signal2' }
      ];

      const confidences = engine.calculateLayerConfidences(signals);
      
      // Should be boosted above the average confidence
      expect(confidences.get('url_reputation')).toBeGreaterThan(0.7);
    });

    it('should return 0 for layers with no signals', () => {
      const signals: DetectionSignal[] = [
        createSignal('url_reputation', 0.8)
      ];

      const confidences = engine.calculateLayerConfidences(signals);
      
      expect(confidences.has('behavioral')).toBe(false);
    });
  });

  describe('resetToDefaults', () => {
    it('should reset configuration to defaults', () => {
      engine.updateConfig({ thresholds: { high: 0.9, medium: 0.6 } });
      engine.resetToDefaults();
      
      const config = engine.getConfig();
      expect(config.thresholds).toEqual(DEFAULT_RISK_THRESHOLDS);
    });
  });

  describe('weighted scoring', () => {
    it('should apply weights correctly', () => {
      // Create engine with specific weights
      const customEngine = new SignalFusionEngine({
        weights: {
          url_reputation: 0.8,
          visual_fingerprint: 0.1,
          behavioral: 0.05,
          ml_model: 0.05
        },
        normalizeWeights: false
      });

      const signals: DetectionSignal[] = [
        createSignal('url_reputation', 1.0),
        createSignal('visual_fingerprint', 0.0)
      ];

      const result = customEngine.fuseSignals(signals);
      
      // URL reputation should dominate due to higher weight
      expect(result.contributingSignals[0].signal.source).toBe('url_reputation');
    });

    it('should take max score when multiple signals from same source', () => {
      const signals: DetectionSignal[] = [
        createSignal('url_reputation', 0.3),
        { ...createSignal('url_reputation', 0.9), name: 'url_check_2' }
      ];

      const result = engine.fuseSignals(signals);
      
      // Should use the higher score (0.9)
      expect(result.contributingSignals[0].signal.score).toBe(0.9);
    });
  });

  describe('confidence calculation (Requirement 11.8)', () => {
    it('should provide per-layer confidence scores in results', () => {
      const signals: DetectionSignal[] = [
        createSignal('url_reputation', 0.8, 0.85),
        createSignal('visual_fingerprint', 0.6, 0.7),
        createSignal('behavioral', 0.5, 0.65),
        createSignal('ml_model', 0.4, 0.6)
      ];

      const result = engine.fuseSignals(signals);
      
      // Verify layerConfidences is populated
      expect(result.layerConfidences).toBeInstanceOf(Map);
      expect(result.layerConfidences.size).toBe(4);
      
      // Verify each layer has a confidence score
      expect(result.layerConfidences.get('url_reputation')).toBeGreaterThan(0);
      expect(result.layerConfidences.get('visual_fingerprint')).toBeGreaterThan(0);
      expect(result.layerConfidences.get('behavioral')).toBeGreaterThan(0);
      expect(result.layerConfidences.get('ml_model')).toBeGreaterThan(0);
    });

    it('should calculate higher confidence with more signals', () => {
      const singleSignal: DetectionSignal[] = [
        createSignal('url_reputation', 0.8, 0.8)
      ];

      const multipleSignals: DetectionSignal[] = [
        createSignal('url_reputation', 0.8, 0.8),
        createSignal('visual_fingerprint', 0.8, 0.8),
        createSignal('behavioral', 0.8, 0.8)
      ];

      const singleResult = engine.fuseSignals(singleSignal);
      const multipleResult = engine.fuseSignals(multipleSignals);
      
      // More signals should lead to higher confidence
      expect(multipleResult.confidence).toBeGreaterThan(singleResult.confidence);
    });

    it('should calculate higher confidence when signals agree', () => {
      const agreeingSignals: DetectionSignal[] = [
        createSignal('url_reputation', 0.8, 0.8),
        createSignal('visual_fingerprint', 0.8, 0.8),
        createSignal('behavioral', 0.8, 0.8)
      ];

      const disagreeingSignals: DetectionSignal[] = [
        createSignal('url_reputation', 0.9, 0.8),
        createSignal('visual_fingerprint', 0.3, 0.8),
        createSignal('behavioral', 0.6, 0.8)
      ];

      const agreeingResult = engine.fuseSignals(agreeingSignals);
      const disagreeingResult = engine.fuseSignals(disagreeingSignals);
      
      // Agreeing signals should have higher confidence
      expect(agreeingResult.confidence).toBeGreaterThan(disagreeingResult.confidence);
    });

    it('should return confidence as percentage (0-100)', () => {
      const signals: DetectionSignal[] = [
        createSignal('url_reputation', 0.8, 0.9),
        createSignal('behavioral', 0.7, 0.8)
      ];

      const result = engine.fuseSignals(signals);
      
      expect(result.confidence).toBeGreaterThanOrEqual(0);
      expect(result.confidence).toBeLessThanOrEqual(100);
      expect(Number.isInteger(result.confidence)).toBe(true);
    });

    it('should use signal confidence when available', () => {
      const highConfidenceSignals: DetectionSignal[] = [
        createSignal('url_reputation', 0.5, 0.95),
        createSignal('behavioral', 0.5, 0.95)
      ];

      const lowConfidenceSignals: DetectionSignal[] = [
        createSignal('url_reputation', 0.5, 0.3),
        createSignal('behavioral', 0.5, 0.3)
      ];

      const highResult = engine.fuseSignals(highConfidenceSignals);
      const lowResult = engine.fuseSignals(lowConfidenceSignals);
      
      // Higher signal confidence should lead to higher overall confidence
      expect(highResult.confidence).toBeGreaterThan(lowResult.confidence);
    });

    it('should fall back to score when confidence not provided', () => {
      const signalsWithoutConfidence: DetectionSignal[] = [
        { source: 'url_reputation', name: 'test', score: 0.8, weight: 0.3, details: {} },
        { source: 'behavioral', name: 'test2', score: 0.7, weight: 0.25, details: {} }
      ];

      const result = engine.fuseSignals(signalsWithoutConfidence);
      
      // Should still calculate confidence using scores
      expect(result.confidence).toBeGreaterThan(0);
      expect(result.layerConfidences.get('url_reputation')).toBeCloseTo(0.8, 1);
    });
  });
});

/**
 * Helper function to create a detection signal.
 */
function createSignal(
  source: SignalSource,
  score: number,
  confidence?: number
): DetectionSignal {
  return {
    source,
    name: `${source}_signal`,
    score,
    weight: DEFAULT_SIGNAL_WEIGHTS[source],
    details: {},
    confidence
  };
}
