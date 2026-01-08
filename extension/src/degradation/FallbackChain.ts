/**
 * PayGuard V2 - Fallback Detection Chain
 * 
 * Implements a fallback chain for detection that gracefully degrades
 * through multiple detection layers when primary methods fail.
 * 
 * Requirements 7.1, 7.2: API unavailable → local ML → URL reputation → blocklist
 */

import {
  DetectionLayer,
  LayerStatus,
  FallbackChainConfig,
  FallbackChainResult,
  IFallbackChain,
  FallbackExhaustedError,
  DEFAULT_FALLBACK_CHAIN_CONFIG
} from '../types/degradation';
import { CircuitBreaker } from './CircuitBreaker';

/**
 * Detection result from any layer.
 */
export interface DetectionResult {
  /** Risk level */
  riskLevel: 'low' | 'medium' | 'high';
  /** Confidence score (0-1) */
  confidence: number;
  /** Detection signals */
  signals: Array<{
    name: string;
    score: number;
    source: string;
  }>;
  /** Processing time in ms */
  processingTimeMs: number;
}

/**
 * Detection input for the fallback chain.
 */
export interface DetectionInput {
  /** URL to analyze */
  url: string;
  /** Optional page content */
  content?: string;
  /** Optional DOM structure */
  dom?: unknown;
}

/**
 * Layer handler function type.
 */
export type LayerHandler = (input: DetectionInput) => Promise<DetectionResult>;

/**
 * Fallback Detection Chain implementation.
 * 
 * Tries detection layers in order until one succeeds:
 * 1. API (cloud-based detection)
 * 2. Local ML (on-device ML models)
 * 3. URL Reputation (threat intelligence feeds)
 * 4. Blocklist (static blocklist)
 */
export class FallbackChain implements IFallbackChain<DetectionResult> {
  private config: FallbackChainConfig;
  private layerStatuses: Map<DetectionLayer, LayerStatus> = new Map();
  private layerHandlers: Map<DetectionLayer, LayerHandler> = new Map();
  private circuitBreakers: Map<DetectionLayer, CircuitBreaker> = new Map();

  constructor(config: Partial<FallbackChainConfig> = {}) {
    this.config = { ...DEFAULT_FALLBACK_CHAIN_CONFIG, ...config };
    this.initializeLayerStatuses();
    this.initializeCircuitBreakers();
  }

  /**
   * Register a handler for a detection layer.
   */
  registerHandler(layer: DetectionLayer, handler: LayerHandler): void {
    this.layerHandlers.set(layer, handler);
    this.markLayerAvailable(layer);
  }

  /**
   * Execute detection with fallback chain.
   * 
   * @param input - Detection input
   * @returns Detection result from the first successful layer
   * @throws FallbackExhaustedError if all layers fail
   */
  async execute(input: unknown): Promise<FallbackChainResult<DetectionResult>> {
    const detectionInput = input as DetectionInput;
    const startTime = Date.now();
    const triedLayers: DetectionLayer[] = [];
    const failedLayers: DetectionLayer[] = [];

    for (const layer of this.config.layerOrder) {
      // Skip if layer is not available
      if (!this.isLayerAvailable(layer)) {
        continue;
      }

      const handler = this.layerHandlers.get(layer);
      if (!handler) {
        continue;
      }

      triedLayers.push(layer);
      const circuitBreaker = this.circuitBreakers.get(layer);

      try {
        // Execute with circuit breaker and timeout
        const result = await this.executeWithTimeout(
          async () => {
            if (circuitBreaker) {
              return circuitBreaker.execute(() => handler(detectionInput));
            }
            return handler(detectionInput);
          },
          this.config.layerTimeoutMs
        );

        // Update layer status on success
        this.updateLayerStatus(layer, true, result.processingTimeMs);

        return {
          result,
          layer,
          triedLayers,
          failedLayers,
          totalTimeMs: Date.now() - startTime
        };
      } catch (error) {
        // Update layer status on failure
        const errorMessage = error instanceof Error ? error.message : String(error);
        this.updateLayerStatus(layer, false, null, errorMessage);
        failedLayers.push(layer);

        // Continue to next layer if configured
        if (!this.config.continueOnTimeout && this.isTimeoutError(error)) {
          break;
        }
      }
    }

    // All layers failed
    throw new FallbackExhaustedError(triedLayers);
  }

  /**
   * Get layer statuses.
   */
  getLayerStatuses(): Map<DetectionLayer, LayerStatus> {
    return new Map(this.layerStatuses);
  }

  /**
   * Check if a specific layer is available.
   */
  isLayerAvailable(layer: DetectionLayer): boolean {
    const status = this.layerStatuses.get(layer);
    if (!status) {
      return false;
    }

    // Check circuit breaker state
    const circuitBreaker = this.circuitBreakers.get(layer);
    if (circuitBreaker && circuitBreaker.getState() === 'open') {
      return false;
    }

    return status.available;
  }

  /**
   * Manually mark a layer as unavailable.
   */
  markLayerUnavailable(layer: DetectionLayer, error: string): void {
    const status = this.layerStatuses.get(layer);
    if (status) {
      status.available = false;
      status.lastError = error;
      status.lastChecked = new Date();
    }
  }

  /**
   * Manually mark a layer as available.
   */
  markLayerAvailable(layer: DetectionLayer): void {
    const status = this.layerStatuses.get(layer);
    if (status) {
      status.available = true;
      status.lastError = null;
      status.lastChecked = new Date();
    }
  }

  /**
   * Get the current active layer (first available layer).
   */
  getActiveLayer(): DetectionLayer | null {
    for (const layer of this.config.layerOrder) {
      if (this.isLayerAvailable(layer) && this.layerHandlers.has(layer)) {
        return layer;
      }
    }
    return null;
  }

  /**
   * Get available layers in order.
   */
  getAvailableLayers(): DetectionLayer[] {
    return this.config.layerOrder.filter(
      layer => this.isLayerAvailable(layer) && this.layerHandlers.has(layer)
    );
  }

  /**
   * Reset all circuit breakers.
   */
  resetCircuitBreakers(): void {
    for (const breaker of this.circuitBreakers.values()) {
      breaker.reset();
    }
  }

  /**
   * Initialize layer statuses.
   */
  private initializeLayerStatuses(): void {
    for (const layer of this.config.layerOrder) {
      this.layerStatuses.set(layer, {
        layer,
        available: false, // Start as unavailable until handler is registered
        lastChecked: null,
        lastError: null,
        responseTimeMs: null
      });
    }
  }

  /**
   * Initialize circuit breakers for each layer.
   */
  private initializeCircuitBreakers(): void {
    for (const layer of this.config.layerOrder) {
      this.circuitBreakers.set(layer, new CircuitBreaker({
        name: `fallback-${layer}`,
        failureThreshold: 3, // Lower threshold for fallback layers
        resetTimeoutMs: 30000 // 30 seconds for faster recovery
      }));
    }
  }

  /**
   * Update layer status after an operation.
   */
  private updateLayerStatus(
    layer: DetectionLayer,
    success: boolean,
    responseTimeMs: number | null,
    error?: string
  ): void {
    const status = this.layerStatuses.get(layer);
    if (status) {
      status.lastChecked = new Date();
      if (success) {
        status.available = true;
        status.lastError = null;
        status.responseTimeMs = responseTimeMs;
      } else {
        status.lastError = error || 'Unknown error';
        // Don't immediately mark as unavailable - let circuit breaker handle it
      }
    }
  }

  /**
   * Execute a function with timeout.
   */
  private async executeWithTimeout<T>(
    fn: () => Promise<T>,
    timeoutMs: number
  ): Promise<T> {
    return Promise.race([
      fn(),
      new Promise<T>((_, reject) => {
        setTimeout(() => {
          reject(new Error(`Operation timed out after ${timeoutMs}ms`));
        }, timeoutMs);
      })
    ]);
  }

  /**
   * Check if an error is a timeout error.
   */
  private isTimeoutError(error: unknown): boolean {
    if (error instanceof Error) {
      return error.message.toLowerCase().includes('timeout');
    }
    return false;
  }
}

/**
 * Create default layer handlers for PayGuard detection.
 */
export function createDefaultLayerHandlers(): Map<DetectionLayer, LayerHandler> {
  const handlers = new Map<DetectionLayer, LayerHandler>();

  // API handler (cloud-based detection)
  handlers.set('api', async (input: DetectionInput): Promise<DetectionResult> => {
    // This would call the PayGuard API
    // For now, simulate API call
    await new Promise(resolve => setTimeout(resolve, 100));
    
    return {
      riskLevel: 'low',
      confidence: 0.95,
      signals: [
        { name: 'api_check', score: 0.1, source: 'api' }
      ],
      processingTimeMs: 100
    };
  });

  // Local ML handler
  handlers.set('local_ml', async (input: DetectionInput): Promise<DetectionResult> => {
    // This would use the MLPipeline
    await new Promise(resolve => setTimeout(resolve, 50));
    
    return {
      riskLevel: 'low',
      confidence: 0.85,
      signals: [
        { name: 'ml_prediction', score: 0.15, source: 'local_ml' }
      ],
      processingTimeMs: 50
    };
  });

  // URL reputation handler
  handlers.set('url_reputation', async (input: DetectionInput): Promise<DetectionResult> => {
    // This would check URL reputation databases
    await new Promise(resolve => setTimeout(resolve, 30));
    
    return {
      riskLevel: 'low',
      confidence: 0.75,
      signals: [
        { name: 'url_reputation', score: 0.1, source: 'url_reputation' }
      ],
      processingTimeMs: 30
    };
  });

  // Blocklist handler
  handlers.set('blocklist', async (input: DetectionInput): Promise<DetectionResult> => {
    // This would check against static blocklist
    await new Promise(resolve => setTimeout(resolve, 10));
    
    return {
      riskLevel: 'low',
      confidence: 0.6,
      signals: [
        { name: 'blocklist_check', score: 0.05, source: 'blocklist' }
      ],
      processingTimeMs: 10
    };
  });

  return handlers;
}

// Export default instance
export const defaultFallbackChain = new FallbackChain();
