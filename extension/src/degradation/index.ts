/**
 * PayGuard V2 - Graceful Degradation Module
 * 
 * Exports all graceful degradation components:
 * - Circuit Breaker (Requirement 7.4)
 * - Retry Handler with Exponential Backoff (Requirement 7.6)
 * - Fallback Detection Chain (Requirements 7.1, 7.2)
 * - Health Checker (Requirement 7.9)
 * - Status Indicator (Requirement 7.7)
 */

// Circuit Breaker
export {
  CircuitBreaker,
  CircuitBreakerRegistry,
  circuitBreakerRegistry
} from './CircuitBreaker';

// Retry Handler
export {
  RetryHandler,
  withRetry,
  executeWithRetry,
  RetryPredicates,
  defaultRetryHandler
} from './RetryHandler';

// Fallback Chain
export {
  FallbackChain,
  createDefaultLayerHandlers,
  defaultFallbackChain
} from './FallbackChain';
export type {
  DetectionResult,
  DetectionInput,
  LayerHandler
} from './FallbackChain';

// Health Checker
export {
  HealthChecker,
  createDefaultHealthChecks,
  defaultHealthChecker
} from './HealthChecker';
export type { HealthCheckFn } from './HealthChecker';

// Status Indicator
export {
  StatusIndicator,
  createConnectedStatusIndicator,
  defaultStatusIndicator
} from './StatusIndicator';

// Re-export types
export * from '../types/degradation';
