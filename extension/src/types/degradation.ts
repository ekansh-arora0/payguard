/**
 * PayGuard V2 - Graceful Degradation Types
 * 
 * Types for circuit breaker, retry logic, fallback detection chain,
 * health checks, and status indicators.
 * 
 * Implements Requirements 7.1, 7.2, 7.3, 7.4, 7.6, 7.7, 7.9
 */

/**
 * Circuit breaker states.
 */
export type CircuitState = 'closed' | 'open' | 'half-open';

/**
 * Circuit breaker configuration.
 */
export interface CircuitBreakerConfig {
  /** Number of consecutive failures before opening circuit */
  failureThreshold: number;
  /** Time in ms before attempting to close circuit */
  resetTimeoutMs: number;
  /** Number of successful calls in half-open state to close circuit */
  successThreshold: number;
  /** Optional name for logging */
  name?: string;
}

/**
 * Default circuit breaker configuration.
 * Requirement 7.4: Open after 5 consecutive failures, 60-second timeout
 */
export const DEFAULT_CIRCUIT_BREAKER_CONFIG: CircuitBreakerConfig = {
  failureThreshold: 5,
  resetTimeoutMs: 60000, // 60 seconds
  successThreshold: 1,
  name: 'default'
};

/**
 * Circuit breaker statistics.
 */
export interface CircuitBreakerStats {
  /** Current state of the circuit */
  state: CircuitState;
  /** Number of consecutive failures */
  failureCount: number;
  /** Number of successful calls in half-open state */
  successCount: number;
  /** Total number of calls */
  totalCalls: number;
  /** Total number of failures */
  totalFailures: number;
  /** Total number of successes */
  totalSuccesses: number;
  /** Time when circuit was last opened */
  lastOpenedAt: Date | null;
  /** Time when circuit was last closed */
  lastClosedAt: Date | null;
  /** Time of last failure */
  lastFailureAt: Date | null;
  /** Time of last success */
  lastSuccessAt: Date | null;
}

/**
 * Circuit breaker interface.
 */
export interface ICircuitBreaker {
  /** Execute a function with circuit breaker protection */
  execute<T>(fn: () => Promise<T>): Promise<T>;
  /** Get current state */
  getState(): CircuitState;
  /** Get statistics */
  getStats(): CircuitBreakerStats;
  /** Manually reset the circuit breaker */
  reset(): void;
  /** Force open the circuit */
  forceOpen(): void;
  /** Force close the circuit */
  forceClose(): void;
}

/**
 * Retry configuration.
 */
export interface RetryConfig {
  /** Maximum number of retry attempts */
  maxRetries: number;
  /** Base delay in ms for exponential backoff */
  baseDelayMs: number;
  /** Maximum delay in ms */
  maxDelayMs: number;
  /** Multiplier for exponential backoff */
  backoffMultiplier: number;
  /** Whether to add jitter to delays */
  jitter: boolean;
  /** Optional function to determine if error is retryable */
  isRetryable?: (error: Error) => boolean;
}

/**
 * Default retry configuration.
 * Requirement 7.6: Max 5 retries with exponential backoff
 */
export const DEFAULT_RETRY_CONFIG: RetryConfig = {
  maxRetries: 5,
  baseDelayMs: 1000,
  maxDelayMs: 30000,
  backoffMultiplier: 2,
  jitter: true
};

/**
 * Retry statistics.
 */
export interface RetryStats {
  /** Total number of operations */
  totalOperations: number;
  /** Number of operations that succeeded on first try */
  firstTrySuccesses: number;
  /** Number of operations that succeeded after retry */
  retrySuccesses: number;
  /** Number of operations that failed after all retries */
  totalFailures: number;
  /** Average number of retries per operation */
  avgRetries: number;
}

/**
 * Retry interface.
 */
export interface IRetryHandler {
  /** Execute a function with retry logic */
  execute<T>(fn: () => Promise<T>, config?: Partial<RetryConfig>): Promise<T>;
  /** Get statistics */
  getStats(): RetryStats;
  /** Reset statistics */
  resetStats(): void;
}

/**
 * Detection layer types for fallback chain.
 */
export type DetectionLayer = 
  | 'api'
  | 'local_ml'
  | 'url_reputation'
  | 'blocklist';

/**
 * Detection layer status.
 */
export interface LayerStatus {
  /** Layer identifier */
  layer: DetectionLayer;
  /** Whether the layer is available */
  available: boolean;
  /** Last check time */
  lastChecked: Date | null;
  /** Last error if any */
  lastError: string | null;
  /** Response time in ms */
  responseTimeMs: number | null;
}

/**
 * Fallback chain configuration.
 */
export interface FallbackChainConfig {
  /** Order of detection layers to try */
  layerOrder: DetectionLayer[];
  /** Timeout for each layer in ms */
  layerTimeoutMs: number;
  /** Whether to continue to next layer on timeout */
  continueOnTimeout: boolean;
}

/**
 * Default fallback chain configuration.
 * Requirement 7.1, 7.2: API → local ML → URL reputation → blocklist
 */
export const DEFAULT_FALLBACK_CHAIN_CONFIG: FallbackChainConfig = {
  layerOrder: ['api', 'local_ml', 'url_reputation', 'blocklist'],
  layerTimeoutMs: 5000,
  continueOnTimeout: true
};

/**
 * Fallback chain result.
 */
export interface FallbackChainResult<T> {
  /** The result from the successful layer */
  result: T;
  /** Which layer provided the result */
  layer: DetectionLayer;
  /** Layers that were tried */
  triedLayers: DetectionLayer[];
  /** Layers that failed */
  failedLayers: DetectionLayer[];
  /** Total time taken in ms */
  totalTimeMs: number;
}

/**
 * Fallback chain interface.
 */
export interface IFallbackChain<T> {
  /** Execute detection with fallback chain */
  execute(input: unknown): Promise<FallbackChainResult<T>>;
  /** Get layer statuses */
  getLayerStatuses(): Map<DetectionLayer, LayerStatus>;
  /** Check if a specific layer is available */
  isLayerAvailable(layer: DetectionLayer): boolean;
  /** Manually mark a layer as unavailable */
  markLayerUnavailable(layer: DetectionLayer, error: string): void;
  /** Manually mark a layer as available */
  markLayerAvailable(layer: DetectionLayer): void;
}

/**
 * Health check result.
 */
export interface HealthCheckResult {
  /** Component name */
  component: string;
  /** Whether the component is healthy */
  healthy: boolean;
  /** Response time in ms */
  responseTimeMs: number;
  /** Last check time */
  checkedAt: Date;
  /** Error message if unhealthy */
  error?: string;
  /** Additional details */
  details?: Record<string, unknown>;
}

/**
 * Overall system health.
 */
export interface SystemHealth {
  /** Overall health status */
  healthy: boolean;
  /** Protection level based on available components */
  protectionLevel: ProtectionLevel;
  /** Individual component health */
  components: HealthCheckResult[];
  /** Last full check time */
  lastCheckedAt: Date;
  /** Time until next check in ms */
  nextCheckInMs: number;
}

/**
 * Health check configuration.
 */
export interface HealthCheckConfig {
  /** Interval between health checks in ms */
  intervalMs: number;
  /** Timeout for each health check in ms */
  timeoutMs: number;
  /** Components to check */
  components: string[];
}

/**
 * Default health check configuration.
 * Requirement 7.9: Check every 60 seconds
 */
export const DEFAULT_HEALTH_CHECK_CONFIG: HealthCheckConfig = {
  intervalMs: 60000, // 60 seconds
  timeoutMs: 5000,
  components: ['api', 'ml_pipeline', 'url_reputation', 'storage']
};

/**
 * Health check interface.
 */
export interface IHealthChecker {
  /** Start periodic health checks */
  start(): void;
  /** Stop periodic health checks */
  stop(): void;
  /** Run a health check immediately */
  checkNow(): Promise<SystemHealth>;
  /** Get last health check result */
  getLastResult(): SystemHealth | null;
  /** Register a health check function for a component */
  registerCheck(component: string, checkFn: () => Promise<HealthCheckResult>): void;
  /** Unregister a health check */
  unregisterCheck(component: string): void;
}

/**
 * Protection level based on available components.
 * Requirement 7.7: Show current protection level
 */
export type ProtectionLevel = 'full' | 'degraded' | 'minimal' | 'offline';

/**
 * Protection level details.
 */
export interface ProtectionLevelInfo {
  /** Current protection level */
  level: ProtectionLevel;
  /** Human-readable description */
  description: string;
  /** Available detection methods */
  availableMethods: string[];
  /** Unavailable detection methods */
  unavailableMethods: string[];
  /** Recommendations for user */
  recommendations: string[];
}

/**
 * Status indicator configuration.
 */
export interface StatusIndicatorConfig {
  /** Whether to show notifications on status change */
  showNotifications: boolean;
  /** Minimum level change to trigger notification */
  notifyOnLevelChange: boolean;
  /** Update interval in ms */
  updateIntervalMs: number;
}

/**
 * Default status indicator configuration.
 */
export const DEFAULT_STATUS_INDICATOR_CONFIG: StatusIndicatorConfig = {
  showNotifications: true,
  notifyOnLevelChange: true,
  updateIntervalMs: 5000
};

/**
 * Status indicator interface.
 */
export interface IStatusIndicator {
  /** Get current protection level info */
  getProtectionLevel(): ProtectionLevelInfo;
  /** Subscribe to status changes */
  onStatusChange(callback: (info: ProtectionLevelInfo) => void): () => void;
  /** Update status based on health check */
  updateFromHealth(health: SystemHealth): void;
  /** Get status history */
  getHistory(limit?: number): ProtectionLevelInfo[];
}

/**
 * Error types for graceful degradation.
 */
export class CircuitOpenError extends Error {
  constructor(message: string = 'Circuit breaker is open') {
    super(message);
    this.name = 'CircuitOpenError';
  }
}

export class RetryExhaustedError extends Error {
  public readonly attempts: number;
  public readonly lastError: Error;

  constructor(attempts: number, lastError: Error) {
    super(`All ${attempts} retry attempts exhausted`);
    this.name = 'RetryExhaustedError';
    this.attempts = attempts;
    this.lastError = lastError;
  }
}

export class FallbackExhaustedError extends Error {
  public readonly triedLayers: DetectionLayer[];

  constructor(triedLayers: DetectionLayer[]) {
    super(`All fallback layers exhausted: ${triedLayers.join(', ')}`);
    this.name = 'FallbackExhaustedError';
    this.triedLayers = triedLayers;
  }
}
