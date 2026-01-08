/**
 * PayGuard V2 - Retry Handler with Exponential Backoff
 * 
 * Implements retry logic with exponential backoff for failed operations.
 * 
 * Requirement 7.6: Max 5 retries with exponential backoff
 */

import {
  RetryConfig,
  RetryStats,
  IRetryHandler,
  RetryExhaustedError,
  DEFAULT_RETRY_CONFIG
} from '../types/degradation';

/**
 * Retry Handler implementation with exponential backoff.
 * 
 * Features:
 * - Configurable max retries (default: 5)
 * - Exponential backoff with configurable base delay
 * - Optional jitter to prevent thundering herd
 * - Configurable retry predicate
 */
export class RetryHandler implements IRetryHandler {
  private config: RetryConfig;
  private stats: RetryStats = {
    totalOperations: 0,
    firstTrySuccesses: 0,
    retrySuccesses: 0,
    totalFailures: 0,
    avgRetries: 0
  };
  private totalRetries: number = 0;

  constructor(config: Partial<RetryConfig> = {}) {
    this.config = { 
      ...DEFAULT_RETRY_CONFIG, 
      ...config
    };
  }

  /**
   * Execute a function with retry logic.
   * 
   * @param fn - The async function to execute
   * @param config - Optional config override for this execution
   * @returns The result of the function
   * @throws RetryExhaustedError if all retries are exhausted
   */
  async execute<T>(
    fn: () => Promise<T>,
    config?: Partial<RetryConfig>
  ): Promise<T> {
    const effectiveConfig = config ? { ...this.config, ...config } : this.config;
    this.stats.totalOperations++;

    let lastError: Error = new Error('Unknown error');
    let attempt = 0;

    while (attempt <= effectiveConfig.maxRetries) {
      try {
        const result = await fn();
        
        // Track success
        if (attempt === 0) {
          this.stats.firstTrySuccesses++;
        } else {
          this.stats.retrySuccesses++;
          this.totalRetries += attempt;
        }
        
        this.updateAvgRetries();
        return result;
      } catch (error) {
        lastError = error instanceof Error ? error : new Error(String(error));
        
        // Check if error is retryable (if predicate is provided)
        const isRetryableFn = effectiveConfig.isRetryable;
        if (isRetryableFn !== undefined) {
          const isRetryable = isRetryableFn(lastError);
          if (!isRetryable) {
            // Error is not retryable, throw immediately
            this.stats.totalFailures++;
            this.updateAvgRetries();
            throw lastError;
          }
        }
        
        // Check if we've exhausted retries
        if (attempt >= effectiveConfig.maxRetries) {
          break;
        }

        // Calculate delay with exponential backoff
        const delay = this.calculateDelay(attempt, effectiveConfig);
        
        // Wait before retrying
        await this.sleep(delay);
        
        attempt++;
      }
    }

    // All retries exhausted
    this.stats.totalFailures++;
    this.totalRetries += attempt;
    this.updateAvgRetries();
    
    throw new RetryExhaustedError(attempt + 1, lastError);
  }

  /**
   * Get retry statistics.
   */
  getStats(): RetryStats {
    return { ...this.stats };
  }

  /**
   * Reset statistics.
   */
  resetStats(): void {
    this.stats = {
      totalOperations: 0,
      firstTrySuccesses: 0,
      retrySuccesses: 0,
      totalFailures: 0,
      avgRetries: 0
    };
    this.totalRetries = 0;
  }

  /**
   * Calculate delay for a given attempt using exponential backoff.
   * 
   * Formula: delay = min(baseDelay * (multiplier ^ attempt), maxDelay)
   * With optional jitter: delay = delay * (0.5 + random * 0.5)
   */
  private calculateDelay(attempt: number, config: RetryConfig): number {
    // Calculate base exponential delay
    let delay = config.baseDelayMs * Math.pow(config.backoffMultiplier, attempt);
    
    // Cap at max delay
    delay = Math.min(delay, config.maxDelayMs);
    
    // Add jitter if enabled (reduces thundering herd problem)
    if (config.jitter) {
      // Jitter between 50% and 100% of calculated delay
      const jitterFactor = 0.5 + Math.random() * 0.5;
      delay = Math.floor(delay * jitterFactor);
    }
    
    return delay;
  }

  /**
   * Update average retries statistic.
   */
  private updateAvgRetries(): void {
    const operationsWithRetries = this.stats.retrySuccesses + this.stats.totalFailures;
    if (operationsWithRetries > 0) {
      this.stats.avgRetries = this.totalRetries / this.stats.totalOperations;
    }
  }

  /**
   * Sleep for a given number of milliseconds.
   */
  private sleep(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
  }
}

/**
 * Decorator function for adding retry logic to async functions.
 * 
 * @param config - Retry configuration
 * @returns Decorator function
 */
export function withRetry(config: Partial<RetryConfig> = {}) {
  const handler = new RetryHandler(config);
  
  return function <T extends (...args: unknown[]) => Promise<unknown>>(
    target: T
  ): T {
    return (async function (...args: Parameters<T>): Promise<ReturnType<T>> {
      return handler.execute(() => target(...args)) as Promise<ReturnType<T>>;
    }) as T;
  };
}

/**
 * Execute a function with retry logic (standalone function).
 * 
 * @param fn - The async function to execute
 * @param config - Retry configuration
 * @returns The result of the function
 */
export async function executeWithRetry<T>(
  fn: () => Promise<T>,
  config: Partial<RetryConfig> = {}
): Promise<T> {
  const handler = new RetryHandler(config);
  return handler.execute(fn);
}

/**
 * Common retry predicates.
 */
export const RetryPredicates = {
  /**
   * Retry on network errors.
   */
  networkErrors: (error: Error): boolean => {
    const networkErrorPatterns = [
      'network',
      'timeout',
      'ECONNREFUSED',
      'ECONNRESET',
      'ETIMEDOUT',
      'ENOTFOUND',
      'fetch failed',
      'Failed to fetch'
    ];
    const message = error.message.toLowerCase();
    return networkErrorPatterns.some(pattern => 
      message.includes(pattern.toLowerCase())
    );
  },

  /**
   * Retry on HTTP 5xx errors.
   */
  serverErrors: (error: Error): boolean => {
    const message = error.message;
    const statusMatch = message.match(/status[:\s]*(\d{3})/i);
    if (statusMatch) {
      const status = parseInt(statusMatch[1], 10);
      return status >= 500 && status < 600;
    }
    return false;
  },

  /**
   * Retry on rate limit errors (HTTP 429).
   */
  rateLimitErrors: (error: Error): boolean => {
    const message = error.message.toLowerCase();
    return message.includes('429') || 
           message.includes('rate limit') ||
           message.includes('too many requests');
  },

  /**
   * Combine multiple predicates with OR logic.
   */
  any: (...predicates: ((error: Error) => boolean)[]): ((error: Error) => boolean) => {
    return (error: Error) => predicates.some(p => p(error));
  },

  /**
   * Combine multiple predicates with AND logic.
   */
  all: (...predicates: ((error: Error) => boolean)[]): ((error: Error) => boolean) => {
    return (error: Error) => predicates.every(p => p(error));
  },

  /**
   * Always retry.
   */
  always: (): boolean => true,

  /**
   * Never retry.
   */
  never: (): boolean => false
};

// Export default instance
export const defaultRetryHandler = new RetryHandler();
