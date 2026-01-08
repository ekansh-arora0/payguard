/**
 * PayGuard V2 - Circuit Breaker Implementation
 * 
 * Implements the circuit breaker pattern to prevent cascading failures
 * when external services are unavailable.
 * 
 * Requirement 7.4: Open after 5 consecutive failures, 60-second timeout before retry
 */

import {
  CircuitState,
  CircuitBreakerConfig,
  CircuitBreakerStats,
  ICircuitBreaker,
  CircuitOpenError,
  DEFAULT_CIRCUIT_BREAKER_CONFIG
} from '../types/degradation';

/**
 * Circuit Breaker implementation.
 * 
 * States:
 * - CLOSED: Normal operation, requests pass through
 * - OPEN: Requests fail immediately without calling the service
 * - HALF-OPEN: Allow one test request to determine if service recovered
 */
export class CircuitBreaker implements ICircuitBreaker {
  private config: CircuitBreakerConfig;
  private state: CircuitState = 'closed';
  private failureCount: number = 0;
  private successCount: number = 0;
  private lastOpenedAt: Date | null = null;
  private lastClosedAt: Date | null = null;
  private lastFailureAt: Date | null = null;
  private lastSuccessAt: Date | null = null;
  private totalCalls: number = 0;
  private totalFailures: number = 0;
  private totalSuccesses: number = 0;
  private resetTimer: ReturnType<typeof setTimeout> | null = null;

  constructor(config: Partial<CircuitBreakerConfig> = {}) {
    this.config = { ...DEFAULT_CIRCUIT_BREAKER_CONFIG, ...config };
  }

  /**
   * Execute a function with circuit breaker protection.
   * 
   * @param fn - The async function to execute
   * @returns The result of the function
   * @throws CircuitOpenError if circuit is open
   * @throws The original error if the function fails
   */
  async execute<T>(fn: () => Promise<T>): Promise<T> {
    this.totalCalls++;

    // Check if circuit is open
    if (this.state === 'open') {
      // Check if reset timeout has passed
      if (this.shouldAttemptReset()) {
        this.transitionToHalfOpen();
      } else {
        throw new CircuitOpenError(
          `Circuit breaker '${this.config.name}' is open. ` +
          `Will retry after ${this.getTimeUntilReset()}ms`
        );
      }
    }

    try {
      const result = await fn();
      this.onSuccess();
      return result;
    } catch (error) {
      this.onFailure();
      throw error;
    }
  }

  /**
   * Get current circuit state.
   */
  getState(): CircuitState {
    // Check if we should transition from open to half-open
    if (this.state === 'open' && this.shouldAttemptReset()) {
      this.transitionToHalfOpen();
    }
    return this.state;
  }

  /**
   * Get circuit breaker statistics.
   */
  getStats(): CircuitBreakerStats {
    return {
      state: this.getState(),
      failureCount: this.failureCount,
      successCount: this.successCount,
      totalCalls: this.totalCalls,
      totalFailures: this.totalFailures,
      totalSuccesses: this.totalSuccesses,
      lastOpenedAt: this.lastOpenedAt,
      lastClosedAt: this.lastClosedAt,
      lastFailureAt: this.lastFailureAt,
      lastSuccessAt: this.lastSuccessAt
    };
  }

  /**
   * Manually reset the circuit breaker to closed state.
   */
  reset(): void {
    this.clearResetTimer();
    this.state = 'closed';
    this.failureCount = 0;
    this.successCount = 0;
    this.lastClosedAt = new Date();
  }

  /**
   * Force the circuit to open state.
   */
  forceOpen(): void {
    this.clearResetTimer();
    this.state = 'open';
    this.lastOpenedAt = new Date();
    this.scheduleReset();
  }

  /**
   * Force the circuit to closed state.
   */
  forceClose(): void {
    this.clearResetTimer();
    this.state = 'closed';
    this.failureCount = 0;
    this.successCount = 0;
    this.lastClosedAt = new Date();
  }

  /**
   * Handle successful execution.
   */
  private onSuccess(): void {
    this.totalSuccesses++;
    this.lastSuccessAt = new Date();

    if (this.state === 'half-open') {
      this.successCount++;
      if (this.successCount >= this.config.successThreshold) {
        this.transitionToClosed();
      }
    } else if (this.state === 'closed') {
      // Reset failure count on success in closed state
      this.failureCount = 0;
    }
  }

  /**
   * Handle failed execution.
   */
  private onFailure(): void {
    this.totalFailures++;
    this.lastFailureAt = new Date();
    this.failureCount++;

    if (this.state === 'half-open') {
      // Any failure in half-open state opens the circuit again
      this.transitionToOpen();
    } else if (this.state === 'closed') {
      if (this.failureCount >= this.config.failureThreshold) {
        this.transitionToOpen();
      }
    }
  }

  /**
   * Transition to open state.
   */
  private transitionToOpen(): void {
    this.state = 'open';
    this.lastOpenedAt = new Date();
    this.successCount = 0;
    this.scheduleReset();
  }

  /**
   * Transition to half-open state.
   */
  private transitionToHalfOpen(): void {
    this.clearResetTimer();
    this.state = 'half-open';
    this.successCount = 0;
    this.failureCount = 0;
  }

  /**
   * Transition to closed state.
   */
  private transitionToClosed(): void {
    this.clearResetTimer();
    this.state = 'closed';
    this.failureCount = 0;
    this.successCount = 0;
    this.lastClosedAt = new Date();
  }

  /**
   * Check if we should attempt to reset (transition to half-open).
   */
  private shouldAttemptReset(): boolean {
    if (!this.lastOpenedAt) {
      return true;
    }
    const elapsed = Date.now() - this.lastOpenedAt.getTime();
    return elapsed >= this.config.resetTimeoutMs;
  }

  /**
   * Get time until reset in milliseconds.
   */
  private getTimeUntilReset(): number {
    if (!this.lastOpenedAt) {
      return 0;
    }
    const elapsed = Date.now() - this.lastOpenedAt.getTime();
    return Math.max(0, this.config.resetTimeoutMs - elapsed);
  }

  /**
   * Schedule automatic transition to half-open state.
   */
  private scheduleReset(): void {
    this.clearResetTimer();
    this.resetTimer = setTimeout(() => {
      if (this.state === 'open') {
        this.transitionToHalfOpen();
      }
    }, this.config.resetTimeoutMs);
  }

  /**
   * Clear the reset timer.
   */
  private clearResetTimer(): void {
    if (this.resetTimer) {
      clearTimeout(this.resetTimer);
      this.resetTimer = null;
    }
  }
}

/**
 * Circuit breaker registry for managing multiple circuit breakers.
 */
export class CircuitBreakerRegistry {
  private breakers: Map<string, CircuitBreaker> = new Map();
  private defaultConfig: Partial<CircuitBreakerConfig>;

  constructor(defaultConfig: Partial<CircuitBreakerConfig> = {}) {
    this.defaultConfig = defaultConfig;
  }

  /**
   * Get or create a circuit breaker for a service.
   */
  getBreaker(name: string, config?: Partial<CircuitBreakerConfig>): CircuitBreaker {
    let breaker = this.breakers.get(name);
    if (!breaker) {
      breaker = new CircuitBreaker({
        ...this.defaultConfig,
        ...config,
        name
      });
      this.breakers.set(name, breaker);
    }
    return breaker;
  }

  /**
   * Get all circuit breaker statistics.
   */
  getAllStats(): Map<string, CircuitBreakerStats> {
    const stats = new Map<string, CircuitBreakerStats>();
    for (const [name, breaker] of this.breakers) {
      stats.set(name, breaker.getStats());
    }
    return stats;
  }

  /**
   * Reset all circuit breakers.
   */
  resetAll(): void {
    for (const breaker of this.breakers.values()) {
      breaker.reset();
    }
  }

  /**
   * Get names of all open circuits.
   */
  getOpenCircuits(): string[] {
    const open: string[] = [];
    for (const [name, breaker] of this.breakers) {
      if (breaker.getState() === 'open') {
        open.push(name);
      }
    }
    return open;
  }
}

// Export default instance
export const circuitBreakerRegistry = new CircuitBreakerRegistry();
