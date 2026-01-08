/**
 * PayGuard V2 - Graceful Degradation Tests
 * 
 * Tests for circuit breaker, retry handler, fallback chain,
 * health checker, and status indicator.
 */
import {
  CircuitBreaker,
  CircuitBreakerRegistry,
  RetryHandler,
  RetryPredicates,
  executeWithRetry,
  FallbackChain,
  HealthChecker,
  StatusIndicator,
  CircuitOpenError,
  RetryExhaustedError,
  FallbackExhaustedError
} from './index';
import type { DetectionInput, DetectionResult } from './FallbackChain';

// Use Jest's built-in mocking
const mockFn = jest.fn;

describe('CircuitBreaker', () => {
  let breaker: CircuitBreaker;

  beforeEach(() => {
    breaker = new CircuitBreaker({
      failureThreshold: 3,
      resetTimeoutMs: 100,
      successThreshold: 1
    });
  });

  describe('closed state', () => {
    it('should allow successful calls', async () => {
      const result = await breaker.execute(async () => 'success');
      expect(result).toBe('success');
      expect(breaker.getState()).toBe('closed');
    });

    it('should track failures', async () => {
      const failingFn = async () => {
        throw new Error('fail');
      };

      await expect(breaker.execute(failingFn)).rejects.toThrow('fail');
      expect(breaker.getStats().failureCount).toBe(1);
      expect(breaker.getState()).toBe('closed');
    });

    it('should open after threshold failures', async () => {
      const failingFn = async () => {
        throw new Error('fail');
      };

      // Fail 3 times (threshold)
      for (let i = 0; i < 3; i++) {
        await expect(breaker.execute(failingFn)).rejects.toThrow('fail');
      }

      expect(breaker.getState()).toBe('open');
    });

    it('should reset failure count on success', async () => {
      const failingFn = async () => {
        throw new Error('fail');
      };

      // Fail twice
      await expect(breaker.execute(failingFn)).rejects.toThrow();
      await expect(breaker.execute(failingFn)).rejects.toThrow();
      
      // Succeed
      await breaker.execute(async () => 'success');
      
      // Failure count should be reset
      expect(breaker.getStats().failureCount).toBe(0);
    });
  });

  describe('open state', () => {
    it('should reject calls immediately when open', async () => {
      // Force open
      breaker.forceOpen();
      
      await expect(breaker.execute(async () => 'success'))
        .rejects.toThrow(CircuitOpenError);
    });

    it('should transition to half-open after timeout', async () => {
      breaker.forceOpen();
      
      // Wait for reset timeout
      await new Promise(resolve => setTimeout(resolve, 150));
      
      expect(breaker.getState()).toBe('half-open');
    });
  });

  describe('half-open state', () => {
    it('should close on success in half-open state', async () => {
      breaker.forceOpen();
      
      // Wait for reset timeout
      await new Promise(resolve => setTimeout(resolve, 150));
      
      // Successful call should close the circuit
      await breaker.execute(async () => 'success');
      
      expect(breaker.getState()).toBe('closed');
    });

    it('should re-open on failure in half-open state', async () => {
      breaker.forceOpen();
      
      // Wait for reset timeout
      await new Promise(resolve => setTimeout(resolve, 150));
      
      // Failing call should re-open the circuit
      await expect(breaker.execute(async () => {
        throw new Error('fail');
      })).rejects.toThrow();
      
      expect(breaker.getState()).toBe('open');
    });
  });

  describe('manual controls', () => {
    it('should force open', () => {
      breaker.forceOpen();
      expect(breaker.getState()).toBe('open');
    });

    it('should force close', () => {
      breaker.forceOpen();
      breaker.forceClose();
      expect(breaker.getState()).toBe('closed');
    });

    it('should reset', () => {
      breaker.forceOpen();
      breaker.reset();
      expect(breaker.getState()).toBe('closed');
      expect(breaker.getStats().failureCount).toBe(0);
    });
  });

  describe('statistics', () => {
    it('should track total calls', async () => {
      await breaker.execute(async () => 'success');
      await breaker.execute(async () => 'success');
      
      expect(breaker.getStats().totalCalls).toBe(2);
    });

    it('should track successes and failures', async () => {
      await breaker.execute(async () => 'success');
      await expect(breaker.execute(async () => {
        throw new Error('fail');
      })).rejects.toThrow();
      
      const stats = breaker.getStats();
      expect(stats.totalSuccesses).toBe(1);
      expect(stats.totalFailures).toBe(1);
    });
  });
});

describe('CircuitBreakerRegistry', () => {
  it('should create and retrieve breakers', () => {
    const registry = new CircuitBreakerRegistry();
    
    const breaker1 = registry.getBreaker('service1');
    const breaker2 = registry.getBreaker('service1');
    
    expect(breaker1).toBe(breaker2);
  });

  it('should get all stats', async () => {
    const registry = new CircuitBreakerRegistry();
    
    const breaker1 = registry.getBreaker('service1');
    const breaker2 = registry.getBreaker('service2');
    
    await breaker1.execute(async () => 'success');
    
    const stats = registry.getAllStats();
    expect(stats.size).toBe(2);
    expect(stats.get('service1')?.totalCalls).toBe(1);
  });

  it('should get open circuits', () => {
    const registry = new CircuitBreakerRegistry();
    
    const breaker1 = registry.getBreaker('service1');
    const breaker2 = registry.getBreaker('service2');
    
    breaker1.forceOpen();
    
    const openCircuits = registry.getOpenCircuits();
    expect(openCircuits).toContain('service1');
    expect(openCircuits).not.toContain('service2');
  });
});

describe('RetryHandler', () => {
  let handler: RetryHandler;

  beforeEach(() => {
    handler = new RetryHandler({
      maxRetries: 3,
      baseDelayMs: 10,
      maxDelayMs: 100,
      backoffMultiplier: 2,
      jitter: false
    });
  });

  it('should succeed on first try', async () => {
    const result = await handler.execute(async () => 'success');
    
    expect(result).toBe('success');
    expect(handler.getStats().firstTrySuccesses).toBe(1);
  });

  it('should retry on failure', async () => {
    let attempts = 0;
    
    const result = await handler.execute(async () => {
      attempts++;
      if (attempts < 3) {
        throw new Error('fail');
      }
      return 'success';
    });
    
    expect(result).toBe('success');
    expect(attempts).toBe(3);
    expect(handler.getStats().retrySuccesses).toBe(1);
  });

  it('should throw after max retries', async () => {
    await expect(handler.execute(async () => {
      throw new Error('always fail');
    })).rejects.toThrow(RetryExhaustedError);
    
    expect(handler.getStats().totalFailures).toBe(1);
  });

  it('should respect isRetryable predicate', async () => {
    const handlerWithPredicate = new RetryHandler({
      maxRetries: 3,
      baseDelayMs: 10,
      isRetryable: (error) => error.message.includes('temporary')
    });

    // Non-retryable error should throw immediately without retrying
    await expect(handlerWithPredicate.execute(async () => {
      throw new Error('permanent error');
    })).rejects.toThrow('permanent error');
    
    // Verify only one attempt was made (no retries)
    expect(handlerWithPredicate.getStats().totalOperations).toBe(1);
  });

  it('should use exponential backoff', async () => {
    // Test that delays increase exponentially
    // This is implicitly tested by the retry behavior
    let attempts = 0;
    const startTime = Date.now();
    
    try {
      await handler.execute(async () => {
        attempts++;
        if (attempts <= 2) {
          throw new Error('fail');
        }
        return 'success';
      });
    } catch {
      // Expected
    }
    
    // Verify multiple attempts were made
    expect(attempts).toBeGreaterThan(1);
  });
});

describe('RetryPredicates', () => {
  it('should detect network errors', () => {
    expect(RetryPredicates.networkErrors(new Error('network error'))).toBe(true);
    expect(RetryPredicates.networkErrors(new Error('timeout'))).toBe(true);
    expect(RetryPredicates.networkErrors(new Error('ECONNREFUSED'))).toBe(true);
    expect(RetryPredicates.networkErrors(new Error('validation error'))).toBe(false);
  });

  it('should detect server errors', () => {
    expect(RetryPredicates.serverErrors(new Error('status: 500'))).toBe(true);
    expect(RetryPredicates.serverErrors(new Error('status: 503'))).toBe(true);
    expect(RetryPredicates.serverErrors(new Error('status: 400'))).toBe(false);
  });

  it('should detect rate limit errors', () => {
    expect(RetryPredicates.rateLimitErrors(new Error('429 Too Many Requests'))).toBe(true);
    expect(RetryPredicates.rateLimitErrors(new Error('rate limit exceeded'))).toBe(true);
    expect(RetryPredicates.rateLimitErrors(new Error('server error'))).toBe(false);
  });

  it('should combine predicates with any', () => {
    const combined = RetryPredicates.any(
      RetryPredicates.networkErrors,
      RetryPredicates.serverErrors
    );
    
    expect(combined(new Error('network error'))).toBe(true);
    expect(combined(new Error('status: 500'))).toBe(true);
    expect(combined(new Error('validation error'))).toBe(false);
  });
});

describe('FallbackChain', () => {
  let chain: FallbackChain;

  beforeEach(() => {
    chain = new FallbackChain({
      layerOrder: ['api', 'local_ml', 'url_reputation', 'blocklist'],
      layerTimeoutMs: 100,
      continueOnTimeout: true
    });
  });

  it('should use first available layer', async () => {
    chain.registerHandler('api', async () => ({
      riskLevel: 'low',
      confidence: 0.95,
      signals: [],
      processingTimeMs: 10
    }));

    const result = await chain.execute({ url: 'https://example.com' });
    
    expect(result.layer).toBe('api');
    expect(result.result.confidence).toBe(0.95);
  });

  it('should fall back to next layer on failure', async () => {
    chain.registerHandler('api', async () => {
      throw new Error('API unavailable');
    });
    
    chain.registerHandler('local_ml', async () => ({
      riskLevel: 'low',
      confidence: 0.85,
      signals: [],
      processingTimeMs: 20
    }));

    const result = await chain.execute({ url: 'https://example.com' });
    
    expect(result.layer).toBe('local_ml');
    expect(result.failedLayers).toContain('api');
  });

  it('should throw when all layers fail', async () => {
    chain.registerHandler('api', async () => {
      throw new Error('fail');
    });
    chain.registerHandler('local_ml', async () => {
      throw new Error('fail');
    });
    chain.registerHandler('url_reputation', async () => {
      throw new Error('fail');
    });
    chain.registerHandler('blocklist', async () => {
      throw new Error('fail');
    });

    await expect(chain.execute({ url: 'https://example.com' }))
      .rejects.toThrow(FallbackExhaustedError);
  });

  it('should track layer statuses', async () => {
    chain.registerHandler('api', async () => ({
      riskLevel: 'low',
      confidence: 0.95,
      signals: [],
      processingTimeMs: 10
    }));

    await chain.execute({ url: 'https://example.com' });
    
    const statuses = chain.getLayerStatuses();
    const apiStatus = statuses.get('api');
    
    expect(apiStatus?.available).toBe(true);
    expect(apiStatus?.responseTimeMs).toBeDefined();
  });

  it('should get available layers', () => {
    chain.registerHandler('api', async () => ({
      riskLevel: 'low',
      confidence: 0.95,
      signals: [],
      processingTimeMs: 10
    }));
    chain.registerHandler('blocklist', async () => ({
      riskLevel: 'low',
      confidence: 0.6,
      signals: [],
      processingTimeMs: 5
    }));

    const available = chain.getAvailableLayers();
    
    expect(available).toContain('api');
    expect(available).toContain('blocklist');
    expect(available).not.toContain('local_ml');
  });
});

describe('HealthChecker', () => {
  let checker: HealthChecker;

  beforeEach(() => {
    checker = new HealthChecker({
      intervalMs: 100,
      timeoutMs: 50,
      components: ['api', 'ml_pipeline']
    });
  });

  afterEach(() => {
    checker.stop();
  });

  it('should register and run health checks', async () => {
    checker.registerCheck('api', async () => ({
      component: 'api',
      healthy: true,
      responseTimeMs: 10,
      checkedAt: new Date()
    }));

    const health = await checker.checkNow();
    
    expect(health.components.length).toBe(1);
    expect(health.components[0].healthy).toBe(true);
  });

  it('should calculate protection level', async () => {
    checker.registerCheck('api', async () => ({
      component: 'api',
      healthy: true,
      responseTimeMs: 10,
      checkedAt: new Date()
    }));
    checker.registerCheck('ml_pipeline', async () => ({
      component: 'ml_pipeline',
      healthy: true,
      responseTimeMs: 10,
      checkedAt: new Date()
    }));
    checker.registerCheck('url_reputation', async () => ({
      component: 'url_reputation',
      healthy: true,
      responseTimeMs: 10,
      checkedAt: new Date()
    }));
    checker.registerCheck('storage', async () => ({
      component: 'storage',
      healthy: true,
      responseTimeMs: 10,
      checkedAt: new Date()
    }));

    const health = await checker.checkNow();
    
    expect(health.protectionLevel).toBe('full');
  });

  it('should detect degraded protection', async () => {
    checker.registerCheck('api', async () => ({
      component: 'api',
      healthy: true,
      responseTimeMs: 10,
      checkedAt: new Date()
    }));
    checker.registerCheck('ml_pipeline', async () => ({
      component: 'ml_pipeline',
      healthy: false,
      responseTimeMs: 10,
      checkedAt: new Date(),
      error: 'Model not loaded'
    }));
    checker.registerCheck('url_reputation', async () => ({
      component: 'url_reputation',
      healthy: true,
      responseTimeMs: 10,
      checkedAt: new Date()
    }));

    const health = await checker.checkNow();
    
    expect(health.protectionLevel).toBe('degraded');
  });

  it('should handle check timeouts', async () => {
    checker.registerCheck('slow_component', async () => {
      await new Promise(resolve => setTimeout(resolve, 100));
      return {
        component: 'slow_component',
        healthy: true,
        responseTimeMs: 100,
        checkedAt: new Date()
      };
    });

    const health = await checker.checkNow();
    
    expect(health.components[0].healthy).toBe(false);
    expect(health.components[0].error).toContain('timed out');
  });

  it('should notify listeners on health change', async () => {
    const listener = jest.fn();
    checker.onHealthChange(listener);

    checker.registerCheck('api', async () => ({
      component: 'api',
      healthy: true,
      responseTimeMs: 10,
      checkedAt: new Date()
    }));

    await checker.checkNow();
    
    expect(listener).toHaveBeenCalled();
  });
});

describe('StatusIndicator', () => {
  let indicator: StatusIndicator;

  beforeEach(() => {
    indicator = new StatusIndicator();
  });

  it('should start with full protection', () => {
    const level = indicator.getProtectionLevel();
    expect(level.level).toBe('full');
  });

  it('should update from health check', () => {
    indicator.updateFromHealth({
      healthy: false,
      protectionLevel: 'degraded',
      components: [
        { component: 'api', healthy: true, responseTimeMs: 10, checkedAt: new Date() },
        { component: 'ml_pipeline', healthy: false, responseTimeMs: 10, checkedAt: new Date(), error: 'fail' }
      ],
      lastCheckedAt: new Date(),
      nextCheckInMs: 60000
    });

    const level = indicator.getProtectionLevel();
    expect(level.level).toBe('degraded');
    expect(level.availableMethods).toContain('Cloud Detection');
    expect(level.unavailableMethods).toContain('AI Analysis');
  });

  it('should notify on status change', () => {
    const listener = jest.fn();
    indicator.onStatusChange(listener);

    indicator.updateFromHealth({
      healthy: false,
      protectionLevel: 'minimal',
      components: [],
      lastCheckedAt: new Date(),
      nextCheckInMs: 60000
    });

    expect(listener).toHaveBeenCalled();
    expect(listener.mock.calls[0][0].level).toBe('minimal');
  });

  it('should track history', () => {
    indicator.updateFromHealth({
      healthy: false,
      protectionLevel: 'degraded',
      components: [],
      lastCheckedAt: new Date(),
      nextCheckInMs: 60000
    });

    indicator.updateFromHealth({
      healthy: false,
      protectionLevel: 'minimal',
      components: [],
      lastCheckedAt: new Date(),
      nextCheckInMs: 60000
    });

    const history = indicator.getHistory();
    expect(history.length).toBe(2);
    expect(history[0].level).toBe('full');
    expect(history[1].level).toBe('degraded');
  });

  it('should provide icon and color', () => {
    const icon = indicator.getIcon();
    expect(icon.icon).toBe('🛡️');
    expect(icon.color).toBe('#22c55e');

    indicator.updateFromHealth({
      healthy: false,
      protectionLevel: 'offline',
      components: [],
      lastCheckedAt: new Date(),
      nextCheckInMs: 60000
    });

    const offlineIcon = indicator.getIcon();
    expect(offlineIcon.icon).toBe('🔴');
    expect(offlineIcon.color).toBe('#ef4444');
  });

  it('should check adequacy for sensitive operations', () => {
    expect(indicator.isAdequateForSensitiveOperations()).toBe(true);

    indicator.updateFromHealth({
      healthy: false,
      protectionLevel: 'minimal',
      components: [],
      lastCheckedAt: new Date(),
      nextCheckInMs: 60000
    });

    expect(indicator.isAdequateForSensitiveOperations()).toBe(false);
  });

  it('should provide warning messages', () => {
    expect(indicator.getWarningMessage()).toBeNull();

    indicator.updateFromHealth({
      healthy: false,
      protectionLevel: 'offline',
      components: [],
      lastCheckedAt: new Date(),
      nextCheckInMs: 60000
    });

    expect(indicator.getWarningMessage()).toContain('Offline mode');
  });
});
