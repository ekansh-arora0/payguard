/**
 * PayGuard V2 - Health Check System
 * 
 * Implements periodic health checks for all system components
 * to determine overall protection level.
 * 
 * Requirement 7.9: Check every 60 seconds
 */

import {
  HealthCheckResult,
  SystemHealth,
  HealthCheckConfig,
  IHealthChecker,
  ProtectionLevel,
  DEFAULT_HEALTH_CHECK_CONFIG
} from '../types/degradation';

/**
 * Health check function type.
 */
export type HealthCheckFn = () => Promise<HealthCheckResult>;

/**
 * Health Checker implementation.
 * 
 * Features:
 * - Periodic health checks (default: every 60 seconds)
 * - Configurable timeout per check
 * - Component registration/unregistration
 * - Protection level calculation
 */
export class HealthChecker implements IHealthChecker {
  private config: HealthCheckConfig;
  private checks: Map<string, HealthCheckFn> = new Map();
  private lastResult: SystemHealth | null = null;
  private intervalId: ReturnType<typeof setInterval> | null = null;
  private isRunning: boolean = false;
  private listeners: Set<(health: SystemHealth) => void> = new Set();

  constructor(config: Partial<HealthCheckConfig> = {}) {
    this.config = { ...DEFAULT_HEALTH_CHECK_CONFIG, ...config };
  }

  /**
   * Start periodic health checks.
   */
  start(): void {
    if (this.isRunning) {
      return;
    }

    this.isRunning = true;
    
    // Run initial check
    this.checkNow().catch(console.error);
    
    // Schedule periodic checks
    this.intervalId = setInterval(() => {
      this.checkNow().catch(console.error);
    }, this.config.intervalMs);
  }

  /**
   * Stop periodic health checks.
   */
  stop(): void {
    if (this.intervalId) {
      clearInterval(this.intervalId);
      this.intervalId = null;
    }
    this.isRunning = false;
  }

  /**
   * Run a health check immediately.
   */
  async checkNow(): Promise<SystemHealth> {
    const startTime = Date.now();
    const componentResults: HealthCheckResult[] = [];

    // Run all health checks in parallel with timeout
    const checkPromises = Array.from(this.checks.entries()).map(
      async ([component, checkFn]) => {
        try {
          const result = await this.executeWithTimeout(
            checkFn,
            this.config.timeoutMs
          );
          return result;
        } catch (error) {
          return {
            component,
            healthy: false,
            responseTimeMs: this.config.timeoutMs,
            checkedAt: new Date(),
            error: error instanceof Error ? error.message : String(error)
          };
        }
      }
    );

    const results = await Promise.all(checkPromises);
    componentResults.push(...results);

    // Calculate overall health and protection level
    const healthy = componentResults.every(r => r.healthy);
    const protectionLevel = this.calculateProtectionLevel(componentResults);

    const systemHealth: SystemHealth = {
      healthy,
      protectionLevel,
      components: componentResults,
      lastCheckedAt: new Date(),
      nextCheckInMs: this.config.intervalMs - (Date.now() - startTime)
    };

    this.lastResult = systemHealth;
    
    // Notify listeners
    this.notifyListeners(systemHealth);

    return systemHealth;
  }

  /**
   * Get last health check result.
   */
  getLastResult(): SystemHealth | null {
    return this.lastResult;
  }

  /**
   * Register a health check function for a component.
   */
  registerCheck(component: string, checkFn: HealthCheckFn): void {
    this.checks.set(component, checkFn);
  }

  /**
   * Unregister a health check.
   */
  unregisterCheck(component: string): void {
    this.checks.delete(component);
  }

  /**
   * Subscribe to health check results.
   */
  onHealthChange(callback: (health: SystemHealth) => void): () => void {
    this.listeners.add(callback);
    return () => this.listeners.delete(callback);
  }

  /**
   * Get registered components.
   */
  getRegisteredComponents(): string[] {
    return Array.from(this.checks.keys());
  }

  /**
   * Check if a specific component is healthy.
   */
  isComponentHealthy(component: string): boolean {
    if (!this.lastResult) {
      return false;
    }
    const result = this.lastResult.components.find(c => c.component === component);
    return result?.healthy ?? false;
  }

  /**
   * Get health check interval in ms.
   */
  getIntervalMs(): number {
    return this.config.intervalMs;
  }

  /**
   * Update configuration.
   */
  updateConfig(config: Partial<HealthCheckConfig>): void {
    const wasRunning = this.isRunning;
    
    if (wasRunning) {
      this.stop();
    }
    
    this.config = { ...this.config, ...config };
    
    if (wasRunning) {
      this.start();
    }
  }

  /**
   * Calculate protection level based on component health.
   */
  private calculateProtectionLevel(results: HealthCheckResult[]): ProtectionLevel {
    const healthyComponents = results.filter(r => r.healthy).map(r => r.component);
    const unhealthyComponents = results.filter(r => !r.healthy).map(r => r.component);

    // Define critical components
    const criticalComponents = ['api', 'ml_pipeline'];
    const importantComponents = ['url_reputation', 'storage'];

    // Check if all components are healthy
    if (unhealthyComponents.length === 0) {
      return 'full';
    }

    // Check if any critical component is healthy
    const hasCriticalHealthy = criticalComponents.some(c => healthyComponents.includes(c));
    const hasImportantHealthy = importantComponents.some(c => healthyComponents.includes(c));

    if (hasCriticalHealthy && hasImportantHealthy) {
      return 'degraded';
    }

    if (hasCriticalHealthy || hasImportantHealthy) {
      return 'minimal';
    }

    // No critical or important components available
    return 'offline';
  }

  /**
   * Execute a function with timeout.
   */
  private async executeWithTimeout(
    fn: HealthCheckFn,
    timeoutMs: number
  ): Promise<HealthCheckResult> {
    return Promise.race([
      fn(),
      new Promise<HealthCheckResult>((_, reject) => {
        setTimeout(() => {
          reject(new Error(`Health check timed out after ${timeoutMs}ms`));
        }, timeoutMs);
      })
    ]);
  }

  /**
   * Notify all listeners of health change.
   */
  private notifyListeners(health: SystemHealth): void {
    for (const listener of this.listeners) {
      try {
        listener(health);
      } catch (error) {
        console.error('Health check listener error:', error);
      }
    }
  }
}

/**
 * Create default health checks for PayGuard components.
 */
export function createDefaultHealthChecks(): Map<string, HealthCheckFn> {
  const checks = new Map<string, HealthCheckFn>();

  // API health check
  checks.set('api', async (): Promise<HealthCheckResult> => {
    const startTime = Date.now();
    try {
      // In production, this would ping the PayGuard API
      // For now, simulate API check
      await new Promise(resolve => setTimeout(resolve, 50));
      
      return {
        component: 'api',
        healthy: true,
        responseTimeMs: Date.now() - startTime,
        checkedAt: new Date(),
        details: { endpoint: 'health' }
      };
    } catch (error) {
      return {
        component: 'api',
        healthy: false,
        responseTimeMs: Date.now() - startTime,
        checkedAt: new Date(),
        error: error instanceof Error ? error.message : String(error)
      };
    }
  });

  // ML Pipeline health check
  checks.set('ml_pipeline', async (): Promise<HealthCheckResult> => {
    const startTime = Date.now();
    try {
      // In production, this would check ML model status
      await new Promise(resolve => setTimeout(resolve, 20));
      
      return {
        component: 'ml_pipeline',
        healthy: true,
        responseTimeMs: Date.now() - startTime,
        checkedAt: new Date(),
        details: { modelsLoaded: true }
      };
    } catch (error) {
      return {
        component: 'ml_pipeline',
        healthy: false,
        responseTimeMs: Date.now() - startTime,
        checkedAt: new Date(),
        error: error instanceof Error ? error.message : String(error)
      };
    }
  });

  // URL Reputation health check
  checks.set('url_reputation', async (): Promise<HealthCheckResult> => {
    const startTime = Date.now();
    try {
      // In production, this would check threat feed status
      await new Promise(resolve => setTimeout(resolve, 30));
      
      return {
        component: 'url_reputation',
        healthy: true,
        responseTimeMs: Date.now() - startTime,
        checkedAt: new Date(),
        details: { feedsActive: 3 }
      };
    } catch (error) {
      return {
        component: 'url_reputation',
        healthy: false,
        responseTimeMs: Date.now() - startTime,
        checkedAt: new Date(),
        error: error instanceof Error ? error.message : String(error)
      };
    }
  });

  // Storage health check
  checks.set('storage', async (): Promise<HealthCheckResult> => {
    const startTime = Date.now();
    try {
      // In production, this would check storage availability
      await new Promise(resolve => setTimeout(resolve, 10));
      
      return {
        component: 'storage',
        healthy: true,
        responseTimeMs: Date.now() - startTime,
        checkedAt: new Date(),
        details: { available: true }
      };
    } catch (error) {
      return {
        component: 'storage',
        healthy: false,
        responseTimeMs: Date.now() - startTime,
        checkedAt: new Date(),
        error: error instanceof Error ? error.message : String(error)
      };
    }
  });

  return checks;
}

// Export default instance
export const defaultHealthChecker = new HealthChecker();
