/**
 * PayGuard V2 - Status Indicator
 * 
 * Provides user-facing status indicators showing current protection level
 * and available detection methods.
 * 
 * Requirement 7.7: Show current protection level
 */

import {
  ProtectionLevel,
  ProtectionLevelInfo,
  SystemHealth,
  StatusIndicatorConfig,
  IStatusIndicator,
  DEFAULT_STATUS_INDICATOR_CONFIG
} from '../types/degradation';

/**
 * Protection level descriptions and recommendations.
 */
const PROTECTION_LEVEL_INFO: Record<ProtectionLevel, {
  description: string;
  recommendations: string[];
}> = {
  full: {
    description: 'Full protection active. All detection systems are operational.',
    recommendations: []
  },
  degraded: {
    description: 'Protection is degraded. Some detection systems are unavailable.',
    recommendations: [
      'Check your internet connection',
      'Some advanced detection features may be limited'
    ]
  },
  minimal: {
    description: 'Minimal protection. Only basic detection is available.',
    recommendations: [
      'Check your internet connection',
      'Consider avoiding sensitive activities until full protection is restored',
      'Basic blocklist protection is still active'
    ]
  },
  offline: {
    description: 'Offline mode. Limited protection using cached data only.',
    recommendations: [
      'Connect to the internet to restore full protection',
      'Avoid entering sensitive information on unfamiliar websites',
      'Only cached threat data is available'
    ]
  }
};

/**
 * Status Indicator implementation.
 * 
 * Features:
 * - Real-time protection level display
 * - Available/unavailable method tracking
 * - Status change notifications
 * - History tracking
 */
export class StatusIndicator implements IStatusIndicator {
  private config: StatusIndicatorConfig;
  private currentLevel: ProtectionLevelInfo;
  private history: ProtectionLevelInfo[] = [];
  private listeners: Set<(info: ProtectionLevelInfo) => void> = new Set();
  private maxHistorySize: number = 100;

  constructor(config: Partial<StatusIndicatorConfig> = {}) {
    this.config = { ...DEFAULT_STATUS_INDICATOR_CONFIG, ...config };
    
    // Initialize with full protection
    this.currentLevel = this.createLevelInfo('full', [], []);
  }

  /**
   * Get current protection level info.
   */
  getProtectionLevel(): ProtectionLevelInfo {
    return { ...this.currentLevel };
  }

  /**
   * Subscribe to status changes.
   * 
   * @param callback - Function to call when status changes
   * @returns Unsubscribe function
   */
  onStatusChange(callback: (info: ProtectionLevelInfo) => void): () => void {
    this.listeners.add(callback);
    return () => this.listeners.delete(callback);
  }

  /**
   * Update status based on health check results.
   */
  updateFromHealth(health: SystemHealth): void {
    const availableMethods = health.components
      .filter(c => c.healthy)
      .map(c => this.componentToMethod(c.component));
    
    const unavailableMethods = health.components
      .filter(c => !c.healthy)
      .map(c => this.componentToMethod(c.component));

    const newLevel = this.createLevelInfo(
      health.protectionLevel,
      availableMethods,
      unavailableMethods
    );

    // Check if level changed
    const levelChanged = this.currentLevel.level !== newLevel.level;
    const methodsChanged = 
      JSON.stringify(this.currentLevel.availableMethods.sort()) !== 
      JSON.stringify(newLevel.availableMethods.sort());

    if (levelChanged || methodsChanged) {
      // Add to history
      this.addToHistory(this.currentLevel);
      
      // Update current level
      this.currentLevel = newLevel;
      
      // Notify listeners
      this.notifyListeners(newLevel);
      
      // Show notification if configured
      if (this.config.showNotifications && 
          this.config.notifyOnLevelChange && 
          levelChanged) {
        this.showNotification(newLevel);
      }
    }
  }

  /**
   * Get status history.
   * 
   * @param limit - Maximum number of entries to return
   */
  getHistory(limit?: number): ProtectionLevelInfo[] {
    const entries = [...this.history];
    if (limit && limit > 0) {
      return entries.slice(-limit);
    }
    return entries;
  }

  /**
   * Get a summary of the current status.
   */
  getSummary(): string {
    const { level, availableMethods, unavailableMethods } = this.currentLevel;
    
    let summary = `Protection Level: ${level.toUpperCase()}\n`;
    summary += `${PROTECTION_LEVEL_INFO[level].description}\n\n`;
    
    if (availableMethods.length > 0) {
      summary += `Active: ${availableMethods.join(', ')}\n`;
    }
    
    if (unavailableMethods.length > 0) {
      summary += `Unavailable: ${unavailableMethods.join(', ')}\n`;
    }
    
    return summary;
  }

  /**
   * Get icon/badge for current protection level.
   */
  getIcon(): { icon: string; color: string; tooltip: string } {
    const icons: Record<ProtectionLevel, { icon: string; color: string }> = {
      full: { icon: '🛡️', color: '#22c55e' },      // Green
      degraded: { icon: '⚠️', color: '#eab308' },  // Yellow
      minimal: { icon: '🔶', color: '#f97316' },   // Orange
      offline: { icon: '🔴', color: '#ef4444' }    // Red
    };

    const { icon, color } = icons[this.currentLevel.level];
    return {
      icon,
      color,
      tooltip: this.currentLevel.description
    };
  }

  /**
   * Check if protection is adequate for sensitive operations.
   */
  isAdequateForSensitiveOperations(): boolean {
    return this.currentLevel.level === 'full' || 
           this.currentLevel.level === 'degraded';
  }

  /**
   * Get warning message if protection is inadequate.
   */
  getWarningMessage(): string | null {
    if (this.currentLevel.level === 'minimal') {
      return 'Warning: Protection is limited. Exercise caution with sensitive information.';
    }
    if (this.currentLevel.level === 'offline') {
      return 'Warning: Offline mode. Protection is severely limited.';
    }
    return null;
  }

  /**
   * Create protection level info object.
   */
  private createLevelInfo(
    level: ProtectionLevel,
    availableMethods: string[],
    unavailableMethods: string[]
  ): ProtectionLevelInfo {
    const info = PROTECTION_LEVEL_INFO[level];
    
    return {
      level,
      description: info.description,
      availableMethods,
      unavailableMethods,
      recommendations: [...info.recommendations]
    };
  }

  /**
   * Convert component name to user-friendly method name.
   */
  private componentToMethod(component: string): string {
    const methodNames: Record<string, string> = {
      'api': 'Cloud Detection',
      'ml_pipeline': 'AI Analysis',
      'url_reputation': 'URL Reputation',
      'storage': 'Local Storage',
      'blocklist': 'Blocklist'
    };
    return methodNames[component] || component;
  }

  /**
   * Add entry to history.
   */
  private addToHistory(info: ProtectionLevelInfo): void {
    this.history.push({ ...info });
    
    // Trim history if too large
    if (this.history.length > this.maxHistorySize) {
      this.history = this.history.slice(-this.maxHistorySize);
    }
  }

  /**
   * Notify all listeners of status change.
   */
  private notifyListeners(info: ProtectionLevelInfo): void {
    for (const listener of this.listeners) {
      try {
        listener(info);
      } catch (error) {
        console.error('Status indicator listener error:', error);
      }
    }
  }

  /**
   * Show notification for status change.
   */
  private showNotification(info: ProtectionLevelInfo): void {
    // In a browser extension, this would use the notifications API
    // For now, just log
    console.log(`[PayGuard] Protection level changed to: ${info.level}`);
    console.log(`[PayGuard] ${info.description}`);
    
    if (info.recommendations.length > 0) {
      console.log('[PayGuard] Recommendations:');
      info.recommendations.forEach(r => console.log(`  - ${r}`));
    }
  }
}

/**
 * Create a status indicator connected to a health checker.
 */
export function createConnectedStatusIndicator(
  healthChecker: { onHealthChange: (callback: (health: SystemHealth) => void) => () => void },
  config?: Partial<StatusIndicatorConfig>
): StatusIndicator {
  const indicator = new StatusIndicator(config);
  
  // Connect to health checker
  healthChecker.onHealthChange((health) => {
    indicator.updateFromHealth(health);
  });
  
  return indicator;
}

// Export default instance
export const defaultStatusIndicator = new StatusIndicator();
