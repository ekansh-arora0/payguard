/**
 * PayGuard V2 - Network Activity Logger
 * 
 * Logs all network transmissions with destination, size, and type.
 * Never logs actual content - only metadata for audit purposes.
 * 
 * Requirements: 5.9
 * 
 * @module privacy/NetworkActivityLogger
 */

import { AuditLogger } from '../types/audit';
import { NetworkActivityEntry, DataType } from '../types/privacy';

/**
 * Filter options for querying network activity.
 */
export interface NetworkActivityFilter {
  /** Filter by destination (partial match) */
  destination?: string;
  
  /** Filter by HTTP method */
  method?: string;
  
  /** Filter by data type */
  dataType?: DataType;
  
  /** Filter by success status */
  success?: boolean;
  
  /** Start date for date range filter */
  startDate?: Date;
  
  /** End date for date range filter */
  endDate?: Date;
  
  /** Maximum number of entries to return */
  limit?: number;
}

/**
 * Statistics about network activity.
 */
export interface NetworkActivityStats {
  /** Total number of transmissions */
  totalTransmissions: number;
  
  /** Number of successful transmissions */
  successfulTransmissions: number;
  
  /** Number of failed transmissions */
  failedTransmissions: number;
  
  /** Total bytes sent */
  totalBytesSent: number;
  
  /** Total bytes received */
  totalBytesReceived: number;
  
  /** Breakdown by data type */
  byDataType: Record<DataType, number>;
  
  /** Breakdown by destination */
  byDestination: Record<string, number>;
  
  /** Time range of logged activity */
  timeRange: {
    earliest: Date | null;
    latest: Date | null;
  };
}

/**
 * NetworkActivityLogger logs all network transmissions.
 * Records destination, size, and type but never content.
 * 
 * Usage:
 * ```typescript
 * const logger = new NetworkActivityLogger(auditLogger);
 * 
 * // Log a transmission
 * await logger.logTransmission({
 *   destination: 'https://api.payguard.io/check',
 *   method: 'POST',
 *   requestSizeBytes: 1024,
 *   responseSizeBytes: 512,
 *   dataType: 'hash',
 *   success: true
 * });
 * 
 * // Query activity
 * const recent = logger.query({ limit: 10 });
 * 
 * // Get statistics
 * const stats = logger.getStats();
 * ```
 */
export class NetworkActivityLogger {
  private auditLogger: AuditLogger;
  private entries: NetworkActivityEntry[] = [];
  private maxEntries: number;

  constructor(auditLogger: AuditLogger, maxEntries: number = 1000) {
    this.auditLogger = auditLogger;
    this.maxEntries = maxEntries;
  }

  /**
   * Log a network transmission.
   * 
   * @param entry - Transmission details (without id and timestamp)
   * 
   * Requirements: 5.9
   */
  async logTransmission(
    entry: Omit<NetworkActivityEntry, 'id' | 'timestamp'>
  ): Promise<NetworkActivityEntry> {
    const fullEntry: NetworkActivityEntry = {
      ...entry,
      id: this.generateId(),
      timestamp: new Date()
    };

    this.entries.push(fullEntry);

    // Trim if exceeds max
    if (this.entries.length > this.maxEntries) {
      this.entries = this.entries.slice(-this.maxEntries);
    }

    // Log to audit trail
    await this.auditLogger.log({
      type: 'transmit',
      action: entry.success ? 'success' : 'failure',
      metadata: {
        destination: this.sanitizeDestination(entry.destination),
        method: entry.method,
        requestSizeBytes: entry.requestSizeBytes,
        responseSizeBytes: entry.responseSizeBytes,
        dataType: entry.dataType,
        error: entry.error
      }
    });

    return fullEntry;
  }

  /**
   * Query network activity with filters.
   * 
   * @param filter - Filter options
   * @returns Matching entries
   */
  query(filter: NetworkActivityFilter = {}): NetworkActivityEntry[] {
    let results = [...this.entries];

    // Apply filters
    if (filter.destination) {
      const dest = filter.destination.toLowerCase();
      results = results.filter(e => 
        e.destination.toLowerCase().includes(dest)
      );
    }

    if (filter.method) {
      results = results.filter(e => e.method === filter.method);
    }

    if (filter.dataType) {
      results = results.filter(e => e.dataType === filter.dataType);
    }

    if (filter.success !== undefined) {
      results = results.filter(e => e.success === filter.success);
    }

    if (filter.startDate) {
      results = results.filter(e => 
        new Date(e.timestamp) >= filter.startDate!
      );
    }

    if (filter.endDate) {
      results = results.filter(e => 
        new Date(e.timestamp) <= filter.endDate!
      );
    }

    if (filter.limit && filter.limit > 0) {
      results = results.slice(-filter.limit);
    }

    return results;
  }

  /**
   * Get all logged entries.
   * 
   * @param limit - Optional limit on number of entries
   * @returns All entries (or limited subset)
   */
  getAll(limit?: number): NetworkActivityEntry[] {
    if (limit && limit > 0) {
      return this.entries.slice(-limit);
    }
    return [...this.entries];
  }

  /**
   * Get statistics about network activity.
   * 
   * @returns Activity statistics
   */
  getStats(): NetworkActivityStats {
    const stats: NetworkActivityStats = {
      totalTransmissions: this.entries.length,
      successfulTransmissions: 0,
      failedTransmissions: 0,
      totalBytesSent: 0,
      totalBytesReceived: 0,
      byDataType: {} as Record<DataType, number>,
      byDestination: {},
      timeRange: {
        earliest: null,
        latest: null
      }
    };

    for (const entry of this.entries) {
      // Count success/failure
      if (entry.success) {
        stats.successfulTransmissions++;
      } else {
        stats.failedTransmissions++;
      }

      // Sum bytes
      stats.totalBytesSent += entry.requestSizeBytes;
      stats.totalBytesReceived += entry.responseSizeBytes;

      // Count by data type
      stats.byDataType[entry.dataType] = 
        (stats.byDataType[entry.dataType] || 0) + 1;

      // Count by destination (sanitized)
      const dest = this.sanitizeDestination(entry.destination);
      stats.byDestination[dest] = (stats.byDestination[dest] || 0) + 1;

      // Track time range
      const timestamp = new Date(entry.timestamp);
      if (!stats.timeRange.earliest || timestamp < stats.timeRange.earliest) {
        stats.timeRange.earliest = timestamp;
      }
      if (!stats.timeRange.latest || timestamp > stats.timeRange.latest) {
        stats.timeRange.latest = timestamp;
      }
    }

    return stats;
  }

  /**
   * Clear all logged entries.
   */
  clear(): void {
    this.entries = [];
  }

  /**
   * Export activity log as JSON.
   * 
   * @returns JSON string of all entries
   */
  exportAsJson(): string {
    return JSON.stringify(this.entries, null, 2);
  }

  /**
   * Export activity log as CSV.
   * 
   * @returns CSV string of all entries
   */
  exportAsCsv(): string {
    const headers = [
      'id',
      'timestamp',
      'destination',
      'method',
      'requestSizeBytes',
      'responseSizeBytes',
      'dataType',
      'success',
      'error'
    ];

    const rows = this.entries.map(e => [
      e.id,
      e.timestamp.toISOString(),
      this.sanitizeDestination(e.destination),
      e.method,
      e.requestSizeBytes.toString(),
      e.responseSizeBytes.toString(),
      e.dataType,
      e.success.toString(),
      e.error || ''
    ].map(v => `"${v}"`).join(','));

    return [headers.join(','), ...rows].join('\n');
  }

  /**
   * Get the number of logged entries.
   */
  get count(): number {
    return this.entries.length;
  }

  /**
   * Generate a unique ID for an entry.
   */
  private generateId(): string {
    return `net_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }

  /**
   * Sanitize destination URL for logging.
   * Removes query parameters that might contain sensitive data.
   */
  private sanitizeDestination(url: string): string {
    try {
      const parsed = new URL(url);
      return `${parsed.origin}${parsed.pathname}`;
    } catch {
      return '[invalid-url]';
    }
  }
}
