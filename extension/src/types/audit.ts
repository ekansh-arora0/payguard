/**
 * PayGuard V2 - Audit Types
 * 
 * Interfaces for audit logging operations.
 */

/**
 * Types of events that can be logged.
 */
export type AuditEventType = 
  | 'consent'
  | 'capture'
  | 'analyze'
  | 'transmit'
  | 'delete'
  | 'access';

/**
 * An audit event to be logged.
 */
export interface AuditEvent {
  /** Type of the event */
  type: AuditEventType;
  
  /** Action performed (e.g., 'grant', 'revoke', 'request') */
  action: string;
  
  /** Additional metadata (never contains actual content) */
  metadata: Record<string, unknown>;
  
  /** Optional user identifier */
  userId?: string;
}

/**
 * A logged audit entry with additional tracking fields.
 */
export interface AuditEntry extends AuditEvent {
  /** Unique identifier for this entry */
  id: string;
  
  /** Timestamp when the event occurred */
  timestamp: Date;
  
  /** Hash of this entry for chain verification */
  hash: string;
  
  /** Hash of the previous entry for tamper detection */
  previousHash: string;
}

/**
 * Filter options for querying audit logs.
 */
export interface AuditFilter {
  /** Filter by event type */
  type?: AuditEventType;
  
  /** Filter by action */
  action?: string;
  
  /** Filter by user ID */
  userId?: string;
  
  /** Start date for date range filter */
  startDate?: Date;
  
  /** End date for date range filter */
  endDate?: Date;
  
  /** Maximum number of entries to return */
  limit?: number;
}

/**
 * Result of integrity verification.
 */
export interface IntegrityResult {
  /** Whether the audit log is valid (no tampering detected) */
  valid: boolean;
  
  /** List of errors found during verification */
  errors: string[];
  
  /** Number of entries checked */
  entriesChecked: number;
  
  /** Timestamp of last verification */
  lastVerified: Date;
}

/**
 * Interface for the audit logger.
 */
export interface AuditLogger {
  /**
   * Log an audit event.
   * @param event - The event to log
   */
  log(event: AuditEvent): Promise<void>;
  
  /**
   * Query the audit log.
   * @param filter - Filter options
   * @returns Matching audit entries
   */
  query(filter: AuditFilter): Promise<AuditEntry[]>;
  
  /**
   * Export audit log in specified format.
   * @param format - Export format
   * @returns Exported data
   */
  export(format: 'json' | 'csv' | 'cef'): Promise<Uint8Array>;
  
  /**
   * Verify the integrity of the audit log.
   * @returns Integrity verification result
   */
  verifyIntegrity(): Promise<IntegrityResult>;
}
