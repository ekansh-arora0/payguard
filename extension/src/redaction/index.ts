/**
 * PayGuard V2 - Redaction Module
 * 
 * Exports for the Redaction Engine that masks sensitive content
 * before any processing or storage.
 */

export { RedactionEngine } from './RedactionEngine';
export { 
  VisualMasking, 
  createRedactionStyles, 
  injectRedactionStyles,
  DEFAULT_MASKING_OPTIONS
} from './VisualMasking';
export { 
  RedactionPipeline, 
  createDefaultPipeline 
} from './RedactionPipeline';
export {
  createRegexPattern,
  createFieldPattern,
  createPhonePattern,
  createDOBPattern,
  createBankAccountPattern,
  createRoutingNumberPattern,
  createPassportPattern,
  createDriversLicensePattern,
  createAPIKeyPattern,
  createHealthInsurancePattern,
  validatePattern,
  serializePatterns,
  deserializePatterns,
  createAllPresetPatterns,
  PATTERN_PRESETS
} from './PatternHelpers';
export type { 
  MaskingOptions 
} from './VisualMasking';
export type { 
  ContentType, 
  PipelineInput, 
  PipelineOutput, 
  AnalysisCallback 
} from './RedactionPipeline';
export * from '../types/redaction';
