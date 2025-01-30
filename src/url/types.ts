export enum VerifioURLErrorCode {
  INVALID_URL = 'INVALID_URL',
  URL_TOO_LONG = 'URL_TOO_LONG',
  INVALID_PROTOCOL = 'INVALID_PROTOCOL',
  INVALID_IP = 'INVALID_IP',
  INVALID_PORT = 'INVALID_PORT',
  INVALID_DOMAIN_LENGTH = 'INVALID_DOMAIN_LENGTH',
  INVALID_HOSTNAME_CHARS = 'INVALID_HOSTNAME_CHARS',
  MALFORMED_URL = 'MALFORMED_URL',
  INVALID_LABEL_LENGTH = 'INVALID_LABEL_LENGTH',
  INVALID_LABEL_FORMAT = 'INVALID_LABEL_FORMAT',
  INVALID_PUNYCODE = 'INVALID_PUNYCODE',
  INVALID_TLD = 'INVALID_TLD',
}

export enum VerifioDomainErrorCode {
  INVALID_URL = 'INVALID_URL',
  EXTRACTION_FAILED = 'EXTRACTION_FAILED',
  URL_VERIFICATION_FAILED = 'URL_VERIFICATION_FAILED',
  DOMAIN_PARSE_ERROR = 'DOMAIN_PARSE_ERROR',
}

export interface VerifioURLError {
  code: VerifioURLErrorCode;
  message?: string;
}

/**
 * Result of URL validation
 * @property isValid - Whether the URL is valid
 * @property normalizedURL - The URL converted to lowercase and trimmed of whitespace
 * @property errors - Array of validation errors, if any
 */
export interface VerifioURLValidityResult {
  isValid: boolean;
  normalizedURL?: string,
  errors?: VerifioURLError[];
}

export interface VerifioURLResult {
  originalURL: string;
  validity: VerifioURLValidityResult;
  expandedURL?: string;
  isAccessible?: boolean;
}

export interface VerifioDomainError {
  code: VerifioDomainErrorCode;
  message?: string;
}

export interface VerifioDomainResult {
  success: boolean;
  domain?: string;
  error?: VerifioDomainError;
}
