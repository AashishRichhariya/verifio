/**
 * Enumeration of possible URL validation error codes
 * @enum {string}
 */
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

/**
 * Enumeration of possible domain extraction error codes
 * @enum {string}
 */
export enum VerifioDomainErrorCode {
  INVALID_URL = 'INVALID_URL',
  EXTRACTION_FAILED = 'EXTRACTION_FAILED',
  URL_VERIFICATION_FAILED = 'URL_VERIFICATION_FAILED',
  DOMAIN_PARSE_ERROR = 'DOMAIN_PARSE_ERROR',
}

/**
 * Interface representing a URL validation error
 * @interface
 * @property {VerifioURLErrorCode} code - The error code indicating the type of validation failure
 * @property {string} [message] - Optional human-readable description of the error
 */
export interface VerifioURLError {
  code: VerifioURLErrorCode;
  message?: string;
}

/**
 * Result of URL validation
 * @interface
 * @property {boolean} isValid - Whether the URL is valid
 * @property {string} [normalizedURL] - The URL converted to lowercase and trimmed of whitespace
 * @property {VerifioURLError[]} [errors] - Array of validation errors, if any
 */
export interface VerifioURLValidityResult {
  isValid: boolean;
  normalizedURL?: string,
  errors?: VerifioURLError[];
}

/**
 * Complete result of URL verification including expansion and accessibility check
 * @interface
 * @property {string} originalURL - The URL as provided before any processing
 * @property {VerifioURLValidityResult} validity - Results of URL validation
 * @property {string} [expandedURL] - Full URL after following any redirects
 * @property {boolean} [isAccessible] - Whether the URL is accessible via HTTP request
 */
export interface VerifioURLResult {
  originalURL: string;
  validity: VerifioURLValidityResult;
  expandedURL?: string;
  isAccessible?: boolean;
}

/**
 * Interface representing a domain extraction error
 * @interface
 * @property {VerifioDomainErrorCode} code - The error code indicating the type of domain extraction failure
 * @property {string} [message] - Optional human-readable description of the error
 */
export interface VerifioDomainError {
  code: VerifioDomainErrorCode;
  message?: string;
}

/**
 * Result of domain extraction from a URL
 * @interface
 * @property {boolean} success - Whether domain extraction was successful
 * @property {string} [domain] - The extracted domain name if successful
 * @property {VerifioDomainError} [error] - Error information if extraction failed
 */
export interface VerifioDomainResult {
  success: boolean;
  domain?: string;
  error?: VerifioDomainError;
}
