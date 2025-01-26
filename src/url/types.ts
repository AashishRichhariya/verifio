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

export interface VerifioURLError {
  code: VerifioURLErrorCode;
  message?: string;
}

export interface VerifioURLValidityResult {
  isValid: boolean;
  errors?: VerifioURLError[];
}

export interface VerifioURLResult {
  originalURL: string;
  validity: VerifioURLValidityResult;
  expandedURL?: string;
  isAccessible?: boolean;
}
