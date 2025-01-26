import {
  VerifioURLResult,
  VerifioURLValidityResult,
  VerifioURLError,
  VerifioURLErrorCode,
} from './types';

export class VerifioURL {
  private static readonly PROTOCOLS = ['http', 'https', 'ftp', 'sftp'];
  private static readonly TLD_MIN_LENGTH = 2;
  private static readonly TLD_MAX_LENGTH = 63;
  private static readonly MAX_DOMAIN_LENGTH = 255;
  private static readonly MAX_URL_LENGTH = 2083;

  // Split regex into parts for better maintainability
  private static readonly IPV4_PATTERN =
    '(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)';

  private static readonly IPV6_PATTERN =
    '\\[(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|' +
    '(?:[0-9a-fA-F]{1,4}:){1,7}:|' +
    '(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|' +
    '(?:[0-9a-fA-F]{1,4}:){1,5}(?::[0-9a-fA-F]{1,4}){1,2}|' +
    '(?:[0-9a-fA-F]{1,4}:){1,4}(?::[0-9a-fA-F]{1,4}){1,3}|' +
    '(?:[0-9a-fA-F]{1,4}:){1,3}(?::[0-9a-fA-F]{1,4}){1,4}|' +
    '(?:[0-9a-fA-F]{1,4}:){1,2}(?::[0-9a-fA-F]{1,4}){1,5}|' +
    '[0-9a-fA-F]{1,4}:(?:(?::[0-9a-fA-F]{1,4}){1,6})|' +
    ':(?:(?::[0-9a-fA-F]{1,4}){1,7}|:)|' +
    'fe80:(?::[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|' +
    '::(?:ffff(?::0{1,4}){0,1}:){0,1}' +
    '(?:(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9])\\.){3,3}' +
    '(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9])|' +
    '(?:[0-9a-fA-F]{1,4}:){1,4}:' +
    '(?:(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9])\\.){3,3}' +
    '(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9])\\]';

  private static readonly DOMAIN_PATTERN =
    '(?:(?:www\\.)?(?:xn--[a-zA-Z0-9]+|[a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9])' +
    `(?:\\.[a-zA-Z]{${VerifioURL.TLD_MIN_LENGTH},${VerifioURL.TLD_MAX_LENGTH}})+)`;

  private static readonly URL_PATTERN = new RegExp(
    '^' +
      // Protocol
      `(?:(?:${VerifioURL.PROTOCOLS.join('|')}):\\/\\/)?` +
      // Authentication (optional)
      '(?:[a-zA-Z0-9_-]+(?::[^@]*)?@)?' +
      // IP address or domain name
      `(?:${VerifioURL.IPV4_PATTERN}|${VerifioURL.IPV6_PATTERN}|${VerifioURL.DOMAIN_PATTERN})` +
      // Port (optional)
      '(?::[1-9][0-9]{0,4})?' +
      // Path (optional)
      "(?:\\/(?:[!$&'()*+,;=\\-._~:@\\/a-zA-Z0-9%])*)*" +
      // Query (optional)
      "(?:\\?(?:[!$&'()*+,;=\\-._~:@\\/a-zA-Z0-9%=&]*)?)?" +
      // Fragment (optional)
      "(?:#(?:[!$&'()*+,;=\\-._~:@\\/a-zA-Z0-9%])*)?$",
    'i'
  );

  /**
   * Validates a URL and returns detailed results
   */
  static isValid(url: string): VerifioURLValidityResult {
    const errors: VerifioURLError[] = [];

    // Basic validation
    if (!url) {
      return {
        isValid: false,
        errors: [
          {
            code: VerifioURLErrorCode.INVALID_URL,
            message: 'URL cannot be empty',
          },
        ],
      };
    }

    if (url.length > this.MAX_URL_LENGTH) {
      errors.push({
        code: VerifioURLErrorCode.URL_TOO_LONG,
        message: `URL length exceeds maximum of ${this.MAX_URL_LENGTH} characters`,
      });
      return {
        isValid: false,
        errors,
      };
    }

    try {
      const urlObject = new URL(url);

      // Protocol validation
      const protocol = urlObject.protocol.replace(':', '');
      if (!this.PROTOCOLS.includes(protocol.toLowerCase())) {
        errors.push({
          code: VerifioURLErrorCode.INVALID_PROTOCOL,
          message: `Protocol '${protocol}' is not supported. Allowed protocols: ${this.PROTOCOLS.join(', ')}`,
        });
      }

      const hostname = urlObject.hostname.replace(/^\[|\]$/g, '');

      // IP Address validation
      if (this.isIPAddress(hostname)) {
        if (this.isIPv4Address(hostname)) {
          if (!this.isValidIPv4Address(hostname)) {
            errors.push({
              code: VerifioURLErrorCode.INVALID_IP,
              message: 'Invalid IPv4 address format',
            });
          }
        } else if (!this.isValidIPv6Address(hostname)) {
          errors.push({
            code: VerifioURLErrorCode.INVALID_IP,
            message: 'Invalid IPv6 address format',
          });
        }
      } else {
        // Domain validation for non-IP addresses
        if (hostname.length > this.MAX_DOMAIN_LENGTH) {
          errors.push({
            code: VerifioURLErrorCode.INVALID_DOMAIN_LENGTH,
            message: `Domain length exceeds maximum of ${this.MAX_DOMAIN_LENGTH} characters`,
          });
        }

        // Hostname character validation
        if (/[^a-zA-Z0-9.-]/.test(hostname)) {
          errors.push({
            code: VerifioURLErrorCode.INVALID_HOSTNAME_CHARS,
            message: 'Hostname contains invalid characters',
          });
        }

        // TLD and label validation
        const labels = hostname.split('.');
        if (labels.length > 0) {
          const tld = labels[labels.length - 1];
          if (!/^[a-zA-Z]+$/.test(tld)) {
            errors.push({
              code: VerifioURLErrorCode.INVALID_TLD,
              message: 'TLD must contain only letters',
            });
          } else if (tld.length < this.TLD_MIN_LENGTH || tld.length > this.TLD_MAX_LENGTH) {
            errors.push({
              code: VerifioURLErrorCode.INVALID_TLD,
              message: `TLD length must be between ${this.TLD_MIN_LENGTH} and ${this.TLD_MAX_LENGTH} characters`,
            });
          }
        }

        // Label validation
        for (const label of labels) {
          if (label.length > 63) {
            errors.push({
              code: VerifioURLErrorCode.INVALID_LABEL_LENGTH,
              message: 'Domain label exceeds maximum length of 63 characters',
            });
          }
          if (label.startsWith('-') || label.endsWith('-')) {
            errors.push({
              code: VerifioURLErrorCode.INVALID_LABEL_FORMAT,
              message: 'Domain labels cannot start or end with hyphens',
            });
          }

          // Punycode validation
          if (label.startsWith('xn--')) {
            if (!/^xn--[a-zA-Z0-9]+$/.test(label)) {
              errors.push({
                code: VerifioURLErrorCode.INVALID_PUNYCODE,
                message: 'Invalid Punycode format in domain label',
              });
            }
          } else {
            // Regular label character validation
            if (/[^a-zA-Z0-9-]/.test(label)) {
              errors.push({
                code: VerifioURLErrorCode.INVALID_HOSTNAME_CHARS,
                message: 'Hostname contains invalid characters',
              });
            }
          }
        }
      }

      // Port validation
      if (urlObject.port) {
        const port = parseInt(urlObject.port);
        if (port <= 0 || port > 65535) {
          errors.push({
            code: VerifioURLErrorCode.INVALID_PORT,
            message: 'Port number must be between 1 and 65535',
          });
        }
      }

      if (!this.URL_PATTERN.test(url)) {
        errors.push({
          code: VerifioURLErrorCode.INVALID_URL,
          message: 'URL format is invalid',
        });
      }
    } catch (error) {
      return {
        isValid: false,
        errors: [
          {
            code: VerifioURLErrorCode.MALFORMED_URL,
            message: 'URL is malformed: ' + (error as Error).message,
          },
        ],
      };
    }

    return {
      isValid: errors.length === 0,
      errors,
    };
  }

  /**
   * Expands a shortened URL to its full form
   * @param url The URL to expand
   * @param timeoutMs The timeout in milliseconds (default: 5000)
   * @returns The expanded URL or null if expansion fails
   */
  static async expand(url: string, timeoutMs: number = 5000): Promise<string | null> {
    try {
      if (timeoutMs <= 0) {
        throw new Error('Timeout must be greater than 0 milliseconds');
      }

      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), timeoutMs);

      try {
        const response = await fetch(url, {
          method: 'HEAD',
          redirect: 'follow',
          signal: controller.signal,
        });

        clearTimeout(timeout);

        if (!response.ok) {
          throw new Error(`HTTP error! status: ${response.status}`);
        }

        return response.url;
      } finally {
        clearTimeout(timeout);
      }
    } catch (error) {
      console.error(
        'Error checking URL:',
        error instanceof Error ? error.message : 'Unknown error'
      );
      return null;
    }
  }

  /**
   * Full URL verification including expansion and accessibility check
   */
  static async verify(url: string): Promise<VerifioURLResult> {
    const validity = this.isValid(url);

    const result: VerifioURLResult = {
      originalURL: url,
      validity,
      expandedURL: undefined,
      isAccessible: undefined,
    };

    if (validity.isValid) {
      const expanded = await this.expand(url);
      if (expanded) {
        result.expandedURL = expanded;
        result.isAccessible = true;
      } else {
        result.isAccessible = false;
      }
    }

    return result;
  }

  // Updated helper methods
  private static isIPAddress(hostname: string): boolean {
    return this.isIPv4Address(hostname) || this.isIPv6Address(hostname);
  }

  private static isIPv4Address(hostname: string): boolean {
    return /^(\d{1,3}\.){3}\d{1,3}$/.test(hostname);
  }

  private static isValidIPv4Address(ip: string): boolean {
    const parts = ip.split('.');
    return parts.every((part) => {
      const num = parseInt(part, 10);
      return num >= 0 && num <= 255;
    });
  }

  private static isIPv6Address(hostname: string): boolean {
    // Remove brackets if present
    hostname = hostname.replace(/^\[|\]$/g, '');

    // Split into groups
    const parts = hostname.split(':');

    // Check for proper length (8 parts, or 7 parts with ::)
    if (parts.length > 8) return false;

    // Check for :: compression
    const hasCompression = hostname.includes('::');
    if (hasCompression) {
      // Only one :: allowed
      if ((hostname.match(/::/g) || []).length > 1) return false;

      // Calculate expected length with compression
      const actualLength = parts.filter((p) => p !== '').length;
      if (actualLength > 7) return false;
    } else if (parts.length !== 8) {
      return false;
    }

    // Validate each part
    return parts.every((part) => {
      // Empty part (part of ::)
      if (part === '') return true;
      // Must be 1-4 hex digits
      return /^[0-9a-fA-F]{1,4}$/.test(part);
    });
  }

  private static isValidIPv6Address(ip: string): boolean {
    // Delegate to isIPv6Address since it already does full validation
    return this.isIPv6Address(ip);
  }
}
