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
    '\\[' + // Opening bracket
    '(?:' +
    // Regular IPv6 with optional compression
    '[0-9a-fA-F:]{2,}' +
    '(?::[0-9a-fA-F]{1,4})*|' +
    // IPv4-mapped IPv6
    '::ffff:[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}' +
    ')' +
    '\\]'; // Closing bracket

  private static readonly DOMAIN_PATTERN =
    '(?:(?:(?:xn--[a-zA-Z0-9]+|[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)\\.)*' + // Multiple subdomains
    '(?:xn--[a-zA-Z0-9]+|[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)' + // Domain name
    `(?:\\.[a-zA-Z]{${VerifioURL.TLD_MIN_LENGTH},${VerifioURL.TLD_MAX_LENGTH}})+)`; // TLD

  private static readonly URL_PATTERN = new RegExp(
    '^' +
      // Protocol
      `(?:(?:${VerifioURL.PROTOCOLS.join('|')}):\\/\\/)?` +
      // Authentication (optional with percent-encoding)
      '(?:[a-zA-Z0-9._~%-](?:[a-zA-Z0-9._~%-]|%[0-9a-fA-F]{2})*' +
      '(?::[a-zA-Z0-9._~%-](?:[a-zA-Z0-9._~%-]|%[0-9a-fA-F]{2})*)?@)?' +
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
      return {
        isValid: false,
        errors: [
          {
            code: VerifioURLErrorCode.URL_TOO_LONG,
            message: `URL length exceeds maximum of ${this.MAX_URL_LENGTH} characters`,
          },
        ],
      };
    }

    // Try parsing the URL first
    let urlObject: URL;
    try {
      urlObject = new URL(url);
    } catch (error) {
      const ipv4Match = url.match(/\/\/([0-9.]+)/);
      const ipv6Match = url.match(/\/\/\[([0-9a-fA-F:]+)\]/);

      if (ipv4Match) {
        const ipAddress = ipv4Match[1];
        if (!this.isIPv4Address(ipAddress)) {
          return {
            isValid: false,
            errors: [
              {
                code: VerifioURLErrorCode.INVALID_IP,
                message: 'Invalid IPv4 address - values must be between 0 and 255',
              },
            ],
          };
        }
      } else if (ipv6Match) {
        const ipAddress = ipv6Match[1];
        if (!this.isIPv6Address(ipAddress)) {
          return {
            isValid: false,
            errors: [
              {
                code: VerifioURLErrorCode.INVALID_IP,
                message: 'Invalid IPv6 address format',
              },
            ],
          };
        }
      }

      // If no specific error was found, return generic malformed URL error
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

    // At this point, we have a valid URL object, so we can do additional validations
    // Protocol validation
    const protocol = urlObject.protocol.replace(':', '');
    if (!this.PROTOCOLS.includes(protocol.toLowerCase())) {
      errors.push({
        code: VerifioURLErrorCode.INVALID_PROTOCOL,
        message: `Protocol '${protocol}' is not supported. Allowed protocols: ${this.PROTOCOLS.join(', ')}`,
      });
    }

    // Get hostname without brackets for IPv6
    const hostname = urlObject.hostname.replace(/^\[|\]$/g, '');

    // Check if it's an IP address
    if (this.isIPAddress(hostname)) {
      // Additional IP validation for edge cases that URL constructor accepts
      if (this.isIPv4Address(hostname)) {
        const parts = hostname.split('.');
        const hasInvalidOctet = parts.some((part) => {
          const num = parseInt(part, 10);
          return num > 255 || part !== num.toString();
        });
        if (hasInvalidOctet) {
          errors.push({
            code: VerifioURLErrorCode.INVALID_IP,
            message: 'Invalid IPv4 address format',
          });
        }
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
          if (!/^xn--[a-zA-Z0-9]+-*[a-zA-Z0-9]+$/.test(label)) {
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

    // Final URL pattern validation
    if (!this.URL_PATTERN.test(url)) {
      errors.push({
        code: VerifioURLErrorCode.INVALID_URL,
        message: 'URL format is invalid',
      });
    }

    return errors.length === 0 ? { isValid: true } : { isValid: false, errors };
  }

  /**
   * Expands a shortened URL to its full form
   * @param url The URL to expand
   * @param timeoutMs The timeout in milliseconds (default: 5000)
   * @returns The expanded URL or null if expansion fails
   */
  static async expand(url: string, timeoutMs: number = 5000): Promise<string | null> {
    if (timeoutMs <= 0) {
      throw new Error('Timeout must be greater than 0 milliseconds');
    }

    const controller = new AbortController();
    const timeoutId = setTimeout(() => {
      controller.abort();
    }, timeoutMs);

    try {
      const response = await fetch(url, {
        method: 'HEAD',
        redirect: 'follow',
        signal: controller.signal,
      });

      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`);
      }

      return response.url;
    } catch (error) {
      if (error instanceof DOMException && error.name === 'AbortError') {
        console.error(`Request timed out after ${timeoutMs}ms`);
      } else {
        console.error(
          'Error checking URL:',
          error instanceof Error ? error.message : 'Unknown error'
        );
      }
      return null;
    } finally {
      clearTimeout(timeoutId);
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
    if (!/^(\d{1,3}\.){3}\d{1,3}$/.test(hostname)) {
      return false;
    }
    const parts = hostname.split('.');
    if (parts.length !== 4) {
      return false;
    }
    return parts.every((part) => {
      const num = parseInt(part, 10);
      if (part !== num.toString()) {
        return false;
      }
      return num >= 0 && num <= 255;
    });
  }

  private static isIPv6Address(hostname: string): boolean {
    // Remove brackets if present
    hostname = hostname.replace(/^\[|\]$/g, '');

    if (hostname.includes(':::')) {
      return false;
    }

    const compressionMarkers = hostname.match(/::/g);
    if (compressionMarkers && compressionMarkers.length > 1) {
      return false;
    }

    if (hostname.endsWith(':') && !hostname.endsWith('::')) {
      return false;
    }

    const parts = hostname.split(':');
    const hasCompression = hostname.includes('::');

    if (hasCompression) {
      const actualSegments = parts.filter((p) => p !== '').length;
      if (actualSegments >= 8) {
        return false;
      }
    } else {
      if (parts.length !== 8) {
        return false;
      }
    }

    return parts.every((part) => {
      if (part === '') {
        return hasCompression;
      }
      return /^[0-9a-fA-F]{1,4}$/.test(part);
    });
  }
}
