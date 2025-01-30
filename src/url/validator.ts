import { URLHelper } from './helper';
import {
  VerifioURLResult,
  VerifioURLValidityResult,
  VerifioURLError,
  VerifioURLErrorCode,
  VerifioDomainResult,
  VerifioDomainErrorCode,
} from './types';

export class VerifioURL {
  /**
   * Checks if a given string is a valid IPv4 address
   * @param {string} address - The string to check
   * @returns {boolean} True if the string is a valid IPv4 address, false otherwise
   * @example
   * VerifioURL.isIPv4Address('192.168.1.1') // returns true
   * VerifioURL.isIPv4Address('256.1.2.3') // returns false
   */
  static isIPv4Address(address: string): boolean {
    const trimmedAddress = address.trim();
    if (!/^(\d{1,3}\.){3}\d{1,3}$/.test(trimmedAddress)) {
      return false;
    }
    const parts = trimmedAddress.split('.');
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

  /**
   * Checks if a given string is a valid IPv6 address
   * @param {string} address - The string to check
   * @returns {boolean} True if the string is a valid IPv6 address, false otherwise
   * @example
   * VerifioURL.isIPv6Address('2001:0db8:85a3:0000:0000:8a2e:0370:7334') // returns true
   * VerifioURL.isIPv6Address('2001:0db8:85a3:0000') // returns false
   * VerifioURL.isIPv6Address('::ffff:192.168.1.1') // returns true
   */
  static isIPv6Address(address: string): boolean {
    // Trim and remove brackets if present
    let trimmedAddress = address.trim().replace(/^\[|\]$/g, '');

    if (trimmedAddress.includes(':::')) {
      return false;
    }

    // Special handling for IPv4-mapped IPv6 addresses
    if (trimmedAddress.toLowerCase().includes('::ffff:')) {
      const [ipv6Part, ipv4Part] = trimmedAddress.split('::ffff:');

      // Check if we have an IPv4 part
      if (!ipv4Part) {
        return false;
      }

      // If it looks like an IPv4 address, validate it as one
      if (ipv4Part.includes('.')) {
        if (!this.isIPv4Address(ipv4Part)) {
          return false;
        }
        // Replace the IPv4 part with a placeholder for IPv6 validation
        trimmedAddress = ipv6Part + '::ffff:0:0';
      }
    }

    const compressionMarkers = trimmedAddress.match(/::/g);
    if (compressionMarkers && compressionMarkers.length > 1) {
      return false;
    }

    if (trimmedAddress.endsWith(':') && !trimmedAddress.endsWith('::')) {
      return false;
    }

    const parts = trimmedAddress.split(':');
    const hasCompression = trimmedAddress.includes('::');

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

  /**
   * Checks if a given string is either a valid IPv4 or IPv6 address
   * @param {string} address - The string to check
   * @returns {boolean} True if the string is either a valid IPv4 or IPv6 address
   * @example
   * VerifioURL.isIPAddress('192.168.1.1') // returns true
   * VerifioURL.isIPAddress('2001:0db8::1') // returns true
   * VerifioURL.isIPAddress('256.256.256.256') // returns false
   * VerifioURL.isIPAddress('2001:xyz::1') // returns false
   */
  static isIPAddress(address: string): boolean {
    const trimmedAddress = address.trim();
    return this.isIPv4Address(trimmedAddress) || this.isIPv6Address(trimmedAddress);
  }

  /**
   * Validates a URL and returns detailed results including any validation errors
   * @param {string} url - The URL to validate
   * @returns {VerifioURLValidityResult} Object containing validation results and any errors
   * @example
   * VerifioURL.isValid('https://example.com ') // returns { isValid: true, normalizedURL: 'https://example.com' }
   */
  static isValid(url: string): VerifioURLValidityResult {
    const trimmedURL = url.trim();
    const errors: VerifioURLError[] = [];

    // Basic validation
    if (!trimmedURL) {
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

    if (trimmedURL.length > URLHelper.MAX_URL_LENGTH) {
      return {
        isValid: false,
        errors: [
          {
            code: VerifioURLErrorCode.URL_TOO_LONG,
            message: `URL length exceeds maximum of ${URLHelper.MAX_URL_LENGTH} characters`,
          },
        ],
      };
    }

    // Try parsing the URL first
    let urlObject: URL;
    try {
      urlObject = new URL(trimmedURL);
    } catch (error) {
      const ipv4Match = trimmedURL.match(/\/\/([0-9.]+)/);
      const ipv6Match = trimmedURL.match(/\/\/\[([0-9a-fA-F:]+)\]/);

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
    if (!URLHelper.PROTOCOLS.includes(protocol.toLowerCase())) {
      errors.push({
        code: VerifioURLErrorCode.INVALID_PROTOCOL,
        message: `Protocol '${protocol}' is not supported. Allowed protocols: ${URLHelper.PROTOCOLS.join(', ')}`,
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
      if (hostname.length > URLHelper.MAX_DOMAIN_LENGTH) {
        errors.push({
          code: VerifioURLErrorCode.INVALID_DOMAIN_LENGTH,
          message: `Domain length exceeds maximum of ${URLHelper.MAX_DOMAIN_LENGTH} characters`,
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
        } else if (tld.length < URLHelper.TLD_MIN_LENGTH || tld.length > URLHelper.TLD_MAX_LENGTH) {
          errors.push({
            code: VerifioURLErrorCode.INVALID_TLD,
            message: `TLD length must be between ${URLHelper.TLD_MIN_LENGTH} and ${URLHelper.TLD_MAX_LENGTH} characters`,
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
    if (!URLHelper.URL_PATTERN.test(trimmedURL)) {
      errors.push({
        code: VerifioURLErrorCode.INVALID_URL,
        message: 'URL format is invalid',
      });
    }

    return errors.length === 0
      ? {
          isValid: true,
          normalizedURL: trimmedURL.toLowerCase(),
        }
      : { isValid: false, errors };
  }

  /**
   * Expands a shortened URL to its full form by following redirects
   * @param {string} url - The URL to expand
   * @param {number} [timeoutMs=5000] - The timeout in milliseconds for the request
   * @returns {Promise<string | null>} The expanded URL if successful, null if expansion fails
   * @throws {Error} If timeout value is invalid
   * @example
   * await VerifioURL.expand('https://bit.ly/xyz') // returns 'https://example.com/full-url'
   */
  static async expand(url: string, timeoutMs: number = 5000): Promise<string | null> {
    const trimmedURL = url.trim();
    if (timeoutMs <= 0) {
      throw new Error('Timeout must be greater than 0 milliseconds');
    }

    const controller = new AbortController();
    const timeoutId = setTimeout(() => {
      controller.abort();
    }, timeoutMs);

    try {
      const response = await fetch(trimmedURL, {
        method: 'HEAD',
        redirect: 'follow',
        signal: controller.signal,
      });

      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`);
      }

      return response.url.toLowerCase();
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
   * Performs comprehensive URL verification including validation, expansion, and accessibility check
   * @param {string} url - The URL to verify
   * @returns {Promise<VerifioURLResult>} Complete verification results including validity, expansion, and accessibility
   * @example
   * await VerifioURL.verify('https://example.com')
   * // returns {
   * //   originalURL: 'https://example.com',
   * //   validity: { isValid: true },
   * //   expandedURL: 'https://example.com',
   * //   isAccessible: true
   * // }
   */
  static async verify(url: string): Promise<VerifioURLResult> {
    const trimmedURL = url.trim();
    const validity = this.isValid(trimmedURL);

    const result: VerifioURLResult = {
      originalURL: trimmedURL,
      validity,
      expandedURL: undefined,
      isAccessible: undefined,
    };

    if (validity.isValid) {
      const expanded = await this.expand(trimmedURL);
      if (expanded) {
        result.expandedURL = expanded.toLowerCase();
        result.isAccessible = true;
      } else {
        result.isAccessible = false;
      }
    }

    return result;
  }

  /**
   * Extracts and validates the domain from a URL. For shortened URLs (e.g., bit.ly links),
   * the URL will first be expanded to get the final destination domain.
   * @param {string} url - The URL to extract domain from
   * @returns {Promise<VerifioDomainResult>} Object containing the extracted domain or error information
   * @example
   * // Regular URL
   * await VerifioURL.extractDomain('https://sub.example.com/path')
   * // returns {
   * //   success: true,
   * //   domain: 'sub.example.com'
   * // }
   *
   * // Shortened URL
   * await VerifioURL.extractDomain('https://bit.ly/xyz')
   * // returns {
   * //   success: true,
   * //   domain: 'example.com'  // domain from expanded URL
   * // }
   */
  static async extractDomain(url: string): Promise<VerifioDomainResult> {
    const trimmedURL = url.trim();
    try {
      // First verify the URL
      const verificationResult = await this.verify(trimmedURL);

      // If URL is invalid, return early with error
      if (!verificationResult.validity.isValid) {
        return {
          success: false,
          error: {
            code: VerifioDomainErrorCode.INVALID_URL,
            message: verificationResult.validity.errors?.[0]?.message || 'Invalid URL',
          },
        };
      }

      // Try to use the expanded URL first, fall back to original URL
      const urlToProcess = (
        verificationResult.expandedURL || verificationResult.originalURL
      ).toLowerCase();

      try {
        // Create URL object to extract hostname
        const urlObject = new URL(urlToProcess);

        // Get hostname and remove any brackets (for IPv6)
        const hostname = urlObject.hostname.replace(/^\[|\]$/g, '');

        // Return the extracted domain
        return {
          success: true,
          domain: hostname,
        };
      } catch (error) {
        return {
          success: false,
          error: {
            code: VerifioDomainErrorCode.DOMAIN_PARSE_ERROR,
            message: error instanceof Error ? error.message : 'Failed to parse domain from URL',
          },
        };
      }
    } catch (error) {
      return {
        success: false,
        error: {
          code: VerifioDomainErrorCode.EXTRACTION_FAILED,
          message: error instanceof Error ? error.message : 'Failed to extract domain',
        },
      };
    }
  }
}
