import { URLHelper } from './helper';
import {
  VerifioURLResult,
  VerifioURLValidityResult,
  VerifioURLError,
  VerifioURLErrorCode,
} from './types';

export class VerifioURL {
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

    if (url.length > URLHelper.MAX_URL_LENGTH) {
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
      urlObject = new URL(url);
    } catch (error) {
      const ipv4Match = url.match(/\/\/([0-9.]+)/);
      const ipv6Match = url.match(/\/\/\[([0-9a-fA-F:]+)\]/);

      if (ipv4Match) {
        const ipAddress = ipv4Match[1];
        if (!URLHelper.isIPv4Address(ipAddress)) {
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
        if (!URLHelper.isIPv6Address(ipAddress)) {
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
    if (URLHelper.isIPAddress(hostname)) {
      // Additional IP validation for edge cases that URL constructor accepts
      if (URLHelper.isIPv4Address(hostname)) {
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
    if (!URLHelper.URL_PATTERN.test(url)) {
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
}
