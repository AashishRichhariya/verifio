// src/url/helper.ts
export class URLHelper {
  static readonly PROTOCOLS = ['http', 'https', 'ftp', 'sftp'];
  static readonly TLD_MIN_LENGTH = 2;
  static readonly TLD_MAX_LENGTH = 63;
  static readonly MAX_DOMAIN_LENGTH = 255;
  static readonly MAX_URL_LENGTH = 2083;

  static readonly IPV4_PATTERN =
    '(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)';

  static readonly IPV6_PATTERN =
    '\\[' + // Opening bracket
    '(?:' +
    // Regular IPv6 with optional compression
    '[0-9a-fA-F:]{2,}' +
    '(?::[0-9a-fA-F]{1,4})*|' +
    // IPv4-mapped IPv6
    '::ffff:[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}' +
    ')' +
    '\\]'; // Closing bracket

  static readonly DOMAIN_PATTERN =
    '(?:(?:(?:xn--[a-zA-Z0-9]+|[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)\\.)*' + // Multiple subdomains
    '(?:xn--[a-zA-Z0-9]+|[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)' + // Domain name
    `(?:\\.[a-zA-Z]{${URLHelper.TLD_MIN_LENGTH},${URLHelper.TLD_MAX_LENGTH}})+)`; // TLD

  static readonly URL_PATTERN = new RegExp(
    '^' +
      // Protocol
      `(?:(?:${URLHelper.PROTOCOLS.join('|')}):\\/\\/)?` +
      // Authentication (optional with percent-encoding)
      '(?:[a-zA-Z0-9._~%-](?:[a-zA-Z0-9._~%-]|%[0-9a-fA-F]{2})*' +
      '(?::[a-zA-Z0-9._~%-](?:[a-zA-Z0-9._~%-]|%[0-9a-fA-F]{2})*)?@)?' +
      // IP address or domain name
      `(?:${URLHelper.IPV4_PATTERN}|${URLHelper.IPV6_PATTERN}|${URLHelper.DOMAIN_PATTERN})` +
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
}
