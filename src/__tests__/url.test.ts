import {
  VerifioURL,
  VerifioURLErrorCode,
  VerifioURLValidityResult,
  VerifioDomainErrorCode,
} from '..';

// Mock fetch for expansion tests
global.fetch = jest.fn();

const expectValidURL = (result: VerifioURLValidityResult): void => {
  expect(result.isValid).toBe(true);
  expect(result.errors).toBeUndefined();
};

const expectInvalidURL = (
  result: VerifioURLValidityResult,
  expectedCode: VerifioURLErrorCode
): void => {
  expect(result.isValid).toBe(false);
  expect(result.errors).toBeDefined();
  expect(result.errors).toContainEqual(
    expect.objectContaining({
      code: expect.stringMatching(`^(${expectedCode}|${VerifioURLErrorCode.MALFORMED_URL})$`),
    })
  );
};

describe('VerifioURL', () => {
  beforeEach(() => {
    (global.fetch as jest.Mock).mockClear();
  });

  describe('isValid', () => {
    describe('Basic URL Validation', () => {
      const validURLs = [
        'https://example.com',
        'http://example.com',
        'ftp://files.example.com',
        'sftp://secure.example.com',
        'https://www.example.com',
        'https://sub1.sub2.example.com',
        'https://example.com:8080',
        'https://example.com/path',
        'https://example.com/path?query=value',
        'https://example.com/path#fragment',
        'https://example.com/path?query=value#fragment',
        'https://user:pass@example.com',
        'https://example.com/path/to/resource.html',
        'https://example.co.uk',
        'https://xn--bcher-kva.example.com', // Punycode

        // miscellaneous
        'http://example.com/path?',
        'http://example.com/path?&',
        'http://example.com/%2e%2e',
        'http://example.com/..%2fm',
        'http://example.com/%2e%2e%2f',
        'HTTP://example.com',
        'Http://example.com',
        'http://example.com/\x0A',

        // Excessive components
        'http://a.b.c.d.e.f.g.h.i.j.k.l.m.n.o.p.q.r.s.t.u.v.w.x.y.z.com',
        'http://example.com/' + 'a'.repeat(2048),

        // Whitespace cases
        ' https://example.com',
        'https://example.com ',
        ' https://example.com ',
        'https://example.com\n',
        'https://example.com\t',
        'https://example.com\r',
        '\nhttps://example.com',
        '\thttps://example.com',
        '\rhttps://example.com',
        ' \n\t\rhttps://example.com\n\t\r ',
      ];

      test.each(validURLs)('should validate correct URL: %s', (url) => {
        const result = VerifioURL.isValid(url);
        expectValidURL(result);
      });

      const invalidURLs = [
        // Empty or null-like values
        '',
        ' ',
        'undefined',
        'null',

        // Invalid protocols and formats
        'not-a-url',
        'http://',
        'http://.',
        'http://..',
        'http://../',
        'http://?',
        'http://??',
        'http://??/',
        'http://#',
        'http://##',
        'http://##/',
        'http://foo.bar?q=Spaces should be encoded',
        '//',
        '//a',
        '///a',
        'http:///a',

        // Spaces and special characters
        'http://foo.bar?q=Spaces should be encoded',
        'http://exa mple.com',
        'https://example. com',
        'https://example.com/ space',
        'http://example.com/path with spaces',
        'http://example.com/path/with/spa ces/',
        'http://example.com?query= space',
        'http://example.com#frag ment',
        'http://user name@example.com',

        // Invalid characters in hostname
        'http://example!.com',
        'http://example*.com',
        'http://example(.com',
        'http://example).com',
        'http://exa\\mple.com',
        'http://exam$ple.com',
        'http://example`.com',
        'http://example{.com',
        'http://example}.com',
        'http://example<.com',
        'http://example>.com',

        // Invalid TLD formats
        'http://example.c',
        'http://example.',
        'http://example.com.',
        'http://example..com',
        'http://example.com..',
        'http://example.c_m',
        'http://example.123',

        // Invalid domain formats
        'http://.example.com',
        'http://example-.com',
        'http://-example.com',
        'http://example.-com',
        'http://example.com-',

        // Invalid credentials format
        'http://@example.com',
        'http://user@:password@example.com',
        'http://:password@example.com',
        'http://user:pass:word@example.com',

        // Invalid port formats
        'http://example.com:',
        'http://example.com:abc',
        'http://example.com:123:456',
        'http://example.com:65536',

        // Malformed paths and queries
        'http://example.com/path??',
        'http://example.com/path#?',
        'http://example.com/path#fragment#another',

        // Unicode and special characters
        'http://exämple.com',
        'http://example.com/päth',
        'http://example.com/path™',
        'http://example.com/path©',
        'http://example.com/path®',
        'http://example.com/path°',

        // Control characters
        'http://example.com/\x00',
        'http://example.com/\x1F',

        // Invalid IP formats
        'http://127.0.0',
        'http://[::1',
        'http://[]',

        // Scheme confusion
        'javascript:alert(1)',
        'data:text/html,<script>alert(1)</script>',
        'vbscript:msgbox(1)',

        // Invalid Punycodes:
        'https://xn--.example.com',
        'https://xn--@@.example.com',

        // Various edge cases
        'http://..',
        'http://...',
        'http://example..com',
        'http://example...com',
        'http://*example.com',
        'http://example.com:65536',
        'http://example.com:999999',
      ];

      test.each(invalidURLs)('should invalidate incorrect URL: %s', (url) => {
        const result = VerifioURL.isValid(url);
        expectInvalidURL(result, VerifioURLErrorCode.INVALID_URL);
      });
    });

    describe('Protocol Validation', () => {
      const invalidProtocols = [
        'gopher://example.com',
        'ws://example.com',
        'wss://example.com',
        'file://example.com',
      ];

      test.each(invalidProtocols)('should reject invalid protocol: %s', (url) => {
        const result = VerifioURL.isValid(url);
        expectInvalidURL(result, VerifioURLErrorCode.INVALID_PROTOCOL);
      });
    });

    describe('IP Address Validation', () => {
      const validIPs = [
        'http://192.168.1.1',
        'https://[2001:0db8:85a3:0000:0000:8a2e:0370:7334]',
        'http://127.0.0.1:8080',
        'https://[::1]',
        'https://[::ffff:192.0.2.1]', // IPv4-mapped IPv6 address
        'https://[2001:db8::1]', // Compressed IPv6
        'https://[fe80::1]', // Link-local address
        'https://[::ffff:192.168.1.1]', // IPv4-mapped address
      ];

      test.each(validIPs)('should validate correct IP address: %s', (url) => {
        const result = VerifioURL.isValid(url);
        expectValidURL(result);
      });

      const invalidIPs = [
        // Invalid IPv4 formats
        'http://1.2.3.256',
        'http://1.2.3.4.5', // Too many IPv4 octets'
        'http://127.0.0.0.1',
        'http://256.256.256.256', //Invalid IPv4 octets

        // Invalid IPv6 formats
        'http://[1:2:3:4:5:6:7]',
        'http://[1:2:3:4:5:6:7:8:9]',
        'https://[2001:0db8:85a3:0000:0000:8a2e:0370:7334:7334]', // Too many IPv6 segments
        'https://[:::1]', // invalid IPv6 compression
        'https://[2001:0db8:85a3:::1]', // Multiple compression markers
        'https://[2001:0db8:85a3:0000:0000:8a2e:0370:]', // Trailing colon
      ];

      test.each(invalidIPs)('should invalidate %s', (url) => {
        const result = VerifioURL.isValid(url);
        expectInvalidURL(result, VerifioURLErrorCode.INVALID_IP);
      });
    });

    describe('Domain Length Validation', () => {
      test('should reject domain exceeding maximum length', () => {
        const longDomain = 'https://' + 'a'.repeat(256) + '.com';
        const result = VerifioURL.isValid(longDomain);
        expectInvalidURL(result, VerifioURLErrorCode.INVALID_DOMAIN_LENGTH);
      });

      test('should reject URL exceeding maximum length', () => {
        const longURL = 'https://example.com/' + 'a'.repeat(2084);
        const result = VerifioURL.isValid(longURL);
        expectInvalidURL(result, VerifioURLErrorCode.URL_TOO_LONG);
      });
    });

    describe('Punycode Validation', () => {
      const validPunycode = ['https://xn--mnchen-3ya.de', 'https://xn--bcher-kva.example.com'];

      test.each(validPunycode)('should validate correct Punycode: %s', (url) => {
        const result = VerifioURL.isValid(url);
        expectValidURL(result);
      });
    });

    describe('TLD Validation', () => {
      const validTLDs = [
        'https://example.com',
        'https://example.co.uk',
        'https://example.travel',
        'https://example.museum',
        'https://example.photography',
      ];

      test.each(validTLDs)('should validate correct TLD: %s', (url) => {
        const result = VerifioURL.isValid(url);
        expectValidURL(result);
      });

      const invalidTLDs = [
        {
          url: 'https://example.c',
          code: VerifioURLErrorCode.INVALID_TLD,
          desc: 'TLD too short',
        },
        {
          url: 'https://example.' + 'a'.repeat(64),
          code: VerifioURLErrorCode.INVALID_TLD,
          desc: 'TLD too long',
        },
        {
          url: 'https://example.123',
          code: VerifioURLErrorCode.INVALID_TLD,
          desc: 'Numeric TLD',
        },
        {
          url: 'https://example.c_m',
          code: VerifioURLErrorCode.INVALID_TLD,
          desc: 'TLD with underscore',
        },
        {
          url: 'https://example.com-',
          code: VerifioURLErrorCode.INVALID_LABEL_FORMAT,
          desc: 'TLD ending with hyphen',
        },
      ];

      test.each(invalidTLDs)('should invalidate $desc: $url', ({ url, code }) => {
        const result = VerifioURL.isValid(url);
        expectInvalidURL(result, code);
      });
    });

    describe('Port Validation', () => {
      const validPorts = [
        'http://example.com:1',
        'http://example.com:8080',
        'http://example.com:65535',
        'http://127.0.0.1:8080',
        'https://[::1]:8080',
      ];

      test.each(validPorts)('should validate correct port: %s', (url) => {
        const result = VerifioURL.isValid(url);
        expectValidURL(result);
      });

      const invalidPorts = [
        {
          url: 'http://example.com:0',
          desc: 'Port zero',
        },
        {
          url: 'http://example.com:65536',
          desc: 'Port exceeds maximum',
        },
        {
          url: 'http://example.com:-1',
          desc: 'Negative port',
        },
        {
          url: 'http://example.com:port',
          desc: 'Non-numeric port',
        },
        {
          url: 'http://example.com:8080:80',
          desc: 'Multiple ports',
        },
      ];

      test.each(invalidPorts)('should invalidate $desc: $url', ({ url }) => {
        const result = VerifioURL.isValid(url);
        expectInvalidURL(result, VerifioURLErrorCode.INVALID_PORT);
      });
    });

    describe('Domain Label Validation', () => {
      const validLabels = [
        'https://sub1.example.com',
        'https://sub-1.example.com',
        'https://sub1-sub2.example.com',
        'https://' + 'a'.repeat(63) + '.example.com',

        // Whitespace cases
        ' https://sub1.example.com',
        'https://sub1.example.com ',
        ' https://sub1.example.com ',
        'https://sub1.example.com\n',
        'https://sub1.example.com\t',
        'https://sub1.example.com\r',
        '\nhttps://sub1.example.com',
        '\thttps://sub1.example.com',
        '\rhttps://sub1.example.com',
        ' \n\t\rhttps://sub1.example.com\n\t\r ',
      ];

      test.each(validLabels)('should validate correct domain label: %s', (url) => {
        const result = VerifioURL.isValid(url);
        expectValidURL(result);
      });

      const invalidLabels = [
        {
          url: 'https://' + 'a'.repeat(64) + '.example.com',
          code: VerifioURLErrorCode.INVALID_LABEL_LENGTH,
          desc: 'Label too long',
        },
        {
          url: 'https://-sub.example.com',
          code: VerifioURLErrorCode.INVALID_LABEL_FORMAT,
          desc: 'Label starts with hyphen',
        },
        {
          url: 'https://sub-.example.com',
          code: VerifioURLErrorCode.INVALID_LABEL_FORMAT,
          desc: 'Label ends with hyphen',
        },
        {
          url: 'https://sub_1.example.com',
          code: VerifioURLErrorCode.INVALID_HOSTNAME_CHARS,
          desc: 'Label contains underscore',
        },
        {
          url: ' https://-sub.example.com ',
          code: VerifioURLErrorCode.INVALID_LABEL_FORMAT,
          desc: 'Label starts with hyphen with whitespace',
        },
        {
          url: '\thttps://sub_1.example.com\n',
          code: VerifioURLErrorCode.INVALID_HOSTNAME_CHARS,
          desc: 'Label contains underscore with whitespace',
        },
      ];

      test.each(invalidLabels)('should invalidate $desc: $url', ({ url, code }) => {
        const result = VerifioURL.isValid(url);
        expectInvalidURL(result, code);
      });
    });
  });

  describe('expand', () => {
    beforeEach(() => {
      jest.clearAllMocks();
      // Silence console.error during tests
      jest.spyOn(console, 'error').mockImplementation(() => {});
    });

    afterEach(() => {
      (console.error as jest.Mock).mockRestore();
    });

    test('should expand shortened URL successfully', async () => {
      const shortUrl = 'https://short.url/abc123';
      const expandedUrl = 'https://example.com/full-path';

      (global.fetch as jest.Mock).mockImplementationOnce(() =>
        Promise.resolve({
          ok: true,
          url: expandedUrl,
        })
      );

      const result = await VerifioURL.expand(shortUrl);
      expect(result).toBe(expandedUrl);
      expect(global.fetch).toHaveBeenCalledWith(
        shortUrl,
        expect.objectContaining({
          method: 'HEAD',
          redirect: 'follow',
        })
      );
    });

    test('should handle expansion failure', async () => {
      const shortUrl = 'https://short.url/invalid';

      (global.fetch as jest.Mock).mockImplementationOnce(() =>
        Promise.resolve({
          ok: false,
          status: 404,
        })
      );

      const result = await VerifioURL.expand(shortUrl);
      expect(result).toBeNull();
    });

    test('should handle timeout', async () => {
      const shortUrl = 'https://short.url/timeout';

      // Mock fetch to reject immediately with AbortError
      (global.fetch as jest.Mock).mockImplementationOnce(() =>
        Promise.reject(new DOMException('The operation was aborted', 'AbortError'))
      );

      const result = await VerifioURL.expand(shortUrl, 100);
      expect(result).toBeNull();
    }, 1000);
  });

  describe('verify', () => {
    beforeEach(() => {
      jest.clearAllMocks();
      jest.spyOn(console, 'error').mockImplementation(() => {});
    });

    afterEach(() => {
      (console.error as jest.Mock).mockRestore();
    });

    test('should verify valid and accessible URL', async () => {
      const url = 'https://example.com';

      (global.fetch as jest.Mock).mockImplementationOnce(() =>
        Promise.resolve({
          ok: true,
          url: url,
        })
      );

      const result = await VerifioURL.verify(url);
      expect(result).toEqual({
        originalURL: url,
        validity: {
          isValid: true,
          errors: undefined,
        },
        expandedURL: url,
        isAccessible: true,
      });
    });

    test('should handle invalid URL', async () => {
      const invalidUrl = 'not-a-url';
      const result = await VerifioURL.verify(invalidUrl);
      expect(result.validity.isValid).toBe(false);
      expect(result.validity.errors).toBeDefined();
      expect(result.validity.errors!.length).toBeGreaterThan(0);
      expect(result.isAccessible).toBeUndefined();
      expect(result.expandedURL).toBeUndefined();
    });

    test('should handle inaccessible URL', async () => {
      const url = 'https://nonexistent.example.com';

      (global.fetch as jest.Mock).mockImplementationOnce(() =>
        Promise.resolve({
          ok: false,
          status: 404,
        })
      );

      const result = await VerifioURL.verify(url);
      expect(result.validity.isValid).toBe(true);
      expect(result.validity.errors).toBeUndefined();
      expect(result.isAccessible).toBe(false);
      expect(result.expandedURL).toBeUndefined();
    });
  });

  describe('extractDomain', () => {
    beforeEach(() => {
      jest.clearAllMocks();
      jest.spyOn(console, 'error').mockImplementation(() => {});
    });

    afterEach(() => {
      (console.error as jest.Mock).mockRestore();
    });

    describe('Basic Domain Extraction', () => {
      const validCases = [
        {
          input: 'https://example.com',
          expected: 'example.com',
          desc: 'simple domain',
        },
        {
          input: 'http://sub.example.com',
          expected: 'sub.example.com',
          desc: 'subdomain',
        },
        {
          input: 'https://sub1.sub2.example.co.uk',
          expected: 'sub1.sub2.example.co.uk',
          desc: 'multiple subdomains',
        },
        {
          input: 'https://example.com:8080',
          expected: 'example.com',
          desc: 'domain with port',
        },
        {
          input: 'https://example.com/path?query=value#fragment',
          expected: 'example.com',
          desc: 'domain with path, query and fragment',
        },
      ];

      test.each(validCases)('should extract $desc: $input', async ({ input, expected }) => {
        const result = await VerifioURL.extractDomain(input);
        expect(result.success).toBe(true);
        expect(result.domain).toBe(expected);
        expect(result.error).toBeUndefined();
      });
    });

    describe('IP Address Extraction', () => {
      const ipCases = [
        {
          input: 'http://192.168.1.1',
          expected: '192.168.1.1',
          desc: 'IPv4 address',
        },
        {
          input: 'https://[2001:0db8:85a3:0000:0000:8a2e:0370:7334]',
          expected: '2001:db8:85a3::8a2e:370:7334',
          desc: 'full IPv6 address',
        },
        {
          input: 'https://[::1]',
          expected: '::1',
          desc: 'localhost IPv6',
        },
        {
          input: 'https://[::ffff:192.0.2.1]',
          expected: '::ffff:c000:201',
          desc: 'IPv4-mapped IPv6 address',
        },
      ];

      test.each(ipCases)('should extract $desc: $input', async ({ input, expected }) => {
        const result = await VerifioURL.extractDomain(input);
        expect(result.success).toBe(true);
        expect(result.domain).toBe(expected);
        expect(result.error).toBeUndefined();
      });
    });

    describe('URL Shortener Cases', () => {
      test('should extract domain from expanded URL', async () => {
        const shortUrl = 'https://bit.ly/abc123';
        const expandedUrl = 'https://example.com/full-path';

        (global.fetch as jest.Mock).mockImplementationOnce(() =>
          Promise.resolve({
            ok: true,
            url: expandedUrl,
          })
        );

        const result = await VerifioURL.extractDomain(shortUrl);
        expect(result.success).toBe(true);
        expect(result.domain).toBe('example.com');
        expect(result.error).toBeUndefined();
      });

      test('should fall back to original domain if expansion fails', async () => {
        const shortUrl = 'https://bit.ly/invalid';

        (global.fetch as jest.Mock).mockImplementationOnce(() =>
          Promise.resolve({
            ok: false,
            status: 404,
          })
        );

        const result = await VerifioURL.extractDomain(shortUrl);
        expect(result.success).toBe(true);
        expect(result.domain).toBe('bit.ly');
        expect(result.error).toBeUndefined();
      });
    });

    describe('Error Cases', () => {
      const invalidCases = [
        {
          input: '',
          errorCode: VerifioDomainErrorCode.INVALID_URL,
          desc: 'empty string',
        },
        {
          input: 'not-a-url',
          errorCode: VerifioDomainErrorCode.INVALID_URL,
          desc: 'malformed URL',
        },
        {
          input: 'http://',
          errorCode: VerifioDomainErrorCode.INVALID_URL,
          desc: 'protocol only',
        },
        {
          input: 'http://[invalid-ipv6]',
          errorCode: VerifioDomainErrorCode.INVALID_URL,
          desc: 'invalid IPv6',
        },
        {
          input: 'http://256.256.256.256',
          errorCode: VerifioDomainErrorCode.INVALID_URL,
          desc: 'invalid IPv4',
        },
        {
          input: 'https://' + 'a'.repeat(256) + '.com',
          errorCode: VerifioDomainErrorCode.INVALID_URL,
          desc: 'domain too long',
        },
      ];

      test.each(invalidCases)('should handle $desc', async ({ input, errorCode }) => {
        const result = await VerifioURL.extractDomain(input);
        expect(result.success).toBe(false);
        expect(result.domain).toBeUndefined();
        expect(result.error).toBeDefined();
        expect(result.error?.code).toBe(errorCode);
      });
    });

    describe('Internationalized Domain Names (IDN)', () => {
      const idnCases = [
        {
          input: 'https://xn--mnchen-3ya.de',
          expected: 'xn--mnchen-3ya.de',
          desc: 'Punycode domain',
        },
        {
          input: 'https://xn--bcher-kva.example.com',
          expected: 'xn--bcher-kva.example.com',
          desc: 'Punycode subdomain',
        },
      ];

      test.each(idnCases)('should extract $desc: $input', async ({ input, expected }) => {
        const result = await VerifioURL.extractDomain(input);
        expect(result.success).toBe(true);
        expect(result.domain).toBe(expected);
        expect(result.error).toBeUndefined();
      });
    });
  });

  describe('VerifioURL IP Address Validation', () => {
    describe('isIPv4Address', () => {
      const validIPv4Cases = [
        // Standard cases
        { input: '192.168.1.1', desc: 'typical local IP' },
        { input: '127.0.0.1', desc: 'localhost' },
        { input: '0.0.0.0', desc: 'all zeros' },
        { input: '255.255.255.255', desc: 'all max values' },
        { input: '1.2.3.4', desc: 'simple numbers' },

        // Edge cases with valid numbers
        { input: '0.0.0.1', desc: 'minimum values with last digit' },
        { input: '100.100.100.100', desc: 'same numbers' },
        { input: '172.16.254.1', desc: 'private network address' },
        { input: '224.0.0.1', desc: 'multicast address' },
        { input: '169.254.0.1', desc: 'link-local address' },

        // Boundary value cases
        { input: '0.0.0.0', desc: 'minimum possible value' },
        { input: '255.255.255.255', desc: 'maximum possible value' },
        { input: '1.255.255.255', desc: 'first octet maximum' },
        { input: '255.1.255.255', desc: 'second octet maximum' },
        { input: '255.255.1.255', desc: 'third octet maximum' },
        { input: '255.255.255.1', desc: 'fourth octet maximum' },

        // Whitespace cases
        { input: ' 192.168.1.1', desc: 'leading space' },
        { input: '192.168.1.1 ', desc: 'trailing space' },
        { input: ' 192.168.1.1 ', desc: 'both side spaces' },
        { input: '192.168.1.1\n', desc: 'newline character' },
        { input: '192.168.1.1\t', desc: 'tab character' },
        { input: '192.168.1.1\r', desc: 'carriage return' },
        { input: '\n192.168.1.1', desc: 'leading newline' },
        { input: '\t192.168.1.1', desc: 'leading tab' },
        { input: '\r192.168.1.1', desc: 'leading carriage return' },
        { input: ' \n\t\r192.168.1.1\n\t\r ', desc: 'mixed whitespace' },
      ];

      const invalidIPv4Cases = [
        // Format errors
        { input: '192.168.1', desc: 'missing octet' },
        { input: '192.168.1.', desc: 'trailing dot' },
        { input: '.192.168.1', desc: 'leading dot' },
        { input: '192.168.1.1.', desc: 'extra trailing dot' },
        { input: '192.168..1', desc: 'empty octet' },
        { input: '192.168.1.1.1', desc: 'extra octet' },

        // Invalid characters
        { input: '192.168.1.1a', desc: 'alphanumeric' },
        { input: 'a.b.c.d', desc: 'letters' },
        { input: '192.168.1.1/24', desc: 'CIDR notation' },
        { input: '192.168.1.-1', desc: 'negative number' },
        { input: '192.168.1.+1', desc: 'plus sign' },
        { input: '192.168.1.1e0', desc: 'scientific notation' },

        // Invalid values
        { input: '256.1.2.3', desc: 'first octet exceeds max' },
        { input: '1.256.2.3', desc: 'second octet exceeds max' },
        { input: '1.2.256.3', desc: 'third octet exceeds max' },
        { input: '1.2.3.256', desc: 'fourth octet exceeds max' },
        { input: '300.300.300.300', desc: 'all octets exceed max' },
        { input: '-1.2.3.4', desc: 'negative first octet' },
        { input: '1.-2.3.4', desc: 'negative second octet' },

        // Whitespace case
        { input: '192. 168.1.1', desc: 'space between octets' },

        // Malformed strings
        { input: '192,168,1,1', desc: 'commas instead of dots' },
        { input: '192_168_1_1', desc: 'underscores instead of dots' },

        // Invalid number formats
        { input: '192.168.1.1.', desc: 'trailing dot' },
        { input: '192.168.01.1', desc: 'octal-like number' },
        { input: '192.168.0x1.1', desc: 'hexadecimal-like number' },
        { input: '192.168.1.1e0', desc: 'scientific notation' },
        { input: '192.168.001.001', desc: 'numbers with leading zeros' },
        { input: '010.000.000.001', desc: 'all segments with leading zeros' },

        // Empty or invalid input
        { input: '', desc: 'empty string' },
        { input: ' ', desc: 'space only' },
        { input: '...', desc: 'dots only' },
        { input: '192.168.1', desc: 'incomplete address' },
        { input: '192.168.1.', desc: 'incomplete final octet' },
      ];

      test.each(validIPv4Cases)('should validate correct IPv4: $desc', ({ input }) => {
        expect(VerifioURL.isIPv4Address(input)).toBe(true);
      });

      test.each(invalidIPv4Cases)('should invalidate incorrect IPv4: $desc', ({ input }) => {
        expect(VerifioURL.isIPv4Address(input)).toBe(false);
      });
    });

    describe('isIPv6Address', () => {
      const validIPv6Cases = [
        // Standard cases
        { input: '2001:0db8:85a3:0000:0000:8a2e:0370:7334', desc: 'full address' },
        { input: '::1', desc: 'localhost' },
        { input: '::', desc: 'unspecified address' },

        // Compressed cases
        { input: '2001:db8:85a3::8a2e:370:7334', desc: 'middle compression' },
        { input: '::ffff:192.168.1.1', desc: 'IPv4-mapped address' },
        { input: '::ffff:c000:0280', desc: 'IPv4-mapped in hex' },
        { input: '2001:db8::', desc: 'trailing compression' },
        { input: '::1234:5678', desc: 'leading compression' },
        { input: '2001::7334', desc: 'middle compression with single group' },

        // Mixed cases
        { input: '2001:0db8:85a3::8a2e:0:0', desc: 'mixed compression and zeros' },
        { input: '::ffff:0:0', desc: 'leading compression with zeros' },
        { input: '2001:db8::1:0:0:1', desc: 'mixed compression and ones' },

        // Case variations
        { input: '2001:DB8:85A3:0000:0000:8A2E:0370:7334', desc: 'uppercase' },
        { input: '2001:db8:85a3:0000:0000:8a2e:0370:7334', desc: 'lowercase' },
        { input: '2001:Db8:85A3:0000:0000:8a2E:0370:7334', desc: 'mixed case' },

        // Leading zeros
        { input: '2001:0db8:0000:0000:0001:0000:0000:0001', desc: 'multiple leading zeros' },
        { input: '0000:0000:0000:0000:0000:0000:0000:0001', desc: 'all leading zeros' },

        // Special addresses
        { input: 'fe80::1', desc: 'link-local address' },
        { input: 'ff02::1', desc: 'multicast address' },
        { input: '2001:db8::', desc: 'documentation prefix' },

        // Whitespace cases
        { input: ' 2001:0db8:85a3:0000:0000:8a2e:0370:7334', desc: 'leading space' },
        { input: '2001:0db8:85a3:0000:0000:8a2e:0370:7334 ', desc: 'trailing space' },
        { input: ' 2001:0db8:85a3:0000:0000:8a2e:0370:7334 ', desc: 'both side spaces' },
        { input: '2001:0db8:85a3:0000:0000:8a2e:0370:7334\n', desc: 'newline character' },
        { input: '2001:0db8:85a3:0000:0000:8a2e:0370:7334\t', desc: 'tab character' },
        { input: '2001:0db8:85a3:0000:0000:8a2e:0370:7334\r', desc: 'carriage return' },
        { input: '\n2001:0db8:85a3:0000:0000:8a2e:0370:7334', desc: 'leading newline' },
        { input: '\t2001:0db8:85a3:0000:0000:8a2e:0370:7334', desc: 'leading tab' },
        { input: '\r2001:0db8:85a3:0000:0000:8a2e:0370:7334', desc: 'leading carriage return' },
        {
          input: ' \n\t\r2001:0db8:85a3:0000:0000:8a2e:0370:7334\n\t\r ',
          desc: 'mixed whitespace',
        },
      ];

      const invalidIPv6Cases = [
        // Format errors
        { input: '2001:db8:85a3:0000:0000:8a2e:0370', desc: 'too few segments' },
        { input: '2001:db8:85a3:0000:0000:8a2e:0370:7334:7334', desc: 'too many segments' },
        { input: '2001:db8::85a3::8a2e:0370:7334', desc: 'multiple compression markers' },
        { input: '2001:db8:::8a2e:0370:7334', desc: 'invalid compression' },

        // Invalid characters
        { input: '2001:db8:85a3:0000:0000:8a2e:0370:733g', desc: 'invalid hex digit' },
        { input: '2001:db8:85a3:0000:0000:8a2e:0370:733.', desc: 'invalid punctuation' },
        { input: '2001:db8:85a3:0000:0000:8a2e:0370:-7334', desc: 'negative number' },
        { input: '2001:db8:85a3:0000:0000:8a2e:0370:+7334', desc: 'plus sign' },

        // Invalid segment lengths
        { input: '2001:db8:85a3:00000:0000:8a2e:0370:7334', desc: 'segment too long' },
        { input: '2001:db8:85a3:0:0:8a2e:0370:7334:', desc: 'trailing colon' },
        { input: ':2001:db8:85a3:0000:0000:8a2e:0370:7334', desc: 'leading colon' },

        // Whitespace case
        { input: '2001:db8:85a3:0000 :0000:8a2e:0370:7334', desc: 'space between segments' },

        // Malformed compression
        { input: '2001::db8::0370:7334', desc: 'multiple double colons' },
        { input: '2001:::db8:0370:7334', desc: 'triple colon' },
        { input: ':::', desc: 'too many colons' },

        // Invalid IPv4-mapped addresses
        { input: '::ffff:256.256.256.256', desc: 'invalid IPv4 in mapped address' },
        { input: '::ffff:192.168.1', desc: 'incomplete IPv4 in mapped address' },
        { input: '::ffff:192.168.1.1.1', desc: 'malformed IPv4 in mapped address' },

        // Empty or invalid input
        { input: '', desc: 'empty string' },
        { input: ' ', desc: 'space only' },
        { input: ':', desc: 'single colon' },
        { input: '2001', desc: 'single segment' },
        { input: '2001:', desc: 'incomplete address with colon' },
      ];

      test.each(validIPv6Cases)('should validate correct IPv6: $desc', ({ input }) => {
        expect(VerifioURL.isIPv6Address(input)).toBe(true);
      });

      test.each(invalidIPv6Cases)('should invalidate incorrect IPv6: $desc', ({ input }) => {
        expect(VerifioURL.isIPv6Address(input)).toBe(false);
      });
    });

    describe('isIPAddress', () => {
      test('should validate IPv4 addresses', () => {
        expect(VerifioURL.isIPAddress('192.168.1.1')).toBe(true);
        expect(VerifioURL.isIPAddress('0.0.0.0')).toBe(true);
        expect(VerifioURL.isIPAddress('255.255.255.255')).toBe(true);
      });

      test('should validate IPv6 addresses', () => {
        expect(VerifioURL.isIPAddress('2001:0db8:85a3:0000:0000:8a2e:0370:7334')).toBe(true);
        expect(VerifioURL.isIPAddress('::1')).toBe(true);
        expect(VerifioURL.isIPAddress('::')).toBe(true);
      });

      test('should invalidate incorrect IP addresses', () => {
        expect(VerifioURL.isIPAddress('')).toBe(false);
        expect(VerifioURL.isIPAddress('not-an-ip')).toBe(false);
        expect(VerifioURL.isIPAddress('256.256.256.256')).toBe(false);
        expect(VerifioURL.isIPAddress('2001:db8::85a3::8a2e:0370:7334')).toBe(false);
      });
    });
  });
});
