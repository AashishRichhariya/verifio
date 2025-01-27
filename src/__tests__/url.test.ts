import { VerifioURL, VerifioURLErrorCode, VerifioURLValidityResult } from '..';

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

        // Excessive components
        'http://a.b.c.d.e.f.g.h.i.j.k.l.m.n.o.p.q.r.s.t.u.v.w.x.y.z.com',
        'http://example.com/' + 'a'.repeat(2048),
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
        'http://example.com/\x0A',
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
});
