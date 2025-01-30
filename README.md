# verifio

A comprehensive TypeScript/JavaScript library for URL validation, verification, and analysis. Verifio helps you validate, normalize, and analyze URLs with support for IPv4/IPv6 addresses, domain extraction, URL expansion, and more.

[![npm version](https://img.shields.io/npm/v/verifio.svg)](https://www.npmjs.com/package/verifio)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://github.com/AashishRichhariya/verifio/blob/main/LICENSE)

## Why Verifio?

Working with URLs in real-world applications presents several challenges:
- Users might submit shortened URLs (bit.ly, t.co, etc.)
- URLs need normalization for consistent storage and comparison
- Domain extraction might be needed for analytics or security checks
- IP addresses (both IPv4 and IPv6) require special handling
- URLs might be malformed or inaccessible

Verifio handles all these cases with a clean, type-safe API that provides detailed validation results and error information.

## Features

### URL Validation & Verification
- 🔍 RFC-compliant URL validation with detailed error reporting
- 🌐 Comprehensive IP address support:
  - IPv4 validation and normalization
  - IPv6 validation with compression handling
  - IPv4-mapped IPv6 address support
- 🔒 Protocol validation (http, https, ftp, sftp)
- 📝 Domain validation including:
  - Length checks
  - TLD validation
  - Punycode support
  - Label validation
- 🔢 Port number validation (1-65535)
- 🔄 URL expansion for shortened URLs
- 🎯 Domain extraction from URLs (including shortened URLs)
- ⚡ Async URL accessibility checking

### Error Handling
- Detailed error messages with specific error codes
- Type-safe error responses
- Comprehensive validation results

## Installation

```bash
npm install verifio
# or
yarn add verifio
# or
pnpm add verifio
```

## Usage

### Basic URL Validation

```typescript
import { VerifioURL } from 'verifio';

// Simple validation
const result = VerifioURL.isValid('https://example.com');
if (result.isValid) {
  console.log('Valid URL:', result.normalizedURL);
} else {
  console.log('Validation errors:', result.errors);
}

// Invalid URL example
const invalid = VerifioURL.isValid('not-a-url');
/* Output:
{
  isValid: false,
  errors: [{
    code: 'INVALID_URL',
    message: 'URL format is invalid'
  }]
}
*/
```

### IP Address Validation

```typescript
import { VerifioURL } from 'verifio';

// IPv4 validation
console.log(VerifioURL.isIPv4Address('192.168.1.1')); // true
console.log(VerifioURL.isIPv4Address('256.1.2.3')); // false

// IPv6 validation
console.log(VerifioURL.isIPv6Address('2001:0db8:85a3:0000:0000:8a2e:0370:7334')); // true
console.log(VerifioURL.isIPv6Address('::ffff:192.168.1.1')); // true (IPv4-mapped)

// General IP validation
console.log(VerifioURL.isIPAddress('192.168.1.1')); // true
console.log(VerifioURL.isIPAddress('2001:db8::1')); // true
```

### Domain Extraction

```typescript
import { VerifioURL } from 'verifio';

// Extract domain from regular URL
const result1 = await VerifioURL.extractDomain('https://sub.example.com/path');
console.log(result1);
/* Output:
{
  success: true,
  domain: 'sub.example.com'
}
*/

// Extract domain from shortened URL
const result2 = await VerifioURL.extractDomain('https://bit.ly/xyz');
console.log(result2);
/* Output:
{
  success: true,
  domain: 'example.com'  // Domain from expanded URL
}
*/
```

### URL Expansion

```typescript
import { VerifioURL } from 'verifio';

// Expand shortened URL
const expanded = await VerifioURL.expand('https://bit.ly/example');
console.log(expanded); // https://example.com/full-url

// With custom timeout (in milliseconds)
const expandedWithTimeout = await VerifioURL.expand('https://bit.ly/example', 3000);
```

### Complete URL Verification

```typescript
import { VerifioURL } from 'verifio';

const verification = await VerifioURL.verify('https://example.com');
console.log(verification);
/* Output:
{
  originalURL: 'https://example.com\t',
  validity: { 
    isValid: true,
    normalizedURL: 'https://example.com'
  },
  expandedURL: 'https://example.com',
  isAccessible: true
}
*/
```

## Error Types

The library provides detailed error information through TypeScript interfaces:

```typescript
interface VerifioURLValidityResult {
  isValid: boolean;
  normalizedURL?: string;
  errors?: VerifioURLError[];
}

interface VerifioURLError {
  code: VerifioURLErrorCode;
  message?: string;
}

enum VerifioURLErrorCode {
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
  INVALID_TLD = 'INVALID_TLD'
}
```

## Future Features

📋 Planned expansions:
- Email validation module (`verifio/email`)
- Domain verification and DNS checks
- SSL certificate validation
- Security and phishing detection
- Configurable validation rules
- Additional protocol support

## Contributing

Contributions are welcome! Please review our contribution guidelines:

1. Fork the repository
2. Create your feature branch
3. Make your changes with appropriate tests
4. Commit with clear, descriptive messages
5. Submit a pull request

For bugs, questions, or suggestions, please create an issue at our [GitHub repository](https://github.com/AashishRichhariya/verifio/issues).

## Testing

```bash
# Run all tests
npm test

# Run tests with coverage
npm run test:coverage

# Run tests in watch mode
npm run test:watch
```

## License

This project is licensed under the MIT License - see the [LICENSE](https://github.com/AashishRichhariya/verifio/blob/main/LICENSE) file for details.