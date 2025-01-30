# Verifio

A robust TypeScript/JavaScript library for URL validation, verification, and expansion, with planned support for additional validators (email, etc.).

[![npm version](https://img.shields.io/npm/v/verifio.svg)](https://www.npmjs.com/package/verifio)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## Features

### URL Validation & Verification
- 🔍 Comprehensive URL validation following RFC standards
- 🌐 Support for both IPv4 and IPv6 addresses
- 🔒 Protocol validation (http, https, ftp, sftp)
- 📝 Domain validation including:
  - Length checks
  - TLD validation
  - Punycode support
  - Label validation
- 🔢 Port number validation (1-65535)
- 🔄 URL expansion for shortened URLs
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
console.log(result.isValid); // true

// Invalid URL example
const invalid = VerifioURL.isValid('not-a-url');
console.log(invalid.isValid); // false
console.log(invalid.errors); // Array of validation errors
```

### URL Expansion

```typescript
import { VerifioURL } from 'verifio';

// Expand shortened URL
const expanded = await VerifioURL.expand('https://bit.ly/example');
console.log(expanded); // https://example.com/full-url

// With custom timeout
const expandedWithTimeout = await VerifioURL.expand('https://bit.ly/example', 3000);
```

### Complete URL Verification

```typescript
import { VerifioURL } from 'verifio';

const verification = await VerifioURL.verify('https://example.com');
console.log(verification);
/* Output:
{
  originalURL: 'https://example.com',
  validity: { isValid: true },
  expandedURL: 'https://example.com',
  isAccessible: true
}
*/
```

### Error Types

```typescript
interface VerifioURLValidityResult {
  isValid: boolean;
  errors?: VerifioURLError[];
}

interface VerifioURLError {
  code: VerifioURLErrorCode;
  message?: string;
}

// Available error codes
enum VerifioURLErrorCode {
  INVALID_URL,
  URL_TOO_LONG,
  INVALID_PROTOCOL,
  INVALID_IP,
  INVALID_PORT,
  INVALID_DOMAIN_LENGTH,
  INVALID_HOSTNAME_CHARS,
  MALFORMED_URL,
  INVALID_LABEL_LENGTH,
  INVALID_LABEL_FORMAT,
  INVALID_PUNYCODE,
  INVALID_TLD
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

Contributions are welcome! Please feel free to submit a Pull Request. For major changes, please open an issue first to discuss what you would like to change.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

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

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.