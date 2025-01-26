# Verifio

Smart validation and verification library for URLs, with future support for emails and more.

## Features
- Strict URL validation following RFC standards
- IP address range validation (0-255)
- Port number validation (1-65535)
- Domain length checks
- Support for authentication credentials
- Protocol validation (http, https, ftp, sftp)
- Configurable validation rules (coming soon)

## Installation
```bash
npm install verifio
```

## Usage
```typescript
import { VerifioURL } from 'verifio';

// Validate URL
const isValid = VerifioURL.isValid('https://example.com');

// Get expanded URL
const expandedURL = await VerifioURL.expand('https://tinyurl.com/example');

// Full verification
const result = await VerifioURL.verify('https://example.com');
```

### Result Type
```typescript
interface VerifioURLResult {
  originalURL: string;
  isValid: boolean;
  expandedURL: string | null;
  isAccessible: boolean;
}
```

## Future Features
- Email validation
- Security checks
- Phishing detection
- Domain verification
- SSL certificate validation

## License
MIT