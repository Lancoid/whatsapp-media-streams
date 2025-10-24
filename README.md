# WhatsApp Media Streams

[![CI](https://github.com/Lancoid/whatsapp-media-streams/workflows/CI/badge.svg)](https://github.com/Lancoid/whatsapp-media-streams/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/Lancoid/whatsapp-media-streams/branch/main/graph/badge.svg)](https://codecov.io/gh/Lancoid/whatsapp-media-streams)

PSR-7 friendly helpers for encrypting and decrypting WhatsApp media payloads (image/video/audio/document).

This library provides:
- Low-level crypto primitives implementing WhatsApp’s HKDF and AES-256-CBC + HMAC scheme.
- Lightweight PSR-7 stream wrappers for on-the-fly encryption and decryption of large media files.

It is dependency-light and designed for integration into HTTP or storage workflows.

## Requirements
- PHP >= 8.1
- psr/http-message ^1.0 || ^2.0

## Installation
Install via Composer:

```bash
  composer require lancoid/whatsapp-media-streams
```

## Quick start

### 1) Encrypt/Decrypt Buffers
Use the helpers in Lancoid\WhatsApp\MediaStreams\Crypto with Lancoid\WhatsApp\MediaStreams\MediaType constants.

```php
use Lancoid\WhatsApp\MediaStreams\Crypto;
use Lancoid\WhatsApp\MediaStreams\MediaType;

$mediaKey = random_bytes(32); // must be exactly 32 bytes
$plaintext = "hello world";

$encrypted = Crypto::encrypt($plaintext, $mediaKey, MediaType::IMAGE);
$decrypted = Crypto::decrypt($encrypted, $mediaKey, MediaType::IMAGE);

assert($decrypted === $plaintext);
```

### 2) Streaming API (PSR-7 StreamInterface)
This package provides utility streams for seamless integration with PSR-7 code.

- EncryptingStream: reads plaintext from a source PSR-7 stream, exposes encrypted bytes
- DecryptingStream: reads encrypted bytes from a source PSR-7 stream, exposes plaintext

```php
use GuzzleHttp\Psr7\Utils;
use Lancoid\WhatsApp\MediaStreams\MediaType;
use Lancoid\WhatsApp\MediaStreams\EncryptingStream;
use Lancoid\WhatsApp\MediaStreams\DecryptingStream;

$mediaKey = random_bytes(32);

// You can adapt any PSR-7 stream here. For demo, we use Guzzle's Utils::streamFor()
$source = Utils::streamFor("Sensitive content");

$encryptedStream = new EncryptingStream($source, $mediaKey, MediaType::VIDEO);
$encryptedBytes = (string)$encryptedStream;           // or $encryptedStream->getContents();

$decryptedStream = new DecryptingStream(Utils::streamFor($encryptedBytes), $mediaKey, MediaType::VIDEO);
$plaintextBytes = (string)$decryptedStream;
```

### 3) Key Derivation
If you need the derived materials (iv, cipherKey, macKey, refKey):

```php
use Lancoid\WhatsApp\MediaStreams\Crypto;
use Lancoid\WhatsApp\MediaStreams\MediaType;

$keys = Crypto::deriveKeys($mediaKey, MediaType::AUDIO);
// $keys = ['iv' => ..., 'cipherKey' => ..., 'macKey' => ..., 'refKey' => ...]
```

## Media types
Use one of the provided constants when encrypting/decrypting:
```php
Lancoid\WhatsApp\MediaStreams\MediaType::IMAGE
Lancoid\WhatsApp\MediaStreams\MediaType::VIDEO
Lancoid\WhatsApp\MediaStreams\MediaType::AUDIO
Lancoid\WhatsApp\MediaStreams\MediaType::DOCUMENT
```

Passing an unknown type will throw an InvalidArgumentException.

## License
MIT
