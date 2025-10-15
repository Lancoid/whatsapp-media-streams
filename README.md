# WhatsApp Media Streams

[![CI](https://github.com/Lancoid/whatsapp-media-streams/workflows/CI/badge.svg)](https://github.com/Lancoid/whatsapp-media-streams/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/Lancoid/whatsapp-media-streams/branch/main/graph/badge.svg)](https://codecov.io/gh/Lancoid/whatsapp-media-streams)

PSR-7 friendly helpers for encrypting and decrypting WhatsApp media payloads (image/video/audio). 

This library provides:
- Low-level crypto primitives that implement WhatsApp’s HKDF and AES-256-CBC + HMAC scheme.
- Simple in-memory streams (PSR-7 StreamInterface) to wrap existing streams and read encrypted/decrypted bytes.

It’s small, dependency-light, and designed to be embedded into bigger HTTP or storage workflows.

## Requirements
- PHP >= 8.4
- psr/http-message ^1.0 || ^2.0

## Installation
Install via Composer:

```bash
  composer require lancoid/whatsapp-media-streams
```

## Quick start

### 1) Encrypt/decrypt raw buffers
Use the high-level helpers in Lancoid\WhatsApp\MediaStreams\Media\Crypto together with Lancoid\WhatsApp\MediaStreams\Media\MediaType constants.

```php
use Lancoid\WhatsApp\MediaStreams\Media\Crypto;
use Lancoid\WhatsApp\MediaStreams\Media\MediaType;

$mediaKey = random_bytes(32); // must be exactly 32 bytes
$plaintext = "hello world";

$encrypted = Crypto::encrypt($plaintext, $mediaKey, MediaType::IMAGE);
$decrypted = Crypto::decrypt($encrypted, $mediaKey, MediaType::IMAGE);

assert($decrypted === $plaintext);
```

### 2) Streaming API (PSR-7 StreamInterface)
This package ships with small utility streams so you can plug into existing PSR-7 code.

- BufferStream: an in-memory, read-only stream over a string
- EncryptingStream: reads plaintext from a source stream, exposes encrypted bytes
- DecryptingStream: reads encrypted bytes from a source stream, exposes plaintext

```php
use Lancoid\WhatsApp\MediaStreams\Media\MediaType;
use Lancoid\WhatsApp\MediaStreams\Media\Stream\BufferStream;
use Lancoid\WhatsApp\MediaStreams\Media\Stream\EncryptingStream;
use Lancoid\WhatsApp\MediaStreams\Media\Stream\DecryptingStream;

$mediaKey = random_bytes(32);

// You can adapt any PSR-7 stream here. For demo, we use the provided BufferStream.
$source = new BufferStream("Sensitive content");

$encryptedStream = new EncryptingStream($source, $mediaKey, MediaType::VIDEO);
$encryptedBytes = (string) $encryptedStream;           // or $encryptedStream->getContents();

$decryptedStream = new DecryptingStream(new BufferStream($encryptedBytes), $mediaKey, MediaType::VIDEO);
$plaintextBytes = (string) $decryptedStream;
```

### 3) Deriving keys only
If you need the derived materials (iv, cipherKey, macKey, refKey):

```php
use Lancoid\WhatsApp\MediaStreams\Media\Crypto;
use Lancoid\WhatsApp\MediaStreams\Media\MediaType;

$keys = Crypto::deriveKeys($mediaKey, MediaType::AUDIO);
// $keys = ['iv' => ..., 'cipherKey' => ..., 'macKey' => ..., 'refKey' => ...]
```

## Media types
Use one of the provided constants when encrypting/decrypting:
```php
Lancoid\WhatsApp\MediaStreams\Media\MediaType::IMAGE
Lancoid\WhatsApp\MediaStreams\Media\MediaType::VIDEO
Lancoid\WhatsApp\MediaStreams\Media\MediaType::AUDIO
```

Passing an unknown type will throw an InvalidArgumentException.

## License
MIT
