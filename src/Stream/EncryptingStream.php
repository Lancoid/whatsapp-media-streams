<?php

declare(strict_types=1);

namespace Lancoid\WhatsApp\MediaStreams\Stream;

use GuzzleHttp\Psr7\Utils;
use InvalidArgumentException;
use Lancoid\WhatsApp\MediaStreams\Crypto;
use Psr\Http\Message\StreamInterface;
use RuntimeException;

/**
 * PSR-7 stream that encrypts data on construction.
 *
 * This stream reads all data from a source stream, encrypts it using WhatsApp's media encryption scheme,
 * and provides the encrypted result as a readable PSR-7 stream.
 *
 * **Important**: This stream loads the entire input into memory, encrypts it, and stores the result in memory.
 * It is suitable for small to medium files but may not be appropriate for very large files.
 *
 * Usage:
 * 1. Wrap any PSR-7 stream (source data)
 * 2. Provide a media key and type
 * 3. Read encrypted bytes from this stream
 */
final class EncryptingStream extends AbstractCryptoStream
{
    /**
     * Create an encrypting stream.
     *
     * The source stream is immediately read in full, encrypted, and stored in an internal buffer.
     *
     * @param StreamInterface $sourceStream Source stream containing plaintext
     * @param string $mediaKey 32-byte media key
     * @param string $mediaType Media type (IMAGE, VIDEO, or AUDIO)
     *
     * @throws InvalidArgumentException If the media key or type is invalid
     * @throws RuntimeException If encryption fails
     */
    public function __construct(StreamInterface $sourceStream, string $mediaKey, string $mediaType)
    {
        $this->buffer = Utils::streamFor(
            Crypto::encrypt((string)$sourceStream, $mediaKey, $mediaType)
        );
    }
}
