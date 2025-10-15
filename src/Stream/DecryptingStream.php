<?php

declare(strict_types=1);

namespace Lancoid\WhatsApp\MediaStreams\Stream;

use GuzzleHttp\Psr7\Utils;
use InvalidArgumentException;
use Lancoid\WhatsApp\MediaStreams\Crypto;
use Psr\Http\Message\StreamInterface;
use RuntimeException;

/**
 * PSR-7 stream that decrypts data on construction.
 *
 * This stream reads all encrypted data from a source stream, decrypts
 * and verifies it using WhatsApp's media encryption scheme, and provides
 * the plaintext result as a readable PSR-7 stream.
 *
 * **Important**: This stream loads the entire encrypted input into memory,
 * decrypts it, and stores the result in memory. It is suitable for small
 * to medium files but may not be appropriate for very large files.
 *
 * The stream throws an exception if:
 * - The MAC verification fails (data tampered)
 * - The padding is invalid (corrupted data)
 * - The media key or type is incorrect
 */
final class DecryptingStream extends AbstractCryptoStream
{
    /**
     * Create a decrypting stream.
     *
     * The source stream is immediately read in full, decrypted and verified,
     * then stored in an internal buffer.
     *
     * @param StreamInterface $sourceStream Source stream containing encrypted data
     * @param string $mediaKey 32-byte media key (the same key used for encryption)
     * @param string $mediaType Media type (IMAGE, VIDEO, or AUDIO)
     *
     * @throws InvalidArgumentException If encrypted data is invalid or too short
     * @throws RuntimeException If MAC verification fails or decryption fails
     */
    public function __construct(StreamInterface $sourceStream, string $mediaKey, string $mediaType)
    {
        $this->buffer = Utils::streamFor(
            Crypto::decrypt((string)$sourceStream, $mediaKey, $mediaType)
        );
    }
}
