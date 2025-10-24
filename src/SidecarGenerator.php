<?php

declare(strict_types=1);

namespace Lancoid\WhatsApp\MediaStreams;

use Psr\Http\Message\StreamInterface;
use RuntimeException;

/**
 * Generates a WhatsApp sidecar file for encrypted media streams.
 *
 * The sidecar contains a sequence of 10-byte HMAC-SHA256 MACs, one for each 64 KiB chunk
 * of the encrypted media file, as required by WhatsApp for video/media integrity verification.
 *
 * @see https://github.com/sigalor/whatsapp-web-reveng for protocol details
 */
final class SidecarGenerator
{
    /**
     * Generates a sidecar string for a given encrypted media stream.
     *
     * @param StreamInterface $encryptedStream Encrypted, seekable media stream
     * @param string $key 32-byte WhatsApp media key
     * @param string $mediaType Media type (IMAGE, VIDEO, AUDIO, DOCUMENT)
     *
     * @return string Concatenated 10-byte MACs for each 64 KiB chunk of the stream
     *
     * @throws RuntimeException If the stream is not seekable or reading fails
     */
    public static function generate(StreamInterface $encryptedStream, string $key, string $mediaType): string
    {
        $keys = Crypto::deriveKeys($key, $mediaType);
        $macKey = $keys['macKey'];
        $initializationVector = $keys['iv'];
        $sidecarData = '';
        $encryptedChunkSize = 64 * 1024 + 16;
        $encryptedOffset = 0;

        $encryptedStream->rewind();
        while (!$encryptedStream->eof()) {
            $encryptedStream->seek($encryptedOffset);
            $encryptedChunk = $encryptedStream->read($encryptedChunkSize);

            if ('' === $encryptedChunk || false === $encryptedChunk) {
                break;
            }

            $macTag = substr(hash_hmac('sha256', $initializationVector . $encryptedChunk, $macKey, true), 0, 10);
            $sidecarData .= $macTag;
            $encryptedOffset += 64 * 1024;
        }

        return $sidecarData;
    }
}
