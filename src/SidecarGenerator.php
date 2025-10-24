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
     * @param StreamInterface $encryptedStream the encrypted media stream (must be seekable)
     * @param string $mediaKey 32-byte WhatsApp media key
     * @param string $type media type (IMAGE, VIDEO, AUDIO, DOCUMENT)
     *
     * @return string concatenated 10-byte MACs for each 64 KiB chunk of the stream
     *
     * @throws RuntimeException if the stream is not seekable or reading fails
     */
    public static function generate(StreamInterface $encryptedStream, string $mediaKey, string $type): string
    {
        $keys = Crypto::deriveKeys($mediaKey, $type);
        $macKey = $keys['macKey'];
        $iv = $keys['iv'];
        $sidecar = '';
        $chunkSize = 64 * 1024 + 16;
        $offset = 0;

        $encryptedStream->rewind();
        while (!$encryptedStream->eof()) {
            $encryptedStream->seek($offset);
            $chunk = $encryptedStream->read($chunkSize);
            if ('' === $chunk || false === $chunk) {
                break;
            }
            $mac = substr(hash_hmac('sha256', $iv . $chunk, $macKey, true), 0, 10);
            $sidecar .= $mac;
            $offset += 64 * 1024;
        }

        return $sidecar;
    }
}
