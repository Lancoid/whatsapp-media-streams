<?php

declare(strict_types=1);

namespace Lancoid\WhatsApp\MediaStreams;

use Psr\Http\Message\StreamInterface;
use RuntimeException;
use Throwable;

/**
 * Decorator for a PSR-7 StreamInterface that transparently decrypts WhatsApp media streams in a memory-efficient, block-wise manner.
 *
 * Reads encrypted data from the underlying stream, decrypts it using the provided media key and type,
 * and exposes the decrypted data as a read-only, seekable stream. Decryption is performed on-the-fly
 * for each 64 KiB chunk, making it suitable for large files.
 *
 * @see Crypto::decrypt for decryption details. The method must support block-wise decryption and accept an offset if required by the protocol.
 *
 * @throws RuntimeException If the underlying stream is not seekable or reading fails
 */
final class DecryptStreamDecorator implements StreamInterface
{
    private const CHUNK_SIZE = 64 * 1024 + 16; // 64 KiB + padding (as per WhatsApp protocol)

    private StreamInterface $stream;
    private string $key;
    private string $mediaType;
    private int $position = 0;
    private int $decryptedChunkStart = 0;
    private ?string $decryptedChunk = null;

    /**
     * Constructs a decorator for a seekable, encrypted stream.
     *
     * @param StreamInterface $stream Encrypted, seekable stream
     * @param string $key WhatsApp 32-byte media key
     * @param string $mediaType Media type (IMAGE, VIDEO, AUDIO, DOCUMENT)
     */
    public function __construct(StreamInterface $stream, string $key, string $mediaType)
    {
        if (!$stream->isSeekable()) {
            throw new RuntimeException('Underlying stream must be seekable');
        }

        $this->stream = $stream;
        $this->key = $key;
        $this->mediaType = $mediaType;
    }

    /**
     * Loads and decrypts the chunk containing the specified position.
     *
     * @param int $position Position in the decrypted stream
     */
    private function loadChunk(int $position): void
    {
        $decryptedChunkStart = intdiv($position, 64 * 1024) * 64 * 1024;

        if (null !== $this->decryptedChunk && $this->decryptedChunkStart === $decryptedChunkStart) {
            return;
        }

        $this->stream->seek($decryptedChunkStart);
        $encryptedChunk = $this->stream->read(self::CHUNK_SIZE);
        $this->decryptedChunk = Crypto::decrypt($encryptedChunk, $this->key, $this->mediaType, $decryptedChunkStart);
        $this->decryptedChunkStart = $decryptedChunkStart;
    }

    /**
     * Reads up to $length bytes from the decrypted stream.
     *
     * @param int $length Number of bytes to read
     *
     * @return string Decrypted data
     */
    public function read($length): string
    {
        if ($length <= 0) {
            return '';
        }

        $output = '';

        while ($length > 0 && !$this->eof()) {
            $this->loadChunk($this->position);
            $offset = $this->position - $this->decryptedChunkStart;
            $decryptedChunkData = substr($this->decryptedChunk, $offset, $length);

            if ('' === $decryptedChunkData || false === $decryptedChunkData) {
                break;
            }

            $bytesRead = strlen($decryptedChunkData);

            $output .= $decryptedChunkData;
            $this->position += $bytesRead;

            $length -= $bytesRead;
            if (0 === $bytesRead) {
                break;
            }
        }

        return $output;
    }

    /**
     * Returns true if the end of the decrypted stream has been reached.
     */
    public function eof(): bool
    {
        $decryptedSize = $this->getSize();

        return null !== $decryptedSize && $this->position >= $decryptedSize;
    }

    /**
     * Returns the remaining contents of the decrypted stream as a string.
     */
    public function getContents(): string
    {
        $output = '';

        while (!$this->eof()) {
            $output .= $this->read(8192);
        }

        return $output;
    }

    /**
     * Returns the size of the decrypted stream, or null if unknown.
     */
    public function getSize(): ?int
    {
        $encryptedStreamSize = $this->stream->getSize();

        if (null === $encryptedStreamSize) {
            return null;
        }

        $this->stream->seek($encryptedStreamSize - Crypto::MAC_LENGTH - Crypto::AES_BLOCK_SIZE);
        $encryptedStreamTail = $this->stream->read(Crypto::AES_BLOCK_SIZE);

        return Crypto::getDecryptedSize(
            $this->stream->getSize(), $this->key, $this->mediaType, $encryptedStreamTail
        );
    }

    /**
     * Returns the current position in the decrypted stream.
     */
    public function tell(): int
    {
        return $this->position;
    }

    /**
     * Seeks to a position in the decrypted stream.
     *
     * @param int $offset Offset to seek
     * @param int $whence Seek mode (SEEK_SET, SEEK_CUR, SEEK_END)
     *
     * @throws RuntimeException If seeking is out of bounds or size is unknown
     */
    public function seek($offset, $whence = SEEK_SET): void
    {
        $decryptedSize = $this->getSize();

        if (SEEK_SET === $whence) {
            $newPosition = $offset;
        } elseif (SEEK_CUR === $whence) {
            $newPosition = $this->position + $offset;
        } elseif (SEEK_END === $whence) {
            if (null === $decryptedSize) {
                throw new RuntimeException('Cannot seek from end: size unknown');
            }

            $newPosition = $decryptedSize + $offset;
        } else {
            throw new RuntimeException('Invalid whence');
        }

        if ($newPosition < 0 || (null !== $decryptedSize && $newPosition > $decryptedSize)) {
            throw new RuntimeException('Seek out of bounds');
        }

        $this->position = $newPosition;
        $this->decryptedChunk = null;
    }

    /**
     * Rewinds the decrypted stream to the beginning.
     */
    public function rewind(): void
    {
        $this->seek(0);
    }

    /**
     * Returns whether the stream is seekable.
     */
    public function isSeekable(): bool
    {
        return $this->stream->isSeekable();
    }

    /**
     * Returns whether the stream is writable.
     */
    public function isWritable(): bool
    {
        return false;
    }

    /**
     * Returns whether the stream is readable.
     */
    public function isReadable(): bool
    {
        return true;
    }

    /**
     * Writing is not supported for decrypted streams.
     *
     * @param string $string
     *
     * @throws RuntimeException Always thrown
     */
    public function write($string): int
    {
        throw new RuntimeException('Not writable');
    }

    /**
     * Detaches the underlying stream and clears decrypted chunk.
     *
     * @return null|resource
     */
    public function detach()
    {
        $this->decryptedChunk = null;

        return $this->stream->detach();
    }

    /**
     * Closes the underlying stream and clears decrypted chunk.
     */
    public function close(): void
    {
        $this->decryptedChunk = null;
        $this->stream->close();
    }

    /**
     * Returns metadata of the underlying stream.
     *
     * @param null|string $key Metadata key or null for all metadata
     *
     * @return mixed
     */
    public function getMetadata($key = null)
    {
        return $this->stream->getMetadata($key);
    }

    /**
     * Returns the entire decrypted stream as a string.
     */
    public function __toString(): string
    {
        try {
            $this->rewind();

            return $this->getContents();
        } catch (Throwable $e) {
            return '';
        }
    }
}
