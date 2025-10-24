<?php

declare(strict_types=1);

namespace Lancoid\WhatsApp\MediaStreams;

use Psr\Http\Message\StreamInterface;
use RuntimeException;
use Throwable;

/**
 * Decorator for a PSR-7 StreamInterface that transparently encrypts WhatsApp media streams in a memory-efficient, block-wise manner.
 *
 * Reads plaintext data from the underlying stream, encrypts it using the provided media key and type,
 * and exposes the encrypted data as a read-only, seekable stream. Encryption is performed on-the-fly
 * for each 64 KiB chunk, making it suitable for large files.
 *
 * @see Crypto::encrypt for encryption details. The method must support block-wise encryption and accept an offset if required by the protocol.
 *
 * @throws RuntimeException If the underlying stream is not seekable or reading fails
 */
final class EncryptStreamDecorator implements StreamInterface
{
    private const CHUNK_SIZE = 64 * 1024;                // 64 KiB
    private const ENCRYPTED_CHUNK_SIZE = 64 * 1024 + 16; // 64 KiB + padding/IV (as per WhatsApp protocol)
    private StreamInterface $stream;
    private string $key;
    private string $mediaType;
    private int $position = 0;
    private int $plainChunkStart = -1;
    private ?string $encryptedChunk = null;

    /**
     * Constructs a decorator for a seekable, plaintext stream.
     *
     * @param StreamInterface $stream Plaintext, seekable stream
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
     * Loads and encrypts the chunk containing the given position.
     *
     * @param int $position Position in the encrypted stream
     */
    private function loadChunk(int $position): void
    {
        $plainChunkStart = intdiv($position, self::ENCRYPTED_CHUNK_SIZE) * self::CHUNK_SIZE;

        if ($this->plainChunkStart === $plainChunkStart && null !== $this->encryptedChunk) {
            return;
        }

        $this->stream->seek($plainChunkStart);
        $plainChunk = $this->stream->read(self::CHUNK_SIZE);

        if ('' === $plainChunk || false === $plainChunk) {
            $this->encryptedChunk = '';
        } else {
            $this->encryptedChunk = Crypto::encrypt($plainChunk, $this->key, $this->mediaType);
        }

        $this->plainChunkStart = $plainChunkStart;
    }

    /**
     * Reads up to $length bytes from the encrypted stream.
     *
     * @param int $length Number of bytes to read
     *
     * @return string Encrypted data
     */
    public function read($length): string
    {
        if ($length <= 0) {
            return '';
        }

        $output = '';

        while ($length > 0 && !$this->eof()) {
            $this->loadChunk($this->position);
            $offsetInChunk = $this->position - $this->plainChunkStart;
            $encryptedChunkData = substr($this->encryptedChunk, $offsetInChunk, $length);

            if ('' === $encryptedChunkData || false === $encryptedChunkData) {
                break;
            }

            $bytesRead = strlen($encryptedChunkData);
            $output .= $encryptedChunkData;
            $this->position += $bytesRead;
            $length -= $bytesRead;

            if (0 === $bytesRead) {
                break;
            }
        }

        return $output;
    }

    /**
     * Returns true if the end of the encrypted stream has been reached.
     */
    public function eof(): bool
    {
        $encryptedSize = $this->getSize();

        return null !== $encryptedSize && $this->position >= $encryptedSize;
    }

    /**
     * Returns the remaining contents of the encrypted stream as a string.
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
     * Returns the size of the encrypted stream, or null if unknown.
     */
    public function getSize(): ?int
    {
        $plainStreamSize = $this->stream->getSize();

        if (null === $plainStreamSize) {
            return null;
        }

        $fullChunkCount = intdiv($plainStreamSize, self::CHUNK_SIZE);
        $lastChunkSize = $plainStreamSize % self::CHUNK_SIZE;
        $encryptedSize = $fullChunkCount * self::ENCRYPTED_CHUNK_SIZE;

        if ($lastChunkSize > 0) {
            $encryptedSize += strlen(Crypto::encrypt(str_repeat("\0", $lastChunkSize), $this->key, $this->mediaType));
        }

        return $encryptedSize;
    }

    /**
     * Returns the current position in the encrypted stream.
     */
    public function tell(): int
    {
        return $this->position;
    }

    /**
     * Seeks to a position in the encrypted stream.
     *
     * @param int $offset Offset to seek
     * @param int $whence Seek mode (SEEK_SET, SEEK_CUR, SEEK_END)
     *
     * @throws RuntimeException If seeking is out of bounds or size is unknown
     */
    public function seek($offset, $whence = SEEK_SET): void
    {
        $encryptedSize = $this->getSize();

        if (SEEK_SET === $whence) {
            $newPosition = $offset;
        } elseif (SEEK_CUR === $whence) {
            $newPosition = $this->position + $offset;
        } elseif (SEEK_END === $whence) {
            if (null === $encryptedSize) {
                throw new RuntimeException('Cannot seek from end: size unknown');
            }

            $newPosition = $encryptedSize + $offset;
        } else {
            throw new RuntimeException('Invalid whence');
        }

        if ($newPosition < 0 || (null !== $encryptedSize && $newPosition > $encryptedSize)) {
            throw new RuntimeException('Seek out of bounds');
        }

        $this->position = $newPosition;
    }

    /**
     * Rewinds the encrypted stream to the beginning.
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
     * Writing is not supported for encrypted streams.
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
     * Detaches the underlying stream and clears encrypted chunk.
     *
     * @return null|resource
     */
    public function detach()
    {
        $this->encryptedChunk = null;

        return $this->stream->detach();
    }

    /**
     * Closes the underlying stream and clears encrypted chunk.
     */
    public function close(): void
    {
        $this->encryptedChunk = null;
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
     * Returns the entire encrypted stream as a string.
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
