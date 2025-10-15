<?php

declare(strict_types=1);

namespace Lancoid\WhatsApp\MediaStreams\Stream;

use Psr\Http\Message\StreamInterface;
use RuntimeException;

/**
 * Abstract base class for crypto streams.
 *
 * This class provides a common implementation of PSR-7 StreamInterface
 * for read-only streams that delegate all operations to an internal
 * buffer stream. It eliminates code duplication between EncryptingStream
 * and DecryptingStream.
 *
 * All crypto streams:
 * - Are read-only (write operations throw exceptions)
 * - Are seekable (via internal buffer)
 * - Support all standard PSR-7 stream operations
 */
abstract class AbstractCryptoStream implements StreamInterface
{
    /**
     * Internal buffer holding the processed (encrypted or decrypted) data.
     *
     * Child classes must initialize this in their constructor.
     */
    protected StreamInterface $buffer;

    public function __toString(): string
    {
        return (string)$this->buffer;
    }

    public function close(): void
    {
        $this->buffer->close();
    }

    public function detach()
    {
        return $this->buffer->detach();
    }

    public function getSize(): ?int
    {
        return $this->buffer->getSize();
    }

    public function tell(): int
    {
        return $this->buffer->tell();
    }

    public function eof(): bool
    {
        return $this->buffer->eof();
    }

    public function isSeekable(): bool
    {
        return $this->buffer->isSeekable();
    }

    public function seek($offset, $whence = SEEK_SET): void
    {
        $this->buffer->seek($offset, $whence);
    }

    public function rewind(): void
    {
        $this->buffer->rewind();
    }

    /**
     * Crypto streams are read-only.
     *
     * @return bool Always returns false
     */
    public function isWritable(): bool
    {
        return false;
    }

    /**
     * Writing is not supported on crypto streams.
     *
     * @param mixed $string
     *
     * @throws RuntimeException Always throws as the stream is read-only
     */
    public function write($string): int
    {
        throw new RuntimeException('Crypto streams are read-only');
    }

    /**
     * Crypto streams are always readable.
     *
     * @return bool Always returns true
     */
    public function isReadable(): bool
    {
        return true;
    }

    public function read($length): string
    {
        return $this->buffer->read($length);
    }

    public function getContents(): string
    {
        return $this->buffer->getContents();
    }

    public function getMetadata($key = null)
    {
        return $this->buffer->getMetadata($key);
    }
}
