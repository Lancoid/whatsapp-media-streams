<?php

declare(strict_types=1);

namespace Lancoid\WhatsApp\MediaStreams\Stream;

use InvalidArgumentException;
use Psr\Http\Message\StreamInterface;
use RuntimeException;

/**
 * Simple in-memory read-only PSR-7 stream.
 *
 * This stream stores data in memory and provides PSR-7 StreamInterface
 * operations for reading. It's useful for:
 * - Wrapping string data as a stream
 * - Testing stream operations
 * - Temporary in-memory buffers
 *
 * Features:
 * - Read-only (write operations throw exceptions)
 * - Seekable by default (can be disabled)
 * - All data stored in memory (not suitable for very large data)
 */
final class BufferStream implements StreamInterface
{
    private string $buffer;
    private int $position = 0;
    private bool $seekable;

    public function __construct(string $data = '', bool $seekable = true)
    {
        $this->buffer = $data;
        $this->seekable = $seekable;
    }

    public function __toString(): string
    {
        return $this->buffer;
    }

    public function close(): void
    {
        // No-op for in-memory buffer
    }

    public function detach(): null
    {
        return null;
    }

    public function getSize(): int
    {
        return strlen($this->buffer);
    }

    public function tell(): int
    {
        return $this->position;
    }

    public function eof(): bool
    {
        return $this->position >= strlen($this->buffer);
    }

    public function isSeekable(): bool
    {
        return $this->seekable;
    }

    public function seek($offset, $whence = SEEK_SET): void
    {
        if (!$this->seekable) {
            throw new RuntimeException('Stream is not seekable');
        }

        $newPosition = match ($whence) {
            // Absolute position
            SEEK_SET => $offset,
            // Relative to current
            SEEK_CUR => $this->position + $offset,
            // Relative to end
            SEEK_END => strlen($this->buffer) + $offset,
            default => throw new InvalidArgumentException('Invalid whence value: ' . $whence),
        };

        if ($newPosition < 0) {
            throw new RuntimeException('Cannot seek to negative position');
        }

        // Clamp position to buffer size (seeking past end is allowed)
        $this->position = min($newPosition, strlen($this->buffer));
    }

    /**
     * Rewind to the beginning of the buffer.
     */
    public function rewind(): void
    {
        $this->position = 0;
    }

    /**
     * Check if the stream is writable.
     *
     * @return bool Always returns false (buffer is read-only)
     */
    public function isWritable(): bool
    {
        return false;
    }

    /**
     * Write data to the stream.
     *
     * Not supported on buffer streams.
     *
     * @param mixed $string
     *
     * @throws RuntimeException Always throws as the stream is read-only
     */
    public function write($string): int
    {
        throw new RuntimeException('BufferStream is read-only');
    }

    /**
     * Check if the stream is readable.
     *
     * @return bool Always returns true
     */
    public function isReadable(): bool
    {
        return true;
    }

    /**
     * Read data from the buffer.
     *
     * Reads up to $length bytes from the current position and advances
     * the position by the number of bytes read.
     *
     * @param int $length Maximum number of bytes to read
     *
     * @return string Data read (maybe shorter than requested if near the end)
     */
    public function read(int $length): string
    {
        if ($this->position >= strlen($this->buffer)) {
            return '';
        }

        $chunk = substr($this->buffer, $this->position, $length);
        $this->position += strlen($chunk);

        return $chunk;
    }

    /**
     * Read remaining buffer content from current position.
     *
     * Reads all data from the current position to the end and moves
     * the position to the end of the buffer.
     *
     * @return string Remaining buffer content
     */
    public function getContents(): string
    {
        $data = substr($this->buffer, $this->position);
        $this->position = strlen($this->buffer);

        return $data;
    }

    /**
     * Get stream metadata.
     *
     * Always returns null as buffer streams have no metadata.
     *
     * @param null|string $key Specific metadata key (ignored)
     */
    public function getMetadata(?string $key = null): null
    {
        return null;
    }
}
