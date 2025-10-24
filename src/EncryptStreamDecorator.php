<?php

declare(strict_types=1);

namespace Lancoid\WhatsApp\MediaStreams;

use Psr\Http\Message\StreamInterface;
use RuntimeException;
use Throwable;

/**
 * Decorator for a PSR-7 StreamInterface that transparently encrypts WhatsApp media streams.
 *
 * This class reads plaintext data from the underlying stream, encrypts it using the provided
 * WhatsApp media key and type, and exposes the encrypted data as a read-only, seekable stream.
 *
 * Encryption is performed once on first access and cached in memory.
 *
 * @see Crypto
 */
final class EncryptStreamDecorator implements StreamInterface
{
    private StreamInterface $stream;
    private string $mediaKey;
    private string $type;
    private int $position = 0;
    private ?string $encryptedBuffer = null;

    /**
     * @param StreamInterface $stream the underlying plaintext stream
     * @param string $mediaKey 32-byte WhatsApp media key
     * @param string $type media type (IMAGE, VIDEO, AUDIO, DOCUMENT)
     */
    public function __construct(StreamInterface $stream, string $mediaKey, string $type)
    {
        $this->stream = $stream;
        $this->mediaKey = $mediaKey;
        $this->type = $type;
    }

    /**
     * Ensures the encrypted buffer is initialized.
     *
     * @throws RuntimeException if encryption fails
     */
    private function ensureEncrypted(): void
    {
        if (null === $this->encryptedBuffer) {
            $this->stream->rewind();
            $plain = $this->stream->getContents();
            $this->encryptedBuffer = Crypto::encrypt($plain, $this->mediaKey, $this->type);
        }
    }

    /**
     * Reads up to $length bytes from the encrypted stream.
     *
     * @param int $length number of bytes to read
     *
     * @return string encrypted data
     */
    public function read($length): string
    {
        $this->ensureEncrypted();
        if ($this->eof()) {
            return '';
        }
        $data = substr($this->encryptedBuffer, $this->position, $length);
        $this->position += strlen($data);

        return $data;
    }

    /**
     * Checks if the end of the encrypted stream has been reached.
     */
    public function eof(): bool
    {
        $this->ensureEncrypted();

        return $this->position >= strlen($this->encryptedBuffer);
    }

    /**
     * Returns the remaining encrypted contents from the current position.
     */
    public function getContents(): string
    {
        $this->ensureEncrypted();
        $data = substr($this->encryptedBuffer, $this->position);
        $this->position = strlen($this->encryptedBuffer);

        return $data;
    }

    /**
     * Returns the total size of the encrypted stream in bytes.
     */
    public function getSize(): int
    {
        $this->ensureEncrypted();

        return strlen($this->encryptedBuffer);
    }

    /**
     * Returns the current position of the read pointer.
     */
    public function tell(): int
    {
        return $this->position;
    }

    /**
     * Moves the read pointer to a new position.
     *
     * @param int $offset
     * @param int $whence one of SEEK_SET, SEEK_CUR, SEEK_END
     *
     * @throws RuntimeException if the position is out of bounds or $whence is invalid
     */
    public function seek($offset, $whence = SEEK_SET): void
    {
        $this->ensureEncrypted();
        $length = strlen($this->encryptedBuffer);
        if (SEEK_SET === $whence) {
            $pos = $offset;
        } elseif (SEEK_CUR === $whence) {
            $pos = $this->position + $offset;
        } elseif (SEEK_END === $whence) {
            $pos = $length + $offset;
        } else {
            throw new RuntimeException('Invalid whence');
        }
        if ($pos < 0 || $pos > $length) {
            throw new RuntimeException('Seek out of bounds');
        }
        $this->position = $pos;
    }

    /**
     * Rewinds the stream to the beginning.
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
        return true;
    }

    /**
     * Returns whether the stream is writable.
     *
     * @return bool always false (read-only)
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
     * Not supported. Always throws.
     *
     * @param string $string
     *
     * @throws RuntimeException
     */
    public function write($string): int
    {
        throw new RuntimeException('Not writable');
    }

    /**
     * Detaches the underlying stream and clears the encrypted buffer.
     *
     * @return null|resource underlying stream resource
     */
    public function detach()
    {
        $this->encryptedBuffer = null;

        return $this->stream->detach();
    }

    /**
     * Closes the stream and clears the encrypted buffer.
     */
    public function close(): void
    {
        $this->encryptedBuffer = null;
        $this->stream->close();
    }

    /**
     * Returns metadata of the underlying stream.
     *
     * @param null|string $key
     *
     * @return mixed
     */
    public function getMetadata($key = null)
    {
        return $this->stream->getMetadata($key);
    }

    /**
     * Returns the entire encrypted contents as a string.
     * Returns an empty string on error.
     */
    public function __toString(): string
    {
        try {
            $this->ensureEncrypted();

            return $this->encryptedBuffer ?? '';
        } catch (Throwable $e) {
            return '';
        }
    }
}
