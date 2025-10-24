<?php

declare(strict_types=1);

namespace Lancoid\WhatsApp\MediaStreams;

use Psr\Http\Message\StreamInterface;
use RuntimeException;
use Throwable;

/**
 * Decorator for a PSR-7 StreamInterface that transparently decrypts WhatsApp media streams.
 *
 * This class reads encrypted data from the underlying stream, decrypts it using the provided
 * media key and type, and exposes the decrypted data as a read-only, seekable stream.
 *
 * @see Crypto
 */
final class DecryptStreamDecorator implements StreamInterface
{
    private StreamInterface $stream;
    private string $mediaKey;
    private string $type;
    private int $position = 0;
    private ?string $decryptedBuffer = null;

    /**
     * @param StreamInterface $stream the underlying encrypted stream
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
     * Ensures the decrypted buffer is initialized.
     *
     * @throws RuntimeException if decryption fails
     */
    private function ensureDecrypted(): void
    {
        if (null === $this->decryptedBuffer) {
            $this->stream->rewind();
            $encrypted = $this->stream->getContents();
            $this->decryptedBuffer = Crypto::decrypt($encrypted, $this->mediaKey, $this->type);
        }
    }

    /**
     * Reads up to $length bytes from the decrypted stream.
     *
     * @param int $length number of bytes to read
     *
     * @return string decrypted data
     */
    public function read($length): string
    {
        $this->ensureDecrypted();
        if ($this->eof()) {
            return '';
        }
        $data = substr($this->decryptedBuffer, $this->position, $length);
        $this->position += strlen($data);

        return $data;
    }

    /**
     * Checks if the end of the decrypted stream has been reached.
     */
    public function eof(): bool
    {
        $this->ensureDecrypted();

        return $this->position >= strlen($this->decryptedBuffer);
    }

    /**
     * Returns the remaining decrypted contents from the current position.
     */
    public function getContents(): string
    {
        $this->ensureDecrypted();
        $data = substr($this->decryptedBuffer, $this->position);
        $this->position = strlen($this->decryptedBuffer);

        return $data;
    }

    /**
     * Returns the total size of the decrypted stream in bytes.
     */
    public function getSize(): int
    {
        $this->ensureDecrypted();

        return strlen($this->decryptedBuffer);
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
        $this->ensureDecrypted();
        $length = strlen($this->decryptedBuffer);
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
     * Detaches the underlying stream and clears the decrypted buffer.
     *
     * @return null|resource underlying stream resource
     */
    public function detach()
    {
        $this->decryptedBuffer = null;

        return $this->stream->detach();
    }

    /**
     * Closes the stream and clears the decrypted buffer.
     */
    public function close(): void
    {
        $this->decryptedBuffer = null;
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
     * Returns the entire decrypted contents as a string.
     * Returns an empty string on error.
     */
    public function __toString(): string
    {
        try {
            $this->ensureDecrypted();

            return $this->decryptedBuffer ?? '';
        } catch (Throwable $e) {
            return '';
        }
    }
}
