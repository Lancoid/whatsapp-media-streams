<?php

declare(strict_types=1);

namespace Tests\unit;

use Lancoid\WhatsApp\MediaStreams\Stream\BufferStream;
use PHPUnit\Framework\Assert;
use RuntimeException;

final class BufferStreamCest
{
    public function basicReadAndEof(): void
    {
        $bufferStream = new BufferStream('abcdef');

        Assert::assertTrue($bufferStream->isReadable());
        Assert::assertSame(0, $bufferStream->tell());
        Assert::assertFalse($bufferStream->eof());
        Assert::assertSame('abc', $bufferStream->read(3));
        Assert::assertSame(3, $bufferStream->tell());
        Assert::assertSame('def', $bufferStream->getContents());
        Assert::assertTrue($bufferStream->eof());
        Assert::assertSame('', $bufferStream->read(10));
    }

    public function seekBehavior(): void
    {
        $bufferStream = new BufferStream('0123456789');

        $bufferStream->seek(5);
        Assert::assertSame('56789', $bufferStream->getContents());
        $bufferStream->rewind();
        $bufferStream->seek(-2, SEEK_END);
        Assert::assertSame('89', $bufferStream->read(10));
        $bufferStream->rewind();
        $bufferStream->seek(2, SEEK_CUR);
        Assert::assertSame('23456789', $bufferStream->getContents());
    }

    public function notSeekableThrows(): void
    {
        $bufferStream = new BufferStream('abc', false);

        try {
            $bufferStream->seek(1);
            Assert::fail('Expected RuntimeException not thrown');
        } catch (RuntimeException $e) {
            Assert::assertStringContainsString('not seekable', $e->getMessage());
        }
    }
}
