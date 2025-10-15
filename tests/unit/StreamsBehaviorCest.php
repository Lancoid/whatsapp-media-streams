<?php

declare(strict_types=1);

namespace Tests\unit;

use GuzzleHttp\Psr7\Utils;
use InvalidArgumentException;
use Lancoid\WhatsApp\MediaStreams\MediaType;
use Lancoid\WhatsApp\MediaStreams\Stream\DecryptingStream;
use Lancoid\WhatsApp\MediaStreams\Stream\EncryptingStream;
use RuntimeException;
use UnitTester;

final class StreamsBehaviorCest
{
    public function encryptingStreamReadOnlyAndNavigation(UnitTester $unitTester): void
    {
        $key = random_bytes(32);
        $data = random_bytes(128 + 13);

        $stream = Utils::streamFor($data);
        $encryptingStream = new EncryptingStream($stream, $key, MediaType::IMAGE);

        $unitTester->assertTrue($encryptingStream->isReadable());
        $unitTester->assertFalse($encryptingStream->isWritable());

        $unitTester->expectThrowable(RuntimeException::class, function () use ($encryptingStream): void {
            $encryptingStream->write('x');
        });

        $size = $encryptingStream->getSize();
        $unitTester->assertNotNull($size);
        $unitTester->assertSame($size, strlen((string)$encryptingStream));

        $encryptingStream->rewind();
        $firstPart = $encryptingStream->read(10);
        $unitTester->assertSame(10, strlen($firstPart));
        $pos = $encryptingStream->tell();
        $unitTester->assertSame(10, $pos);

        $encryptingStream->seek(0);
        $unitTester->assertSame(0, $encryptingStream->tell());
        $all = $encryptingStream->getContents();
        $unitTester->assertSame($size, strlen($all));

        $meta = $encryptingStream->getMetadata();
        $unitTester->assertIsArray($meta);
        $encryptingStream->close();
    }

    public function decryptingStreamReadOnlyAndConstructionErrors(UnitTester $unitTester): void
    {
        $key = random_bytes(32);
        $data = random_bytes(256);

        $cipher = (string)new EncryptingStream(Utils::streamFor($data), $key, MediaType::AUDIO);
        $decryptingStream = new DecryptingStream(Utils::streamFor($cipher), $key, MediaType::AUDIO);

        $unitTester->assertTrue($decryptingStream->isReadable());
        $unitTester->assertFalse($decryptingStream->isWritable());

        $content = (string)$decryptingStream;
        $unitTester->assertSame($data, $content);

        // Too short encrypted input should throw on construction
        $unitTester->expectThrowable(InvalidArgumentException::class, function () use ($key): void {
            new DecryptingStream(Utils::streamFor('short'), $key, MediaType::AUDIO);
        });
    }
}
