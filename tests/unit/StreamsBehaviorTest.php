<?php

declare(strict_types=1);

namespace Tests\unit;

use Codeception\Test\Unit;
use GuzzleHttp\Psr7\Utils;
use Lancoid\WhatsApp\MediaStreams\DecryptStreamDecorator;
use Lancoid\WhatsApp\MediaStreams\EncryptStreamDecorator;
use Lancoid\WhatsApp\MediaStreams\MediaType;
use RuntimeException;

/**
 * @covers \Lancoid\WhatsApp\MediaStreams\DecryptStreamDecorator
 * @covers \Lancoid\WhatsApp\MediaStreams\EncryptStreamDecorator
 *
 * @internal
 */
final class StreamsBehaviorTest extends Unit
{
    /**
     * @dataProvider mediaTypeProvider
     */
    public function testEncryptStreamDecoratorReadOnlyAndNavigation(string $type): void
    {
        $key = random_bytes(32);
        $data = random_bytes(128 + 13);

        $stream = Utils::streamFor($data);
        $encryptStreamDecorator = new EncryptStreamDecorator($stream, $key, $type);

        $this->assertTrue($encryptStreamDecorator->isReadable());
        $this->assertFalse($encryptStreamDecorator->isWritable());

        $this->expectException(RuntimeException::class);
        $encryptStreamDecorator->write('x');

        $this->assertNull($encryptStreamDecorator->getSize());

        $encryptStreamDecorator->rewind();
        $firstPart = $encryptStreamDecorator->read(10);
        $this->assertSame(10, strlen($firstPart));
        $pos = $encryptStreamDecorator->tell();
        $this->assertSame(10, $pos);

        $encryptStreamDecorator->seek(0);
        $this->assertSame(0, $encryptStreamDecorator->tell());
        $all = $encryptStreamDecorator->getContents();
        $this->assertGreaterThan(0, strlen($all));

        $meta = $encryptStreamDecorator->getMetadata();
        $this->assertIsArray($meta);
        $encryptStreamDecorator->close();
    }

    /**
     * @dataProvider mediaTypeProvider
     */
    public function testDecryptStreamDecoratorReadOnlyAndErrors(string $type): void
    {
        $key = random_bytes(32);
        $data = random_bytes(256);

        $cipher = (string)new EncryptStreamDecorator(Utils::streamFor($data), $key, $type);
        $decryptStreamDecorator = new DecryptStreamDecorator(Utils::streamFor($cipher), $key, $type);

        $this->assertTrue($decryptStreamDecorator->isReadable());
        $this->assertFalse($decryptStreamDecorator->isWritable());

        $content = (string)$decryptStreamDecorator;
        $this->assertSame($data, $content);

        $decryptStream = new DecryptStreamDecorator(Utils::streamFor('short'), $key, $type);
        $this->expectException(RuntimeException::class);
        $decryptStream->read(100);
    }

    public function mediaTypeProvider(): array
    {
        return [
            [MediaType::IMAGE],
            [MediaType::AUDIO],
            [MediaType::VIDEO],
            [MediaType::DOCUMENT],
        ];
    }
}
