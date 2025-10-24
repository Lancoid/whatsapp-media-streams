<?php

declare(strict_types=1);

namespace Tests\unit;

use Codeception\Test\Unit;
use InvalidArgumentException;
use Lancoid\WhatsApp\MediaStreams\Crypto;
use ReflectionClass;
use RuntimeException;

/**
 * @covers \Lancoid\WhatsApp\MediaStreams\Crypto
 *
 * @internal
 */
final class CryptoTest extends Unit
{
    private string $mediaKey;

    protected function _before(): void
    {
        $this->mediaKey = random_bytes(32);
    }

    /**
     * @dataProvider mediaTypeProvider
     */
    public function testDeriveKeysReturnsValidKeys(string $type): void
    {
        $keys = Crypto::deriveKeys($this->mediaKey, $type);
        $this->assertCount(4, $keys);
        $this->assertSame(16, strlen($keys['iv']));
        $this->assertSame(32, strlen($keys['cipherKey']));
        $this->assertSame(32, strlen($keys['macKey']));
        $this->assertSame(32, strlen($keys['refKey']));
    }

    public function mediaTypeProvider(): array
    {
        return [
            ['IMAGE'],
            ['VIDEO'],
            ['AUDIO'],
            ['DOCUMENT'],
            ['image'],
        ];
    }

    public function testDeriveKeysThrowsOnInvalidKey(): void
    {
        $this->expectException(InvalidArgumentException::class);
        Crypto::deriveKeys('shortkey', 'IMAGE');
    }

    public function testDeriveKeysThrowsOnUnknownType(): void
    {
        $this->expectException(InvalidArgumentException::class);
        Crypto::deriveKeys($this->mediaKey, 'UNKNOWN');
    }

    public function testEncryptAndDecryptAreInverse(): void
    {
        $data = random_bytes(1000);
        $enc = Crypto::encrypt($data, $this->mediaKey, 'IMAGE');
        $this->assertNotSame($data, $enc);
        $dec = Crypto::decrypt($enc, $this->mediaKey, 'IMAGE');
        $this->assertSame($data, $dec);
    }

    public function testDecryptThrowsOnInvalidMac(): void
    {
        $data = random_bytes(100);
        $enc = Crypto::encrypt($data, $this->mediaKey, 'AUDIO');
        $enc = substr($enc, 0, -1) . chr((ord($enc[-1]) ^ 0xFF)); // портим MAC
        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('MAC verification failed');
        Crypto::decrypt($enc, $this->mediaKey, 'AUDIO');
    }

    public function testDecryptThrowsOnShortData(): void
    {
        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('Data too short');
        Crypto::decrypt('short', $this->mediaKey, 'IMAGE');
    }

    public function testPkcs7PadAndUnpad(): void
    {
        $reflectionClass = new ReflectionClass(Crypto::class);
        $reflectionMethod = $reflectionClass->getMethod('pkcs7Pad');
        $reflectionMethod->setAccessible(true);

        $unpad = $reflectionClass->getMethod('pkcs7Unpad');
        $unpad->setAccessible(true);

        $data = 'testdata';
        $block = 16;
        $padded = $reflectionMethod->invoke(null, $data, $block);
        $this->assertSame($data, $unpad->invoke(null, $padded));
    }

    public function testPkcs7UnpadThrowsOnInvalid(): void
    {
        $reflectionClass = new ReflectionClass(Crypto::class);
        $reflectionMethod = $reflectionClass->getMethod('pkcs7Unpad');
        $reflectionMethod->setAccessible(true);

        $this->expectException(RuntimeException::class);
        $reflectionMethod->invoke(null, 'badpad');
    }

    /**
     * @dataProvider hkdfProvider
     */
    public function testHkdf(string $algo, string $ikm, int $length, string $info, string $salt): void
    {
        $result = Crypto::hkdf($algo, $ikm, $length, $info, $salt);
        $this->assertSame($length, strlen($result));
    }

    public function hkdfProvider(): array
    {
        return [
            ['sha256', random_bytes(32), 64, 'test', ''],
            ['sha256', random_bytes(16), 32, 'info', random_bytes(32)],
        ];
    }
}
