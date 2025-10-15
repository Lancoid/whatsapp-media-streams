<?php

declare(strict_types=1);

namespace Tests\unit;

use InvalidArgumentException;
use Lancoid\WhatsApp\MediaStreams\Crypto;
use Lancoid\WhatsApp\MediaStreams\MediaType;
use Lancoid\WhatsApp\MediaStreams\Stream\BufferStream;
use Lancoid\WhatsApp\MediaStreams\Stream\DecryptingStream;
use Lancoid\WhatsApp\MediaStreams\Stream\EncryptingStream;
use PHPUnit\Framework\Assert;
use RuntimeException;

final class CryptoCest
{
    public function hkdfLengthAndDeterminism(): void
    {
        $inputKeyMaterial = str_repeat('A', 32);
        $salt = '';
        $infoString = 'info';
        $length = 64;

        $outputKeyMaterial1 = Crypto::hkdfSha256($inputKeyMaterial, $salt, $infoString, $length);
        $outputKeyMaterial2 = Crypto::hkdfSha256($inputKeyMaterial, $salt, $infoString, $length);

        Assert::assertSame($length, strlen($outputKeyMaterial1));
        Assert::assertSame($outputKeyMaterial1, $outputKeyMaterial2);
    }

    public function deriveKeysDeterministic(): void
    {
        $mediaKey = str_repeat("\x01", 32);

        $derivedKeys1 = Crypto::deriveKeys($mediaKey, MediaType::IMAGE);
        $derivedKeys2 = Crypto::deriveKeys($mediaKey, MediaType::IMAGE);

        Assert::assertSame($derivedKeys1, $derivedKeys2);
        Assert::assertSame(16, strlen($derivedKeys1['iv']));
        Assert::assertSame(32, strlen($derivedKeys1['cipherKey']));
        Assert::assertSame(32, strlen($derivedKeys1['macKey']));
        Assert::assertSame(32, strlen($derivedKeys1['refKey']));
    }

    public function encryptDecryptRoundTripSmall(): void
    {
        $mediaKey = random_bytes(32);
        $plaintext = 'hello world';
        $encrypted = Crypto::encrypt($plaintext, $mediaKey, MediaType::AUDIO);
        $decrypted = Crypto::decrypt($encrypted, $mediaKey, MediaType::AUDIO);
        Assert::assertSame($plaintext, $decrypted);
    }

    public function encryptDecryptRoundTripLarge(): void
    {
        $mediaKey = random_bytes(32);
        $plaintext = random_bytes(1024 + 37);

        $encrypted = Crypto::encrypt($plaintext, $mediaKey, MediaType::VIDEO);
        $decrypted = Crypto::decrypt($encrypted, $mediaKey, MediaType::VIDEO);

        Assert::assertSame($plaintext, $decrypted);
    }

    public function decryptFailsOnBadMac(): void
    {
        $mediaKey = random_bytes(32);
        $data = random_bytes(300);

        $encrypted = Crypto::encrypt($data, $mediaKey, MediaType::IMAGE);
        // flip last bit
        $tamperedCiphertext = substr($encrypted, 0, -1) . (substr($encrypted, -1) ^ "\x01");

        try {
            Crypto::decrypt($tamperedCiphertext, $mediaKey, MediaType::IMAGE);
            Assert::fail('Expected RuntimeException was not thrown');
        } catch (RuntimeException $e) {
            Assert::assertStringContainsString('MAC verification failed', $e->getMessage());
        }
    }

    public function encryptDecryptStreams(): void
    {
        $mediaKey = random_bytes(32);
        $plaintext = random_bytes(777);

        $bufferStream = new BufferStream($plaintext);
        $encryptingStream = new EncryptingStream($bufferStream, $mediaKey, MediaType::IMAGE);

        $ciphertext = (string)$encryptingStream;
        $decryptingStream = new DecryptingStream(new BufferStream($ciphertext), $mediaKey, MediaType::IMAGE);

        $decryptedContent = (string)$decryptingStream;
        Assert::assertSame($plaintext, $decryptedContent);
    }

    public function invalidMediaKeyLength(): void
    {
        try {
            Crypto::deriveKeys('short', MediaType::IMAGE);
            Assert::fail('Expected InvalidArgumentException was not thrown');
        } catch (InvalidArgumentException $e) {
            Assert::assertStringContainsString('mediaKey must be exactly 32 bytes', $e->getMessage());
        }
    }
}
