<?php

declare(strict_types=1);

namespace Tests\unit;

use GuzzleHttp\Psr7\Utils;
use InvalidArgumentException;
use Lancoid\WhatsApp\MediaStreams\Crypto;
use Lancoid\WhatsApp\MediaStreams\MediaType;
use Lancoid\WhatsApp\MediaStreams\Stream\DecryptingStream;
use Lancoid\WhatsApp\MediaStreams\Stream\EncryptingStream;
use RuntimeException;
use UnitTester;

final class CryptoCest
{
    public function hkdfLengthAndDeterminism(UnitTester $unitTester): void
    {
        $inputKeyMaterial = str_repeat('A', 32);
        $salt = '';
        $infoString = 'info';
        $length = 64;

        $outputKeyMaterial1 = Crypto::hkdfSha256($inputKeyMaterial, $salt, $infoString, $length);
        $outputKeyMaterial2 = Crypto::hkdfSha256($inputKeyMaterial, $salt, $infoString, $length);

        $unitTester->assertSame($length, strlen($outputKeyMaterial1));
        $unitTester->assertSame($outputKeyMaterial1, $outputKeyMaterial2);
    }

    public function deriveKeysDeterministic(UnitTester $unitTester): void
    {
        $mediaKey = str_repeat("\x01", 32);

        $derivedKeys1 = Crypto::deriveKeys($mediaKey, MediaType::IMAGE);
        $derivedKeys2 = Crypto::deriveKeys($mediaKey, MediaType::IMAGE);

        $unitTester->assertSame($derivedKeys1, $derivedKeys2);
        $unitTester->assertSame(16, strlen($derivedKeys1['iv']));
        $unitTester->assertSame(32, strlen($derivedKeys1['cipherKey']));
        $unitTester->assertSame(32, strlen($derivedKeys1['macKey']));
        $unitTester->assertSame(32, strlen($derivedKeys1['refKey']));
    }

    public function encryptDecryptRoundTripSmall(UnitTester $unitTester): void
    {
        $mediaKey = random_bytes(32);
        $plaintext = 'hello world';

        $encrypted = Crypto::encrypt($plaintext, $mediaKey, MediaType::AUDIO);
        $decrypted = Crypto::decrypt($encrypted, $mediaKey, MediaType::AUDIO);

        $unitTester->assertSame($plaintext, $decrypted);
    }

    public function encryptDecryptRoundTripLarge(UnitTester $unitTester): void
    {
        $mediaKey = random_bytes(32);
        $plaintext = random_bytes(1024 + 37);

        $encrypted = Crypto::encrypt($plaintext, $mediaKey, MediaType::VIDEO);
        $decrypted = Crypto::decrypt($encrypted, $mediaKey, MediaType::VIDEO);

        $unitTester->assertSame($plaintext, $decrypted);
    }

    public function decryptFailsOnBadMac(UnitTester $unitTester): void
    {
        $mediaKey = random_bytes(32);
        $data = random_bytes(300);

        $encrypted = Crypto::encrypt($data, $mediaKey, MediaType::IMAGE);
        // flip last bit
        $tamperedCiphertext = substr($encrypted, 0, -1) . (substr($encrypted, -1) ^ "\x01");

        $unitTester->expectThrowable(RuntimeException::class, function () use ($tamperedCiphertext, $mediaKey): void {
            Crypto::decrypt($tamperedCiphertext, $mediaKey, MediaType::IMAGE);
        });
    }

    public function encryptDecryptStreams(UnitTester $unitTester): void
    {
        $mediaKey = random_bytes(32);
        $plaintext = random_bytes(777);

        $bufferStream = Utils::streamFor($plaintext);
        $encryptingStream = new EncryptingStream($bufferStream, $mediaKey, MediaType::IMAGE);

        $ciphertext = (string)$encryptingStream;
        $decryptingStream = new DecryptingStream(Utils::streamFor($ciphertext), $mediaKey, MediaType::IMAGE);

        $decryptedContent = (string)$decryptingStream;
        $unitTester->assertSame($plaintext, $decryptedContent);
    }

    public function invalidMediaKeyLength(UnitTester $unitTester): void
    {
        $unitTester->expectThrowable(InvalidArgumentException::class, function (): void {
            Crypto::deriveKeys('short', MediaType::IMAGE);
        });
    }
}
