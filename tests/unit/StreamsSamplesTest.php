<?php

declare(strict_types=1);

namespace Tests\unit;

use Codeception\Test\Unit;
use Lancoid\WhatsApp\MediaStreams\Crypto;
use Lancoid\WhatsApp\MediaStreams\MediaType;
use RuntimeException;

/**
 * @covers \Lancoid\WhatsApp\MediaStreams\Crypto
 *
 * @internal
 */
final class StreamsSamplesTest extends Unit
{
    /**
     * @dataProvider sampleProvider
     */
    public function testSampleEncryptDecrypt(string $type): void
    {
        $originalContent = file_get_contents($this->samplePath($type . '.original'));
        $encryptedContent = file_get_contents($this->samplePath($type . '.encrypted'));
        $mediaKey = file_get_contents($this->samplePath($type . '.key'));

        $this->assertNotFalse($originalContent, $type . ' original file missing or unreadable');
        $this->assertNotFalse($encryptedContent, $type . ' encrypted file missing or unreadable');
        $this->assertNotFalse($mediaKey, $type . ' key file missing or unreadable');
        $this->assertSame(32, strlen($mediaKey), $type . ' media key must be 32 bytes, got ' . strlen($mediaKey));

        if (MediaType::VIDEO === $type) {
            $sidecarPath = $this->samplePath('VIDEO.sidecar');
            $this->assertFileExists($sidecarPath);
            $this->assertNotFalse(file_get_contents($sidecarPath));
        }

        try {
            $decryptedContent = Crypto::decrypt($encryptedContent, $mediaKey, $type);
        } catch (RuntimeException $e) {
            $this->fail($type . ' decrypt failed: ' . $e->getMessage());
        }
        $this->assertSame($originalContent, $decryptedContent, $type . ' decrypt mismatch');

        try {
            $reEncryptedContent = Crypto::encrypt($originalContent, $mediaKey, $type);
        } catch (RuntimeException $e) {
            $this->fail($type . ' encrypt failed: ' . $e->getMessage());
        }
        $this->assertSame($encryptedContent, $reEncryptedContent, $type . ' encrypt mismatch');
    }

    public function sampleProvider(): array
    {
        return [
            [MediaType::IMAGE],
            [MediaType::AUDIO],
            [MediaType::VIDEO],
        ];
    }

    public function testDecryptThrowsOnCorruptedData(): void
    {
        $mediaKey = str_repeat('A', 32);
        $this->expectException(RuntimeException::class);
        Crypto::decrypt('corrupted', $mediaKey, MediaType::IMAGE);
    }

    private function samplePath(string $name): string
    {
        $path = codecept_data_dir('samples/' . $name);

        $this->assertFileExists($path);

        return $path;
    }
}
