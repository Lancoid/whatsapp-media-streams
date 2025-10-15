<?php

declare(strict_types=1);

namespace Tests\unit;

use Lancoid\WhatsApp\MediaStreams\Crypto;
use Lancoid\WhatsApp\MediaStreams\MediaType;
use UnitTester;

final class StreamsSamplesCest
{
    private function samplePath(string $name): string
    {
        return codecept_data_dir('samples/' . $name);
    }

    public function imageSampleEncryptDecrypt(UnitTester $unitTester): void
    {
        $originalContent = file_get_contents($this->samplePath('IMAGE.original'));
        $encryptedContent = file_get_contents($this->samplePath('IMAGE.encrypted'));
        $mediaKey = file_get_contents($this->samplePath('IMAGE.key'));
        $unitTester->assertSame(strlen($mediaKey), 32, 'media key must be 32 bytes');

        $decryptedContent = Crypto::decrypt($encryptedContent, $mediaKey, MediaType::IMAGE);
        $unitTester->assertSame($originalContent, $decryptedContent, 'IMAGE decrypt mismatch');

        $reEncryptedContent = Crypto::encrypt($originalContent, $mediaKey, MediaType::IMAGE);
        $unitTester->assertSame($encryptedContent, $reEncryptedContent, 'IMAGE encrypt mismatch');
    }

    public function audioSampleEncryptDecrypt(UnitTester $unitTester): void
    {
        $originalContent = file_get_contents($this->samplePath('AUDIO.original'));
        $encryptedContent = file_get_contents($this->samplePath('AUDIO.encrypted'));
        $mediaKey = file_get_contents($this->samplePath('AUDIO.key'));
        $unitTester->assertSame(strlen($mediaKey), 32, 'media key must be 32 bytes');

        $decryptedContent = Crypto::decrypt($encryptedContent, $mediaKey, MediaType::AUDIO);
        $unitTester->assertSame($originalContent, $decryptedContent, 'AUDIO decrypt mismatch');

        $reEncryptedContent = Crypto::encrypt($originalContent, $mediaKey, MediaType::AUDIO);
        $unitTester->assertSame($encryptedContent, $reEncryptedContent, 'AUDIO encrypt mismatch');
    }

    public function videoSampleEncryptDecrypt(UnitTester $unitTester): void
    {
        $originalContent = file_get_contents($this->samplePath('VIDEO.original'));
        $encryptedContent = file_get_contents($this->samplePath('VIDEO.encrypted'));
        $mediaKey = file_get_contents($this->samplePath('VIDEO.key'));

        // Sidecar is not used by crypto, but ensure it exists
        $sidecarPath = $this->samplePath('VIDEO.sidecar');
        if (file_exists($sidecarPath)) {
            $sidecarContents = file_get_contents($sidecarPath);
            $unitTester->assertNotFalse($sidecarContents);
        }
        $unitTester->assertSame(strlen($mediaKey), 32, 'media key must be 32 bytes');

        $decryptedContent = Crypto::decrypt($encryptedContent, $mediaKey, MediaType::VIDEO);
        $unitTester->assertSame($originalContent, $decryptedContent, 'VIDEO decrypt mismatch');

        $reEncryptedContent = Crypto::encrypt($originalContent, $mediaKey, MediaType::VIDEO);
        $unitTester->assertSame($encryptedContent, $reEncryptedContent, 'VIDEO encrypt mismatch');
    }
}
