<?php

declare(strict_types=1);

namespace Tests\unit;

use Lancoid\WhatsApp\MediaStreams\Crypto;
use Lancoid\WhatsApp\MediaStreams\MediaType;
use PHPUnit\Framework\Assert;

final class StreamsSamplesCest
{
    private function samplePath(string $name): string
    {
        return dirname(__DIR__) . '/_data/samples/' . $name;
    }

    public function imageSampleEncryptDecrypt(): void
    {
        $originalContent = file_get_contents($this->samplePath('IMAGE.original'));
        $encryptedContent = file_get_contents($this->samplePath('IMAGE.encrypted'));
        $mediaKey = file_get_contents($this->samplePath('IMAGE.key'));
        Assert::assertSame(strlen($mediaKey), 32, 'media key must be 32 bytes');

        $decryptedContent = Crypto::decrypt($encryptedContent, $mediaKey, MediaType::IMAGE);
        Assert::assertSame($originalContent, $decryptedContent, 'IMAGE decrypt mismatch');

        $reEncryptedContent = Crypto::encrypt($originalContent, $mediaKey, MediaType::IMAGE);
        Assert::assertSame($encryptedContent, $reEncryptedContent, 'IMAGE encrypt mismatch');
    }

    public function audioSampleEncryptDecrypt(): void
    {
        $originalContent = file_get_contents($this->samplePath('AUDIO.original'));
        $encryptedContent = file_get_contents($this->samplePath('AUDIO.encrypted'));
        $mediaKey = file_get_contents($this->samplePath('AUDIO.key'));
        Assert::assertSame(strlen($mediaKey), 32, 'media key must be 32 bytes');

        $decryptedContent = Crypto::decrypt($encryptedContent, $mediaKey, MediaType::AUDIO);
        Assert::assertSame($originalContent, $decryptedContent, 'AUDIO decrypt mismatch');

        $reEncryptedContent = Crypto::encrypt($originalContent, $mediaKey, MediaType::AUDIO);
        Assert::assertSame($encryptedContent, $reEncryptedContent, 'AUDIO encrypt mismatch');
    }

    public function videoSampleEncryptDecrypt(): void
    {
        $originalContent = file_get_contents($this->samplePath('VIDEO.original'));
        $encryptedContent = file_get_contents($this->samplePath('VIDEO.encrypted'));
        $mediaKey = file_get_contents($this->samplePath('VIDEO.key'));

        // Sidecar is not used by crypto, but ensure it exists
        $sidecarPath = $this->samplePath('VIDEO.sidecar');
        if (file_exists($sidecarPath)) {
            $sidecarContents = file_get_contents($sidecarPath);
            Assert::assertNotFalse($sidecarContents);
        }
        Assert::assertSame(strlen($mediaKey), 32, 'media key must be 32 bytes');

        $decryptedContent = Crypto::decrypt($encryptedContent, $mediaKey, MediaType::VIDEO);
        Assert::assertSame($originalContent, $decryptedContent, 'VIDEO decrypt mismatch');

        $reEncryptedContent = Crypto::encrypt($originalContent, $mediaKey, MediaType::VIDEO);
        Assert::assertSame($encryptedContent, $reEncryptedContent, 'VIDEO encrypt mismatch');
    }
}
