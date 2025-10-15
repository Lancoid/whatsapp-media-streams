<?php

declare(strict_types=1);

namespace Tests\unit;

use InvalidArgumentException;
use Lancoid\WhatsApp\MediaStreams\MediaType;
use PHPUnit\Framework\Assert;

final class MediaTypeCest
{
    public function infoStrings(): void
    {
        Assert::assertSame('WhatsApp Image Keys', MediaType::getInfoString(MediaType::IMAGE));
        Assert::assertSame('WhatsApp Video Keys', MediaType::getInfoString(MediaType::VIDEO));
        Assert::assertSame('WhatsApp Audio Keys', MediaType::getInfoString(MediaType::AUDIO));
    }

    public function invalidTypeThrows(): void
    {
        try {
            MediaType::getInfoString('doc');
            Assert::fail('Expected InvalidArgumentException not thrown');
        } catch (InvalidArgumentException $e) {
            Assert::assertStringContainsString('Unknown media type', $e->getMessage());
        }
    }
}
