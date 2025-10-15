<?php

declare(strict_types=1);

namespace Tests\unit;

use InvalidArgumentException;
use Lancoid\WhatsApp\MediaStreams\MediaType;
use UnitTester;

final class MediaTypeCest
{
    public function infoStrings(UnitTester $unitTester): void
    {
        $unitTester->assertSame('WhatsApp Image Keys', MediaType::getInfoString(MediaType::IMAGE));
        $unitTester->assertSame('WhatsApp Video Keys', MediaType::getInfoString(MediaType::VIDEO));
        $unitTester->assertSame('WhatsApp Audio Keys', MediaType::getInfoString(MediaType::AUDIO));
    }

    public function invalidTypeThrows(UnitTester $unitTester): void
    {
        $unitTester->expectThrowable(InvalidArgumentException::class, function (): void {
            MediaType::getInfoString('doc');
        });
    }
}
