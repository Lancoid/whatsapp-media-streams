<?php

declare(strict_types=1);

namespace Lancoid\WhatsApp\MediaStreams;

use InvalidArgumentException;

/**
 * WhatsApp media type constants and utilities.
 *
 * This class defines the three supported media types used in WhatsApp's encryption scheme.
 * Each type has a unique "info" string used in the HKDF key derivation process.
 *
 * @see Crypto::deriveKeys() for key derivation usage
 */
final class MediaType
{
    /**
     * Image media type.
     *
     * Used for encrypting/decrypting image files (JPEG, PNG, etc.).
     */
    public const string IMAGE = 'image';

    /**
     * Video media type.
     *
     * Used for encrypting/decrypting video files (MP4, AVI, etc.).
     */
    public const string VIDEO = 'video';

    /**
     * Audio media type.
     *
     * Used for encrypting/decrypting audio files (MP3, OGG, AAC, etc.).
     */
    public const string AUDIO = 'audio';

    /**
     * Get the HKDF info string for a media type.
     *
     * WhatsApp uses different info strings in the HKDF key derivation for each media type.
     * This ensures that keys derived for one type cannot be used for another type.
     *
     * @param string $type One of MediaType::IMAGE, MediaType::VIDEO, or MediaType::AUDIO
     *
     * @return string The HKDF info string for key derivation
     *
     * @throws InvalidArgumentException If the media type is unknown
     */
    public static function getInfoString(string $type): string
    {
        return match ($type) {
            self::IMAGE => 'WhatsApp Image Keys',
            self::VIDEO => 'WhatsApp Video Keys',
            self::AUDIO => 'WhatsApp Audio Keys',
            default => throw new InvalidArgumentException('Unknown media type: ' . $type),
        };
    }
}
