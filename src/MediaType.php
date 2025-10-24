<?php

declare(strict_types=1);

namespace Lancoid\WhatsApp\MediaStreams;

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
    public const IMAGE = 'IMAGE';

    /**
     * Video media type.
     *
     * Used for encrypting/decrypting video files (MP4, AVI, etc.).
     */
    public const VIDEO = 'VIDEO';

    /**
     * Audio media type.
     *
     * Used for encrypting/decrypting audio files (MP3, OGG, AAC, etc.).
     */
    public const AUDIO = 'AUDIO';

    /**
     * Document media type.
     *
     * Used for encrypting/decrypting document files (PDF, DOCX, XLSX, etc.).
     * This type is required for WhatsApp's document media encryption scheme.
     */
    public const DOCUMENT = 'DOCUMENT';
}
