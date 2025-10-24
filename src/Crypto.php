<?php

declare(strict_types=1);

namespace Lancoid\WhatsApp\MediaStreams;

use InvalidArgumentException;
use RuntimeException;

/**
 * Provides cryptographic operations for WhatsApp media streams:
 * - HKDF key derivation (RFC 5869)
 * - AES-256-CBC encryption/decryption
 * - PKCS#7 padding/unpadding
 * - HMAC-SHA256 authentication (truncated to 10 bytes)
 *
 * This class is designed for secure processing of WhatsApp media files.
 */
final class Crypto
{
    private const MEDIA_KEY_LENGTH = 32;
    private const IV_LENGTH = 16;
    private const CIPHER_KEY_LENGTH = 32;
    private const MAC_KEY_LENGTH = 32;
    private const REF_KEY_LENGTH = 32;
    private const MAC_LENGTH = 10;
    private const AES_BLOCK_SIZE = 16;
    private const HKDF_LENGTH = 112;

    /** @var array<string, string> */
    private const INFO = [
        MediaType::IMAGE => 'WhatsApp Image Keys',
        MediaType::VIDEO => 'WhatsApp Video Keys',
        MediaType::AUDIO => 'WhatsApp Audio Keys',
        MediaType::DOCUMENT => 'WhatsApp Document Keys',
    ];

    /**
     * Derives encryption, MAC, IV, and reference keys from a media key and media type.
     *
     * @param string $mediaKey 32-byte base media key
     * @param string $type Media type (IMAGE, VIDEO, AUDIO, DOCUMENT)
     *
     * @return array{iv: string, cipherKey: string, macKey: string, refKey: string}
     *
     * @throws InvalidArgumentException If the media key length or type is invalid
     */
    public static function deriveKeys(string $mediaKey, string $type): array
    {
        if (self::MEDIA_KEY_LENGTH !== strlen($mediaKey)) {
            throw new InvalidArgumentException(
                sprintf('mediaKey must be %d bytes, got %d', self::MEDIA_KEY_LENGTH, strlen($mediaKey))
            );
        }

        $type = strtoupper($type);
        $infoKeys = array_change_key_case(self::INFO, CASE_UPPER);

        if (!isset($infoKeys[$type])) {
            throw new InvalidArgumentException('Unknown media type: ' . $type);
        }

        $info = $infoKeys[$type];
        $hkdf = self::hkdf('sha256', $mediaKey, self::HKDF_LENGTH, $info, '');

        return [
            'iv' => substr($hkdf, 0, self::IV_LENGTH),
            'cipherKey' => substr($hkdf, self::IV_LENGTH, self::CIPHER_KEY_LENGTH),
            'macKey' => substr($hkdf, self::IV_LENGTH + self::CIPHER_KEY_LENGTH, self::MAC_KEY_LENGTH),
            'refKey' => substr($hkdf, self::IV_LENGTH + self::CIPHER_KEY_LENGTH + self::MAC_KEY_LENGTH, self::REF_KEY_LENGTH),
        ];
    }

    /**
     * HKDF key derivation function (RFC 5869).
     *
     * @param string $algo Hash algorithm (e.g., 'sha256')
     * @param string $ikm Input keying material
     * @param int $length Length of output key in bytes
     * @param string $info Context/application-specific information
     * @param string $salt Optional salt value (if empty, uses zeros)
     *
     * @return string Derived key of requested length
     *
     * @throws InvalidArgumentException If requested length is too large
     */
    public static function hkdf(string $algo, string $ikm, int $length, string $info, string $salt): string
    {
        $hashLen = strlen(hash($algo, '', true));
        if ($length > 255 * $hashLen) {
            throw new InvalidArgumentException('HKDF: length too large');
        }
        if ('' === $salt) {
            $salt = str_repeat("\0", $hashLen);
        }
        $prk = hash_hmac($algo, $ikm, $salt, true);
        $t = '';
        $lastBlock = '';
        for ($block = 1; strlen($t) < $length; ++$block) {
            $lastBlock = hash_hmac($algo, $lastBlock . $info . chr($block), $prk, true);
            $t .= $lastBlock;
        }

        return substr($t, 0, $length);
    }

    /**
     * Encrypts data using WhatsApp's AES-256-CBC and HMAC-SHA256 protocol.
     *
     * @param string $data Plaintext data to encrypt
     * @param string $mediaKey 32-byte media key
     * @param string $type Media type (IMAGE, VIDEO, AUDIO, DOCUMENT)
     *
     * @return string Encrypted data with appended 10-byte MAC
     *
     * @throws RuntimeException If encryption fails
     */
    public static function encrypt(string $data, string $mediaKey, string $type): string
    {
        $keys = self::deriveKeys($mediaKey, $type);
        $padded = self::pkcs7Pad($data);

        $enc = openssl_encrypt(
            $padded,
            'aes-256-cbc',
            $keys['cipherKey'],
            OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING,
            $keys['iv']
        );

        if (!is_string($enc)) {
            throw new RuntimeException('Encryption failed: ' . (openssl_error_string() ?: 'unknown error'));
        }

        $mac = substr(hash_hmac('sha256', $keys['iv'] . $enc, $keys['macKey'], true), 0, self::MAC_LENGTH);

        return $enc . $mac;
    }

    /**
     * Decrypts data using WhatsApp's AES-256-CBC and HMAC-SHA256 protocol.
     *
     * @param string $data Encrypted data with appended 10-byte MAC
     * @param string $mediaKey 32-byte media key
     * @param string $type Media type (IMAGE, VIDEO, AUDIO, DOCUMENT)
     *
     * @return string Decrypted plaintext data
     *
     * @throws RuntimeException If decryption or MAC verification fails
     */
    public static function decrypt(string $data, string $mediaKey, string $type): string
    {
        if ('' === $data) {
            return '';
        }

        $keys = self::deriveKeys($mediaKey, $type);

        if (strlen($data) < self::MAC_LENGTH + self::IV_LENGTH) {
            throw new RuntimeException('Data too short for decryption');
        }

        $enc = substr($data, 0, -self::MAC_LENGTH);
        $mac = substr($data, -self::MAC_LENGTH);
        // Verify MAC before attempting decryption (fail fast on tampering)
        self::verifyMac($keys['iv'] . $enc, $keys['macKey'], $mac);

        $decrypted = openssl_decrypt(
            $enc,
            'aes-256-cbc',
            $keys['cipherKey'],
            OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING,
            $keys['iv']
        );

        if (!is_string($decrypted)) {
            throw new RuntimeException('Decryption failed: ' . (openssl_error_string() ?: 'unknown error'));
        }

        return self::pkcs7Unpad($decrypted);
    }

    /**
     * Applies PKCS#7 padding to data.
     *
     * @param string $data Data to pad
     *
     * @return string Padded data
     */
    private static function pkcs7Pad(string $data): string
    {
        $padLength = self::AES_BLOCK_SIZE - (strlen($data) % self::AES_BLOCK_SIZE);
        if (0 === $padLength) {
            $padLength = self::AES_BLOCK_SIZE;
        }

        return $data . str_repeat(chr($padLength), $padLength);
    }

    /**
     * Removes PKCS#7 padding from data.
     *
     * @param string $data Padded data
     *
     * @return string Unpadded data
     *
     * @throws RuntimeException If padding is invalid
     */
    private static function pkcs7Unpad(string $data): string
    {
        $length = strlen($data);
        if (0 === $length) {
            return '';
        }
        $padLength = ord($data[$length - 1]);
        if ($padLength < 1 || $padLength > self::AES_BLOCK_SIZE) {
            throw new RuntimeException(
                sprintf('Invalid PKCS#7 padding length: %d (must be 1-%d)', $padLength, self::AES_BLOCK_SIZE)
            );
        }
        if (substr($data, -$padLength) !== str_repeat(chr($padLength), $padLength)) {
            throw new RuntimeException('Invalid PKCS#7 padding: inconsistent padding bytes');
        }

        return substr($data, 0, $length - $padLength);
    }

    /**
     * Calculates a truncated HMAC-SHA256 (10 bytes) for WhatsApp protocol.
     *
     * @param string $data Data to authenticate
     * @param string $key HMAC key
     *
     * @return string 10-byte MAC
     */
    private static function calculateMac(string $data, string $key): string
    {
        return substr(hash_hmac('sha256', $data, $key, true), 0, self::MAC_LENGTH);
    }

    /**
     * Verifies the MAC in constant time to prevent timing attacks.
     *
     * @param string $data Data that was authenticated
     * @param string $key HMAC key
     * @param string $expectedMac MAC to verify against
     *
     * @throws RuntimeException If MAC verification fails
     */
    private static function verifyMac(string $data, string $key, string $expectedMac): void
    {
        $calculatedMac = self::calculateMac($data, $key);

        if (!hash_equals($expectedMac, $calculatedMac)) {
            throw new RuntimeException('MAC verification failed: data may have been tampered with');
        }
    }
}
