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
    public const MAC_LENGTH = 10;
    public const AES_BLOCK_SIZE = 16;
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
     * @param string $key 32-byte base media key
     * @param string $mediaType Media type (IMAGE, VIDEO, AUDIO, DOCUMENT)
     *
     * @return array{iv: string, cipherKey: string, macKey: string, refKey: string}
     *
     * @throws InvalidArgumentException If the media key length or type is invalid
     */
    public static function deriveKeys(string $key, string $mediaType): array
    {
        if (self::MEDIA_KEY_LENGTH !== strlen($key)) {
            throw new InvalidArgumentException(
                sprintf('mediaKey must be %d bytes, got %d', self::MEDIA_KEY_LENGTH, strlen($key))
            );
        }

        $mediaType = strtoupper($mediaType);

        if (!isset(self::INFO[$mediaType])) {
            throw new InvalidArgumentException('Unknown media type: ' . $mediaType);
        }

        $info = self::INFO[$mediaType];
        $hkdf = self::hkdf('sha256', $key, self::HKDF_LENGTH, $info, '');

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
     * @param string $algorithm Hash algorithm (e.g., 'sha256')
     * @param string $inputKeyMaterial Input keying material
     * @param int $outputLength Output key length in bytes
     * @param string $info Context/application-specific information
     * @param string $salt Optional salt value (if empty, uses zeros)
     *
     * @return string Derived key of requested length
     *
     * @throws InvalidArgumentException If requested length is too large
     */
    public static function hkdf(string $algorithm, string $inputKeyMaterial, int $outputLength, string $info, string $salt): string
    {
        $hashLength = strlen(hash($algorithm, '', true));

        if ($outputLength > 255 * $hashLength) {
            throw new InvalidArgumentException('HKDF: length too large');
        }

        if ('' === $salt) {
            $salt = str_repeat("\0", $hashLength);
        }

        $prk = hash_hmac($algorithm, $inputKeyMaterial, $salt, true);
        $output = '';
        $block = '';

        for ($blockIndex = 1; strlen($output) < $outputLength; ++$blockIndex) {
            $block = hash_hmac($algorithm, $block . $info . chr($blockIndex), $prk, true);
            $output .= $block;
        }

        return substr($output, 0, $outputLength);
    }

    /**
     * Encrypts data using WhatsApp AES-256-CBC and HMAC-SHA256 protocol.
     *
     * @param string $plaintext Plaintext data to encrypt
     * @param string $key 32-byte media key
     * @param string $mediaType Media type (IMAGE, VIDEO, AUDIO, DOCUMENT)
     *
     * @return string Encrypted data with appended 10-byte MAC
     *
     * @throws RuntimeException If encryption fails
     */
    public static function encrypt(string $plaintext, string $key, string $mediaType): string
    {
        $keys = self::deriveKeys($key, $mediaType);
        $padded = self::pkcs7Pad($plaintext);

        $encrypted = openssl_encrypt(
            $padded,
            'aes-256-cbc',
            $keys['cipherKey'],
            OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING,
            $keys['iv']
        );

        if (!is_string($encrypted)) {
            throw new RuntimeException('Encryption failed: ' . (openssl_error_string() ?: 'unknown error'));
        }

        $macTag = substr(hash_hmac('sha256', $keys['iv'] . $encrypted, $keys['macKey'], true), 0, self::MAC_LENGTH);

        return $encrypted . $macTag;
    }

    /**
     * Decrypts data using WhatsApp AES-256-CBC and HMAC-SHA256 protocol.
     *
     * @param string $encryptedData Encrypted data with appended 10-byte MAC
     * @param string $key 32-byte media key
     * @param string $mediaType Media type (IMAGE, VIDEO, AUDIO, DOCUMENT)
     * @param int $offset Optional offset for IV modification
     *
     * @return string Decrypted plaintext data
     *
     * @throws RuntimeException If decryption or MAC verification fails
     */
    public static function decrypt(string $encryptedData, string $key, string $mediaType, int $offset = 0): string
    {
        if ('' === $encryptedData) {
            return '';
        }

        $keys = self::deriveKeys($key, $mediaType);

        if (strlen($encryptedData) < self::MAC_LENGTH + self::IV_LENGTH) {
            throw new RuntimeException('Data too short for decryption');
        }

        $encrypted = substr($encryptedData, 0, -self::MAC_LENGTH);
        $macTag = substr($encryptedData, -self::MAC_LENGTH);

        $initializationVector = $keys['iv'];

        if (0 !== $offset) {
            $initializationVector ^= pack('J', $offset) . substr($initializationVector, 8);
        }

        self::verifyMac($initializationVector . $encrypted, $keys['macKey'], $macTag);

        $decrypted = openssl_decrypt(
            $encrypted,
            'aes-256-cbc',
            $keys['cipherKey'],
            OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING,
            $initializationVector
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
        $paddingLength = self::AES_BLOCK_SIZE - (strlen($data) % self::AES_BLOCK_SIZE);

        if (0 === $paddingLength) {
            $paddingLength = self::AES_BLOCK_SIZE;
        }

        return $data . str_repeat(chr($paddingLength), $paddingLength);
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

        $paddingByte = ord($data[$length - 1]);

        if ($paddingByte < 1 || $paddingByte > self::AES_BLOCK_SIZE) {
            throw new RuntimeException(
                sprintf('Invalid PKCS#7 padding length: %d (must be 1-%d)', $paddingByte, self::AES_BLOCK_SIZE)
            );
        }

        if (substr($data, -$paddingByte) !== str_repeat(chr($paddingByte), $paddingByte)) {
            throw new RuntimeException('Invalid PKCS#7 padding: inconsistent padding bytes');
        }

        return substr($data, 0, $length - $paddingByte);
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

    /**
     * Returns the decrypted data size based on the encrypted stream size.
     *
     * @param int $encryptedSize Size of the encrypted stream (in bytes)
     * @param string $key 32-byte media key
     * @param string $mediaType Media type (IMAGE, VIDEO, AUDIO, DOCUMENT)
     * @param null|string $encryptedTail Last 16 bytes of encrypted data (optional, for accurate padding calculation)
     *
     * @return null|int Decrypted data size or null if it cannot be determined
     */
    public static function getDecryptedSize(int $encryptedSize, string $key, string $mediaType, ?string $encryptedTail = null): ?int
    {
        if ($encryptedSize < self::MAC_LENGTH + self::AES_BLOCK_SIZE) {
            return null;
        }

        $encryptedSizeWithoutMac = $encryptedSize - self::MAC_LENGTH;

        if (null !== $encryptedTail && self::AES_BLOCK_SIZE === strlen($encryptedTail)) {
            $keys = self::deriveKeys($key, $mediaType);
            $initializationVector = $keys['iv'];
            $cipherKey = $keys['cipherKey'];
            $lastBlock = openssl_decrypt($encryptedTail, 'aes-256-cbc', $cipherKey, OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING, $initializationVector);

            if (false === $lastBlock) {
                return null;
            }

            $paddingByte = ord(substr($lastBlock, -1));

            if ($paddingByte < 1 || $paddingByte > self::AES_BLOCK_SIZE) {
                return null;
            }

            return $encryptedSizeWithoutMac - $paddingByte;
        }

        return $encryptedSizeWithoutMac - 1;
    }
}
