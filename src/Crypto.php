<?php

declare(strict_types=1);

namespace Lancoid\WhatsApp\MediaStreams;

use InvalidArgumentException;
use RuntimeException;

/**
 * WhatsApp media encryption and decryption implementation.
 *
 * This class implements WhatsApp's media encryption scheme, which uses:
 * - HKDF-SHA256 for key derivation
 * - AES-256-CBC for encryption/decryption
 * - HMAC-SHA256 (truncated to 10 bytes) for authentication
 * - PKCS#7 padding for block alignment
 *
 * Security properties:
 * - Confidentiality: AES-256-CBC with derived keys
 * - Integrity: HMAC-SHA256 over IV + ciphertext
 * - Authenticity: MAC verification prevents tampering
 */
final class Crypto
{
    /**
     * Required length of the media key in bytes.
     *
     * WhatsApp uses a 32-byte (256-bit) random media key per file.
     */
    private const int MEDIA_KEY_LENGTH = 32;

    /**
     * Length of the initialization vector (IV) in bytes.
     *
     * AES-256-CBC requires a 16-byte IV.
     */
    private const int INITIALIZATION_VECTOR_LENGTH = 16;

    /**
     * Length of the AES cipher key in bytes.
     *
     * AES-256 uses a 32-byte (256-bit) key.
     */
    private const int CIPHER_KEY_LENGTH = 32;

    /**
     * Length of the HMAC key in bytes.
     *
     * HMAC-SHA256 typically uses a 32-byte key.
     */
    private const int HMAC_KEY_LENGTH = 32;

    /**
     * Length of the reference key in bytes.
     *
     * The reference key is part of WhatsApp's key derivation but not used
     * in the encryption/decryption process itself.
     */
    private const int REFERENCE_KEY_LENGTH = 32;

    /**
     * Total length of derived key material from HKDF.
     *
     * Sum of IV + cipher key + MAC key + ref key = 112 bytes.
     */
    private const int DERIVED_KEY_LENGTH = 112;

    /**
     * Length of the truncated MAC in bytes.
     *
     * WhatsApp truncates the 32-byte HMAC-SHA256 output to 10 bytes.
     */
    private const int HMAC_TRUNCATED_LENGTH = 10;

    /**
     * AES block size in bytes.
     *
     * AES always uses 16-byte (128-bit) blocks regardless of key size.
     */
    private const int AES_BLOCK_SIZE = 16;

    /**
     * SHA-256 hash output length in bytes.
     */
    private const int HASH_LENGTH = 32;

    /**
     * Derive encryption keys from a media key using HKDF-SHA256.
     *
     * This method implements WhatsApp's key derivation scheme.
     * From a single 32-byte media key, it derives four separate keys:
     * - iv: Initialization vector for AES-CBC
     * - cipherKey: Encryption/decryption key for AES-256
     * - macKey: HMAC key for message authentication
     * - refKey: Reference key (part of protocol, not used in crypto operations)
     *
     * The derivation uses HKDF (HMAC-based Key Derivation Function) with:
     * - No salt (empty string, converted to zero bytes in HKDF)
     * - Info string based on media type (see MediaType::getInfoString())
     * - Output length of 112 bytes
     *
     * @param string $mediaKey The 32-byte media key (must be cryptographically random)
     * @param string $type Media type constant (IMAGE, VIDEO, or AUDIO)
     *
     * @return array{
     *     iv:string,
     *     cipherKey:string,
     *     macKey:string,
     *     refKey:string
     * } Derived keys
     *
     * @throws InvalidArgumentException If a media key is not exactly 32 bytes
     * @throws InvalidArgumentException If the media type is unknown
     */
    public static function deriveKeys(string $mediaKey, string $type): array
    {
        if (self::MEDIA_KEY_LENGTH !== strlen($mediaKey)) {
            throw new InvalidArgumentException(
                sprintf('mediaKey must be exactly %d bytes, got %d', self::MEDIA_KEY_LENGTH, strlen($mediaKey))
            );
        }

        $infoString = MediaType::getInfoString($type);
        $outputKeyMaterial = self::hkdfSha256($mediaKey, '', $infoString, self::DERIVED_KEY_LENGTH);

        return [
            'iv' => substr($outputKeyMaterial, 0, self::INITIALIZATION_VECTOR_LENGTH),
            'cipherKey' => substr($outputKeyMaterial, self::INITIALIZATION_VECTOR_LENGTH, self::CIPHER_KEY_LENGTH),
            'macKey' => substr($outputKeyMaterial, self::INITIALIZATION_VECTOR_LENGTH + self::CIPHER_KEY_LENGTH, self::HMAC_KEY_LENGTH),
            'refKey' => substr($outputKeyMaterial, self::INITIALIZATION_VECTOR_LENGTH + self::CIPHER_KEY_LENGTH + self::HMAC_KEY_LENGTH, self::REFERENCE_KEY_LENGTH),
        ];
    }

    /**
     * Encrypt plaintext using WhatsApp's media encryption scheme.
     *
     * This method:
     * 1. Derives keys from the media key
     * 2. Applies PKCS#7 padding to plaintext
     * 3. Encrypts with AES-256-CBC
     * 4. Computes HMAC-SHA256 over (IV || ciphertext)
     * 5. Truncates MAC to 10 bytes
     * 6. Returns ciphertext || MAC
     *
     * The output format is: encrypted_data + 10_byte_mac
     *
     * @param string $plaintext The data to encrypt (any length)
     * @param string $mediaKey The 32-byte media key
     * @param string $type Media type constant (IMAGE, VIDEO, or AUDIO)
     *
     * @return string Encrypted data with appended MAC
     *
     * @throws InvalidArgumentException If the media key or type is invalid
     * @throws RuntimeException If OpenSSL encryption fails
     */
    public static function encrypt(string $plaintext, string $mediaKey, string $type): string
    {
        $keys = self::deriveKeys($mediaKey, $type);
        $padded = self::applyPkcs7Padding($plaintext);

        $ciphertext = openssl_encrypt(
            $padded,
            'aes-256-cbc',
            $keys['cipherKey'],
            OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING,
            $keys['iv']
        );

        if (false === $ciphertext) {
            throw new RuntimeException('Encryption failed: ' . openssl_error_string());
        }

        $mac = self::calculateMac($keys['iv'] . $ciphertext, $keys['macKey']);

        return $ciphertext . $mac;
    }

    /**
     * Decrypt and verify WhatsApp encrypted media.
     *
     * This method:
     * 1. Extracts the 10-byte MAC from the end
     * 2. Derives keys from the media key
     * 3. Verifies HMAC-SHA256 in constant time
     * 4. Decrypts with AES-256-CBC
     * 5. Removes and validates PKCS#7 padding
     *
     * @param string $encrypted The encrypted data with appended MAC
     * @param string $mediaKey The 32-byte media key
     * @param string $type Media type constant (IMAGE, VIDEO, or AUDIO)
     *
     * @return string Decrypted plaintext
     *
     * @throws InvalidArgumentException If encrypted data is too short or invalid
     * @throws RuntimeException If MAC verification fails (data tampered)
     * @throws RuntimeException If decryption fails or padding is invalid
     */
    public static function decrypt(string $encrypted, string $mediaKey, string $type): string
    {
        if (strlen($encrypted) < self::HMAC_TRUNCATED_LENGTH) {
            throw new InvalidArgumentException(
                sprintf('Encrypted data too short: minimum %d bytes required', self::HMAC_TRUNCATED_LENGTH)
            );
        }

        $keys = self::deriveKeys($mediaKey, $type);
        $mac = substr($encrypted, -self::HMAC_TRUNCATED_LENGTH);
        $ciphertext = substr($encrypted, 0, -self::HMAC_TRUNCATED_LENGTH);

        // Verify MAC before attempting decryption (fail fast on tampering)
        self::verifyMac($keys['iv'] . $ciphertext, $keys['macKey'], $mac);

        if (0 !== strlen($ciphertext) % self::AES_BLOCK_SIZE) {
            throw new RuntimeException(
                sprintf('Ciphertext length must be a multiple of %d bytes', self::AES_BLOCK_SIZE)
            );
        }

        $padded = openssl_decrypt(
            $ciphertext,
            'aes-256-cbc',
            $keys['cipherKey'],
            OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING,
            $keys['iv']
        );

        if (false === $padded) {
            throw new RuntimeException('Decryption failed: ' . openssl_error_string());
        }

        return self::removePkcs7Padding($padded);
    }

    /**
     * HKDF-SHA256 key derivation function (RFC 5869).
     *
     * HKDF is a key derivation function that extracts a fixed-length
     * pseudorandom key from input key material and expands it to the
     * desired length.
     *
     * Steps:
     * 1. Extract: PRK = HMAC-SHA256(salt, IKM)
     * 2. Expand: OKM = HMAC-SHA256(PRK, T(i-1) || info || counter)
     *
     * @param string $inputKeyMaterial Input key material (the source key)
     * @param string $saltBytes Optional salt (uses zero bytes if empty)
     * @param string $contextInfo Optional context/application-specific info
     * @param int $outputLength Desired output length in bytes
     *
     * @return string Derived key material of a specified length
     */
    public static function hkdfSha256(string $inputKeyMaterial, string $saltBytes, string $contextInfo, int $outputLength): string
    {
        // Use zero bytes if no salt provided (as per RFC 5869)
        if ('' === $saltBytes) {
            $saltBytes = str_repeat("\x00", self::HASH_LENGTH);
        }

        // Extract: derive a pseudorandom key
        $pseudorandomKey = hash_hmac('sha256', $inputKeyMaterial, $saltBytes, true);

        // Expand: generate output key material
        $outputKeyMaterial = '';
        $previousBlock = '';

        for ($blockIndex = 1; strlen($outputKeyMaterial) < $outputLength; ++$blockIndex) {
            $previousBlock = hash_hmac('sha256', $previousBlock . $contextInfo . chr($blockIndex), $pseudorandomKey, true);
            $outputKeyMaterial .= $previousBlock;
        }

        return substr($outputKeyMaterial, 0, $outputLength);
    }

    /**
     * Apply PKCS#7 padding to data.
     *
     * PKCS#7 padding ensures data is a multiple of the block size by appending N bytes,
     * each with value N, where N is the number of padding bytes needed.
     *
     * @param string $data Data to pad
     *
     * @return string Padded data (always a multiple of 16 bytes)
     */
    private static function applyPkcs7Padding(string $data): string
    {
        $padLength = self::AES_BLOCK_SIZE - (strlen($data) % self::AES_BLOCK_SIZE);

        // If data is already aligned, add a full block of padding
        if (0 === $padLength) {
            $padLength = self::AES_BLOCK_SIZE;
        }

        return $data . str_repeat(chr($padLength), $padLength);
    }

    /**
     * Remove and verify PKCS#7 padding from data.
     *
     * This method:
     * 1. Reads the last byte to determine padding length
     * 2. Validates padding length is between 1-16
     * 3. Verifies all padding bytes have the correct value
     * 4. Removes padding and returns original data
     *
     * @param string $data Padded data
     *
     * @return string Original data without padding
     *
     * @throws RuntimeException If padding is invalid or corrupted
     */
    private static function removePkcs7Padding(string $data): string
    {
        $length = strlen($data);

        if (0 === $length) {
            return '';
        }

        $padLength = ord($data[$length - 1]);

        // Validate padding length
        if ($padLength < 1 || $padLength > self::AES_BLOCK_SIZE) {
            throw new RuntimeException(
                sprintf('Invalid PKCS#7 padding length: %d (must be 1-%d)', $padLength, self::AES_BLOCK_SIZE)
            );
        }

        // Verify all padding bytes are correct
        for ($i = 1; $i <= $padLength; ++$i) {
            if (ord($data[$length - $i]) !== $padLength) {
                throw new RuntimeException('Invalid PKCS#7 padding: inconsistent padding bytes');
            }
        }

        return substr($data, 0, $length - $padLength);
    }

    /**
     * Calculate truncated HMAC-SHA256.
     *
     * Computes HMAC-SHA256 and truncates to 10 bytes as per WhatsApp protocol.
     *
     * @param string $data Data to authenticate
     * @param string $key HMAC key
     *
     * @return string 10-byte MAC
     */
    private static function calculateMac(string $data, string $key): string
    {
        return substr(hash_hmac('sha256', $data, $key, true), 0, self::HMAC_TRUNCATED_LENGTH);
    }

    /**
     * Verify MAC in constant time.
     *
     * Uses hash_equals() for timing-attack-safe comparison.
     * This prevents attackers from learning information about the MAC through timing analysis.
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
