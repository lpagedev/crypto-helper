<?php

namespace lpagedev\Helpers;

use Exception;
use RangeException;
use SodiumException;

class CryptoHelper
{
    /**
     * @return string Returns a base64 encoded secret key used to encrypt data
     */
    public static function CreateSecretKey(): string
    {
        return base64_encode(sodium_crypto_secretbox_keygen());
    }

    /**
     * Standard PHP sodium implementation for decryption, must use the same key used during encryption.
     * @param string $pString Base64 encoded and encrypted string
     * @param string $pKey Base64 encoded secret key used to encrypt data
     * @return string
     * @throws SodiumException
     */
    public static function DecryptString(string $pString, string $pKey): string
    {
        $decoded = base64_decode($pString);
        $nonce = mb_substr($decoded, 0, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES, '8bit');
        $encrypted_result = mb_substr($decoded, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES, null, '8bit');
        $results = sodium_crypto_secretbox_open($encrypted_result, $nonce, $pKey);
        sodium_memzero($pString);
        sodium_memzero($pKey);
        sodium_memzero($decoded);
        sodium_memzero($nonce);
        sodium_memzero($encrypted_result);
        return $results;
    }

    /**
     * Standard PHP sodium implementation for encryption, must use a key generated with CreateSecretKey().
     * @param string $pString String to encrypt
     * @param string $pKey Base64 encoded secret key used to encrypt data
     * @return string
     * @throws SodiumException
     * @throws Exception
     *
     */
    public static function EncryptString(string $pString, string $pKey): string
    {
        if (mb_strlen(base64_decode($pKey), '8bit') !== SODIUM_CRYPTO_SECRETBOX_KEYBYTES) {
            sodium_memzero($pKey);
            sodium_memzero($pString);
            throw new RangeException('Key is not the correct size (must be 32 bytes).');
        }
        $nonce = random_bytes(SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
        $results = base64_encode($nonce . sodium_crypto_secretbox($pString, $nonce, $pKey));
        sodium_memzero($pString);
        sodium_memzero($pKey);
        sodium_memzero($nonce);
        return $results;
    }

    /**
     * Standard PHP hashing implementation, decreasing the memory cost or time cost will speed up the process but at cost of security.
     * @param string $pString String to hash
     * @param int $pMemoryCost Memory cost for hash function
     * @param int $pTimeCost Time cost for hash function
     * @param int $pThreads Threads to use for hashing
     * @return string
     * @throws SodiumException
     */
    public static function HashString(string $pString, int $pMemoryCost = 2048, int $pTimeCost = 4, int $pThreads = 4): string
    {
        $results = password_hash($pString, PASSWORD_ARGON2I, ['memory_cost' => $pMemoryCost, 'time_cost' => $pTimeCost, 'threads' => $pThreads]);
        sodium_memzero($pString);
        return $results;
    }

    /**
     * Standard PHP hashing verification, knows what settings were used during hashing.
     * @param string $pString String to compare
     * @param string $pHash Hash to compare with
     * @return bool
     * @throws SodiumException
     */
    public static function HashStringVerify(string $pString, string $pHash): bool
    {
        $results = password_verify($pString, $pHash);
        sodium_memzero($pString);
        sodium_memzero($pHash);
        return $results;
    }

}
