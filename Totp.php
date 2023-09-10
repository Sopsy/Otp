<?php
declare(strict_types=1);

namespace Otp;

use InvalidArgumentException;
use BaseNEncoder\Encoder;
use BaseNEncoder\Scheme\Base32;

use function count;
use function floor;
use function hash_equals;
use function hash_hmac;
use function http_build_query;
use function mb_strlen;
use function pack;
use function rawurlencode;
use function str_contains;
use function str_pad;
use function strtoupper;
use function time;
use function unpack;

use const STR_PAD_LEFT;

final class Totp
{
    private readonly string $algorithm;
    private readonly int $digits;
    private readonly int $period;

    public function __construct(
        private readonly string $secretBinary,
        private readonly int $window = 1
    ) {
        // The following values are hardcoded because Google Authenticator only supports these
        $this->algorithm = 'sha1';
        $this->digits = 6;
        $this->period = 30;

        if (mb_strlen($this->secretBinary, '8bit') !== 20) {
            throw new InvalidArgumentException('Secret has to be 20 bytes long');
        }
    }

    public function at(int $timestamp): string
    {
        return $this->keyFromStepNumber($this->stepNumberFromTimestamp($timestamp));
    }

    public function keyUri(string $issuer, string $account): string
    {
        // https://github.com/google/google-authenticator/wiki/Key-Uri-Format

        if (str_contains($issuer . $account, ':')) {
            throw new InvalidArgumentException('Neither issuer nor account may contain a colon.');
        }

        $label = rawurlencode($issuer) . ':' . rawurlencode($account);
        $params = http_build_query(
            [
                'secret' => $this->secret(),
                'issuer' => rawurlencode($issuer),
                'algorithm' => strtoupper($this->algorithm),
                'digits' => $this->digits,
                'period' => $this->period,
            ]
        );

        return "otpauth://totp/{$label}?{$params}";
    }

    public function secret(bool $binary = false): string
    {
        if ($binary) {
            return $this->secretBinary;
        }

        return (new Encoder(new Base32()))->encode($this->secretBinary);
    }

    private function stepNumberFromTimestamp(int $timestamp): int
    {
        return (int)floor($timestamp / $this->period);
    }

    private function keyFromStepNumber(int $stepNumber): string
    {
        // Get hash with step number converted to 64bit unsigned long
        $hashString = hash_hmac($this->algorithm, pack('N*', 0, $stepNumber), $this->secretBinary, true);

        // Break down hash to bytes for easier slicing
        /** @var int[] $hash */
        $hash = unpack('C*', $hashString);

        // Get last 4 bits for the random offset
        // +1 because unpack arrays start at index 1 instead of 0
        $offset = ($hash[count($hash)] & 0xf) + 1;

        // Get 4 bytes from the hash beginning from the offset
        // First bit is set low to avoid ambiguity with signing
        $code = ($hash[$offset] & 0x7f) << 24 | $hash[$offset + 1] << 16 | $hash[$offset + 2] << 8 | $hash[$offset + 3];

        // Modulo to shorten the number to the wanted number of digits
        $otp = $code % (10 ** $this->digits);

        // Pad the OTP with zeroes so we get "000001" instead of "1"
        return str_pad((string)$otp, $this->digits, '0', STR_PAD_LEFT);
    }

    public function verify(string $key): bool
    {
        $currentStep = $this->stepNumberFromTimestamp(time());

        // Try current first because most probably it matches
        if (hash_equals($this->keyFromStepNumber($currentStep), $key)) {
            return true;
        }

        for ($i = $currentStep - $this->window; $i <= $currentStep + $this->window; ++$i) {
            if ($i === $currentStep) {
                continue;
            }

            if (hash_equals($this->keyFromStepNumber($i), $key)) {
                return true;
            }
        }

        return false;
    }
}