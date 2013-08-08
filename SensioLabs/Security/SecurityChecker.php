<?php

/*
 * This file is part of the SensioLabs Security Checker.
 *
 * (c) 2013 Fabien Potencier
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace SensioLabs\Security;

class SecurityChecker
{
    private $vulnerabilitiesCount;

    /**
     * Checks a composer.lock file.
     *
     * @param string $lock   The path to the composer.lock file
     * @param string $format The return format
     *
     * @return mixed The vulnerabilities
     *
     * @throws \InvalidArgumentException When the output format is unsupported
     * @throws \RuntimeException         When the lock file does not exist
     * @throws \RuntimeException         When curl does not work or is unavailable
     */
    public function check($lock, $format = 'text')
    {
        if (!function_exists('curl_init')) {
            throw new \RuntimeException('Curl is required to use this command.');
        }

        if (false === $curl = curl_init()) {
            throw new \RuntimeException('Unable to create a new curl handle.');
        }

        if (is_dir($lock) && file_exists($lock.'/composer.lock')) {
            $lock = $lock.'/composer.lock';
        } elseif (preg_match('/composer\.json$/', $lock)) {
            $lock = str_replace('composer.json', 'composer.lock', $lock);
        }

        if (!is_file($lock)) {
            throw new \RuntimeException('Lock file does not exist.');
        }

        switch ($format) {
            case 'text':
                $accept = 'text/plain';
                break;
            case 'json':
                $accept = 'application/json';
                break;
            default:
                throw new \InvalidArgumentException(sprintf('Unsupported format "%s".', $format));
        }

         if (strpos(__FILE__, 'phar://') !== false) {
            $certFile = $this->preparePharCacert();
        } else {
            $certFile = __DIR__ . "/Resources/security.sensiolabs.org.crt";
        }

        curl_setopt($curl, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($curl, CURLOPT_HEADER, true);
        curl_setopt($curl, CURLOPT_URL, 'https://security.sensiolabs.org/check_lock');
        curl_setopt($curl, CURLOPT_HTTPHEADER, array('Accept: '.$accept));
        curl_setopt($curl, CURLOPT_POSTFIELDS, array('lock' => '@'.$lock));
        curl_setopt($curl, CURLOPT_CONNECTTIMEOUT, 5);
        curl_setopt($curl, CURLOPT_TIMEOUT, 10);
        curl_setopt($curl, CURLOPT_FOLLOWLOCATION, 1);
        curl_setopt($curl, CURLOPT_MAXREDIRS, 3);
        curl_setopt($curl, CURLOPT_FAILONERROR, false);
        curl_setopt($curl, CURLOPT_SSL_VERIFYPEER, 1);
        curl_setopt($curl, CURLOPT_SSL_VERIFYHOST, 2);
        curl_setopt($curl, CURLOPT_CAINFO, $certFile);

        $response = curl_exec($curl);

        if (false === $response) {
            $error = curl_error($curl);
            curl_close($curl);

            throw new \RuntimeException(sprintf('An error occurred: %s.', $error));
        }

        $headersSize = curl_getinfo($curl, CURLINFO_HEADER_SIZE);
        $headers = substr($response, 0, $headersSize);
        $body = substr($response, $headersSize);

        $statusCode = curl_getinfo($curl, CURLINFO_HTTP_CODE);
        if (400 == $statusCode) {
            if ('text' == $format) {
                $error = trim($body);
            } else {
                $data = json_decode($body, true);
                $error = $data['error'];
            }

            curl_close($curl);

            throw new \InvalidArgumentException($error);
        }

        if (200 != $statusCode) {
            curl_close($curl);

            throw new \RuntimeException('The web service failed for an unknown reason (HTTP '.$statusCode.').');
        }

        curl_close($curl);

        if (!(preg_match('/X-Alerts: (\d+)/', $headers, $matches) || 2 == count($matches))) {
            throw new \RuntimeException('The web service did not return alerts count');
        }

        $this->vulnerabilitiesCount = intval($matches[1]);

        return $body;
    }

    public function getLastVulnerabilityCount()
    {
        return $this->vulnerabilitiesCount;
    }

    /**
    * Copy the cacert.pem file from the phar if it is not in the temp folder and validate the Sha1 checksum
    * required because curl can't read from a phar stream wrapper
    * method taken from guzzle https://github.com/guzzle/guzzle/blob/v3.7.2/src/Guzzle/Http/Client.php#L336
    *
    * @param bool $sha1Check Set to false to not perform the Sha1 validation
    *
    * @return string Returns the path to the extracted cacert
    * @throws RuntimeException if the file cannot be copied or there is a Sha1 mismatch
    */
    public function preparePharCacert($sha1Check = true)
    {
        $from = __DIR__ . '/Resources/security.sensiolabs.org.crt';
        $certFile = sys_get_temp_dir() . '/sensio-security-checker-cacert.pem';
        if (!file_exists($certFile) && !copy($from, $certFile)) {
            throw new \RuntimeException("Could not copy {$from} to {$certFile}: " . var_export(error_get_last(), true));
        } elseif ($sha1Check) {
            $actualSha1 = sha1_file($certFile);
            $expectedSha1 = explode(' ', trim(file_get_contents("{$from}.sha")));
            $expectedSha1 = array_shift($expectedSha1);
            if ($actualSha1 != $expectedSha1) {
                throw new \RuntimeException("{$certFile} Sha1 mismatch: expected {$expectedSha1} but got {$actualSha1}");
            }
        }

        return $certFile;
    }
}
