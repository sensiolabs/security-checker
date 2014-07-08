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
    private $endPoint = 'https://security.sensiolabs.org/check_lock';
    private $vulnerabilitiesCount;

    public function setEndPoint($endPoint)
    {
        $this->endPoint = $endPoint;
    }

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
     * @throws \RuntimeException         When the certificate can not be copied
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

        $postFields = array('lock' => '@'.$lock);

        if (version_compare(PHP_VERSION, '5.5.0') >= 0) {
            $postFields['lock'] = new \CurlFile($lock);
        }

        curl_setopt($curl, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($curl, CURLOPT_HEADER, true);
        curl_setopt($curl, CURLOPT_URL, $this->endPoint);
        curl_setopt($curl, CURLOPT_HTTPHEADER, array('Accept: '.$accept));
        curl_setopt($curl, CURLOPT_POSTFIELDS, $postFields);
        curl_setopt($curl, CURLOPT_CONNECTTIMEOUT, 0);
        curl_setopt($curl, CURLOPT_TIMEOUT, 10);
        curl_setopt($curl, CURLOPT_FOLLOWLOCATION, 1);
        curl_setopt($curl, CURLOPT_MAXREDIRS, 3);
        curl_setopt($curl, CURLOPT_FAILONERROR, false);
        curl_setopt($curl, CURLOPT_SSL_VERIFYPEER, 1);
        curl_setopt($curl, CURLOPT_SSL_VERIFYHOST, 2);

        $cert = __DIR__.'/Resources/security.sensiolabs.org.crt';
        $tmpFile = null;
        if ('phar://' === substr(__FILE__, 0, 7)) {
            $tmpFile = tempnam(sys_get_temp_dir(), 'sls');
            if (false === @copy($cert, $cert = $tmpFile)) {
                throw new \RuntimeException(sprintf('Unable to copy the certificate in "%s".', $tmpFile));
            }
        }
        curl_setopt($curl, CURLOPT_CAINFO, $cert);

        $response = curl_exec($curl);

        if (false === $response) {
            $error = curl_error($curl);
            curl_close($curl);
            if ($tmpFile) {
                unlink($tmpFile);
            }

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
            if ($tmpFile) {
                unlink($tmpFile);
            }

            throw new \InvalidArgumentException($error);
        }

        if (200 != $statusCode) {
            curl_close($curl);
            if ($tmpFile) {
                unlink($tmpFile);
            }

            throw new \RuntimeException(sprintf('The web service failed for an unknown reason (HTTP %s).', $statusCode));
        }

        curl_close($curl);
        if ($tmpFile) {
            unlink($tmpFile);
        }

        if (!(preg_match('/X-Alerts: (\d+)/', $headers, $matches) || 2 == count($matches))) {
            throw new \RuntimeException('The web service did not return alerts count.');
        }

        $this->vulnerabilitiesCount = intval($matches[1]);

        return $body;
    }

    public function getLastVulnerabilityCount()
    {
        return $this->vulnerabilitiesCount;
    }
}
