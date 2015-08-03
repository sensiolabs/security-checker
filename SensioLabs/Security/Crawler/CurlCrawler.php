<?php

/*
 * This file is part of the SensioLabs Security Checker.
 *
 * (c) Fabien Potencier
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace SensioLabs\Security\Crawler;

use SensioLabs\Security\Exception\RuntimeException;

/**
 * @internal
 */
class CurlCrawler extends BaseCrawler
{
    public function __construct()
    {
        if (!function_exists('curl_init')) {
            throw new RuntimeException('cURL is required to use the cURL crawler.');
        }
    }

    /**
     * {@inheritdoc}
     */
    protected function doCheck($lock, $certFile)
    {
        if (false === $curl = curl_init()) {
            throw new RuntimeException('Unable to create a cURL handle.');
        }

        $postFields = array('lock' => PHP_VERSION_ID >= 50500 ? new \CurlFile($lock) : '@'.$lock);

        curl_setopt($curl, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($curl, CURLOPT_HEADER, true);
        curl_setopt($curl, CURLOPT_URL, $this->endPoint);
        curl_setopt($curl, CURLOPT_HTTPHEADER, array('Accept: application/json'));
        curl_setopt($curl, CURLOPT_POSTFIELDS, $postFields);
        curl_setopt($curl, CURLOPT_CONNECTTIMEOUT, $this->timeout);
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

            throw new RuntimeException(sprintf('An error occurred: %s.', $error));
        }

        $headersSize = curl_getinfo($curl, CURLINFO_HEADER_SIZE);
        $headers = substr($response, 0, $headersSize);
        $body = substr($response, $headersSize);

        $statusCode = curl_getinfo($curl, CURLINFO_HTTP_CODE);
        curl_close($curl);

        if (400 == $statusCode) {
            $data = json_decode($body, true);
            $error = $data['error'];

            throw new RuntimeException($error);
        }

        if (200 != $statusCode) {
            throw new RuntimeException(sprintf('The web service failed for an unknown reason (HTTP %s).', $statusCode));
        }

        return array($headers, $body);
    }
}
