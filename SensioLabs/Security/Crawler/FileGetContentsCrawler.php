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
class FileGetContentsCrawler extends BaseCrawler
{
    /**
     * {@inheritdoc}
     */
    protected function doCheck($lock, $certFile)
    {
        $boundary = '------------------------'.md5(microtime(true));
        $context = stream_context_create(array(
            'http' => array(
                'method' => 'POST',
                'header' => "Content-Type: multipart/form-data; boundary=$boundary\r\nAccept: application/json",
                'content' => "--$boundary\r\nContent-Disposition: form-data; name=\"lock\"; filename=\"$lock\"\r\nContent-Type: application/octet-stream\r\n\r\n".file_get_contents($lock)."\r\n--$boundary\r\n--\r\n",
                'ignore_errors' => true,
                'follow_location' => true,
                'max_redirects' => 3,
                'timeout' => $this->timeout,
                'user_agent' => 'SecurityChecker-CLI/4 FGC PHP',
            ),
            'ssl' => array(
                'cafile' => $certFile,
                'verify_peer' => 1,
                'verify_host' => 2,
            ),
        ));

        $level = error_reporting(0);
        $body = file_get_contents($this->endPoint, 0, $context);
        error_reporting($level);
        if (false === $body) {
            $error = error_get_last();

            throw new RuntimeException(sprintf('An error occurred: %s.', $error['message']));
        }

        // status code
        if (!preg_match('{HTTP/\d\.\d (\d+) }i', $http_response_header[0], $match)) {
            throw new RuntimeException('An unknown error occurred.');
        }

        $statusCode = $match[1];
        if (400 == $statusCode) {
            $data = json_decode($body, true);

            throw new RuntimeException($data['error']);
        }

        if (200 != $statusCode) {
            throw new RuntimeException(sprintf('The web service failed for an unknown reason (HTTP %s).', $statusCode));
        }

        $headers = '';
        foreach ($http_response_header as $header) {
            if (false !== strpos($header, 'X-Alerts: ')) {
                $headers = $header;
            }
        }

        return array($headers, $body);
    }
}
