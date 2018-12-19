<?php

/*
 * This file is part of the SensioLabs Security Checker.
 *
 * (c) Fabien Potencier
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace SensioLabs\Security;

use Composer\CaBundle\CaBundle;
use SensioLabs\Security\Exception\HttpException;
use SensioLabs\Security\Exception\RuntimeException;

/**
 * @internal
 */
class Crawler
{
    private $endPoint = 'https://security.symfony.com/check_lock';
    private $timeout = 20;
    private $headers = [];

    public function setTimeout($timeout)
    {
        $this->timeout = $timeout;
    }

    public function setEndPoint($endPoint)
    {
        $this->endPoint = $endPoint;
    }

    public function setToken($token)
    {
        $this->addHeader('Authorization', 'Token '.$token);
    }

    /**
     * Adds a global header that will be sent with all requests to the server.
     */
    public function addHeader($key, $value)
    {
        $this->headers[] = $key.': '.$value;
    }

    /**
     * Checks a Composer lock file.
     *
     * @param string $lock    The path to the composer.lock file or a string able to be opened via file_get_contents
     * @param string $format  The format of the result
     * @param array  $headers An array of headers to add for this specific HTTP request
     *
     * @return Result
     */
    public function check($lock, $format = 'json', array $headers = [])
    {
        list($headers, $body) = $this->doCheck($lock, $format, $headers);

        if (!(preg_match('/X-Alerts: (\d+)/i', $headers, $matches) || 2 == count($matches))) {
            throw new RuntimeException('The web service did not return alerts count.');
        }

        return new Result((int) $matches[1], $body, $format);
    }

    /**
     * @return array An array where the first element is a headers string and second one the response body
     */
    private function doCheck($lock, $format = 'json', array $contextualHeaders = [])
    {
        $boundary = '------------------------'.md5(microtime(true));
        $headers = "Content-Type: multipart/form-data; boundary=$boundary\r\nAccept: ".$this->getContentType($format);
        foreach ($this->headers as $header) {
            $headers .= "\r\n$header";
        }
        foreach ($contextualHeaders as $key => $value) {
            $headers .= "\r\n$key: $value";
        }
        $opts = [
            'http' => [
                'method' => 'POST',
                'header' => $headers,
                'content' => "--$boundary\r\nContent-Disposition: form-data; name=\"lock\"; filename=\"composer.lock\"\r\nContent-Type: application/octet-stream\r\n\r\n".$this->getLockContents($lock)."\r\n--$boundary--\r\n",
                'ignore_errors' => true,
                'follow_location' => true,
                'max_redirects' => 3,
                'timeout' => $this->timeout,
                'user_agent' => sprintf('SecurityChecker-CLI/%s FGC PHP', SecurityChecker::VERSION),
            ],
            'ssl' => [
                'verify_peer' => 1,
                'verify_host' => 2,
            ],
        ];

        $caPathOrFile = CaBundle::getSystemCaRootBundlePath();
        if (is_dir($caPathOrFile) || (is_link($caPathOrFile) && is_dir(readlink($caPathOrFile)))) {
            $opts['ssl']['capath'] = $caPathOrFile;
        } else {
            $opts['ssl']['cafile'] = $caPathOrFile;
        }

        $context = stream_context_create($opts);
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
            $data = trim($body);
            if ('json' === $format) {
                $data = json_decode($body, true)['error'];
            }

            throw new RuntimeException($data);
        }

        if (200 != $statusCode) {
            throw new HttpException(sprintf('The web service failed for an unknown reason (HTTP %s).', $statusCode), $statusCode);
        }

        $headers = '';
        foreach ($http_response_header as $header) {
            if (false !== stripos($header, 'X-Alerts: ')) {
                $headers = $header;
            }
        }

        return [$headers, $body];
    }

    private function getContentType($format)
    {
        static $formats = [
            'text' => 'text/plain',
            'simple' => 'text/plain',
            'markdown' => 'text/markdown',
            'yaml' => 'text/yaml',
            'json' => 'application/json',
            'ansi' => 'text/plain+ansi',
        ];

        return isset($formats[$format]) ? $formats[$format] : 'text';
    }

    private function getLockContents($lock)
    {
        $contents = json_decode(file_get_contents($lock), true);
        $hash = isset($contents['content-hash']) ? $contents['content-hash'] : (isset($contents['hash']) ? $contents['hash'] : '');
        $packages = ['content-hash' => $hash, 'packages' => [], 'packages-dev' => []];
        foreach (['packages', 'packages-dev'] as $key) {
            if (!is_array($contents[$key])) {
                continue;
            }
            foreach ($contents[$key] as $package) {
                $data = [
                    'name' => $package['name'],
                    'version' => $package['version'],
                ];
                if (isset($package['time']) && false !== strpos($package['version'], 'dev')) {
                    $data['time'] = $package['time'];
                }
                $packages[$key][] = $data;
            }
        }

        return json_encode($packages);
    }
}
