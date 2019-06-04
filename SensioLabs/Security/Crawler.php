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

use SensioLabs\Security\Exception\HttpException;
use SensioLabs\Security\Exception\RuntimeException;
use Symfony\Component\HttpClient\HttpClient;
use Symfony\Component\Mime\Part\DataPart;
use Symfony\Component\Mime\Part\Multipart\FormDataPart;
use Symfony\Contracts\HttpClient\ResponseInterface;

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
        $response = $this->doCheck($lock, $format, $headers);

        $headers = $response->getHeaders();
        if (!isset($headers['x-alerts']) || !ctype_digit($count = $headers['x-alerts'][0])) {
            throw new RuntimeException('The web service did not return alerts count.');
        }

        return new Result((int) $count, $response->getContent(), $format);
    }

    /**
     * @return array An array where the first element is a headers string and second one the response body
     */
    private function doCheck($lock, $format = 'json', array $contextualHeaders = []): ResponseInterface
    {
        $client = HttpClient::create();
        $body = new FormDataPart([
            'lock' => new DataPart($this->getLockContents($lock), 'composer.lock'),
        ]);
        $headers = array_merge($this->headers, [
            'Accept' => $this->getContentType($format),
            'User-Agent' => sprintf('SecurityChecker-CLI/%s FGC PHP', SecurityChecker::VERSION),
        ], $body->getPreparedHeaders()->toArray());

        $response = $client->request('POST', $this->endPoint, [
            'headers' => $headers,
            'timeout' => $this->timeout,
            'body' => $body->bodyToIterable(),
        ]);

        if (400 === $statusCode = $response->getStatusCode()) {
            $data = trim($response->getContent(false));
            if ('json' === $format) {
                $data = json_decode($data, true)['message'] ?? $data;
            }

            throw new HttpException(sprintf('%s (HTTP %s).', $data, $statusCode), $statusCode);
        }

        if (200 !== $statusCode) {
            throw new HttpException(sprintf('The web service failed for an unknown reason (HTTP %s).', $statusCode), $statusCode);
        }

        return $response;
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
            if (!\is_array($contents[$key])) {
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
