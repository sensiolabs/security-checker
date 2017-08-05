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
use SensioLabs\Security\Result;

/**
 * @internal
 */
abstract class BaseCrawler implements CrawlerInterface
{
    protected $endPoint = 'https://security.symfony.com/check_lock';
    protected $timeout = 20;
    protected $headers = array();

    /**
     * {@inheritdoc}
     */
    public function setTimeout($timeout)
    {
        $this->timeout = $timeout;
    }

    /**
     * {@inheritdoc}
     */
    public function setEndPoint($endPoint)
    {
        $this->endPoint = $endPoint;
    }

    /**
     * {@inheritdoc}
     */
    public function setToken($token)
    {
        $this->addHeader('Authorization', 'Token '.$token);
    }

    public function addHeader($key, $value)
    {
        $this->headers[] = $key.': '.$value;
    }

    /**
     * {@inheritdoc}
     */
    public function check($lock, $format = 'json', array $headers = array())
    {
        list($headers, $body) = $this->doCheck($lock, $format, $headers);

        if (!(preg_match('/X-Alerts: (\d+)/', $headers, $matches) || 2 == count($matches))) {
            throw new RuntimeException('The web service did not return alerts count.');
        }

        return new Result((int) $matches[1], $body, $format);
    }

    /**
     * @return array An array where the first element is a headers string and second one the response body
     */
    abstract protected function doCheck($lock, $format = 'json');

    protected function getContentType($format)
    {
        static $formats = array(
            'text' => 'text/plain',
            'simple' => 'text/plain',
            'markdown' => 'text/markdown',
            'yaml' => 'text/yaml',
            'json' => 'application/json',
            'ansi' => 'text/plain+ansi',
        );

        return isset($formats[$format]) ? $formats[$format] : 'text';
    }

    protected function getLockContents($lock)
    {
        $contents = json_decode(file_get_contents($lock), true);
        $hash = isset($contents['content-hash']) ? $contents['content-hash'] : (isset($contents['hash']) ? $contents['hash'] : '');
        $packages = array('content-hash' => $hash, 'packages' => array(), 'packages-dev' => array());
        foreach (array('packages', 'packages-dev') as $key) {
            if (!is_array($contents[$key])) {
                continue;
            }
            foreach ($contents[$key] as $package) {
                $data = array(
                    'name' => $package['name'],
                    'version' => $package['version'],
                );
                if (isset($package['time']) && false !== strpos($package['version'], 'dev')) {
                    $data['time'] = $package['time'];
                }
                $packages[$key][] = $data;
            }
        }

        return json_encode($packages);
    }
}
