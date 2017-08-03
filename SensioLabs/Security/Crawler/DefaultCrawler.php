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

/**
 * @internal
 */
class DefaultCrawler implements CrawlerInterface
{
    private $crawler;
    private $fgc;

    public function __construct()
    {
        $this->fgc = new FileGetContentsCrawler();
        $this->crawler = function_exists('curl_init') ? new CurlCrawler() : $this->fgc;
    }

    /**
     * {@inheritdoc}
     */
    public function check($lock)
    {
        if (0 !== strpos($lock, 'data://text/plain;base64,')) {
            return $this->crawler->check($lock);
        }

        // we must use FileGetContentsCrawler() here
        return $this->fgc->check($lock);
    }

    /**
     * {@inheritdoc}
     */
    public function setTimeout($timeout)
    {
        $this->crawler->setTimeout($timeout);
        $this->fgc->setTimeout($timeout);
    }

    /**
     * {@inheritdoc}
     */
    public function setEndPoint($endPoint)
    {
        $this->crawler->setEndPoint($endPoint);
        $this->fgc->setEndPoint($endPoint);
    }


    /**
     * {@inheritdoc}
     */
    public function setToken($token)
    {
        $this->crawler->setToken($token);
        $this->fgc->setToken($token);
    }
}
