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

    public function __construct()
    {
        $this->crawler = ('stream' === getenv('SENSIOLABS_SECURITY_CHECKER_TRANSPORT') || !function_exists('curl_init')) ? new FileGetContentsCrawler() : new CurlCrawler();
    }

    /**
     * {@inheritdoc}
     */
    public function check($lock)
    {
        return $this->crawler->check($lock);
    }

    /**
     * {@inheritdoc}
     */
    public function setTimeout($timeout)
    {
        $this->crawler->setTimeout($timeout);
    }

    /**
     * {@inheritdoc}
     */
    public function setEndPoint($endPoint)
    {
        $this->crawler->setEndPoint($endPoint);
    }
}
