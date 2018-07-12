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

use SensioLabs\Security\Exception\RuntimeException;

class SecurityChecker
{
    const VERSION = '5.0';

    private $crawler;

    public function __construct(Crawler $crawler = null)
    {
        $this->crawler = null === $crawler ? new Crawler() : $crawler;
    }

    /**
     * Checks a composer.lock file.
     *
     * @param string $lock    The path to the composer.lock file
     * @param string $format  The format of the result
     * @param array  $headers An array of headers to add for this specific HTTP request
     *
     * @return Result
     *
     * @throws RuntimeException When the lock file does not exist
     * @throws RuntimeException When the certificate can not be copied
     */
    public function check($lock, $format = 'json', array $headers = [])
    {
        if (0 !== strpos($lock, 'data://text/plain;base64,')) {
            if (is_dir($lock) && file_exists($lock.'/composer.lock')) {
                $lock = $lock.'/composer.lock';
            } elseif (preg_match('/composer\.json$/', $lock)) {
                $lock = str_replace('composer.json', 'composer.lock', $lock);
            }

            if (!is_file($lock)) {
                throw new RuntimeException('Lock file does not exist.');
            }
        }

        return $this->crawler->check($lock, $format, $headers);
    }

    /**
     * @internal
     *
     * @return Crawler
     */
    public function getCrawler()
    {
        return $this->crawler;
    }
}
