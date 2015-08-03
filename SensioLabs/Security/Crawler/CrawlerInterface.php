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
interface CrawlerInterface
{
    /**
     * Checks a Composer lock file.
     *
     * @param string $lock The path to the composer.lock file
     *
     * @return An array of two items: the number of vulnerabilities and an array of vulnerabilities
     */
    public function check($lock);

    public function setTimeout($timeout);

    public function setEndPoint($endPoint);
}
