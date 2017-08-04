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
     * @param string $lock    The path to the composer.lock file or a string able to be opened via file_get_contents
     * @param array  $headers An array of headers to add for this specific HTTP request
     *
     * @return An array of two items: the number of vulnerabilities and an array of vulnerabilities
     */
    public function check($lock, array $headers = array());

    public function setTimeout($timeout);

    public function setEndPoint($endPoint);

    public function setToken($token);

    /**
     * Adds a global header that will be sent with all requests to the server.
     */
    public function addHeader($key, $value);
}
