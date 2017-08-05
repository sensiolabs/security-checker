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

class Result implements \Countable
{
    private $count;
    private $vulnerabilities;
    private $format;

    public function __construct($count, $vulnerabilities, $format)
    {
        $this->count = $count;
        $this->vulnerabilities = $vulnerabilities;
        $this->format = $format;
    }

    public function getFormat()
    {
        return $this->format;
    }

    public function __toString()
    {
        return $this->vulnerabilities;
    }

    public function count()
    {
        return $this->count;
    }
}
