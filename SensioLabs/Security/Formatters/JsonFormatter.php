<?php

/*
 * This file is part of the SensioLabs Security Checker.
 *
 * (c) 2013 Fabien Potencier
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace SensioLabs\Security\Formatters;

use Symfony\Component\Console\Output\OutputInterface;

if (!defined('JSON_PRETTY_PRINT')) {
    define('JSON_PRETTY_PRINT', 0);
}

class JsonFormatter
{

    public function displayResults(OutputInterface $output, $lockFilePath, array $vulnerabilities)
    {
        $output->write(json_encode($vulnerabilities, JSON_PRETTY_PRINT));
    }

}
