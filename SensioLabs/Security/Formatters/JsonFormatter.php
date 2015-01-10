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

class JsonFormatter implements FormatterInterface
{
    /**
     * Displays a security report as json.
     *
     * @param OutputInterface $output
     * @param string          $lockFilePath    The file path to the checked lock file
     * @param array           $vulnerabilities An array of vulnerabilities
     */
    public function displayResults(OutputInterface $output, $lockFilePath, array $vulnerabilities)
    {
        if (defined('JSON_PRETTY_PRINT')) {
            $output->write(json_encode($vulnerabilities, JSON_PRETTY_PRINT));
        } else {
            $output->write(json_encode($vulnerabilities));
        }
    }
}
