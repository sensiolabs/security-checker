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
use Symfony\Component\Console\Helper\FormatterHelper;

class SimpleFormatter implements FormatterInterface
{
    public function __construct(FormatterHelper $formatter)
    {
        $this->formatter = $formatter;
    }

    /**
     * Displays a security report as simple plain text.
     *
     * @param OutputInterface $output
     * @param string          $lockFilePath    The file path to the checked lock file
     * @param array           $vulnerabilities An array of vulnerabilities
     */
    public function displayResults(OutputInterface $output, $lockFilePath, array $vulnerabilities)
    {
        $output->writeln(sprintf('Security Check Report: <comment>%s</>', realpath($lockFilePath)));

        if ($count = count($vulnerabilities)) {
            $status = 'CRITICAL';
            $style = 'error';
        } else {
            $status = 'OK';
            $style = 'info';
        }

        $output->writeln(sprintf('<%s>[%s] %d packages have known vulnerabilities</>', $style, $status, $count));

        if (0 !== $count) {
            $output->write("\n");

            foreach ($vulnerabilities as $dependency => $issues) {
                $dependencyFullName = $dependency.' ('.$issues['version'].')';
                $output->writeln('<info>'.$dependencyFullName."\n".str_repeat('-', strlen($dependencyFullName))."</>\n");

                foreach ($issues['advisories'] as $issue => $details) {
                    $output->write(' * ');
                    if ($details['cve']) {
                        $output->write('<comment>'.$details['cve'].': </comment>');
                    }
                    $output->writeln($details['title']);

                    if ('' !== $details['link']) {
                        $output->writeln('   '.$details['link']);
                    }

                    $output->writeln('');
                }
            }
        }
    }
}
