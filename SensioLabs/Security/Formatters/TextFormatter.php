<?php

/*
 * This file is part of the SensioLabs Security Checker.
 *
 * (c) Fabien Potencier
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace SensioLabs\Security\Formatters;

use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Console\Helper\FormatterHelper;
use Symfony\Component\Console\Input\ArrayInput;
use Symfony\Component\Console\Style\SymfonyStyle;

class TextFormatter implements FormatterInterface
{
    public function __construct(FormatterHelper $formatter)
    {
        $this->formatter = $formatter;
    }

    /**
     * Displays a security report as plain text.
     *
     * @param OutputInterface $output
     * @param string          $lockFilePath    The file path to the checked lock file
     * @param array           $vulnerabilities An array of vulnerabilities
     */
    public function displayResults(OutputInterface $output, $lockFilePath, array $vulnerabilities)
    {
        $output = new SymfonyStyle(new ArrayInput(array()), $output);
        $output->title('Symfony Security Check Report');
        $output->comment(sprintf('Checked file: <comment>%s</>', realpath($lockFilePath)));

        if ($count = count($vulnerabilities)) {
            $output->error(sprintf('%d packages have known vulnerabilities.', $count));
        } else {
            $output->success('No packages have known vulnerabilities.');
        }

        if (0 !== $count) {
            foreach ($vulnerabilities as $dependency => $issues) {
                $output->section(sprintf('%s (%s)', $dependency, $issues['version']));

                $details = array_map(function ($value) {
                    return sprintf("<info>%s</>: %s\n   %s", $value['cve'] ?: '(no CVE ID)', $value['title'], $value['link']);
                }, $issues['advisories']);

                $output->listing($details);
            }
        }

        $output->note('This checker can only detect vulnerabilities that are referenced in the SensioLabs security advisories database. Execute this command regularly to check the newly discovered vulnerabilities.');
    }
}
