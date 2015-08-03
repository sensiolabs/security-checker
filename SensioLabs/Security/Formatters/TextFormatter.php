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
        $output->writeln("\n<fg=blue>Security Check Report\n~~~~~~~~~~~~~~~~~~~~~</>\n");
        $output->writeln(sprintf('Checked file: <comment>%s</>', realpath($lockFilePath)));
        $output->write("\n");

        if ($count = count($vulnerabilities)) {
            $status = 'CRITICAL';
            $style = 'error';
        } else {
            $status = 'OK';
            $style = 'bg=green;fg=white';
        }

        $message = sprintf('%d %s known vulnerabilities', $count, 1 === $count ? 'package has' : 'packages have');
        $output->writeln($this->formatter->formatBlock(array('['.$status.']', $message), $style, true));
        $output->write("\n");

        if (0 !== $count) {
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

        $output->writeln('<bg=yellow;fg=white>            </> This checker can only detect vulnerabilities that are referenced');
        $output->writeln('<bg=yellow;fg=white> Disclaimer </> in the SensioLabs security advisories database. Execute this');
        $output->writeln("<bg=yellow;fg=white>            </> command regularly to check the newly discovered vulnerabilities.\n");
    }
}
