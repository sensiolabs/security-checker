<?php

/*
 * This file is part of the SensioLabs Security Checker.
 *
 * (c) 2013 Fabien Potencier
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace SensioLabs\Security\Command;

use SensioLabs\Security\SecurityChecker;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputOption;
use SensioLabs\Security\Exception\ExceptionInterface;

if (!defined('JSON_PRETTY_PRINT')) {
    define('JSON_PRETTY_PRINT', 0);
}

class SecurityCheckerCommand extends Command
{
    private $checker;

    public function __construct(SecurityChecker $checker)
    {
        $this->checker = $checker;

        parent::__construct();
    }

    /**
     * @see Command
     */
    protected function configure()
    {
        $this
            ->setName('security:check')
            ->setDefinition(array(
                new InputArgument('lock', InputArgument::OPTIONAL, 'The path to the composer.lock file', 'composer.lock'),
                new InputOption('format', '', InputOption::VALUE_REQUIRED, 'The output format', 'text'),
                new InputOption('end-point', '', InputOption::VALUE_REQUIRED, 'The security checker server URL'),
                new InputOption('timeout', '', InputOption::VALUE_REQUIRED, 'The HTTP timeout'),
            ))
            ->setDescription('Checks security issues in your project dependencies')
            ->setHelp(<<<EOF
The <info>%command.name%</info> command looks for security issues in the
project dependencies:

<info>php %command.full_name%</info>

You can also pass the path to a <info>composer.lock</info> file as an argument:

<info>php %command.full_name% /path/to/composer.lock</info>

By default, the command displays the result in plain text, but you can also
configure it to output JSON instead by using the <info>--format</info> option:

<info>php %command.full_name% /path/to/composer.lock --format=json</info>
EOF
            );
    }

    /**
     * @see Command
     * @see SecurityChecker
     */
    protected function execute(InputInterface $input, OutputInterface $output)
    {
        if ($endPoint = $input->getOption('end-point')) {
            $this->checker->setEndPoint($endPoint);
        }

        if ($timeout = $input->getOption('timeout')) {
            $this->checker->setTimeout($timeout);
        }

        try {
            $vulnerabilities = $this->checker->check($input->getArgument('lock'));
        } catch (ExceptionInterface $e) {
            $output->writeln($this->getHelperSet()->get('formatter')->formatBlock($e->getMessage(), 'error', true));

            return 1;
        }

         if ('json' === $input->getOption('format')) {
             $output->write(json_encode($vulnerabilities, JSON_PRETTY_PRINT));
         } else {
             $this->displayResults($output, $input->getArgument('lock'), $vulnerabilities);
         }

        if ($this->checker->getLastVulnerabilityCount() > 0) {
            return 1;
        }
    }

    /**
     * Displays a security report as plain text.
     *
     * @param OutputInterface $output
     * @param string          $lockFilePath    The file path to the checked lock file
     * @param array           $vulnerabilities An array of vulnerabilities
     */
    private function displayResults(OutputInterface $output, $lockFilePath, array $vulnerabilities)
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

        $output->writeln($this->getHelper('formatter')->formatBlock(array('['.$status.']', $count.' packages have known vulnerabilities'), $style, true));
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

        $output->writeln("<bg=yellow;fg=white>            </> This checker can only detect vulnerabilities that are referenced");
        $output->writeln("<bg=yellow;fg=white> Disclaimer </> in the SensioLabs security advisories database. Execute this");
        $output->writeln("<bg=yellow;fg=white>            </> command regularly to check the newly discovered vulnerabilities.\n");
    }
}
