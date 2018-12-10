<?php

/*
 * This file is part of the SensioLabs Security Checker.
 *
 * (c) Fabien Potencier
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

class SecurityCheckerCommand extends Command
{
    protected static $defaultName = 'security:check';

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
            ->setDefinition([
                new InputArgument('lockfile', InputArgument::OPTIONAL, 'The path to the composer.lock file', 'composer.lock'),
                new InputOption('format', '', InputOption::VALUE_REQUIRED, 'The output format', 'ansi'),
                new InputOption('end-point', '', InputOption::VALUE_REQUIRED, 'The security checker server URL'),
                new InputOption('timeout', '', InputOption::VALUE_REQUIRED, 'The HTTP timeout in seconds'),
                new InputOption('token', '', InputOption::VALUE_REQUIRED, 'The server token', ''),
            ])
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
            $this->checker->getCrawler()->setEndPoint($endPoint);
        }

        if ($timeout = $input->getOption('timeout')) {
            $this->checker->getCrawler()->setTimeout($timeout);
        }

        if ($token = $input->getOption('token')) {
            $this->checker->getCrawler()->setToken($token);
        }

        $format = $input->getOption('format');
        if ($input->getOption("no-ansi") && 'ansi' === $format) {
            $format = 'text';
        }

        try {
            $result = $this->checker->check($input->getArgument('lockfile'), $format);
        } catch (ExceptionInterface $e) {
            $output->writeln($this->getHelperSet()->get('formatter')->formatBlock($e->getMessage(), 'error', true));

            return 1;
        }

        $output->writeln((string) $result);

        if (count($result) > 0) {
            return 1;
        }
    }
}
