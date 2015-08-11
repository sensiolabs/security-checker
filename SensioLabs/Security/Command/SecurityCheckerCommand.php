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
use SensioLabs\Security\Formatters\JsonFormatter;
use SensioLabs\Security\Formatters\SimpleFormatter;
use SensioLabs\Security\Formatters\TextFormatter;

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
                new InputArgument('lockfile', InputArgument::OPTIONAL, 'The path to the composer.lock file', 'composer.lock'),
                new InputOption('format', '', InputOption::VALUE_REQUIRED, 'The output format', 'text'),
                new InputOption('end-point', '', InputOption::VALUE_REQUIRED, 'The security checker server URL'),
                new InputOption('timeout', '', InputOption::VALUE_REQUIRED, 'The HTTP timeout in seconds'),
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
            $this->checker->getCrawler()->setEndPoint($endPoint);
        }

        if ($timeout = $input->getOption('timeout')) {
            $this->checker->getCrawler()->setTimeout($timeout);
        }

        try {
            $vulnerabilities = $this->checker->check($input->getArgument('lockfile'));
        } catch (ExceptionInterface $e) {
            $output->writeln($this->getHelperSet()->get('formatter')->formatBlock($e->getMessage(), 'error', true));

            return 1;
        }

        switch ($input->getOption('format')) {
            case 'json':
                $formatter = new JsonFormatter();
                break;
            case 'simple':
                $formatter = new SimpleFormatter($this->getHelperSet()->get('formatter'));
                break;
            case 'text':
            default:
                $formatter = new TextFormatter($this->getHelperSet()->get('formatter'));
        }

        $formatter->displayResults($output, $input->getArgument('lockfile'), $vulnerabilities);

        if ($this->checker->getLastVulnerabilityCount() > 0) {
            return 1;
        }
    }
}
