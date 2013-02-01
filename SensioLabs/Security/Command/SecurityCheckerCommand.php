<?php

namespace SensioLabs\Security\Command;

use SensioLabs\Security\SecurityChecker;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputOption;

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
                new InputArgument('lock', InputArgument::REQUIRED, 'The path to the composer.lock file'),
                new InputOption('format', '', InputOption::VALUE_REQUIRED, 'The output format', 'text'),
            ))
            ->setDescription('Checks security issues in your project dependencies')
            ->setHelp(<<<EOF
The <info>%command.name%</info> command checks a <info>composer.lock</info>
file for security issues in the project dependencies:

<info>php %command.full_name% security:check /path/to/composer.lock</info>

By default, the command displays the result in plain text, but you can also
configure it to output JSON instead by using the <info>--format</info> option:

<info>php %command.full_name% security:check /path/to/composer.lock --format=json</info>
EOF
            );
    }

    /**
     * @see Command
     * @see SecurityChecker
     */
    protected function execute(InputInterface $input, OutputInterface $output)
    {
        try {
            $data = $this->checker->check($input->getArgument('lock'), $input->getOption('format'));
        } catch (\Exception $e) {
            $output->writeln($this->getHelperSet()->get('formatter')->formatBlock($e->getMessage(), 'error', true));

            return 1;
        }

        $output->write($data);
    }
}
