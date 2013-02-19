<?php

namespace SensioLabs\Security\Command;

use SensioLabs\Security\SecurityChecker;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputOption;

class SecurityReporterCommand extends Command
{
    private $checker;
    private $transport;

    public function __construct(SecurityChecker $checker, \Swift_Transport $transport)
    {
        $this->checker = $checker;
        $this->transport = $transport;

        parent::__construct();
    }

    /**
     * @see Command
     */
    protected function configure()
    {
        $this
            ->setName('security:report')
            ->setDefinition(array(
                new InputArgument('email', InputArgument::REQUIRED, 'Address to report errors to'),
                new InputArgument('lock', InputArgument::OPTIONAL, 'The path to the composer.lock file', 'composer.lock'),
                new InputOption('from', null, InputOption::VALUE_OPTIONAL, 'Address from', 'security@' . gethostname()),
            ))
            ->setDescription('Reports security issues in your project dependencies')
            ->setHelp(<<<EOF
The <info>%command.name%</info> command checks a <info>composer.lock</info>
file for security issues in the project dependencies, and mails it to <info>security@domain.tld</info>
if issues were found:

<info>php %command.full_name% security:report security@domain.tld /path/to/composer.lock</info>
EOF
            );
    }

    /**
     * @see Command
     * @see SecurityChecker
     */
    protected function execute(InputInterface $input, OutputInterface $output)
    {
        $result = false;

        try {
            if (count(json_decode($this->checker->check($input->getArgument('lock'), 'json'))) !== 0) {
                $result = $this->checker->check($input->getArgument('lock'), 'text');
            }
        } catch (\Exception $e) {
            $result = 'The check failed and therefore cannot guarantee that you are secure.';
        }

        if ($result !== false) {
            $message = \Swift_Message::newInstance()
                ->setSubject('Security issue found on "' . gethostname() . '"')
                ->setFrom($input->getOption('from'))
                ->setTo($input->getArgument('email'))
                ->setBody($result);
            $mailer = \Swift_Mailer::newInstance($this->transport);

            return $mailer->send($message);
        }
    }
}
