SensioLabs Security Checker
===========================

The SensioLabs Security Checker is a command line tool that checks if your
application uses dependencies with known security vulnerabilities. It uses the
[SensioLabs Security Check Web service][1] and the [Security Advisories Database][2]
behind the scenes:

    $ php security-checker security:check /path/to/composer.lock

You can also integrate the checker in your own application/project

 * by using the `SecurityCheckerCommand` class into your Symfony Console
   application.

 * by using the `SecurityChecker` class directly into your own code:

        use SensioLabs\Security\SecurityChecker;

        $checker = new SecurityChecker();
        $alerts = $checker->check('/path/to/composer.lock', 'json');

Create Phar File
---------------------

To create a phar file you can use [Box][3]

        php box.phar build

[1]: http://security.sensiolabs.org/
[2]: https://github.com/sensiolabs/security-advisories
[3]: http://box-project.org/
