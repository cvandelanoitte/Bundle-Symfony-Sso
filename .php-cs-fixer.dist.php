<?php

declare(strict_types=1);

$finder = (new PhpCsFixer\Finder())
    ->in([__DIR__.'/src', __DIR__.'/config', __DIR__.'/tests']);

return (new PhpCsFixer\Config())
    ->setRiskyAllowed(true)
    ->setRules([
        '@Symfony' => true,
        '@Symfony:risky' => true,
        'declare_strict_types' => true,
        'native_function_invocation' => ['include' => ['@compiler_optimized'], 'scope' => 'namespaced'],
    ])
    ->setFinder($finder)
    ->setCacheFile(__DIR__.'/.php-cs-fixer.cache');
