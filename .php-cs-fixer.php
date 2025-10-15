<?php

$finder = PhpCsFixer\Finder::create()
    ->in(__DIR__)
    ->notPath([
        'tests/_support/_generated',
    ])
    ->exclude([
        'vendor'
    ]);

return (new PhpCsFixer\Config())
    ->setCacheFile(__DIR__ . '/.php-cs-fixer.cache')
    ->setRules([
        /* Rule sets https://cs.symfony.com/doc/ruleSets/index.html */
        '@PhpCsFixer' => true,
        '@PHP81Migration' => true,
        /* Alias https://cs.symfony.com/doc/rules/index.html#alias */
        'ereg_to_preg' => true,                              /* Замена устаревшие ereg-функции на preg */
        'no_alias_functions' => true,                        /* Вместо псевдонимов должны использоваться основные функции */
        'random_api_migration' => true,                      /* Заменяет rand, srand, getrandmax функции их mt_*аналогами или random_int */
        'set_type_to_cast' => true,                          /* Должен использоваться Cast, а не settype */
        /* Basic https://cs.symfony.com/doc/rules/index.html#basic */
        'non_printable_character' => true,                   /* Удаление пробела нулевой ширины (ZWSP), неразрывного пробела (NBSP) и других невидимых символов Юникода */
        'octal_notation' => false,                           /* Буквенный восьмеричный должен быть в 0o* записи */
        /* Cast Notation https://cs.symfony.com/doc/rules/index.html#cast-notation */
        'cast_spaces' => ['space' => 'none'],                /* Между приведением и переменной ни должно быть пробела */
        'modernize_types_casting' => true,                   /* Заменяет вызовы функций *val оператором соответствующего приведения типа */
        /* Class Notation https://cs.symfony.com/doc/rules/index.html#class-notation */
        'ordered_class_elements' => [                        /* Упорядочивает элементы classes/interfaces/traits/enums */
            'order' => ['use_trait'],
        ],
        'protected_to_private' => false,                     /* Преобразует protected переменные и методы в private, где это возможно */
        /* Comment https://cs.symfony.com/doc/rules/index.html#comment */
        'comment_to_phpdoc' => [
            'ignored_tags' => ['codeCoverageIgnoreStart', 'codeCoverageIgnoreEnd'],
        ],                         /* Комментарии с аннотацией должны быть DocBlock */
        'single_line_comment_style' => [                     /* Комментарии только с одной строкой должны начинаться с // */
            'comment_types' => ['hash'],
        ],
        /* Control Structure https://cs.symfony.com/doc/rules/index.html#control-structure */
        'no_superfluous_elseif' => false,                    /* Заменяет лишнее elseif на if */
        'no_unneeded_control_parentheses' => false,          /* Удаление ненужных круглых скобок вокруг операторов управления */
        /* Function Notation https://cs.symfony.com/doc/rules/index.html#function-notation */
        'fopen_flag_order' => true,                          /* Порядок флагов в fopen-функциях (b и t должны быть последними) */
        'method_argument_space' => [                         /* В аргументах метода и вызове метода пробелы после запятой */
            'on_multiline' => 'ignore',                      /* Как обрабатывать списки аргументов функций, которые содержат символы новой строки */
        ],
        /* Import https://cs.symfony.com/doc/rules/index.html#import */
        'global_namespace_import' => [                       /* Импортирует или полностью уточняет глобальные classes/functions/constants. */
            'import_classes' => true,
            'import_constants' => false,
            'import_functions' => false,
        ],
        /* Language Construct https://cs.symfony.com/doc/rules/index.html#language-construct */
        'dir_constant' => true,                              /* Заменяет dirname(__FILE__) эквивалентной __DIR__константой. */
        'is_null' => true,                                   /* Заменяет is_null($var) на null === $var /
        /* Naming https://cs.symfony.com/doc/rules/index.html#naming */
        'no_homoglyph_names' => true,                        /* Заменить случайное использование омоглифов (не ascii-символов) в именах */
        /* Operator https://cs.symfony.com/doc/rules/index.html#operator */
        'assign_null_coalescing_to_coalesce_equal' => false, /* Использовать нулевой оператор присваивания ??= там, где это возможно.*/
        'concat_space' => ['spacing' => 'one'],              /* Конкатенация должна располагаться в соответствии с конфигурацией */
        'logical_operators' => true,                         /* Использовать && и || вместо and и or */
        'no_useless_concat_operator' => true,                /* Не должно быть бесполезных операций concat */
        /* PHP Tag https://cs.symfony.com/doc/rules/index.html#php-tag */
        'echo_tag_syntax' => ['format' => 'short'],          /* Формат языковой конструкции */
        /* PHPDoc https://cs.symfony.com/doc/rules/index.html#phpdoc */
        'no_superfluous_phpdoc_tags' => [                    /* Удаляет бесполезные теги @param/@var/@return */
            'allow_mixed' => true,                           /* Разрешен ли тип mixed без описания */
            'remove_inheritdoc' => true,                     /* Удаление @inheritDoc тегов */
        ],
        'phpdoc_align' => [                                  /* Все phpdoc-тэги должны быть либо выровнены по левому краю, либо по вертикали */
            'tags' => ['method', 'param', 'property', 'property-read', 'property-write', 'return', 'throws', 'type', 'var'],
            'align' => 'left',
        ],
        'phpdoc_order' => [                                  /* Аннотации в PHPDoc должны располагаться в определенной последовательности */
            'order' => ['param', 'return', 'throws'],
        ],
        'phpdoc_to_comment' => [                             /* Однострочный phpDoc разрешён на элементах */
            'ignored_tags' => ['var'],
        ],
        /* Semicolon https://cs.symfony.com/doc/rules/index.html#semicolon */
        'multiline_whitespace_before_semicolons' => [
            'strategy' => 'no_multi_line',                   /* Запрет многострочных пробелов перед закрывающей точкой с запятой */
        ],
        'semicolon_after_instruction' => false,              /* Инструкции должны заканчиваться точкой с запятой */
        /* Strict https://cs.symfony.com/doc/rules/index.html#strict */
        'strict_comparison' => true,                        /* Сравнения должны быть строгими */
        /* Whitespace https://cs.symfony.com/doc/rules/index.html#whitespace */
        'blank_line_before_statement' => [                   /* Перечисленным операторам должен предшествовать пустой перевод строки */
            'statements' => ['break', 'case', 'continue', 'declare', 'default', 'exit', 'goto', 'return', 'switch', 'throw', 'try'],
        ],
        'blank_line_between_import_groups' => true,          /* Вставка пустых строк между use-группами */
    ])
    ->setFinder($finder);
