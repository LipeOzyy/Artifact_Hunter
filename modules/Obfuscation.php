<?php

namespace Modules;

class Obfuscation
{
    private static $obfuscationFunctions = [
        'base64_decode',
        'base64_encode',
        'gzinflate',
        'gzdeflate',
        'gzcompress',
        'gzuncompress',
        'str_rot13',
        'strrev',
        'chr',
        'ord',
        'hex2bin',
        'bin2hex',
        'md5',
        'sha1',
    ];

    private static $obfuscationPatterns = [
        '/eval\s*\(\s*base64_decode\s*\(/i' => 'eval(base64_decode()) pattern',
        '/gzinflate\s*\(\s*base64_decode\s*\(/i' => 'gzinflate(base64_decode()) pattern',
        '/base64_encode\s*\(\s*gzcompress/i' => 'base64_encode(gzcompress()) pattern',
        '/unserialize\s*\(\s*\$_/i' => 'unserialize() on user input',
        '/preg_replace\s*\(\s*["\']\/[^"\']*\/e/i' => 'preg_replace() /e modifier (deprecated)',
        '/create_function\s*\(/i' => 'create_function() - dynamic function creation',
        '/\$[a-zA-Z_]\w*\s*=\s*base64_decode/i' => 'Variable assignment from base64_decode',
        '/call_user_func\s*\(\s*base64_decode/i' => 'call_user_func(base64_decode()) pattern',
    ];

    public static function detect($filePath)
    {
        if (!file_exists($filePath)) {
            throw new \Exception("File not found: {$filePath}");
        }

        $content = file_get_contents($filePath);
        $results = [
            'found_functions' => [],
            'found_patterns' => [],
            'base64_strings' => [],
            'hex_strings' => [],
            'nested_obfuscation' => false,
            'risk_score' => 0,
            'obfuscation_level' => 0,
	];
        foreach (self::$obfuscationFunctions as $func) {
            if (preg_match('/\b' . preg_quote($func) . '\s*\(/i', $content)) {
                $results['found_functions'][] = $func;
                $results['risk_score'] += 10;
                $results['obfuscation_level']++;
            }
        }

        foreach (self::$obfuscationPatterns as $pattern => $description) {
            if (preg_match($pattern, $content)) {
                $results['found_patterns'][] = $description;
                $results['risk_score'] += 15;
                $results['obfuscation_level']++;
            }
        }

        $extractedStrings = \Modules\Strings::extract($filePath);
        $results['base64_strings'] = \Modules\Strings::findBase64Strings($extractedStrings);
        $results['hex_strings'] = \Modules\Strings::findHexStrings($extractedStrings);

        if (count($results['base64_strings']) > 5) {
            $results['risk_score'] += 10;
        }

        if (count($results['hex_strings']) > 5) {
            $results['risk_score'] += 8;
        }

        if (preg_match('/eval\s*\(\s*base64_decode\s*\(\s*gzinflate/i', $content)) {
            $results['nested_obfuscation'] = true;
            $results['risk_score'] += 20;
        }

        // Check for variable variables or function name manipulation
        if (preg_match('/\$\$\w+|call_user_func|variable_functions/i', $content)) {
            $results['nested_obfuscation'] = true;
            $results['risk_score'] += 15;
        }

        return $results;
    }

    public static function format($results)
    {
        $output = "Obfuscation Detection\n";
        $output .= sprintf("  Level: %d techniques found\n", $results['obfuscation_level']);

        if (!empty($results['found_functions'])) {
            $output .= "  Encoding Functions:\n";
            foreach ($results['found_functions'] as $func) {
                $output .= sprintf("    - %s\n", $func);
            }
        }

        if (!empty($results['found_patterns'])) {
            $output .= "  Obfuscation Patterns:\n";
            foreach ($results['found_patterns'] as $pattern) {
                $output .= sprintf("    - %s\n", $pattern);
            }
        }

        if ($results['nested_obfuscation']) {
            $output .= "  WARNING: Multi-layer obfuscation detected\n";
        }

        if (count($results['base64_strings']) > 0) {
            $output .= sprintf("  Base64 Strings: %d found (likely encoded payload)\n", count($results['base64_strings']));
        }

        if (count($results['hex_strings']) > 0) {
            $output .= sprintf("  Hex Strings: %d found\n", count($results['hex_strings']));
        }

        if ($results['obfuscation_level'] === 0) {
            $output .= "  No obfuscation techniques detected\n";
        }

        return $output;
    }

    public static function attemptDecoding($results)
    {
        $decoded = [];
        $limit = min(5, count($results['base64_strings']));

        for ($i = 0; $i < $limit; $i++) {
            $str = $results['base64_strings'][$i];
            try {
                $decoded_str = @base64_decode($str, true);
                if ($decoded_str !== false && strlen($decoded_str) > 0) {
                    $decoded[] = [
                        'encoded' => substr($str, 0, 50) . '...',
                        'decoded' => substr($decoded_str, 0, 70),
                        'is_text' => mb_check_encoding($decoded_str, 'UTF-8'),
                    ];
                }
            } catch (\Exception $e) {
            }
        }

        return $decoded;
    }

}
