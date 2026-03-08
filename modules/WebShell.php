<?php 
namespace Modules;

class WebShell{
	private static $suspiciousFunctions = [
        	'eval',
        	'assert',
	        'system',
	        'shell_exec',
	        'exec',
	        'passthru',
	        'popen',
	        'proc_open',
	        'proc_get_status',
	        'pcntl_exec',
	        'create_function',
	        'include_once',
	        'require_once',
	        'unserialize',
	        'call_user_func',
	        'call_user_func_array',
    	];

	private static $suspiciousPatterns = [
	        '/eval\s*\(\s*base64_decode/i',
	        '/eval\s*\(\s*gzinflate/i',
	        '/gzinflate\s*\(\s*base64_decode/i',
	        '/assert\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)/i',
	        '/system\s*\(\s*\$_(GET|POST|REQUEST)/i',
        	'/shell_exec\s*\(\s*\$_(GET|POST|REQUEST)/i',
	        '/exec\s*\(\s*\$_(GET|POST|REQUEST)/i',
	        '/passthru\s*\(\s*\$_(GET|POST|REQUEST)/i',
	        '/\$_\s*\[\s*["\']cmd["\']\s*\]\s*\|/i',
	        '/<\?php\s*@eval\(\$_/i',
	        '/base64_encode\s*\(\s*gzcompress/i',
	        '/serialize\s*\(\s*\$_/i',
   	];

	public static function detect($filePath){
		if (!file_exists($filePath)) {
                	throw new \Exception("File not found: {$filePath}");
        	}

        	$content = file_get_contents($filePath);
        	$results = [
            		'found_functions' => [],
            		'suspicious_patterns' => [],
            		'risk_score' => 0,
            		'is_webshell' => false,
		];
		
		// conferir funcoes 
        foreach (self::$suspiciousFunctions as $func) {
            if (preg_match('/\b' . preg_quote($func) . '\s*\(/i', $content)) {
                $results['found_functions'][] = $func;
                $results['risk_score'] += 20;
            }
        }
		// conferir pattern 
        foreach (self::$suspiciousPatterns as $pattern) {
            if (preg_match($pattern, $content)) {
                preg_match($pattern, $content, $matches);
                $results['suspicious_patterns'][] = $matches[0] ?? $pattern;
                $results['risk_score'] += 25;
            }
        }
		// check backdoor 
		if (preg_match('/<\?php\s*@/i', $content)){
			$results['suspicious_patterns'][] = '@eval() usage (error suppression)';
                	$results['risk_score'] += 15;
		}

		// post/get
        	if (preg_match('/\$_(POST|GET|REQUEST).*?(eval|system|exec|shell_exec|passthru)/i', $content)) {
                	$results['suspicious_patterns'][] = 'Direct execution of user input';
            		$results['risk_score'] += 30;
        	}
		
		if (count($results['found_functions']) >= 2 || count($results['suspicious_patterns']) >= 2) {
                	$results['is_webshell'] = true;
        	}

        	return $results;
	}

	public static function format($results){
		$output = "Web Shell Detection\n";

		if (!empty($results['found_functions'])){
			$output .= "	Suspicius Functions Found:\n";
			foreach ($results['found_functions'] as $func){
				$output .= sprintf("	- %s", $func);
			}
		}

		
	        if (!empty($results['suspicious_patterns'])) {
            		$output .= "  Suspicious Patterns:\n";
            		foreach ($results['suspicious_patterns'] as $pattern) {
                		$output .= sprintf("    - %s\n", $pattern);
           		}	
		}

		if (empty($results['found_functions']) && empty($results['suspicious_patterns'])) {
            		$output .= "  No suspicious indicators detected\n";
        	}

        	return $output;

	}

    	public static function getSummary($results){
        	if ($results['is_webshell']) {
            		return 'LIKELY WEB SHELL';
        	} elseif (count($results['found_functions']) > 0 || count($results['suspicious_patterns']) > 0) {
            		return 'SUSPICIOUS';
        	}
        	return 'CLEAN';
    	}

}
