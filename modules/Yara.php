<?php

namespace Modules;

class Yara{
	public static function isAvailable()
	{
    	$commands = [
        	'command -v yara',
        	'which yara',
        	'where yara'
   		];

    	foreach ($commands as $cmd) {
        	$output = @shell_exec($cmd . ' 2>&1');
        	if (!empty($output)) {
            	return true;
        	}
    	}

    	$version = @shell_exec('yara --version 2>&1');
    	if (!empty($version)) {
        	return true;
    	}

    	$paths = [
        	'/usr/bin/yara',
        	'/usr/local/bin/yara',
        	'/opt/yara/yara',
        	'/bin/yara'
    	];

    	foreach ($paths as $path) {
        	if (file_exists($path) && is_executable($path)) {
            	return true;
        	}
    	}

    return false;
	}

    public static function scan($filePath, $rulesPath)
    {
        if (!file_exists($filePath)) {
            throw new \Exception("File not found: {$filePath}");
        }

        if (!file_exists($rulesPath)) {
            return [
                'success' => false,
                'error' => "YARA rules file not found: {$rulesPath}",
                'matches' => [],
            ];
        }

        if (!self::isAvailable()) {
            return [
                'success' => false,
                'error' => 'YARA is not installed or not available in PATH',
                'matches' => [],
            ];
        }

        $filePath = escapeshellarg($filePath);
        $rulesPath = escapeshellarg($rulesPath);

        $command = "yara {$rulesPath} {$filePath} 2>&1";
        $output = shell_exec($command);

        if ($output === null || trim($output) === '') {
            return [
                'success' => true,
                'error' => null,
                'matches' => [],
                'note' => 'No YARA rules matched',
            ];
        }

        return [
            'success' => true,
            'error' => null,
            'matches' => self::parseYaraOutput($output),
            'raw_output' => $output,
        ];
    }


	private static function parseYaraOutput($output)
    {
        $matches = [];
        $lines = explode("\n", trim($output));

        foreach ($lines as $line) {
            if (trim($line) === '') {
                continue;
            }

            
            preg_match('/^(\S+)(.*?)(\S+)$/', $line, $parts);

            if (isset($parts[1])) {
                $matches[] = [
                    'rule' => $parts[1],
                    'tags' => isset($parts[2]) ? trim($parts[2]) : '',
                    'file' => isset($parts[3]) ? $parts[3] : '',
                ];
            }
        }

        return $matches;
    }

	    public static function scanMultiple($filePath, $rulesDir)
    {
        if (!is_dir($rulesDir)) {
            return [
                'success' => false,
                'error' => "Rules directory not found: {$rulesDir}",
                'results' => [],
            ];
        }

        $results = [
            'success' => true,
            'error' => null,
            'results' => [],
            'total_matches' => 0,
        ];

        $ruleFiles = glob($rulesDir . '/*.yar');

        if (empty($ruleFiles)) {
            return [
                'success' => false,
                'error' => 'No YARA rule files found in: ' . $rulesDir,
                'results' => [],
            ];
        }

        foreach ($ruleFiles as $ruleFile) {
            $scan = self::scan($filePath, $ruleFile);
            $results['results'][basename($ruleFile)] = $scan;
            
            if ($scan['success'] && !empty($scan['matches'])) {
                $results['total_matches'] += count($scan['matches']);
            }
        }

        return $results;
    }

	public static function getRiskScore($matches)
    {
        if (empty($matches)) {
            return 0;
        }

        $score = 40; 

        $matchCount = count($matches);
        if ($matchCount > 1) {
            $score += min($matchCount * 5, 30);
        }

        return min($score, 50); 
    }

	public static function format($results)
    {
        $output = "YARA Scan Results\n";

        if (!$results['success']) {
            $output .= sprintf("  Error: %s\n", $results['error']);
            return $output;
        }

        if (empty($results['matches'])) {
            $output .= "  No matches found\n";
            return $output;
        }

        $output .= sprintf("  Matches: %d\n", count($results['matches']));
        foreach ($results['matches'] as $match) {
            $output .= sprintf("  - %s\n", $match['rule']);
        }

        return $output;
    }

	    public static function formatMultiple($results)
    {
        $output = "YARA Scan Results\n";

        if (!$results['success']) {
            $output .= sprintf("  Error: %s\n", $results['error']);
            return $output;
        }

        $output .= sprintf("  Total Matches: %d\n", $results['total_matches']);

        foreach ($results['results'] as $ruleName => $result) {
            if ($result['success'] && !empty($result['matches'])) {
                $output .= sprintf("\n  File: %s (%d matches)\n", $ruleName, count($result['matches']));
                foreach ($result['matches'] as $match) {
                    $output .= sprintf("    - %s\n", $match['rule']);
                }
            }
        }

        if ($results['total_matches'] === 0) {
            $output .= "  No YARA rules matched\n";
        }

        return $output;
    }

}
