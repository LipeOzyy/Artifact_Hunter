<?php

namespace Modules;

class RiskScore
{
    public static function calculate($analysis)
    {
        $score = 0;
        $breakdown = [];

        $breakdown['hashes'] = 0;

        if (isset($analysis['entropy']) && $analysis['entropy'] > 7) {
            $entropyScore = Entropy::getRiskScore($analysis['entropy']);
            $score += $entropyScore;
            $breakdown['entropy'] = $entropyScore;
        } else {
            $breakdown['entropy'] = 0;
        }

        $breakdown['strings'] = 0; 
        if (isset($analysis['webshell'])) {
            $webshellScore = self::getWebShellScore($analysis['webshell']);
            $score += $webshellScore;
            $breakdown['webshell'] = $webshellScore;
        } else {
            $breakdown['webshell'] = 0;
        }

        if (isset($analysis['obfuscation'])) {
            $obfuscationScore = self::getObfuscationScore($analysis['obfuscation']);
            $score += $obfuscationScore;
            $breakdown['obfuscation'] = $obfuscationScore;
        } else {
            $breakdown['obfuscation'] = 0;
        }

        if (isset($analysis['yara']) && $analysis['yara']['success']) {
            $yaraScore = Yara::getRiskScore($analysis['yara']['matches'] ?? []);
            $score += $yaraScore;
            $breakdown['yara'] = $yaraScore;
        } else {
            $breakdown['yara'] = 0;
        }

        $score = min($score, 100);

        return [
            'total' => $score,
            'breakdown' => $breakdown,
            'classification' => self::classify($score),
        ];
    }

    private static function getWebShellScore($webshellResult)
    {
        $score = 0;

        if (!empty($webshellResult['found_functions'])) {
            $score += min(count($webshellResult['found_functions']) * 15, 35);
        }

        if (!empty($webshellResult['suspicious_patterns'])) {
            $score += min(count($webshellResult['suspicious_patterns']) * 10, 25);
        }

        if ($webshellResult['is_webshell']) {
            $score += 20;
        }

        return min($score, 60);
    }


    private static function getObfuscationScore($obfuscationResult)
    {
        $score = 0;

        if (!empty($obfuscationResult['found_functions'])) {
            $score += min(count($obfuscationResult['found_functions']) * 8, 20);
        }

        if (!empty($obfuscationResult['found_patterns'])) {
            $score += min(count($obfuscationResult['found_patterns']) * 12, 25);
        }

        if ($obfuscationResult['nested_obfuscation']) {
            $score += 15;
        }

        return min($score, 50);
    }

    public static function classify($score)
    {
        if ($score >= 80) {
            return 'HIGHLY SUSPICIOUS';
        } elseif ($score >= 60) {
            return 'SUSPICIOUS';
        } elseif ($score >= 40) {
            return 'POTENTIALLY MALICIOUS';
        } elseif ($score >= 20) {
            return 'CAUTION ADVISED';
        }
        return 'CLEAN';
    }

    public static function getColor($score)
    {
        if ($score >= 80) {
            return "\033[91m"; 
        } elseif ($score >= 60) {
            return "\033[95m"; 
        } elseif ($score >= 40) {
            return "\033[93m";
        } elseif ($score >= 20) {
            return "\033[94m"; 
        }
        return "\033[92m"; 
    }

    public static function resetColor()
    {
        return "\033[0m";
    }

    public static function format($riskData, $color = true)
    {
        $score = $riskData['total'];
        $classification = $riskData['classification'];

        $colorStart = $color ? self::getColor($score) : '';
        $colorReset = $color ? self::resetColor() : '';

        $output = "Risk Score\n";
        $output .= sprintf("  %s%d / 100%s\n", $colorStart, $score, $colorReset);
        $output .= sprintf("  Classification: %s%s%s\n", $colorStart, $classification, $colorReset);

        return $output;
    }

    public static function formatDetailed($riskData)
    {
        $output = "Risk Score Breakdown\n";
        $output .= sprintf("  Total Score: %d / 100\n", $riskData['total']);
        $output .= sprintf("  Classification: %s\n\n", $riskData['classification']);

        $breakdown = $riskData['breakdown'];
        $output .= "  Component Scores:\n";
        foreach ($breakdown as $component => $points) {
            $output .= sprintf("    - %-15s: %2d pts\n", ucfirst($component), $points);
        }

        return $output;
    }
}
