<?php

namespace Modules;

class Entropy
{ 
	public static function calculate($filePath){
		if (!file_exists($filePath)){
			throw new \Exeption("File not found: {$filePath}");
		}

		$data = file_get_contents($filePath);

		if (strlen($data) == 0){
			return 0.0;
		}

		$frequencies = array_count_values(str_split($data));
		$len = strlen($data);
		$entropy = 0;

		foreach ($frequencies as $frequency){
			$p = $frequency / $len;
			if ($p > 0) {
				$entropy -= $p * log($p, 2);
			}
		}

		return round($entropy, 2);
	}

	public static function classify($entropy){
		if ($entropy <= 3){
			return 'Plain Text';
		} elseif ($entropy <= 6){
			return 'Normal Code';
		} elseif ($entropy <=8){
			return 'High (Entropy/Packed)';
		}
		return 'Critical (likely packed/encrypted)';
	}

	public static function getRiskScore($entropy){
		if($entropy > 7.5){
			return 15;
		} elseif ($entropy > 7){
			return 10;
		} elseif ($entropy > 6){
			return 5;
		}
		return 0;
	}
	public static function format($entropy){
		$classification = self::classify($entropy);
		$output = "Entropy\n";
		$output .= sprintf("	Value: %.2f\n", $entropy);
		$output .= sprintf("	Status: %s\n", $classification);
		return $output;
	}
}

