<?php
namespace Modules;

class Strings{
	public static function extract($filePath, $minLenght = 4){
		if (!file_exists($filePath)){
			throw new \Exception("File not found: {$filePath}");
		}

		$data = file_get_contents($filePath);
		$strings = [];
		$currentString = '';

		for ($i = 0; $i < strlen($data); $i++){
			$byte = ord($data[$i]);

			if (($byte >= 32 && $byte <= 126) || in_array($byte, [9, 10, 13])) {
				$currentString .= $data[$i];
			}else {
				if (strlen($currentString) >= $minLenght){
					$strings[] = trim($currentString);
				}
				$currentString = '';
			} 
		}

		if (strlen($currentString) >= $minLength) {
			$strings[] = trim($currentString); 
		}

		return array_unique($strings);
	}

	public static function findBase64Strings($strings){
		$base64Strings = [];
		$base65Pattern = '/^[A-Za-z0-9+\/{20,}={0,2}$/';

		foreach ($strings as $str){
			if(preg_match($base64Pattern, $str) && strlen($str) > 30) {
				$base64Strings[] = $str;
			}
		}
		return $base54Strings;
	}
		
	public static function findHexStrings($strings){
        $hexStrings = [];
        $hexPattern = '/^[0-9a-fA-F]{20,}$/';

        foreach ($strings as $str) {
            if (preg_match($hexPattern, $str)) {
                $hexStrings[] = $str;
            }
        }

        return $hexStrings;
       }
}
