<?php

namespace Modules;

class hash {
	public static function analyze($filePath){
		if (!file_exists($filePath)){
			throw new \Exception("File not found: {$filePath}");
		}
		$fileData = file_get_contents($filePath);

		return [
			'md5' => hash('md5', $fileData),
			'sha1' => hash('sha1', $fileData),
			'sha256' => hash('sha256', $fileData),
		];	
	}

	public static function format($hashes) {
		$output = "Hashes\n";
		$output .= sprintf("	MD5:	%s\n", substr($hashes['md5'], 0, 8) . '...');
		$output .= sprintf("  SHA1:   %s\n", substr($hashes['sha1'], 0, 8) . '...');
        	$output .= sprintf("  SHA256: %s\n", substr($hashes['sha256'], 0, 8) . '...');
        	return $output;
	}

	public static function formatFull($hashes)
    	{
        	$output = "Hashes\n";
        	$output .= sprintf("  MD5:    %s\n", $hashes['md5']);
        	$output .= sprintf("  SHA1:   %s\n", $hashes['sha1']);
        	$output .= sprintf("  SHA256: %s\n", $hashes['sha256']);
        	return $output;
    	}
}
