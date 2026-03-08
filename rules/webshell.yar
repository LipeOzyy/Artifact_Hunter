rule PHP_Webshell_Generic
{
    meta:
        description = "Generic PHP webshell indicators"
        author = "Security Research"
        severity = "medium"

    strings:
        $eval = "eval" ascii wide nocase
        $base64 = "base64_decode" ascii wide nocase
        $system = "system" ascii wide nocase
        $shell = "shell_exec" ascii wide nocase
        $exec = "exec" ascii wide nocase
        $passthru = "passthru" ascii wide nocase
        $popen = "popen" ascii wide nocase
        $proc = "proc_open" ascii wide nocase

        $post = "$_POST"
        $get = "$_GET"
        $request = "$_REQUEST"
        $cookie = "$_COOKIE"

    condition:
        (2 of ($eval,$system,$shell,$exec,$passthru,$popen,$proc,$base64))
        and any of ($post,$get,$request,$cookie)
}

rule PHP_Webshell_Obfuscated
{
    meta:
        description = "Obfuscated PHP webshell patterns"
        severity = "high"

    strings:
        $b64eval = /eval\s*\(\s*base64_decode\s*\(/ nocase
        $gzinf = /gzinflate\s*\(\s*base64_decode/ nocase
        $multi_layer = /(eval|assert)\s*\(\s*(gzinflate|base64_decode|str_rot13)/ nocase
        $chr_build = /chr\s*\(\s*\d+\s*\)\s*\./ nocase
        $hex = /hex2bin\s*\(/ nocase

    condition:
        any of them
}

rule PHP_Shell_Command_Execution
{
    meta:
        description = "PHP command execution from user input"
        severity = "high"

    strings:
        $system_exec = /system\s*\(\s*\$_\w+/ nocase
        $shell_exec = /shell_exec\s*\(\s*\$_\w+/ nocase
        $exec_call = /exec\s*\(\s*\$_\w+/ nocase
        $passthru_call = /passthru\s*\(\s*\$_\w+/ nocase
        $backtick = /`\s*\$_\w+/ nocase

    condition:
        any of them
}

rule PHP_Shell_Command_Execution
{
    meta:
        description = "PHP command execution from user input"
        severity = "high"

    strings:
        $system_exec = /system\s*\(\s*\$_\w+/ nocase
        $shell_exec = /shell_exec\s*\(\s*\$_\w+/ nocase
        $exec_call = /exec\s*\(\s*\$_\w+/ nocase
        $passthru_call = /passthru\s*\(\s*\$_\w+/ nocase
        $backtick = /`\s*\$_\w+/ nocase

    condition:
        any of them
}

rule PHP_Command_Injection
{
    meta:
        description = "PHP command injection indicators"
        severity = "high"

    strings:
        $cmd_param = /\$_(GET|POST|REQUEST)\[['"]cmd['"]\]/ nocase
        $pipe_exec = /\|\s*\$_(GET|POST|REQUEST)/ nocase
        $popen = /popen\s*\(/ nocase
        $proc = /proc_open\s*\(/ nocase

    condition:
        any of them
}

rule PHP_Backdoor_Indicators
{
    meta:
        description = "Suspicious PHP backdoor functions"
        severity = "medium"

    strings:
        $create_func = "create_function" nocase
        $call_user = "call_user_func" nocase
        $call_user_array = "call_user_func_array" nocase
        $preg_eval = /preg_replace\s*\(.*\/e/ nocase
        $assert_exec = /assert\s*\(\s*\$_/ nocase
        $var_var = /\$\$\w+/ nocase

    condition:
        any of them
}

rule PHP_Webshell_WSO
{
    meta:
        description = "WSO PHP webshell"
        severity = "high"

    strings:
        $wso1 = "WSO" nocase
        $wso2 = "Web Shell Operators" nocase
        $wso3 = "FilesMan" nocase
        $wso_func = /(gzinflate|assert|base64_decode|\$_POST)/ nocase

    condition:
        $wso1 or ($wso2 and $wso_func) or ($wso3 and $wso_func)
}


rule PHP_Webshell_b374k
{
    meta:
        description = "b374k PHP webshell"
        severity = "high"

    strings:
        $b374k = "b374k" nocase
        $shell_ops = /(eval|assert).*(base64_decode|gzinflate)/ nocase

    condition:
        $b374k or $shell_ops
}