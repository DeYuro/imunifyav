<?php

if ($argc < 3) {
    die("Usage: $argv[0] </path/to/ai-bolit-hoster.db> </path/to/result-file-name.db>\n");
}

function loadSignatures($path)
{
    $content = file_get_contents($path);
    $avdb = explode("\n", gzinflate(base64_decode(str_rot13(strrev(trim($content))))));

    // get meta information
    $avdb_meta_info = json_decode(base64_decode($avdb[16]), true);

    $build_date     = $avdb_meta_info ? $avdb_meta_info['build-date']   : 'n/a';
    $version        = $avdb_meta_info ? $avdb_meta_info['version']      : 'n/a';
    $release_type   = $avdb_meta_info ? $avdb_meta_info['release-type'] : 'n/a';

    $result = [];
    $result['_FlexDBShe']   = explode("\n", base64_decode($avdb[2]));
    $result['_JSVirSig']    = explode("\n", base64_decode($avdb[8]));
    $result['_SusDB']       = explode("\n", base64_decode($avdb[10]));
    $result['_Mnemo']       = @array_flip(@array_combine(explode("\n", base64_decode($avdb[14])), explode("\n", base64_decode($avdb[15]))));
    $result['version']      = $version;

    echo "build_date:   $build_date\n";
    echo "version:      $version\n";
    echo "release_type: $release_type\n";
    echo "\n\n";

    return $result;
}


function prepareRegexps($db, $mnemo)
{
    foreach($db as $j => $regexp) {
        $id = @$mnemo[hash('crc32b', $regexp)];
        preg_match('~\w+-\w+-(\d+)-~smi', $id, $m);
        $id = (int)$m[1];
        $reg_exp = simplyRegexp($regexp);
        $reg[$id] = $reg_exp;
    }
    return $reg;
}

function simplyRegexp($regexp)
{
    $reg_exp = preg_replace_callback('~\{(\d+),(\d+)?\}~mis', function($m) {
        if ((isset($m[1]) && $m[1] === '0') || (!isset($m[1]))) {
            return '*';
        }
        return '+';
    }, $regexp);

    $reg_exp = preg_replace_callback('~\{(\d+)\}~ms', function($m) {
        return '+';
    }, $reg_exp);

    return $reg_exp;
}

function compile_hsdb($reg)
{
    $not_supported = [];
    $not_supported_prefilter = [];
    $flags = HS_FLAG_DOTALL | HS_FLAG_MULTILINE | HS_FLAG_CASELESS | HS_FLAG_SINGLEMATCH;
    $keys = array_keys($reg);
    $patterns = array_values($reg);
    $flags = array_fill(0, count($reg), $flags);
    for ($i = 0, $iMax = count($reg); $i < $iMax; $i++) {
        $db = null;
        if (hs_compile($patterns[$i], $flags[$i], HS_MODE_BLOCK, $db) === HS_COMPILER_ERROR) {
            $not_supported[$keys[$i]] = $patterns[$i];
            $flags[$i] |= HS_FLAG_PREFILTER;
            if (hs_compile($patterns[$i], $flags[$i], HS_MODE_BLOCK, $db) === HS_COMPILER_ERROR) {
                $not_supported_prefilter[$keys[$i]] = $patterns[$i];
                unset($keys[$i]);
                unset($patterns[$i]);
                unset($flags[$i]);
            }
        }
    }
    $flags = array_values($flags);
    $keys = array_values($keys);
    $patterns = array_values($patterns);
    $err = hs_compile_multi($patterns, $flags, $keys, count($patterns), HS_MODE_BLOCK, $db, [HS_CPU_FEATURES_SSE3, HS_TUNE_FAMILY_GENERIC]);
    if ($err === HS_SUCCESS) {
        return $db;
    }

    exitWithError('Warning: [HSDB_maker] Can\'t compile database. Error: ' . $err, -1);
    return false;
}

function exitWithError($message, $code)
{
    if ($message !== '') {
        fwrite(STDERR, $message . PHP_EOL);
    }
    exit($code);
}

function writeToFile($folder, $data)
{
    $fname = tempnam($folder, 'hstmp_');
    if (file_put_contents($fname, $data) === false) {
        exitWithError('Warning: [HSDB_maker] Error: Can\'t write data to file ' . $fname, -1);
    }
    return $fname;
}


function serialize_db($folder, $source)
{
    $fname = '';
    $ser = '';
    $db = compile_hsdb($source);
    if ($db && ($err = hs_database_serialize($db, $ser)) === HS_SUCCESS) {
        $fname = writeToFile($folder, $ser);
    } else {
        exitWithError('Warning: [HSDB_maker] Error: Can\'t serialize malware database. Error: ' . $err, -1);
    }
    return $fname;
}

function clean($folder)
{
    foreach(glob($folder . '/hstmp_*') as $tmp_file) {
        @unlink($tmp_file);
    }
}

function create_archive($name, $files)
{
    $zip = new ZipArchive;
    if ($zip->open($name, ZipArchive::CREATE) === true) {
        foreach($files as $file => $local) {
            if (!file_exists($file)) {
                $zip->close();
                @unlink($name);
                exitWithError('Warning: [HSDB_maker] Not found required file ' . $file . ' => ' . $local, -1);
            }
            $zip->addFile($file, $local);
            $zip->setCompressionName($local, ZipArchive::CM_STORE);
        }
        $zip->close();
    } else {
        exitWithError('Warning: [HSDB_maker] Error creating archive', -1);
    }
}

$folder = dirname($argv[2]);

if(file_exists($argv[2])) {
    @unlink($argv[2]);
}

clean($folder);

$signs      =  loadSignatures($argv[1]);
$reg_php    =  prepareRegexps($signs['_FlexDBShe'], $signs['_Mnemo']);
$reg_js     =  prepareRegexps($signs['_JSVirSig'],  $signs['_Mnemo']);
$reg_sus    =  prepareRegexps($signs['_SusDB'],     $signs['_Mnemo']);

$php_fname  = serialize_db($folder, $reg_php);
$js_fname   = serialize_db($folder, $reg_js);
$sus_fname  = serialize_db($folder, $reg_sus);
$ver        = writeToFile($folder,  $signs['version']);

$files = [
    $php_fname  => 'hs_php.db',
    $js_fname   => 'hs_js.db',
    $sus_fname  => 'hs_sus.db',
    $ver        => 'version.txt'
];

create_archive($argv[2], $files);

clean($folder);
exitWithError('', 0);


