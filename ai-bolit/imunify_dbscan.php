<?php


$scan_signatures    = null;
$clean_signatures   = null;
$start_time         = time();
$print              = true;
$report             = null;
$lic                = null;
$detached           = null;

if (!isset($argv)) {
    $argv = $_SERVER['argv'];
}

$config = new MDSConfig();
$cli = new MDSCliParse($argv, $config);

Factory::configure($config->get(MDSConfig::PARAM_FACTORY_CONFIG));

if (!$config->get(MDSConfig::PARAM_DO_NOT_SEND_STATS)) {
    $lic = Factory::instance()->create(ImLicense::class, ['/var/imunify360/license.json', '/usr/share/imunify360/cln-pub.key']);
    if (!$lic->isValid()) {
        $config->set(MDSConfig::PARAM_DO_NOT_SEND_STATS, true);
    }
}

if ($config->get(MDSConfig::PARAM_SEARCH_CONFIGS) !== '') {
    $filter = new MDSCMSConfigFilter();
    $finder = new Finder($filter, $config->get(MDSConfig::PARAM_SEARCH_DEPTH));
    $creds = new MDSDBCredsFromConfig($finder, $config->get(MDSConfig::PARAM_SEARCH_CONFIGS));
    $tty = true;
    if (function_exists('stream_isatty') && !@stream_isatty(STDOUT)) {
        $tty = false;
    }
    if ($tty) {
        $creds->printCreds();
    } else {
        $creds->printForXArgs();
    }
    exit(0);
}

echo 'MDS - an Intelligent Malware Database Scanner for Websites.' . PHP_EOL;

$log_levels = explode(',', $config->get(MDSConfig::PARAM_LOG_LEVEL));
$log = new Logger($config->get(MDSConfig::PARAM_LOG_FILE), $log_levels);
$log->info('MDS: start');

$state = null;
$state_filepath = $config->get(MDSConfig::PARAM_STATE_FILEPATH);
if ($state_filepath) {
    $state = new MDSState($state_filepath);
    $state->setWorking();
}

set_exception_handler(function ($ex) use ($report, $print) {
    if ($ex instanceof MDSException) {
        if (isset($report) && $report->getError() === null) {
            $report->addError($ex->getErrCode(), $ex->getErrMsg());
            $report->save();
        }
        if ($print) {
            print('Error: ' . $ex->getErrMsg() . PHP_EOL);
        }
        exit($ex->getErrCode());
    } else {
        echo $ex->getMessage() . PHP_EOL;
        exit(-1);
    }
});

$progress = new MDSProgress($config->get(MDSConfig::PARAM_PROGRESS));
$progress->setPrint(
    function ($text) {
        $text = str_pad($text, 160, ' ', STR_PAD_RIGHT);
        echo str_repeat(chr(8), 160) . $text;
    }
);

$tables_config = new MDSTablesConfig(__DIR__ . '/mds_tables.config.json');

if (is_string($config->get(MDSConfig::PARAM_AVD_APP))) {
    $config->set(MDSConfig::PARAM_AVD_APP, [$config->get(MDSConfig::PARAM_AVD_APP)]);
} else {
    $config->set(MDSConfig::PARAM_AVD_APP, $tables_config->getSupportedApplications());
}

if (is_string($config->get(MDSConfig::PARAM_AVD_PATH)) && substr($config->get(MDSConfig::PARAM_AVD_PATH), -1) == DIRECTORY_SEPARATOR) {
    $config->set(MDSConfig::PARAM_AVD_PATH, substr($config->get(MDSConfig::PARAM_AVD_PATH), 0, -1));
}

if ($config->get(MDSConfig::PARAM_AVD_PATHS) && file_exists($config->get(MDSConfig::PARAM_AVD_PATHS))) {
    $paths = file($config->get(MDSConfig::PARAM_AVD_PATHS), FILE_SKIP_EMPTY_LINES | FILE_IGNORE_NEW_LINES);
    foreach ($paths as &$path) {
        $path = base64_decode($path);
        if (substr($path, -1) == DIRECTORY_SEPARATOR) {
            $path = substr($path, 0, -1);
        }
    }
    $config->set(MDSConfig::PARAM_AVD_PATHS, $paths);
}

$creds = getCreds($config, $argc, $argv, $progress);

$prescan ='';
if (file_exists(__DIR__ . '/mds_prescan.config.bin')) {
    $prescan = trim(file_get_contents(__DIR__ . '/mds_prescan.config.bin'));
} else {
    throw new MDSException(MDSErrors::MDS_PRESCAN_CONFIG_ERROR, __DIR__ . '/mds_prescan.config.bin');
}

list($scan_signatures, $clean_db) = loadMalwareSigns($config);

if ($config->get(MDSConfig::PARAM_DETACHED)) {
    $detached = Factory::instance()->create(MDSDetachedMode::class, [$config->get(MDSConfig::PARAM_DETACHED)]);
    $config->set(MDSConfig::PARAM_DO_NOT_SEND_STATS, true);
}

$filter = new MDSAVDPathFilter($config->get(MDSConfig::PARAM_IGNORELIST));

$scanned = 0;

foreach($creds as $i => $cred) {
    if (($cred === false) || (isset($cred['db_path']) && $filter && MDSConfig::PARAM_AVD_PATH && !$filter->needToScan($cred['db_path']))) {
        continue;
    }
    $config->set(MDSConfig::PARAM_HOST, gethostbyname($cred['db_host']));
    $config->set(MDSConfig::PARAM_PORT, $cred['db_port']);
    $config->set(MDSConfig::PARAM_LOGIN, $cred['db_user']);
    $config->set(MDSConfig::PARAM_PASSWORD, $cred['db_pass']);
    $config->set(MDSConfig::PARAM_DATABASE, $cred['db_name']);
    $config->set(MDSConfig::PARAM_PREFIX, $cred['db_prefix']);

    if ($config->get(MDSConfig::PARAM_OVERRIDE_PORT)) {
        $config->set(MDSConfig::PARAM_PORT, $config->get(MDSConfig::PARAM_OVERRIDE_PORT));
    }
    if ($config->get(MDSConfig::PARAM_OVERRIDE_HOST)) {
        $config->set(MDSConfig::PARAM_HOST, $config->get(MDSConfig::PARAM_OVERRIDE_HOST));
    }

    scanDB($config, $scan_signatures, $progress, $log, $tables_config, $prescan, $clean_db, $state, $lic, $i, $detached, $cred);

    $scanned++;
}

if ($scanned === 0 && !$detached) {
    throw new MDSException(MDSErrors::MDS_NO_SCANNED);
}

if ($detached) {
    if ($scanned === 0) {
        $report = new MDSJSONReport(
            time(),
            $detached->getWorkDir() . '/' . 'report0.json',
            '0.001-dev',
            isset($scan_signatures) ? $scan_signatures->getDBMetaInfoVersion() : '',
            '',
            '',
            '',
            ''
        );
        setOpFromConfig($config, $report, $detached);
        $report->setPath(null);
        $report->setApp(null);
        $report->save();
    }
    $detached->complete();
}

if ($state && !$state->isCanceled()) {
    $state->setDone();
}

exit(0);
////////////////////////////////////////////////////////////////////////////////////////////////////////////////
function getCreds($config, $argc, $argv, $progress)
{
    $creds = [];
    if ($config->get(MDSConfig::PARAM_AVD_PATH) || $config->get(MDSConfig::PARAM_AVD_PATHS)) {
        $avd_creds = Factory::instance()->create(MDSDBCredsFromAVD::class);
        $recursive = $config->get(MDSConfig::PARAM_SCAN);
        $paths = $config->get(MDSConfig::PARAM_AVD_PATHS) ? $config->get(MDSConfig::PARAM_AVD_PATHS) : [$config->get(MDSConfig::PARAM_AVD_PATH)];
        $avd_creds->countApps($paths, $config->get(MDSConfig::PARAM_AVD_APP), $recursive);
        $creds = $avd_creds->getCredsFromApps($paths, $config->get(MDSConfig::PARAM_AVD_APP), $recursive);
        $progress->setDbCount($avd_creds->getAppsCount());
    } elseif ($config->get(MDSConfig::PARAM_CREDS_FROM_XARGS)) {
        $creds_xargs = explode(';;', $argv[$argc - 1]);
        $creds[] = [
            'db_host'   => $creds_xargs[0],
            'db_port'   => $creds_xargs[1],
            'db_user'   => $creds_xargs[2],
            'db_pass'   => $creds_xargs[3],
            'db_name'   => $creds_xargs[4],
            'db_prefix' => $creds_xargs[5],
        ];
        $progress->setDbCount(1);
    } else {
        $password = $config->get(MDSConfig::PARAM_PASSWORD);
        if ($config->get(MDSConfig::PARAM_PASSWORD_FROM_STDIN)) {
            $f = @fopen('php://stdin', 'r');
            echo "Enter password for db:" . PHP_EOL;
            $password = str_replace("\n","", fgets($f));
            fclose($f);
        }
        $creds[] = [
            'db_host'   => $config->get(MDSConfig::PARAM_HOST),
            'db_port'   => $config->get(MDSConfig::PARAM_PORT),
            'db_user'   => $config->get(MDSConfig::PARAM_LOGIN),
            'db_pass'   => $password,
            'db_name'   => $config->get(MDSConfig::PARAM_DATABASE),
            'db_prefix' => $config->get(MDSConfig::PARAM_PREFIX),
        ];
        $progress->setDbCount(1);
    }
    return $creds;
}

function scanDB($config, $scan_signatures, $progress, $log, $tables_config, $prescan, $clean_db, $state, $lic, $i, $detached, $cred)
{
    try {
        $backup = null;
        if (empty($config->get(MDSConfig::PARAM_DATABASE))) {
            throw new MDSException(MDSErrors::MDS_NO_DATABASE);
        }

        if ($progress->getDbCount() > 1 && !$config->get(MDSConfig::PARAM_SCAN)) {
            throw new MDSException(MDSErrors::MDS_MULTIPLE_DBS);
        }

        $progress->setCurrentDb($i, $config->get(MDSConfig::PARAM_DATABASE));

        $log->info('MDS DB scan: started ' . $config->get(MDSConfig::PARAM_DATABASE));

        $report_filename = 'dbscan-' . $config->get(MDSConfig::PARAM_DATABASE) . '-' . $config->get(MDSConfig::PARAM_LOGIN) . '-' . time() . '.json';


        if ($config->get(MDSConfig::PARAM_DETACHED)) {
            $config->set(MDSConfig::PARAM_REPORT_FILE, $detached->getWorkDir() . '/' . 'report' . $i . '.json');
        }

        if (!$config->get(MDSConfig::PARAM_REPORT_FILE)) {
            $report_file = __DIR__ . '/' . $report_filename;
        } else {
            if (is_dir($config->get(MDSConfig::PARAM_REPORT_FILE))) {
                $report_file = $config->get(MDSConfig::PARAM_REPORT_FILE) . '/' . $report_filename;
            } else {
                $report_file = $config->get(MDSConfig::PARAM_REPORT_FILE);
            }
        }

        $report = new MDSJSONReport(
            time(),
            $report_file,
            '0.001-dev',
            isset($scan_signatures) ? $scan_signatures->getDBMetaInfoVersion() : '',
            $config->get(MDSConfig::PARAM_HOST),
            $config->get(MDSConfig::PARAM_DATABASE),
            $config->get(MDSConfig::PARAM_LOGIN),
            $config->get(MDSConfig::PARAM_PORT)
        );

        if ($report->getError() !== null) {
            throw $report->getError();
        }

        $report->setMalwareDbVer($scan_signatures->getDBMetaInfoVersion());

        setOpFromConfig($config, $report, $detached);

        $report->setScanId($config->get(MDSConfig::PARAM_DETACHED));

        if (isset($cred['db_app'])) {
            $report->setApp($cred['db_app']);
        }

        if (isset($cred['app_owner_uid'])) {
            $report->setAppOwnerUId($cred['app_owner_uid']);
        }

        if (isset($cred['db_path'])) {
            $report->setPath($cred['db_path']);
        }

        if ($config->get(MDSConfig::PARAM_CLEAN)) {
            $backup = new MDSBackup($config->get(MDSConfig::PARAM_BACKUP_FILEPATH));
        }

        mysqli_report(MYSQLI_REPORT_STRICT);
        $db_connection = mysqli_init();
        $db_connection->options(MYSQLI_OPT_CONNECT_TIMEOUT, $config->get(MDSConfig::PARAM_DB_TIMEOUT));
        $db_connection->options(MYSQLI_OPT_READ_TIMEOUT, $config->get(MDSConfig::PARAM_DB_TIMEOUT));
        if (!$db_connection->real_connect($config->get(MDSConfig::PARAM_HOST), $config->get(MDSConfig::PARAM_LOGIN),
            $config->get(MDSConfig::PARAM_PASSWORD),
            $config->get(MDSConfig::PARAM_DATABASE), $config->get(MDSConfig::PARAM_PORT))) {
            $log->error('Can\'t connect to database: ' . $db_connection->connect_error);
            throw new MDSException(MDSErrors::MDS_CONNECT_ERROR, $db_connection->connect_error);
        }

        $db_connection->set_charset('utf8');

        $mds_find = new MDSFindTables($db_connection, $tables_config);

        if (!$config->get(MDSConfig::PARAM_DONT_SEND_UNK_URLS)) {
            $report->setUnknownUrlsSend(new MDSSendUrls(Factory::instance()->create(MDSCollectUrlsRequest::class)));
        }

        if ($config->get(MDSConfig::PARAM_CLEAN) || $config->get(MDSConfig::PARAM_SCAN)) {
            MDSScanner::scan($prescan, $config->get(MDSConfig::PARAM_DATABASE), $config->get(MDSConfig::PARAM_PREFIX),
                $mds_find, $db_connection, $scan_signatures,
                $config->get(MDSConfig::PARAM_MAX_CLEAN_BATCH), $clean_db, $progress, $state, $report, $backup,
                $config->get(MDSConfig::PARAM_SCAN), $config->get(MDSConfig::PARAM_CLEAN), $log);
        }

        if ($config->get(MDSConfig::PARAM_RESTORE)) {
            $report->setOp(MDSJSONReport::OP_RESTORE);
            $restore = new MDSRestore($config->get(MDSConfig::PARAM_RESTORE), $db_connection, $progress, $report,
                $state,
                $log);
            $restore->restore($config->get(MDSConfig::PARAM_MAX_RESTORE_BATCH));
            $restore->finish();
        }

        $ch = null;
        if (!$config->get(MDSConfig::PARAM_DO_NOT_SEND_STATS)) {
            $request = new MDSCHRequest();
            $ch = Factory::instance()->create(MDSSendToCH::class, [$request, $lic]);
        }

        if ($report) {
            $report->setCH($ch);
            $report->save();
        }

        $db_connection->close();
        $log->info('MDS DB scan: finished ' . $config->get(MDSConfig::PARAM_DATABASE));

    } catch (MDSException $ex) {
        onError($detached, $progress, $report, $ex);
    } catch (mysqli_sql_exception $e) {
        $ex = new MDSException(MDSErrors::MDS_CONNECT_ERROR, $config->get(MDSConfig::PARAM_LOGIN) . '@' . $config->get(MDSConfig::PARAM_HOST));
        onError($detached, $progress, $report, $ex);
    }
}

function onError($detached, $progress, $report, $ex)
{
    if ((isset($detached) || ($progress->getDbCount() > 1)) && (isset($report) && $report->getError() === null)) {
        $report->setPath(null);
        $report->setApp(null);
        $report->addError($ex->getErrCode(), $ex->getErrMsg());
        $report->save();
    } else {
        throw $ex;
    }
}

function setOpFromConfig($config, $report, $detached = null)
{
    if ($config->get(MDSConfig::PARAM_SCAN)) {
        $report->setOp(MDSJSONReport::OP_SCAN);
    } else if ($config->get(MDSConfig::PARAM_CLEAN)) {
        $report->setOp(MDSJSONReport::OP_CLEAN);
    } else if ($config->get(MDSConfig::PARAM_RESTORE)) {
        $report->setOp(MDSJSONReport::OP_RESTORE);
    }

    if (!isset($detached)) {
        return;
    }

    if ($config->get(MDSConfig::PARAM_SCAN)) {
        $detached->setOp(MDSJSONReport::OP_SCAN);
    } else if ($config->get(MDSConfig::PARAM_CLEAN)) {
        $detached->setOp(MDSJSONReport::OP_CLEAN);
    } else if ($config->get(MDSConfig::PARAM_RESTORE)) {
        $detached->setOp(MDSJSONReport::OP_RESTORE);
    }
}

function loadMalwareSigns($config)
{
    $scan_signatures = null;
    $clean_signatures = null;

    if ($config->get(MDSConfig::PARAM_SCAN) || $config->get(MDSConfig::PARAM_CLEAN) || $config->get(MDSConfig::PARAM_RESTORE)) {
        $avdb = trim($config->get(MDSConfig::PARAM_AV_DB));
        $scan_signatures = new LoadSignaturesForScan($avdb, 2, 0);
        if ($scan_signatures->getResult() == LoadSignaturesForScan::SIGN_EXTERNAL) {
            echo 'Loaded external scan signatures from ' . $avdb . PHP_EOL;
        }
        $sign_count = $scan_signatures->getDBCount();
        echo 'Malware scan signatures: ' . $sign_count . PHP_EOL;

        $scan_signatures->blackUrls = new MDSUrls(__DIR__ . '/blacklistedUrls.db');
        $scan_signatures->whiteUrls = new MDSUrls(__DIR__ . '/whitelistUrls.db');

        if ($config->get(MDSConfig::PARAM_CLEAN)) {
            $procudb = trim($config->get(MDSConfig::PARAM_PROCU_DB));
            $clean_signatures = new LoadSignaturesForClean('', $procudb);
            if ($clean_signatures->getDBLocation() == 'external') {
                echo 'Loaded external clean signatures from ' . $procudb . PHP_EOL;
            }
            $clean_db = $clean_signatures->getDB();
            $clean_signatures->setScanDB($scan_signatures);
            echo 'Malware clean signatures: ' . count($clean_db) . PHP_EOL;
        }
        echo PHP_EOL;
    }
    return [$scan_signatures, $clean_signatures];
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////////////////


/**
 * Class Factory.
 */
class Factory
{
    /**
     * @var Factory
     */
    private static $instance;
    /**
     * @var array
     */
    private static $config;

    /**
     * Factory constructor.
     *
     * @throws Exception
     */
    private function __construct()
    {

    }

    /**
     * Instantiate and return a factory.
     *
     * @return Factory
     * @throws Exception
     */
    public static function instance()
    {
        if (self::$instance === null) {
            self::$instance = new self();
        }

        return self::$instance;
    }

    /**
     * Configure a factory.
     *
     * This method can be called only once.
     *
     * @param array $config
     * @throws Exception
     */
    public static function configure($config = [])
    {
        if (self::isConfigured()) {
            throw new Exception('The Factory::configure() method can be called only once.');
        }

        self::$config = $config;
    }

    /**
     * Return whether a factory is configured or not.
     *
     * @return bool
     */
    public static function isConfigured()
    {
        return self::$config !== null;
    }

    /**
     * Creates and returns an instance of a particular class.
     *
     * @param string $class
     *
     * @param array $constructorArgs
     * @return mixed
     * @throws Exception
     */
    public function create($class, $constructorArgs = [])
    {
        if (!isset(self::$config[$class])) {
            throw new Exception("The factory is not contains configuration for '{$class}'.");
        }

        if (is_callable(self::$config[$class])) {
            return call_user_func(self::$config[$class], $constructorArgs);
        } else {
            return new self::$config[$class](...$constructorArgs);
        }
    }
}
class Config
{
    /**
     * @var array Configuration data 
     */
    private $config     = [];

    /**
     * Returns valued of a particular option.
     *
     * @param string $key
     * @return mixed
     * @throws Exception
     */
    public function get($key)
    {
        if (!array_key_exists($key, $this->config)) {
            throw new Exception('An invalid option requested. Key: ' . $key);
        }
        return $this->config[$key];
    }

    /**
     * Set value to config by key
     *
     * @param string $key
     * @param mixed $value
     * @return mixed
     * @throws Exception
     */
    public function set($key, $value)
    {
        $this->config[$key] = $value;
    }

    /**
     * Set default config
     *
     * @param array $defaults
     */
    protected function setDefaultConfig($defaults)
    {
        $this->config = $defaults;
    }
}
class MDSConfig extends Config
{
    const PARAM_HELP                = 'help';
    const PARAM_VERSION             = 'version';
    const PARAM_HOST                = 'host';
    const PARAM_PORT                = 'port';
    const PARAM_LOGIN               = 'login';
    const PARAM_PASSWORD            = 'password';
    const PARAM_PASSWORD_FROM_STDIN = 'password-from-stdin';
    const PARAM_DATABASE            = 'database';
    const PARAM_PREFIX              = 'prefix';
    const PARAM_SCAN                = 'scan';
    const PARAM_CLEAN               = 'clean';
    const PARAM_REPORT_FILE         = 'report-file';
    const PARAM_SIGDB               = 'signature-db';
    const PARAM_PROGRESS            = 'progress';
    const PARAM_FACTORY_CONFIG      = 'factory-config';
    const PARAM_AV_DB               = 'avdb';
    const PARAM_PROCU_DB            = 'procudb';
    const PARAM_SHARED_MEM          = 'shared-mem-progress';
    const PARAM_SHARED_MEM_CREATE   = 'create-shared-mem';
    const PARAM_STATE_FILEPATH      = 'state-file';
    const PARAM_MAX_CLEAN_BATCH     = 'max-clean';
    const PARAM_MAX_RESTORE_BATCH   = 'max-restore';
    const PARAM_RESTORE             = 'restore';
    const PARAM_LOG_FILE            = 'log-file';
    const PARAM_BACKUP_FILEPATH     = 'backup-file';
    const PARAM_LOG_LEVEL           = 'log-level';
    const PARAM_DONT_SEND_UNK_URLS  = 'do-not-send-urls';
    const PARAM_SEARCH_CONFIGS      = 'search-configs';
    const PARAM_SEARCH_DEPTH        = 'search-depth';
    const PARAM_CREDS_FROM_XARGS    = 'creds-from-xargs';
    const PARAM_OVERRIDE_PORT       = 'override_port';
    const PARAM_OVERRIDE_HOST       = 'override_host';
    const PARAM_DO_NOT_SEND_STATS   = 'do-not-send-stats';
    const PARAM_DB_TIMEOUT          = 'db-timeout';
    const PARAM_DETACHED            = 'detached';
    const PARAM_AVD_APP             = 'app-name';
    const PARAM_AVD_PATH            = 'path';
    const PARAM_AVD_PATHS           = 'paths';
    const PARAM_RESCAN              = 'rescan';
    const PARAM_IGNORELIST          = 'ignore-list';

    /**
     * @var array Default config
     */
    protected $defaultConfig = [
        self::PARAM_HELP                => false,
        self::PARAM_VERSION             => false,
        self::PARAM_SCAN                => false,
        self::PARAM_CLEAN               => false,
        self::PARAM_HOST                => '127.0.0.1',
        self::PARAM_PORT                => 3306,
        self::PARAM_LOGIN               => null,
        self::PARAM_PASSWORD            => null,
        self::PARAM_PASSWORD_FROM_STDIN => false,
        self::PARAM_DATABASE            => null,
        self::PARAM_PREFIX              => null,
        self::PARAM_REPORT_FILE         => null,
        self::PARAM_SIGDB               => null,
        self::PARAM_PROGRESS            => null,
        self::PARAM_FACTORY_CONFIG      => [
            MDSDetachedMode::class          => MDSDetachedMode::class,
            MDSDBCredsFromAVD::class        => MDSDBCredsFromAVD::class,
            ImLicense::class                => ImLicense::class,
            MDSSendToCH::class              => MDSSendToCH::class,
            MDSCollectUrlsRequest::class    => MDSCollectUrlsRequest::class,
        ],
        self::PARAM_AV_DB               => null,
        self::PARAM_PROCU_DB            => null,
        self::PARAM_SHARED_MEM          => false,
        self::PARAM_SHARED_MEM_CREATE   => false,
        self::PARAM_STATE_FILEPATH      => null,
        self::PARAM_MAX_CLEAN_BATCH     => 100,
        self::PARAM_MAX_RESTORE_BATCH   => 100,
        self::PARAM_RESTORE             => null,
        self::PARAM_LOG_FILE            => null,
        self::PARAM_LOG_LEVEL           => 'INFO',
        self::PARAM_DONT_SEND_UNK_URLS  => false,
        self::PARAM_SEARCH_CONFIGS      => '',
        self::PARAM_SEARCH_DEPTH        => 3,
        self::PARAM_CREDS_FROM_XARGS    => false,
        self::PARAM_OVERRIDE_PORT       => false,
        self::PARAM_OVERRIDE_HOST       => false,
        self::PARAM_BACKUP_FILEPATH     => '',
        self::PARAM_DO_NOT_SEND_STATS   => false,
        self::PARAM_DB_TIMEOUT          => 15,
        self::PARAM_DETACHED            => false,
        self::PARAM_AVD_APP             => false,
        self::PARAM_AVD_PATH            => false,
        self::PARAM_AVD_PATHS           => false,
        self::PARAM_RESCAN              => false,
        self::PARAM_IGNORELIST          => false,
    ];

    /**
     * Construct
     */
    public function __construct() 
    {
        $this->setDefaultConfig($this->defaultConfig);
    }
}
/*
 * Abstract class for parse cli command
 */
abstract class CliParse
{
    /**
     * @var Config Config for fill
     */
    protected $config = null;
    
    /**
     * @var array List of options. Example of one element: ['short' => 'v', 'long' => 'version,ver', 'needValue' => false]
     */
    protected $opts     = [];
    
    /**
     * @var array Current of options from $argv
     */
    private $options    = [];
    
    /**
     * @var array Arguments left after getopt() processing
     */
    private $freeAgrs   = [];
    
    /**
     * Construct
     *
     * @param array $argv
     * @param Config $config
     * @throws Exception
     */
    public function __construct($argv, Config $config)
    {
        $this->config   = $config;
        $cliLongOpts    = [];
        $cliShortOpts   = [];
        foreach ($this->opts as $params) {
            $postfix = $params['needValue'] ? ':' : '';
            if ($params['long']) {
                $cliLongOpts = array_merge($cliLongOpts, $this->getMultiOpts($params['long'], $params['needValue']));
            }
            if ($params['short']) {
                $cliShortOpts = array_merge($cliShortOpts, $this->getMultiOpts($params['short'], $params['needValue']));
            }
        }
        $this->parseOptions($argv, $cliShortOpts, $cliLongOpts);
        $this->parse();
    }
    
    /**
     * Parse comand line params
     */
    abstract protected function parse();

    /**
     * Checking if the parameter was used in the cli line
     *
     * @param string $paramKey
     * @return bool
     * @throws Exception
     */
    protected function issetParam($paramKey)
    {
        if (!isset($this->opts[$paramKey])) {
            throw new Exception('An invalid option requested.');
        }
        if ($this->getExistingOpt($this->opts[$paramKey]['long'])) {
            return true;
        }
        elseif ($this->getExistingOpt($this->opts[$paramKey]['short'])) {
            return true;
        }
        return false;
    }

    /**
     * Checking if the parameter was used in the cli line
     *
     * @param string $paramKey
     * @return bool
     * @throws Exception
     */
    protected function getParamValue($paramKey, $default = null)
    {
        if (!isset($this->opts[$paramKey])) {
            throw new Exception('An invalid option requested.');
        }
        $existingLongOpt = $this->getExistingOpt($this->opts[$paramKey]['long']);
        if ($existingLongOpt) {
            return $this->options[$existingLongOpt];
        }
        $existingShortOpt = $this->getExistingOpt($this->opts[$paramKey]['short']);
        if ($existingShortOpt) {
            return $this->options[$existingShortOpt];
        }
        return $default;
    }

    /**
     * Return free arguments after using getopt()
     *
     * @return array
     * @throws Exception
     */
    protected function getFreeAgrs()
    {
        return $this->freeAgrs;
    }
    
    /**
     * Parse by getopt() and fill vars: $this->options $this->freeAgrs
     * 
     * @return void
     */
    private function parseOptions($argv, $cliShortOpts, $cliLongOpts)
    {
        if (count($argv) <= 1) {
            return;
        }
        $this->options  = getopt(implode('', $cliShortOpts), $cliLongOpts);
        //$this->freeAgrs = array_slice($argv, $optind); // getopt(,,$optind) only for PHP7.1 and upper
        
        for($i = 1; $i < count($argv); $i++) {
            if (strpos($argv[$i], '-') !== 0) {
                $this->freeAgrs = array_slice($argv, $i);
                break;
            }
        }
    }    

    /**
     * Clean cli parameter
     *
     * @param string $optName Paramenter may be with ":" postfix
     * @return array
     */
    private function getCleanOptName($optName)
    {
        return str_replace(':', '', $optName);
    }
    
    /**
     * Return options with or without ":" postfix
     *
     * @param array $optString String with one or more options separated by ","
     * @param bool $addPostfix True if need add postfix
     * @return array Array list of options
     */
    private function getMultiOpts($optString, $addPostfix = false)
    {
        $opts = explode(',', $optString);
        if ($addPostfix) {
            $opts = array_map(function($value) { 
                return $value . ':';
            }, $opts);
        }
        return $opts;
    }
    
    /**
     * Return existing options from string. 
     *
     * @param string $optsString String with one or more options separated by ","
     * @return string|bool Name of finded options in getopt()
     */
    private function getExistingOpt($optsString)
    {
        $opts = $this->getMultiOpts($optsString);
        foreach ($opts as $opt) {
            if (isset($this->options[$opt])) { 
                return $opt;
            }
        }
        return false;
    }
}
/*
 * Abstract class for MDS which can parse cli command
 */
class MDSCliParse extends CliParse
{
    /**
     * @var array Project options for cli
     */
    protected $opts = [
        MDSConfig::PARAM_HELP                   => ['short' => 'h', 'long' => 'help',                   'needValue' => false],
        MDSConfig::PARAM_VERSION                => ['short' => 'v', 'long' => 'version,ver',            'needValue' => false],
        MDSConfig::PARAM_HOST                   => ['short' => '',  'long' => 'host',                   'needValue' => true],
        MDSConfig::PARAM_PORT                   => ['short' => '',  'long' => 'port',                   'needValue' => true],
        MDSConfig::PARAM_LOGIN                  => ['short' => '',  'long' => 'login',                  'needValue' => true],
        MDSConfig::PARAM_PASSWORD               => ['short' => '',  'long' => 'password',               'needValue' => true],
        MDSConfig::PARAM_PASSWORD_FROM_STDIN    => ['short' => '',  'long' => 'password-from-stdin',    'needValue' => false],
        MDSConfig::PARAM_DATABASE               => ['short' => '',  'long' => 'database',               'needValue' => true],
        MDSConfig::PARAM_PREFIX                 => ['short' => '',  'long' => 'prefix',                 'needValue' => true],
        MDSConfig::PARAM_SCAN                   => ['short' => '',  'long' => 'scan',                   'needValue' => false],
        MDSConfig::PARAM_CLEAN                  => ['short' => '',  'long' => 'clean',                  'needValue' => false],
        MDSConfig::PARAM_REPORT_FILE            => ['short' => '',  'long' => 'report-file',            'needValue' => true],
        MDSConfig::PARAM_SIGDB                  => ['short' => '',  'long' => 'signature-db',           'needValue' => true],
        MDSConfig::PARAM_PROGRESS               => ['short' => '',  'long' => 'progress',               'needValue' => true],
        MDSConfig::PARAM_AV_DB                  => ['short' => '',  'long' => 'avdb',                   'needValue' => true],
        MDSConfig::PARAM_PROCU_DB               => ['short' => '',  'long' => 'procudb',                'needValue' => true],
        MDSConfig::PARAM_SHARED_MEM             => ['short' => '',  'long' => 'shared-mem-progress',    'needValue' => true],
        MDSConfig::PARAM_SHARED_MEM_CREATE      => ['short' => '',  'long' => 'create-shared-mem',      'needValue' => false],
        MDSConfig::PARAM_STATE_FILEPATH         => ['short' => '',  'long' => 'state-file',             'needValue' => true],
        MDSConfig::PARAM_RESTORE                => ['short' => '',  'long' => 'restore',                'needValue' => true],
        MDSConfig::PARAM_LOG_FILE               => ['short' => '',  'long' => 'log-file',               'needValue' => true],
        MDSConfig::PARAM_LOG_LEVEL              => ['short' => '',  'long' => 'log-level',              'needValue' => true],
        MDSConfig::PARAM_DONT_SEND_UNK_URLS     => ['short' => '',  'long' => 'do-not-send-urls',       'needValue' => false],
        MDSConfig::PARAM_SEARCH_CONFIGS         => ['short' => '',  'long' => 'search-configs',         'needValue' => true],
        MDSConfig::PARAM_SEARCH_DEPTH           => ['short' => '',  'long' => 'search-depth',           'needValue' => true],
        MDSConfig::PARAM_CREDS_FROM_XARGS       => ['short' => '',  'long' => 'creds-from-xargs',       'needValue' => false],
        MDSConfig::PARAM_OVERRIDE_PORT          => ['short' => '',  'long' => 'override_port',          'needValue' => true],
        MDSConfig::PARAM_OVERRIDE_HOST          => ['short' => '',  'long' => 'override_host',          'needValue' => true],
        MDSConfig::PARAM_BACKUP_FILEPATH        => ['short' => '',  'long' => 'backup-file',            'needValue' => true],
        MDSConfig::PARAM_DO_NOT_SEND_STATS      => ['short' => '',  'long' => 'do-not-send-stats',      'needValue' => false],
        MDSConfig::PARAM_DB_TIMEOUT             => ['short' => '',  'long' => 'db-timeout',             'needValue' => true],
        MDSConfig::PARAM_DETACHED               => ['short' => '',  'long' => 'detached',               'needValue' => true],
        MDSConfig::PARAM_FACTORY_CONFIG         => ['short' => '',  'long' => 'factory-config',         'needValue' => true],
        MDSConfig::PARAM_AVD_APP                => ['short' => '',  'long' => 'app-name',               'needValue' => true],
        MDSConfig::PARAM_AVD_PATH               => ['short' => '',  'long' => 'path',                   'needValue' => true],
        MDSConfig::PARAM_AVD_PATHS              => ['short' => '',  'long' => 'paths',                  'needValue' => true],
        MDSConfig::PARAM_IGNORELIST             => ['short' => '',  'long' => 'ignore-list',            'needValue' => true],
    ];

    /**
     * Parse comand line params
     * 
     * @return void
     * @throws Exception
     */
    protected function parse()
    {
        foreach ($this->opts as $configName => $params) {
            $default    = $params['needValue'] ? $this->config->get($configName) : null;
            $result     = $this->getParamValue($configName, $default);
            if (!$params['needValue'] && $result === false) { // $result === false because opt without value
                $result = true;
            }
            if ($configName == MDSConfig::PARAM_FACTORY_CONFIG) {
                $file = $result;
                if (is_string($file) && !empty($file) && @file_exists($file) && @is_readable($file) && @filesize($file) > 5) {
                    $optionalFactoryConfig = require($file);
                    $result = array_merge($this->config->get(MDSConfig::PARAM_FACTORY_CONFIG), $optionalFactoryConfig);
                }
            }
            $this->config->set($configName, $result);
        }
        
        $factoryConfig = $this->config->get(MDSConfig::PARAM_FACTORY_CONFIG);
        
        if ($this->config->get(MDSConfig::PARAM_HELP)) {
            $this->showHelp();
        }
        elseif ($this->config->get(MDSConfig::PARAM_VERSION)) {
            $this->showVersion();
        }
        elseif (!$this->config->get(MDSConfig::PARAM_SCAN) && !$this->config->get(MDSConfig::PARAM_CLEAN) && !$this->config->get(MDSConfig::PARAM_RESTORE) && !$this->config->get(MDSConfig::PARAM_SEARCH_CONFIGS) && !$this->config->get(MDSConfig::PARAM_CREDS_FROM_XARGS)) {
            $this->showHelp();
        }
        
        // here maybe re-define some of $factoryConfig elements 
        
        $this->config->set(MDSConfig::PARAM_FACTORY_CONFIG, $factoryConfig);
    }
    
    /**
     * Cli show help
     * 
     * @return void
     */
    private function showHelp()
    {
        echo <<<HELP
MDS - an Intelligent Malware Database Scanner for Websites.

Usage: php {$_SERVER['PHP_SELF']} [OPTIONS]

      --host=<host>                     Database host
      --port=<port>                     Database port
      --login=<username>                Database username
      --password=<password>             Database password
      --password-from-stdin             Get database password from stdin
      --database=<db_name>              Database name
      --prefix=<prefix>                 Prefix for table
      --scan                            Do scan
      --clean                           Do clean
      --report-file=<filepath>          Filepath where to put the report
      --signature-db=<filepath>         Filepath with signatures
      --progress=<filepath>             Filepath with progress
      --shared-mem-progress=<shmem_id>  ID of shared memory segment
      --create-shared-mem               MDS create own shared memory segment
      --state=<filepath>                Filepath with state for control task
      --backup-filepath=<filepath>      Backup file
      --avdb=<filepath>                 Filepath with ai-bolit signatures db
      --procudb=<filepath>              Filepath with procu signatures db
      --state-file=<filepath>           Filepath with info about state(content: new|working|done|canceled). You can change it on canceled
      --restore=<filepath>              Filepath to restore csv file
      --log-file=<filepath>             Filepath to log file
      --log-level=<LEVEL>               Log level (types: ERROR|DEBUG|INFO|ALL). You can use multiple by using comma (example: DEBUG,INFO)
      --do-not-send-urls                Do not send unknown urls to server for deeper analysis
      --search-configs                  Search supported CMS configs and print db credentials
      --search-depth=<depth>            Search depth for CMS configs (default: 3)
      --creds-from-xargs                Get db credentials from last free arg (template: host;;port;;user;;pass;;name)
      --do-not-send-stats               Do not send report to Imunify correlation server
      --db-timeout=<timeout>            Timeout for connect/read db in seconds
      --detached=<scan_id>              Run MDS in detached mode
      --path=<path>                     Scan/clean CMS dbs from <path> with help AppVersionDetector
      --paths=<file>                    Scan/clean CMS dbs base64 encoded paths from <file> with help AppVersionDetector
      --app-name=<app-name>             Filter AppVersionDetector dbs for scan with <app-name>. Currently supported only 'wp-core'.

  -h, --help                            Display this help and exit
  -v, --version                         Show version


HELP;
        exit(0);
    }

    /**
     * Cli show version
     * 
     * @return void
     */
    private function showVersion()
    {
        echo "Unknown\n";
        exit(0);
    }
}
/**
 * Class MDSTablesConfig for work with config file in MDS
 */
class MDSTablesConfig
{
    private $raw_config = [];

    /**
     * MDSTablesConfig constructor.
     * @param $file
     * @throws Exception
     */
    public function __construct($file)
    {
        if (empty($file) || !file_exists($file)) {
            throw new MDSException(MDSErrors::MDS_CONFIG_ERROR, $file);
        }

        $this->raw_config = json_decode(file_get_contents($file), true);
    }

    /**
     * Get all applications defined in config
     * @return array
     */
    public function getSupportedApplications()
    {
        return array_keys($this->raw_config['applications']);
    }

    /**
     * Get all tables defined in config for application
     * @param $application
     * @return array
     */
    public function getSupportedTables($application)
    {
        return isset($this->raw_config['applications'][$application]) ? array_keys($this->raw_config['applications'][$application]) : [];
    }

    /**
     * Get all fields defined in config for table in application
     * @param $application
     * @param $table
     * @return array|mixed
     */
    public function getTableFields($application, $table)
    {
        return $this->raw_config['applications'][$application][$table]['fields'] ?? [];
    }

    /**
     * Get key field defined in config for table in application
     * @param $application
     * @param $table
     * @return string
     */
    public function getTableKey($application, $table)
    {
        return $this->raw_config['applications'][$application][$table]['key'] ?? '';
    }

    /**
     * Get array of defined in config fields with key
     * @param $application
     * @param $table
     * @return array
     */
    public function getTableFieldsWithKey($application, $table)
    {
        $fields = $this->getTableFields($application, $table);
        if ($this->getTableKey($application, $table) !== '') {
            $fields[] = $this->getTableKey($application, $table);
        }
        return $fields;
    }

    /**
     * Get satisfied application table by fields and key
     * @param $fields
     * @param $key
     * @return array
     */
    public function getTableSatisfied($fields, $key)
    {
        $res = [];
        foreach($this->getSupportedApplications() as $app) {
            foreach($this->getSupportedTables($app) as $table) {
                $config_fields = $this->getTableFieldsWithKey($app, $table);
                $config_key = $this->getTableKey($app, $table);
                if ($config_key === $key && empty(array_diff($fields, $config_fields))) {
                    $res[] = ['app' => $app, 'table' => $table];
                }
            }
        }
        return $res;
    }

    /**
     * Check application defined in config
     * @param $app
     * @return bool
     */
    public function isApplicationDefined($app)
    {
        return isset($this->raw_config['applications'][$app]);
    }

    /**
     * Check table for application defined in config
     * @param $app
     * @param $table
     * @return bool
     */
    public function isTableDefined($app, $table)
    {
        return isset($this->raw_config['applications'][$app][$table]);
    }

    /**
     * @param $application
     * @param $table
     * @return array
     */
    public function getConfigForTable($application, $table)
    {
        return isset($this->raw_config['applications'][$application][$table]) ? $this->raw_config['applications'][$application][$table] : [];
    }

    /**
     * @param $application
     * @return string
     */
    public function getApplicationDomainQuery($application)
    {
        return isset($this->raw_config['applications'][$application]['domain_name']) ? $this->raw_config['applications'][$application]['domain_name'] : '';
    }
}
/**
 * Class MDSFindTables Find tables that we have in config
 */
class MDSFindTables
{
    private $db;
    private $config;

    public function __construct($db, MDSTablesConfig $config)
    {
        $this->db = $db;
        $this->config = $config;
    }

    public function find($db = null, $prefix = null)
    {
        $result = [];
        foreach ($this->config->getSupportedApplications() as $app)
        {
            foreach ($this->config->getSupportedTables($app) as $table) {
                $query = 'SELECT DISTINCT table_schema as db, table_name as tab '
                        . 'FROM information_schema.columns '
                        . 'WHERE column_name = \'' . $this->config->getTableKey($app, $table) . '\' AND column_key = \'PRI\'';
                if (isset($db)) {
                    $query .= ' AND table_schema = \'' . $db . '\'';
                }
                if (isset($prefix)) {
                    $query .= ' AND table_name LIKE \'' . $prefix . '%\'';
                }
                $fields = $this->config->getTableFields($app, $table);
                foreach($fields as $field) {
                    $query .= ' AND table_name IN (SELECT DISTINCT table_name FROM information_schema.columns WHERE column_name = \'' . $field . '\'';
                }
                $query .= str_repeat(')', count($fields));
                $query .= ';';
                $tables = $this->db->query($query);
                if ($tables->num_rows === 0) {
                    continue;
                }
                foreach($tables as $value) {
                    if (!isset($prefix)) {
                        $prefix = explode('_', $value['tab']);
                        $prefix = $prefix[0] . '_';
                    }
                    $domain_query = str_replace(['%db%', '%prefix%'], [$value['db'], $prefix], $this->config->getApplicationDomainQuery($app));
                    $domain_name_res = $this->db->query($domain_query);
                    
                    $domain_name    = '';
                    $own_url        = '';
                    if ($domain_name_res) {
                        $row = array_values($domain_name_res->fetch_row());
                        if (isset($row[0])) {
                            $own_url = $row[0];
                        }
                    }
                    if ($own_url) {
                        $domain_name = parse_url($own_url, PHP_URL_HOST);
                        $domain_name = preg_replace('~^www\.~ism', '', $domain_name);
                        $domain_name = strtolower($domain_name);
                    }
                    
                    $result[] = [
                        'config_app'    => $app,
                        'config_tab'    => $table,
                        'db'            => $value['db'],
                        'table'         => $value['tab'],
                        'prefix'        => $prefix,
                        'domain_name'   => $domain_name,
                        'config'        => $this->config->getConfigForTable($app, $table),
                    ];
                }
            }
            return $result;
        }
    }
}
/**
 * Class MDSJSONReport need for prepare and wirte JSON report
 */
class MDSJSONReport
{
    const STATUS_DETECTED   = 'detected';
    const STATUS_CLEAN      = 'clean';
    const STATUS_RESTORE    = 'restore';
    
    const STATE_DONE        = 'done';
    const STATE_CANCELED    = 'canceled';

    const OP_SCAN           = 'scan';
    const OP_CLEAN          = 'cleanup';
    const OP_RESTORE        = 'restore';
    
    private $start_time         = '';
    private $report_filename    = '';
    private $unknown_urls_send  = '';
    private $mds_version        = '';
    private $malware_db_version = '';
    private $db_host            = '';
    private $db_name            = '';
    private $db_username        = '';
    private $db_port            = 3306;
    
    private $report = [];
    private $report_url = [];
    private $unknown_urls = [];
    private $urls_counter = 0;
    
    private $table_total_rows = [];

    private $count_tables_scanned   = 0;
    private $running_time           = 0;
    private $errors                 = [];
    private $state                  = self::STATE_DONE;

    private $report_error           = null;
    
    private $uniq_tables_affected   = [];
    private $rows_infected          = 0;
    private $rows_cleaned           = 0;
    private $rows_restored          = 0;
    private $rows_with_errors       = [];
    
    private $count_of_detected_malicious_entries    = 0;
    private $count_of_cleaned_malicious_entries     = 0;
    private $operation = '';
    private $ch = null;

    private $app = null;
    private $app_owner_uid = null;
    private $path = null;
    private $scan_id = null;
    private $save_urls_limit = 5000;

    /**
     * MDSJSONReport constructor.
     * @param string $report_filename
     * @param string $mds_version
     * @param string $malware_db_version
     * @param string $db_host
     * @param string $db_name
     * @param string $db_username
     * @param string $db_port
     */
    public function __construct($start_time, $report_filename, $mds_version, $malware_db_version, $db_host, $db_name, $db_username, $db_port)
    {
        $this->start_time           = $start_time;
        $this->report_filename      = $report_filename;
        $this->mds_version          = $mds_version;
        $this->malware_db_version   = $malware_db_version;
        $this->db_host              = $db_host;
        $this->db_name              = $db_name;
        $this->db_username          = $db_username;
        $this->db_port              = $db_port;

        if (empty($report_filename) || (!file_exists($report_filename) && !is_writable(dirname($report_filename)))) {
            $this->report_error = new MDSException(MDSErrors::MDS_REPORT_ERROR, $report_filename);
        }
    }

    public function setSaveUrlsLimit($limit)
    {
        $this->save_urls_limit = $limit;
    }

    public function setMalwareDbVer($ver)
    {
        $this->malware_db_version = $ver;
    }

    public function setOp($op)
    {
        $this->operation = $op;
    }

    public function setApp($app)
    {
        $this->app = $app;
    }

    public function setAppOwnerUId($app_owner_uid)
    {
        $this->app_owner_uid = $app_owner_uid;
    }

    public function setPath($path)
    {
        $this->path = $path;
    }

    public function setScanId($scan_id)
    {
        $this->scan_id = $scan_id;
    }

    public function setCH($ch)
    {
        $this->ch = $ch;
    }

    public function getUser()
    {
        return $this->db_username;
    }

    public function getHost()
    {
        return $this->db_host;
    }


    public function getDbName()
    {
        return $this->db_name;
    }

    public function getError()
    {
        return $this->report_error;
    }

    /**
     * Set the total number of tables that we scanned
     * @param int $count
     * @return void
     */
    public function setCountTablesScanned($count)
    {
        $this->count_tables_scanned = $count;
    }

    /**
     * Set the total number of tables that we scanned
     * @param int $count
     * @return void
     */
    public function setUnknownUrlsSend($send_urls)
    {
        $this->unknown_urls_send = $send_urls;
    }

    /**
     * Set the total running time of the script
     * @param int $running_time_in_sec
     * @return void
     */
    public function setRunningTime($running_time_in_sec)
    {
        $this->running_time = $running_time_in_sec;
    }

    /**
     * Add total scanned rows for every table
     * @param string $table_name
     * @param int $count
     * @return void
     */
    public function addTotalTableRows($table_name, $count)
    {
        $this->table_total_rows[$table_name] = $count;
    }

    /**
     * Add error code and message
     * @param int $error_code
     * @param string $error_msg
     * @return void
     */
    public function addError($error_code, $error_msg)
    {
        $this->errors[] = [
            'code'      => $error_code,
            'message'   => $error_msg,
        ];
    }
    
    /**
     * Change state
     * @param string $state
     * @return void
     */
    public function setState($state)
    {
        $this->state = $state;
    }

    /**
     * Add errors
     * @param array $errors
     * @return void
     */
    public function addErrors($errors)
    {
        $this->errors = $errors;
    }
    
    /**
     * Add detected info
     * @param string $signature_id
     * @param string $snippet
     * @param string $table_name
     * @param int $row_id
     * @return void
     */
    public function addDetected($signature_id, $snippet, $table_name, $row_id, $field = '')
    {
        $this->addSignatureRowId($signature_id, $snippet, $table_name, $row_id, $field, self::STATUS_DETECTED);
        $this->rows_infected++;
    }

    /**
     * Add detected info
     * @param string $signature_id
     * @param string $snippet
     * @param string $table_name
     * @param int $row_id
     * @return void
     */
    public function addDetectedUrl($signature_id, $snippet, $table_name, $row_id, $field = '')
    {
        $this->addSignatureRowId($signature_id, $snippet, $table_name, $row_id, $field, self::STATUS_DETECTED, true);
        $this->rows_infected++;
    }

    /**
     * @param $url
     */
    public function addUnknownUrl($url)
    {
        if (!isset($this->unknown_urls[$url])) {
            $this->unknown_urls[$url] = '';
            $this->urls_counter++;
        }

        if ($this->unknown_urls_send !== '' && $this->urls_counter >= $this->save_urls_limit) {
            $this->unknown_urls_send->send(array_keys($this->unknown_urls));
            $this->urls_counter = 0;
            $this->unknown_urls = [];
        }
    }

    /**
     * Add detected error info
     * @param string $signature_id
     * @param string $snippet
     * @param string $error_code
     * @return void
     */
    public function addDetectedError($signature_id, $snippet, $table_name, $row_id, $field, $error_code)
    {
        $this->addSignatureError($signature_id, $snippet, $table_name, $row_id, $field, $error_code, self::STATUS_DETECTED);
    }

    /**
     * Add clean info
     * @param string $signature_id
     * @param string $snippet
     * @param string $table_name
     * @param int $row_id
     * @return void
     */
    public function addCleaned($signature_id, $snippet, $table_name, $row_id, $field = '')
    {
        $this->addSignatureRowId($signature_id, $snippet, $table_name, $row_id, $field, self::STATUS_CLEAN);
        $this->rows_cleaned++;
    }

    /**
     * Add clean error info
     * @param string $signature_id
     * @param string $snippet
     * @param string $error_code
     * @return void
     */
    public function addCleanedError($signature_id, $snippet, $table_name, $row_id, $field, $error_code)
    {
        $this->addSignatureError($signature_id, $snippet, $table_name, $row_id, $field, $error_code, self::STATUS_CLEAN);
    }

    /**
     * Add restored info
     * @param string $table_name
     * @param int $row_id
     * @param string $field
     * @return void
     */
    public function addRestored($table_name, $row_id, $field = '')
    {
        $this->addSignatureRowId('', '', $table_name, $row_id, $field, self::STATUS_RESTORE);
        $this->rows_restored++;
    }

    /**
     * Add restored error info
     * @param string $error_code
     * @return void
     */
    public function addRestoredError($error_code, $table_name, $row_id, $field = '')
    {
        $this->addSignatureError('', '', $table_name, $row_id, $field, $error_code, self::STATUS_RESTORE);
    }

    /**
     * Save report
     * @return void
     */
    public function save()
    {
        $report = $this->prepareReport();
        $json = json_encode($report);
        file_put_contents($this->report_filename, $json);

        if ($this->unknown_urls_send !== '' && !empty($this->unknown_urls)) {
            $this->unknown_urls_send->send(array_keys($this->unknown_urls));
        }

        if(isset($this->ch)) {
            $this->ch->prepareData($report);
            $this->ch->send();
        }
    }
    
    // /////////////////////////////////////////////////////////////////////////

    /**
     * Prepare report data for save
     * @return array
     */
    private function prepareReport()
    {

        $report =  [
            'start_time'                            => $this->start_time,
            'scanning_engine_version'               => $this->mds_version,
            'malware_database_version'              => $this->malware_db_version,
            'count_of_tables_scanned'               => $this->count_tables_scanned,
            'count_of_tables_affected'              => count($this->uniq_tables_affected),
            'count_of_rows_infected'                => $this->rows_infected,
            'count_of_rows_cleaned'                 => $this->rows_cleaned,
            'count_of_rows_restored'                => $this->rows_restored,
            'count_of_detected_malicious_entries'   => $this->count_of_detected_malicious_entries,
            'count_of_cleaned_malicious_entries'    => $this->count_of_cleaned_malicious_entries,
            'running_time'                          => $this->running_time,
            'error_list'                            => $this->errors,
            'database_host'                         => $this->db_host,
            'database_port'                         => $this->db_port,
            'database_name'                         => $this->db_name,
            'database_username'                     => $this->db_username,
            'detailed_reports'                      => $this->processReport(),
            'detailed_urls_reports'                 => $this->processReport(true),
            'rows_with_error'                       => $this->rows_with_errors,
            'state'                                 => $this->state,
            'operation'                             => $this->operation,
            'app'                                   => $this->app,
            'app_owner_uid'                         => $this->app_owner_uid,
            'path'                                  => $this->path,
        ];
        if ($this->scan_id) {
            $report['scan_id'] = $this->scan_id;
        }
        return $report;
    }

    /**
     * @param bool $url
     * @return array
     */
    private function processReport($url = false)
    {
        if ($url) {
            $report = &$this->report_url;
        } else {
            $report = &$this->report;
        }

        $reports = [];
        foreach ($report as $signature_id => $signature_params)
        {
            if (isset($signature_params['error'])) {
                $reports[] = [
                    'sigid'     => $signature_id,
                    'snpt'      => $signature_params['snippet'],
                    'status'    => 'error',
                    'errcode'   => $signature_params['error'],
                    'tables'    => [],
                ];
                continue;
            }
            $tables_result = [];
            foreach ($signature_params['tables_info'] as $table_name => $fields) {
                $fields_data = [];
                foreach ($fields as $field => $row_ids) {
                    $fields_data[] = [
                        'field'     => $field,
                        'row_ids'   => $row_ids,
                        'row_inf'   => count($row_ids),
                    ];
                }
                if ($fields_data) {
                    $tables_result[] = [
                        'table'         => $table_name,
                        'total_rows'    => isset($this->table_total_rows[$table_name]) ? $this->table_total_rows[$table_name] : 0,
                        'fields'        => $fields_data,
                    ];
                }
            }
            $reports[] = [
                'sigid'     => $signature_id,
                'snpt'      => $signature_params['snippet'],
                'status'    => $signature_params['status'],
                'tables'    => $tables_result,
                'errcode'   => 0,
            ];
        }
        return $reports;
    }

    /**
     * General method for adding detection and clean information
     * @param string $signature_id
     * @param string $snippet
     * @param string $table_name
     * @param string $row_id
     * @param string $status
     * @return void
     */
    private function addSignatureRowId($signature_id, $snippet, $table_name, $row_id, $field, $status = self::STATUS_DETECTED, $url = false)
    {
        if ($url) {
            $report = &$this->report_url;
        } else {
            $report = &$this->report;
        }

        if ($this->initReportRow($signature_id, $snippet, $status, $url)) {
            if ($status == self::STATUS_DETECTED) {
                $this->count_of_detected_malicious_entries++;
            }
            elseif ($status == self::STATUS_CLEAN) {
                $this->count_of_cleaned_malicious_entries++;
            }
        }
        if (!isset($report[$signature_id]['tables_info'][$table_name])) {
            $report[$signature_id]['tables_info'][$table_name] = [];
        }
        if (!isset($report[$signature_id]['tables_info'][$table_name][$field])) {
            $report[$signature_id]['tables_info'][$table_name][$field] = [];
        }
        $report[$signature_id]['tables_info'][$table_name][$field][] = $row_id;
        $this->uniq_tables_affected[$table_name] = '';
    }

    /**
     * General method for adding detection and clean error information
     * @param string $signature_id
     * @param string $snippet
     * @param string $error_code
     * @param string $status
     * @return void
     */
    private function addSignatureError($signature_id, $snippet, $table_name, $row_id, $field, $error_code, $status = self::STATUS_DETECTED, $url = false)
    {
        if ($url) {
            $report = &$this->report_url;
        } else {
            $report = &$this->report;
        }

        $this->initReportRow($signature_id, $snippet, $status, $url);
        $report[$signature_id]['error'] = $error_code;
        if (!isset($this->rows_with_errors['tables_info'][$table_name])) {
            $this->rows_with_errors['tables_info'][$table_name] = [];
        }
        if (!isset($this->rows_with_errors['tables_info'][$table_name][$field])) {
            $this->rows_with_errors['tables_info'][$table_name][$field] = [];
        }
        $this->rows_with_errors['tables_info'][$table_name][$field][] = $row_id;
    }

    /**
     * Initiate an array element if not exists
     * @param string $signature_id
     * @param string $snippet
     * @param string $status
     * @return void
     */
    private function initReportRow($signature_id, $snippet, $status = self::STATUS_DETECTED, $url = false)
    {
        if ($url) {
            $report = &$this->report_url;
        } else {
            $report = &$this->report;
        }

        if (isset($report[$signature_id])) {
            return false;
        }
        $report[$signature_id] = [
            'snippet'       => $snippet,
            'total_rows'    => 0,
            'status'        => $status,
            'rows_infected' => 0,
            'tables_info'   => [],
            'error'         => null,
        ];
        return true;
    }
}
/**
 * Class MDSProgress module for tracking progress
 */
class MDSProgress
{
    private $total;
    private $total_table;
    private $num_tables = 1;
    private $current_table;
    private $current_table_num;
    private $current_db;
    private $current_db_num;
    private $last_file_update = 0;
    private $last_update = 0;
    private $progress_file;
    private $shared_mem;
    private $create_shared_mem;
    private $file_write_interval;
    private $update_interval;
    private $start;
    private $progress_string;
    private $tables;
    private $last_table_key;
    private $first_table_key;
    private $print = null;
    private $percent_main;
    private $db_count = 1;
    private $percent_table;

    private $one_db_percent;
    private $one_table_percent;
    private $one_record_percent;

    /**
     * MDSProgress constructor.
     * @param string $file - file for writing progress
     * @param int $update_interval - interval for update progress
     * @param int $file_write_interval - interval for writing to file progress
     * @param int $shared_mem - write to shared memory
     * @param bool $need_create_shmem - need to create shared memory
     * @throws Exception
     */
    public function __construct($file = false, $update_interval = 0, $file_write_interval = 1, $shared_mem = false, $need_create_shmem = false)
    {
        $this->start = time();
        $this->update_interval = $update_interval;
        $this->file_write_interval = $file_write_interval;
        if ($shared_mem) {
            $this->create_shared_mem = $need_create_shmem;
            if ($this->create_shared_mem) {
                @$this->shared_mem = new SharedMem((int)$shared_mem, "n", 0600, 5000);
            } else {
                @$this->shared_mem = new SharedMem((int)$shared_mem, "w", 0, 0);
            }
            if (!$this->shared_mem->isValid()) {
                if ($need_create_shmem) {
                    throw new MDSException(MDSErrors::MDS_PROGRESS_SHMEM_CRT_ERROR, $shared_mem);
                } else {
                    throw new MDSException(MDSErrors::MDS_PROGRESS_SHMEM_ERROR, $shared_mem);
                }
            }
        }

        if ($file) {
            if (is_writable(dirname($file)) || (file_exists($file) && is_writable($file))) {
                $this->progress_file = $file;
            } else {
                throw new MDSException(MDSErrors::MDS_PROGRESS_FILE_ERROR, $file);
            }
        }
    }

    /**
     * @param $total - total records for scanning
     */
    public function setTotal($total)
    {
        $this->total = $total;
    }

    /**
     * @param $num_dbs - num of tables for scan
     */
    public function setDbCount($num_dbs)
    {
        $this->db_count = $num_dbs;
        $this->one_db_percent = $num_dbs ? 100 / $num_dbs : 0;
    }

    /**
     *
     */
    public function getDbCount()
    {
        return $this->db_count;
    }

    /**
     * @param $tables - array of tables for scan
     */
    public function setTables($tables)
    {
        $this->tables = $tables;
        $this->num_tables = count($tables);
        $this->one_table_percent = $this->one_db_percent / $this->num_tables;
    }

    /**
     * @param $print - print function to printout progress
     */
    public function setPrint($print)
    {
        $this->print = $print;
    }

    /**
     * @param $i - index of currently scanned table
     * @param $table - name of currently scanned table
     */
    public function setCurrentTable($i, $table)
    {
        $new_percent = number_format(($this->current_db_num * $this->one_db_percent) + ($i * $this->one_table_percent), 1);
        $this->progress_string = str_replace(substr($this->progress_string, 0, strpos($this->progress_string, '% of whole scan')), '[' . ($i + 1) . '/' . $this->num_tables . ' tbls of ' . ($this->current_db_num + 1) . '/' . $this->db_count . ' dbs] ' . $new_percent, $this->progress_string);
        $this->current_table_num = $i;
        $this->current_table = $table;
        $this->percent_main = $new_percent;
        if ($this->print !== null && is_callable($this->print)) {
            $this->print->call($this, $this->getProgressAsString());
        }
    }

    /**
     * @param $i - index of currently scanned table
     * @param $table - name of currently scanned table
     */
    public function setCurrentDb($i, $db)
    {
        $new_percent = number_format($i * $this->one_db_percent, 1);
        $this->progress_string = str_replace(substr($this->progress_string, 0, strpos($this->progress_string, '% of whole scan')), '[' . ($this->current_table_num + 1) . '/' . $this->num_tables . ' tbls of ' . ($i + 1) . '/' . $this->db_count . ' dbs] ' . $new_percent, $this->progress_string);
        $this->current_db_num = $i;
        $this->current_db = $db;
        $this->percent_main = $new_percent;
        if ($this->print !== null && is_callable($this->print)) {
            $this->print->call($this, $this->getProgressAsString());
        }
    }

    /**
     * @param $key_start - first key of table
     * @param $key_last - last key of table
     */
    public function setKeysRange($key_start, $key_last)
    {
        $this->first_table_key = $key_start;
        $this->last_table_key = $key_last;
        $this->setTotalTable(($key_last - $key_start) + 1);
    }

    /**
     * @param $total_table - total records for table
     */
    public function setTotalTable($total_table)
    {
        $this->total_table = $total_table;
        $this->one_record_percent = $this->one_table_percent / $this->total_table;
    }

    /**
     * @param $row_id - current record
     * @param $detected - num of detected malicious
     * @param $db - current db
     * @param $table - current table
     */
    public function updateProgress($row_id, $detected, $cleaned, $db, $table)
    {
        if (time() - $this->last_update < $this->update_interval) {
            return;
        }

        $corrected_start_value = $row_id - $this->first_table_key;
        $percent_table = number_format($this->total_table ? $corrected_start_value * 100 / $this->total_table : 0, 1);
        $elapsed_time    = microtime(true) - $this->start;

        $stat            = '';
        $left            = 0;
        $left_time       = 0;
        $elapsed_seconds = 0;

        $percent_main = $this->percent_main;

        $percent_main += number_format($corrected_start_value * $this->one_record_percent, 1);

        if ($elapsed_time >= 1) {
            $elapsed_seconds = round($elapsed_time, 0);
            $fs              = floor($corrected_start_value / $elapsed_seconds);
            $left            = $this->total_table - $corrected_start_value;
            $clean = ($cleaned > 0 ? '/' . $cleaned : '');
            $malware = ($detected > 0 ? '[Mlw:' . $detected . $clean . ']' : '');
            if ($fs > 0) {
                $left_time = ($left / $fs);
                $stat = ' [Avg: ' . round($fs, 2) . ' rec/s' . ($left_time > 0 ? ' Left: ' . AibolitHelpers::seconds2Human($left_time) . ' for current table' : '') . '] ' . $malware;
            }
        }

        $this->progress_string = '[' . ($this->current_table_num + 1) . '/' . $this->num_tables . ' tbls of ' . ($this->current_db_num + 1) . '/' . $this->db_count . ' dbs] ' . $percent_main . '% of whole scan' . '/' . $percent_table . '% [' . $db . '.' . $table . '] ' . $corrected_start_value . ' of ' . $this->total_table . ' rows ' . $stat;

        $data = [
            'self'                  => __FILE__,
            'started'               => $this->start,
            'updated'               => time(),
            'progress_table'        => $percent_table,
            'progress_main'         => $percent_main,
            'time_elapsed'          => $elapsed_seconds,
            'time_left'             => round($left_time),
            'left'                  => $left,
            'total_table'           => $this->total_table,
            'current_index'         => $corrected_start_value,
            'current_db_num'        => $this->current_db_num,
            'current_table_num'     => $this->current_table_num,
            'total_db_count'        => $this->db_count,
            'total_tbl_db_count'    => $this->num_tables,
            'current_row_id'        => $row_id,
            'current'               => $db . '.' . $table . '/' . $row_id,
        ];

        if ($this->progress_file && (time() - $this->last_file_update > $this->file_write_interval)) {
            if (function_exists('json_encode')) {
                file_put_contents($this->progress_file, json_encode($data));
            } else {
                file_put_contents($this->progress_file, serialize($data));
            }

            $this->last_file_update = time();
        }

        if ($this->shared_mem && $this->shared_mem->isValid()) {
            $this->shared_mem->write($data);
        }

        if ($this->print !== null && is_callable($this->print)) {
            $this->print->call($this, $this->getProgressAsString());
        }
    }

    /**
     * @return string
     */
    public function getProgressAsString()
    {
        return $this->progress_string;
    }

    public function finalize()
    {
        if ($this->progress_file && file_exists($this->progress_file)) {
            @unlink($this->progress_file);
        }
        if ($this->shared_mem && $this->shared_mem->isValid()) {
            $this->shared_mem->close($this->create_shared_mem);
        }
        $this->shared_mem = null;
    }
}
/**
 * Class MDSScan module for scan string with signatures
 */
class MDSScan
{
    /**
     * Scan function
     * @param $content
     * @param $signature_db
     * @return array|bool
     */
    public static function scan($content, $signature_db, $table_config)
    {
        $checkers['CriticalPHP'] = true;
        $checkers['CriticalJS'] = true;

        $checker_url['UrlChecker'] = false;

        $result = [];
        $resultUrl = [];

        $processResult = function ($checker, $content, $l_Pos, $l_SigId, &$return) use (&$result, $signature_db) {
            $return = null;
            $result = [
                'content' => self::getFragment($content, $l_Pos),
                'pos' => $l_Pos,
                'sigid' => $l_SigId,
            ];
            if (isset($l_SigId) && isset($signature_db->_Mnemo[$l_SigId])) {
                $result['sn'] = $signature_db->_Mnemo[$l_SigId];
            } else {
                $result['sn'] = '';
            }
        };

        $processUrlResult = function ($checker, $content, $l_Pos, $l_SigId, &$return) use (&$resultUrl, $signature_db) {
            $return = null;
            if (isset($l_Pos['black'])) {
                for ($i=0, $iMax = count($l_Pos['black']); $i < $iMax; $i++) {
                    $resultUrl['black'][] = [
                        'content' => self::getFragment($content, $l_Pos['black'][$i]),
                        'pos' => $l_Pos['black'][$i],
                        'sigid' => $l_SigId['black'][$i],
                    ];
                }
            }

            if (isset($l_Pos['unk'])) {
                for ($i=0, $iMax = count($l_Pos['unk']); $i < $iMax; $i++) {
                    $resultUrl['unk'][] = [
                        'content' => self::getFragment($content, $l_Pos['unk'][$i]),
                        'pos' => $l_Pos['unk'][$i],
                        'sigid' => $l_SigId['unk'][$i],
                    ];
                }
            }
        };

        $l_Unwrapped = $content;
        if (isset($table_config['escaped']) && $table_config['escaped'] === true) {
            $l_Unwrapped = Normalization::unescape($l_Unwrapped);
        }
        $l_Unwrapped = Normalization::strip_whitespace($l_Unwrapped);
        $l_UnicodeContent = Encoding::detectUTFEncoding($content);
        if ($l_UnicodeContent !== false && Encoding::iconvSupported()) {
            $l_Unwrapped = Encoding::convertToCp1251($l_UnicodeContent, $l_Unwrapped);
        }
        $l_DeobfObj = new Deobfuscator($l_Unwrapped, $content);
        $l_DeobfType = $l_DeobfObj->getObfuscateType($l_Unwrapped);
        if ($l_DeobfType !== '') {
            $l_Unwrapped = $l_DeobfObj->deobfuscate();
        }

        $l_Unwrapped = Normalization::normalize($l_Unwrapped);
        $found = ScanUnit::QCR_ScanContent($checkers, $l_Unwrapped, $content, $signature_db, null, null, $processResult);
        $found_urls = ScanUnit::QCR_ScanContent($checker_url, $l_Unwrapped, $content, $signature_db, null, null, $processUrlResult);
        $ret = false;
        if ($found) {
            $ret['mlw'] = $result;
        }
        if ($found_urls) {
            $ret['url'] = $resultUrl;
        }
        return $ret;
    }

    public static function scanBatch($contents, $signature_db, $table_config)
    {
        $result = [];
        foreach($contents as $index => $fields) {
            foreach($fields as $field => $content) {
                if ($res = self::scan($content, $signature_db, $table_config)) {
                    $result[$index][$field] = $res;
                }
            }
        }
        return $result;
    }

    /**
     * Get snippet from string
     * @param $par_Content
     * @param $par_Pos
     * @return string|string[]
     */
    private static function getFragment($par_Content, $par_Pos)
    {
        $l_MaxChars = 120;

        $par_Content = preg_replace('/[\x00-\x1F\x80-\xFF]/', '~', $par_Content);

        $l_MaxLen   = strlen($par_Content);
        $l_RightPos = min($par_Pos + $l_MaxChars, $l_MaxLen);
        $l_MinPos   = max(0, $par_Pos - $l_MaxChars);

        $l_Res = ($l_MinPos > 0 ? '…' : '') . substr($par_Content, $l_MinPos, $par_Pos - $l_MinPos) . '__AI_MARKER__' . substr($par_Content, $par_Pos, $l_RightPos - $par_Pos - 1);

        $l_Res = AibolitHelpers::makeSafeFn(Normalization::normalize($l_Res));

        $l_Res = str_replace('~', ' ', $l_Res);

        $l_Res = preg_replace('~[\s\t]+~', ' ', $l_Res);

        $l_Res = str_replace('' . '?php', '' . '?php ', $l_Res);

        return $l_Res;
    }
}
/**
 * Class MDSPreScanQuery generates PreScan SQL Query to get suspicious rows
 */
class MDSPreScanQuery
{
    private $aliases = [];
    private $limit = 0;
    private $last = 0;
    private $key;
    private $table;
    private $fields;
    private $prescan;

    /**
     * MDSPreScanQuery constructor.
     * @param $prescan
     * @param $fields
     * @param $key
     * @param $table
     * @param $db
     * @param int $limit
     * @param int $last
     */
    public function __construct($prescan, $fields, $key, $table, $db, $limit = 0, $last = 0)
    {
        $this->limit = $limit;
        $this->prescan = $prescan;
        $this->fields = $fields;
        $this->key = $key;
        $this->table = $table;
        $this->last = $last;
        $this->db = $db;
        $this->generateAliases();
    }

    /**
     * @return array
     */
    public function getAliases()
    {
        return $this->aliases;
    }

    /**
     * @param $alias
     * @return bool|string
     */
    public function getFieldByAlias($alias)
    {
        foreach ($this->aliases as $key => $field) {
            if ($field === $alias) {
                return $key;
            }
        }
        return false;
    }

    /**
     * @param $value
     */
    public function setLastKey($value)
    {
        $this->last = $value;
    }

    /**
     * @return int
     */
    public function getKey()
    {
        return $this->key;
    }

    /**
     * @return string
     */
    public function getDB()
    {
        return $this->db;
    }

    /**
     * @return string
     */
    public function getTable()
    {
        return $this->table;
    }

    /**
     * Generate pre scan sql query
     * @return string
     */
    public function generateSqlQuery()
    {
        $res = 'SELECT ';
        $numItems = count($this->aliases);
        $i = 0;
        foreach($this->aliases as $column => $alias) {
            $res .= $column . ' as ' . $alias;
            if(++$i !== $numItems) {
                $res .= ',';
            }
        }
        $res .= ' FROM ' . $this->db . '.' . $this->table;
        $res .= ' WHERE ' . $this->key . ' > ' . $this->last;
        $res .= ' AND (' . $this->generatePreScanClause() . ')';
        $res .= ' ORDER BY ' . $this->key;
        if ($this->limit > 0) {
            $res .= ' LIMIT ' . $this->limit;
        }
        $res .= ';';
        return $res;
    }

    /**
     * generate aliases for fields
     */
    private function generateAliases()
    {
        $alphabet = 'abcdefghijklmnopqrstuvwxyz';
        $fields = $this->fields;
        $fields[] = $this->key;
        $res = [];
        for ($i = 0, $iMax = count($fields); $i < $iMax; $i++) {
            $res[$fields[$i]] = $alphabet[$i];
        }
        $this->aliases = $res;
    }


    /**
     * Generate where clause part for sql pre scan query
     * @return string
     */
    private function generatePreScanClause()
    {
        $res = '';
        for ($i = 0, $iMax = count($this->fields); $i < $iMax; $i++) {
            $res .= str_replace('$$FF$$', $this->fields[$i], '(' . $this->prescan . ')');
            if ($i !== $iMax - 1) {
                $res .= ' OR ';
            }
        }
        return $res;
    }
}
/**
 * Class MDSScannerTable module for scan whole table
 */
class MDSScannerTable
{
    /**
     * @param mysqli        $connection
     * @param string        $query
     * @param array         $signature_db
     * @param int           $max_clean
     * @param array         $clean_db
     * @param MDSProgress   $progress
     * @param MDSState      $state
     * @param MDSJSONReport $report
     * @param MDSBackup     $backup
     * @param Logger        $log
     * @throws Exception
     */
    public static function scan($connection, $query, $signature_db, $max_clean, $clean_db = null, $progress = null, $state = null, $report = null, $backup = null, $log = null, $table_config = null)
    {
        $total_scanned = 0;
        $detected = 0;
        $cleaned = 0;
        list($min_key, $last_key) = $connection->query('SELECT MIN(' . $query->getKey() .') as start_key, MAX(' . $query->getKey() .') as last_key FROM ' . $query->getDB() . '.' . $query->getTable() . ';')->fetch_array(MYSQLI_NUM);
        if ($progress instanceof MDSProgress) {
            $progress->setKeysRange($min_key, $last_key);
        }
        $res = $connection->query($query->generateSqlQuery());
        if (self::isCanceled($state)) {
            $log->info('Task canceled');
            $report->setState(MDSJSONReport::STATE_CANCELED);
            return;
        }
        while($res && $res->num_rows > 0) {
            if (!isset($clean_db)) {
                foreach ($res as $row) {
                    if (self::isCanceled($state)) {
                        $log->info('Task canceled in progress');
                        $report->setState(MDSJSONReport::STATE_CANCELED);
                        return;
                    }
                    $val = end($row);
                    $key = key($row);
                    array_pop($row);
                    $key = $query->getFieldByAlias($key);
                    foreach($row as $k => $v) {
                        $result = MDSScan::scan($v, $signature_db, $table_config);
                        if (isset($result['mlw'])) {
                            $log->debug(
                                sprintf(
                                    'DETECTED. Field: "%s", ID: %d, sn: "%s", content: "%s"',
                                    $query->getFieldByAlias($k),
                                    $val,
                                    $result['mlw']['sn'] ?? '',
                                    $result['mlw']['content']
                                )
                            );
                            if ($report !== null) {
                                $report->addDetected($result['mlw']['sn'], $result['mlw']['content'], $query->getTable(), $val, $query->getFieldByAlias($k));
                            }
                            $detected++;
                        }
                        if (isset($result['url']['black'])) {
                            foreach($result['url']['black'] as $url) {
                                if ($report !== null) {
                                    $report->addDetectedUrl($url['sigid'], $url['content'], $query->getTable(), $val, $query->getFieldByAlias($k));
                                }
                            }
                        }
                        if (isset($result['url']['unk'])) {
                            foreach($result['url']['unk'] as $url) {
                                if ($report !== null) {
                                    $report->addUnknownUrl($url['sigid']);
                                }
                            }
                        }
                    }
                    $total_scanned++;
                    if ($progress instanceof MDSProgress) {
                        $progress->updateProgress($val, $detected, 0, $query->getDB(), $query->getTable());
                    }
                    $query->setLastKey($val);
                }
            } else {
                $batch = [];
                $i = $max_clean;
                $forclean = [];
                $forscan = [];
                while (true) {
                    $row = $res->fetch_assoc();
                    if ($i-- && $row) {
                        $batch[end($row)] = $row;
                        continue;
                    } else if (!$row && empty($batch)) {
                        break;
                    }
                    if ($row) {
                        $batch[end($row)] = $row;
                    }
                    foreach ($batch as $index => $row) {
                        array_pop($row);
                        foreach ($row as $k => $v) {
                            $forscan[$index][$query->getFieldByAlias($k)] = $v;
                        }
                    }
                    $last = end($batch);
                    $last_key = end($last);
                    $query->setLastKey($last_key);
                    $scan_res = MDSScan::scanBatch($forscan, $signature_db, $table_config);
                    foreach ($scan_res as $index => $fields) {
                        if (self::isCanceled($state)) {
                            $report->setState(MDSJSONReport::STATE_CANCELED);
                            return;
                        }
                        foreach ($fields as $field => $result) {
                            if (isset($result['mlw'])) {
                                $log->debug(
                                    sprintf(
                                        'DETECTED. Field: "%s", ID: %d, sn: "%s", content: "%s"',
                                        $field,
                                        $index,
                                        $result['mlw']['sn'] ?? '',
                                        $result['mlw']['content'] ?? ''
                                    )
                                );
                                $detected++;
                                $forclean[$index][$field] = $forscan[$index][$field];
                            }
                            if (isset($result['url']['black'])) {
                                foreach($result['url']['black'] as $url) {
                                    $detected++;
                                    $forclean[$index][$field] = $forscan[$index][$field];
                                }
                            }
                            if (isset($result['url']['unk'])) {
                                foreach($result['url']['unk'] as $url) {
                                    if ($report !== null) {
                                        $report->addUnknownUrl($url['sigid']);
                                    }
                                }
                            }
                        }
                    }
                    if ($backup instanceof MDSBackup) {
                        foreach ($forclean as $index => $fields) {
                            foreach($fields as $field => $result) {
                                $backup->backup($query->getDB(), $query->getTable(), $field, $query->getKey(), $index, $forclean[$index][$field]);
                            }
                        }
                    }
                    $clean_res = MDSCleanup::cleanBatch($forclean, $detected, $cleaned, $clean_db, $connection, $query, $progress, $table_config);
                    if ($clean_res) {
                        foreach ($clean_res as $index => $fields) {
                            foreach ($fields as $field => $result) {
                                if (!$result) {
                                    $report->addCleanedError('', '', $query->getTable(), $index, $field, MDSErrors::MDS_CLEANUP_ERROR);
                                } else {
                                    foreach ($result as $val) {
                                        $log->debug(
                                            sprintf('CLEANED. Field: "%s", ID: %d, sn: %s', $field, $index,
                                                $val['id'] ?? '')
                                        );
                                        $report->addCleaned($val['id'], $scan_res[$index][$field]['mlw']['content'],
                                            $query->getTable(), $index, $field);
                                    }
                                }
                            }
                        }
                    }
                    $total_scanned += count($batch);
                    if ($progress instanceof MDSProgress) {
                        $progress->updateProgress($last_key, $detected, $cleaned, $query->getDB(), $query->getTable());
                    }
                    $batch = [];
                    $i = $max_clean;
                    $forclean = [];
                    $forscan = [];
                }
            }
            $res = $connection->query($query->generateSqlQuery());
        }

        $log->info(
            sprintf(
                'Scanning table "%s" finished. Scanned: %d, Detected: %d, Cleaned: %d',
                $query->getTable(),
                $total_scanned,
                $detected,
                $cleaned
            )
        );

        if ($report !== null) {
            $report->addTotalTableRows($query->getTable(), $total_scanned);
        }

        if ($res === false) {
            $log->error('Error with db connection ' . $connection->error);
            throw new MDSException(MDSErrors::MDS_DROP_CONNECT_ERROR, $connection->error);
        }
    }

    /**
     * Check on cancel
     * @param MDSState  $state
     * @return bool
     */
    private static function isCanceled($state)
    {
        if (is_null($state)) {
            return false;
        }
        return $state->isCanceled();
    }
}
/**
 * Class MDSScanner module for scan whole user
 */
class MDSScanner
{
    /**
     * @param string                $prescan - prescan string
     * @param string                $database - db name (null to scan all dbs that user have access to)
     * @param string                $prefix - prefix (null to disable filter by prefix)
     * @param MDSFindTables         $mds_find
     * @param mysqli                $connection
     * @param LoadSignaturesForScan $scan_signatures
     * @param int                   $max_clean
     * @param array                 $clean_db
     * @param MDSProgress           $progress
     * @param MDSState              $state
     * @param MDSJSONReport         $report
     * @param MDSBackup             $backup
     * @param bool                  $scan
     * @param bool                  $clean
     * @param Logger $log
     * @throws Exception
     */
    public static function scan($prescan, $database, $prefix, $mds_find, $connection, $scan_signatures, $max_clean = 100, $clean_db = null, $progress = null, $state = null, $report = null, $backup = null, $scan = true, $clean = false, $log = null)
    {

        $start_time = microtime(true);

        $tables = $mds_find->find($database, $prefix);
        if (empty($tables)) {
            $log->error('Not found any supported tables. Nothing to scan.');
            throw new MDSException(MDSErrors::MDS_NO_SUP_TABLES_ERROR, $database, $report->getUser(), $report->getHost());
        }

        if ($progress instanceof MDSProgress) {
            $progress->setTables($tables);
        }

        if (!$scan && !$clean) {
            return;
        }

        $log->info('MDS Scan: started');

        if ($progress instanceof MDSProgress) {
            $progress->setCurrentTable(0, $tables[0]);
        }
        
        foreach($tables as $i => $table) {
            $scan_signatures->setOwnUrl($table['domain_name']);
            $prescan_query = new MDSPreScanQuery($prescan, $table['config']['fields'], $table['config']['key'], $table['table'], $table['db'], 10000);

            $log->debug(sprintf('Scanning table: "%s"', $table['table']));
            MDSScannerTable::scan($connection, $prescan_query, $scan_signatures, $max_clean, $clean_db, $progress, $state, $report, $backup, $log, $table['config']);
            if ($progress instanceof MDSProgress) {
                $progress->setCurrentTable($i, $table);
            }
        }
        
        if ($report !== null) {
            $report->setCountTablesScanned(count($tables));
            $report->setRunningTime(microtime(true) - $start_time);
        }

        $log->info(sprintf('MDS Scan: finished. Time taken: %f second(s)', microtime(true) - $start_time));

        if ($progress instanceof MDSProgress) {
            $progress->finalize();
        }

        if ($backup instanceof MDSBackup) {
            $backup->finish();
        }
    }
}
/**
 * The MDSState class is needed to pass the MDS state of work
 */
class MDSState
{
    private $cache_ttl              = 1; //sec
    private $cache_data             = null;
    private $last_update_time_cache = 0;
    
    const STATE_NEW         = 'new';
    const STATE_WORKING     = 'working';
    const STATE_DONE        = 'done';
    const STATE_CANCELED    = 'canceled';

    private $state_filepath = null;
   
    /**
     * MDSState constructor.
     * @param string $state_filepath
     * @param int $cache_ttl
     */
    public function __construct($state_filepath, $cache_ttl = 1)
    {
        $this->state_filepath   = $state_filepath;
        $this->cache_ttl        = $cache_ttl;
    }
    
    /**
     * Scan or cure process not started
     * @return bool
     */
    public function isNew()
    {
        return $this->getCurrentState() == self::STATE_NEW;
    }
    
    /**
     * The scan or cure process is currently running
     * @return bool
     */
    public function isWorking()
    {
        return $this->getCurrentState() == self::STATE_WORKING;
    }

    /**
     * The scan or cure process is canceled
     * @return bool
     */
    public function isCanceled()
    {
        return $this->getCurrentState() == self::STATE_CANCELED;
    }
    
    /**
     * The scan or cure process is done
     * @return bool
     */
    public function isDone()
    {
        return $this->getCurrentState() == self::STATE_DONE;
    }

    /**
     * Set process to work state
     * @return bool
     */
    public function setWorking()
    {
        return $this->setStateWithoutCheck(self::STATE_WORKING);
    }

    /**
     * Set process to done state
     * @return bool
     */
    public function setDone()
    {
        return $this->setStateWithoutCheck(self::STATE_DONE);
    }

    /**
     * Set process to canceled state
     * @return bool
     */
    public function setCanceled()
    {
        $func = function($data) {
            return ($data == self::STATE_WORKING) ? self::STATE_CANCELED : $data;
        };
        $new_data = $this->editFileWithClosure($this->state_filepath, $func);
        $this->setCache($new_data);
        return $new_data == self::STATE_CANCELED;
    }
    
    // /////////////////////////////////////////////////////////////////////////

    /**
     * Overwrite the file with new data with the condition programmed in the closure
     * @param string $filepath
     * @param function $edit_func
     * @param mixed $default
     * @return mixed
     */
    private function editFileWithClosure($filepath, $edit_func, $default = null)
    {
        $result = $default;
        $fh     = @fopen($filepath, 'c+');
        if (!$fh) {
            return $result;
        }
        if (flock($fh, LOCK_EX)) {
            $data   = trim(stream_get_contents($fh));
            $result = $edit_func($data);
            
            fseek($fh, 0);
            ftruncate($fh, 0);
            fwrite($fh, $result);
        }
        else {
            fclose($fh);
            return $result;
        }
        fclose($fh);
        return $result;
    }

    /**
     * Get file data
     * @param string $filepath
     * @return string|bool
     */
    private function readFile($filepath)
    {
        if (!file_exists($filepath)) {
            $this->setCache(false);
            return false;
        }
        $fh = @fopen($filepath, 'r');
        if (!$fh) {
            $this->setCache(false);
            return false;
        }
        $data = false;
        if (flock($fh, LOCK_SH)) {
            $data = trim(stream_get_contents($fh));
        }
        fclose($fh);
        $this->setCache($data);
        return $data;
    }

    /**
     * Set cache data
     * @param string $cache_data
     * @return void
     */
    private function setCache($cache_data)
    {
        $this->last_update_time_cache = time();
        $this->cache_data = $cache_data;
    }

    /**
     * Set state without checking
     * @param string $state
     * @return bool
     */
    private function setStateWithoutCheck($state)
    {
        $func = function($data) use ($state) {
            return $state;
        };
        $new_data = $this->editFileWithClosure($this->state_filepath, $func, false);
        $this->setCache($new_data);
        return (bool)$new_data;
    }

    /**
     * Get current status
     * @return string
     */
    private function getCurrentState()
    {
        $current_state = $this->cache_data;
        if (is_null($this->cache_data) || $this->last_update_time_cache + $this->cache_ttl < time()) {
            $current_state = $this->readFile($this->state_filepath);
        }
        if (in_array($current_state, [self::STATE_WORKING, self::STATE_DONE, self::STATE_CANCELED])) {
            return $current_state;
        }
        return self::STATE_NEW;
    }

}
/**
 * Class MDSBackup Backup data to csv
 */
class MDSBackup
{
    private $fhandle;
    private $hmemory;

    /**
     * MDSBackup constructor.
     * @param string $file
     */
    public function __construct($file = '')
    {
        if ($file == '') {
            $file = getcwd();
            $file .= '/mds_backup_' . time() . '.csv';
        }
        $this->fhandle = fopen($file, 'a');
        $this->hmemory = fopen('php://memory', 'w+');

        if (!($this->fhandle && $this->hmemory)) {
            throw new MDSException(MDSErrors::MDS_BACKUP_ERROR);
        }
    }

    /**
     * Backup one record to csv
     * @param $db
     * @param $table
     * @param $field
     * @param $id
     * @param $data
     */
    public function backup($db, $table, $field, $key, $id, $data)
    {
        fputcsv($this->hmemory, [$db, $table, $field, $key, $id, base64_encode($data)]);
        $size = fstat($this->hmemory);
        $size = $size['size'];
        if ($size > 32768) {
            $this->flush();
        }
    }

    /**
     * Backup array of records to csv
     * @param $rows
     */
    public function backupBatch($rows)
    {
        foreach($rows as list($db, $table, $field, $key, $id, $data)) {
             $this->backup($db, $table, $field, $key, $id, $data);
        }
    }

    /**
     * Flush to disk and close handles
     */
    public function finish()
    {
        $this->flush();
        fclose($this->hmemory);
        fclose($this->fhandle);
    }

    /**
     * Flush to disk
     */
    private function flush()
    {
        rewind($this->hmemory);
        stream_copy_to_stream($this->hmemory, $this->fhandle);
        fflush($this->fhandle);
        rewind($this->hmemory);
        ftruncate($this->hmemory, 0);
    }
}
class MDSCleanup
{
    public static function clean($content, $clean_db, $connection, $query, $field, $key, $report = null, $table_config = null)
    {
        $old_content = $content;
        $clean_result = CleanUnit::CleanContent($content, $clean_db, true, $table_config['escaped'] ?? false);
        if ($clean_result) {
            $query_str = 'UPDATE ' . $query->getDb() . '.' . $query->getTable() . ' SET ' . $field . '=\'' . $connection->real_escape_string($content) . '\'';
            $query_str .= ' WHERE ' . $query->getKey() . '=' . $key . ' AND ' . $field . '=\'' . $connection->real_escape_string($old_content) . '\';';
            if ($connection->query($query_str) && $connection->affected_rows === 1 && $old_content !== $content) {
                return $clean_result;
            }
        }
        return false;
    }

    public static function cleanBatch($content_for_clean, $detected, &$cleaned, $clean_db, $connection, $query, $progress = null, $table_config = null)
    {
        $res = [];
        if (!empty($content_for_clean)) {
            @$connection->begin_transaction(MYSQLI_TRANS_START_READ_WRITE);
            foreach ($content_for_clean as $index => $fields) {
                foreach($fields as $field => $result) {
                    $clean = self::clean($result, $clean_db, $connection, $query, $field, $index, null, $table_config);
                    if ($clean) {
                        $res[$index][$field] = $clean;
                        $cleaned++;
                    } else {
                        $res[$index][$field] = false;
                    }
                    if ($progress instanceof MDSProgress) {
                        $progress->updateProgress($index, $detected, $cleaned, $query->getDB(), $query->getTable());
                    }
                }
            }
            @$connection->commit();
        }
        return $res;
    }
}
/**
 * Class MDSRestore Restore data from csv backup
 */
class MDSRestore
{
    private $fhandle;
    private $connection;
    private $progress;
    private $report;
    private $current_row = 0;
    private $start_time = 0;
    private $state = null;
    private $log = null;

    /**
     * MDSRestore constructor.
     * @param string        $file
     * @param mysqli        $connection
     * @param MDSProgress   $progress
     * @param MDSJSONReport $report
     * @param MDSState      $state
     */
    public function __construct($file, $connection, $progress = null, $report = null, MDSState $state = null, $log = null)
    {
        if (!$this->fhandle = fopen($file, 'r')) {
            throw new MDSException(MDSErrors::MDS_RESTORE_BACKUP_ERROR, $file);
        }
        $this->connection = $connection;
        $this->progress = $progress;
        $this->report = $report;
        $this->state = $state;
        $this->log = $log;

        $file = new \SplFileObject($file, 'r');
        $file->setFlags(SplFileObject::READ_AHEAD | SplFileObject::SKIP_EMPTY | SplFileObject::DROP_NEW_LINE);
        $file->seek(PHP_INT_MAX);

        if ($progress instanceof MDSProgress) {
            $progress->setTotal($file->key());
            $progress->setKeysRange(0, $file->key());
            $progress->setTotalTable($file->key());
            $progress->setCurrentTable(0, '');
        }

        $this->start_time = microtime(true);
    }

    /**
     * Write to db one record
     * @param $db
     * @param $table
     * @param $field
     * @param $key
     * @param $id
     * @param $data
     * @return bool
     */
    public function writeToDb($db, $table, $field, $key, $id, $data)
    {
        $ret = false;
        $data = base64_decode($data);
        $query_str = 'UPDATE ' . $db . '.' . $table . ' SET ' . $field . '=\'' . $this->connection->real_escape_string($data) . '\'';
        $query_str .= ' WHERE ' . $key . '=' . $id .';';
        if ($this->connection->query($query_str) && $this->connection->affected_rows === 1) {
            $ret = true;
        }
        if ($this->progress instanceof MDSProgress) {
            $this->progress->updateProgress(++$this->current_row, 0, 0, $db, $table);
        }
        if (isset($this->report)) {
            if ($ret === true) {
                $this->report->addRestored($table, $id, $field);
            } else {
                $this->report->addRestoredError(MDSErrors::MDS_RESTORE_UPDATE_ERROR, $table, $id, $field);
            }

        }
        return $ret;
    }

    /**
     * Write to db array of records
     * @param $rows
     */
    public function writeToDbBatch($rows)
    {
        foreach($rows as list($db, $table, $field, $key, $id, $data)) {
            $this->writeToDb($db, $table, $field, $key, $id, $data);
        }
    }

    public function restore($count)
    {
        $batch = $count;
        $for_restore = [];
        while (true) {
            if ($this->isCanceled()) {
                $this->log->info('Task canceled in progress');
                $this->report->setState(MDSJSONReport::STATE_CANCELED);
                break;
            }
            $row = fgetcsv($this->fhandle);
            if ($batch-- && $row) {
                $for_restore[] = $row;
                continue;
            } else {
                if (!$row && empty($for_restore)) {
                    break;
                }
            }
            if ($row) {
                $for_restore[] = $row;
            }
            $this->writeToDbBatch($for_restore);
            $for_restore = [];
            $batch = $count;
        }
    }

    /**
     * Close file handle and save report
     */
    public function finish()
    {
        fclose($this->fhandle);
        if (isset($this->report)) {
            $this->report->setCountTablesScanned(1);
            $this->report->setRunningTime(microtime(true) - $this->start_time);
        }
    }
    
    /**
     * Check on cancel
     * @return bool
     */
    private function isCanceled()
    {
        if (is_null($this->state)) {
            return false;
        }
        return $this->state->isCanceled();
    }
    
}
/**
 * Class MDSUrls store urls data
 */
class MDSUrls
{
    private $optimized_db;
    private $urls;

    /**
     * MDSUrls constructor.
     * @param $file
     * @throws Exception
     */
    public function __construct($file)
    {
        if (empty($file) || !file_exists($file)) {
            throw new MDSException(MDSErrors::MDS_DB_URLS_ERROR, $file);
        }

        $db = new \SplFileObject($file, 'r');
        $db->setFlags(SplFileObject::READ_AHEAD | SplFileObject::SKIP_EMPTY | SplFileObject::DROP_NEW_LINE);
        foreach ($db as $url) {
            $url = explode('-', $url, 2);
            $this->urls[$url[0]] = strpos($url[1],'//') === 0 ? substr_replace($url[1],'//(www\.)?',0,2) : $url[1];
        }
        unset($db);

        $this->optimized_db = $this->urls;
        $this->optSig($this->optimized_db);
    }

    /**
     * Signature optimization (glue)
     * @param $sigs
     */
    private function optSig(&$sigs)
    {
        $sigs = array_unique($sigs);

        // Add SigId
        foreach ($sigs as $index => &$s) {
            $s .= '(?<X' . $index . '>)';
        }
        unset($s);

        $fix = [
            '([^\?\s])\({0,1}\.[\+\*]\){0,1}\2[a-z]*e'  => '(?J)\.[+*](?<=(?<d>[^\?\s])\(..|(?<d>[^\?\s])..)\)?\g{d}[a-z]*e',
            'http://.+?/.+?\.php\?a'                    => 'http://[^?\s]++(?<=\.php)\?a',
            '\s*[\'"]{0,1}.+?[\'"]{0,1}\s*'             => '.+?',
            '[\'"]{0,1}.+?[\'"]{0,1}'                   => '.+?'
        ];

        $sigs = str_replace(array_keys($fix), array_values($fix), $sigs);
        
        $fix = [
            '~^\\\\[d]\+&@~'                            => '&@(?<=\d..)',
            '~^((\[\'"\]|\\\\s|@)(\{0,1\}\.?|[?*]))+~'  => ''
        ];

        $sigs = preg_replace(array_keys($fix), array_values($fix), $sigs);

        $this->optSigCheck($sigs);

        $tmp = [];
        foreach ($sigs as $i => $s) {
            if (!preg_match('~^(?>(?!\.[*+]|\\\\\d)(?:\\\\.|\[.+?\]|.))+$~', $s)) {
                unset($sigs[$i]);
                $tmp[] = $s;
            }
        }
        
        usort($sigs, 'strcasecmp');
        $txt = implode("\n", $sigs);

        for ($i = 24; $i >= 1; ($i > 4) ? $i -= 4 : --$i) {
            $txt = preg_replace_callback('#^((?>(?:\\\\.|\\[.+?\\]|[^(\n]|\((?:\\\\.|[^)(\n])++\))(?:[*?+]\+?|\{\d+(?:,\d*)?\}[+?]?|)){' . $i . ',})[^\n]*+(?:\\n\\1(?![{?*+]).+)+#im', [$this, 'optMergePrefixes'], $txt);
        }

        $sigs = array_merge(explode("\n", $txt), $tmp);
        
        $this->optSigCheck($sigs);
    }

    /**
     * @param $m
     * @return string
     */
    private function optMergePrefixes($m)
    {
        $limit = 8000;

        $prefix     = $m[1];
        $prefix_len = strlen($prefix);

        $len = $prefix_len;
        $r   = [];

        $suffixes = [];
        foreach (explode("\n", $m[0]) as $line) {

            if (strlen($line) > $limit) {
                $r[] = $line;
                continue;
            }

            $s = substr($line, $prefix_len);
            $len += strlen($s);
            if ($len > $limit) {
                if (count($suffixes) == 1) {
                    $r[] = $prefix . $suffixes[0];
                } else {
                    $r[] = $prefix . '(?:' . implode('|', $suffixes) . ')';
                }
                $suffixes = [];
                $len      = $prefix_len + strlen($s);
            }
            $suffixes[] = $s;
        }

        if (!empty($suffixes)) {
            if (count($suffixes) == 1) {
                $r[] = $prefix . $suffixes[0];
            } else {
                $r[] = $prefix . '(?:' . implode('|', $suffixes) . ')';
            }
        }

        return implode("\n", $r);
    }

    /*
     * Checking errors in pattern
     */
    private function optSigCheck(&$sigs)
    {
        $result = true;

        foreach ($sigs as $k => $sig) {
            if (trim($sig) == "") {
                unset($sigs[$k]);
                $result = false;
            }

            if (@preg_match('~' . $sig . '~smiS', '') === false) {
                $error = error_get_last();
                unset($sigs[$k]);
                $result = false;
            }
        }

        return $result;
    }

    /**
     * Return optimized db
     * @return mixed
     */
    public function getDb()
    {
        return $this->optimized_db;
    }

    public function getSig($l_Found)
    {
        foreach ($l_Found as $key => &$v) {
            if (is_string($key) && $v[1] !== -1 && strlen($key) > 1) {
                return 'CMW-URL-' . substr($key, 1);
            }
        }
        return null;
    }

    public function getSigUrl($id)
    {
        if (strpos($id, 'CMW-URL-') !== false) {
            $id = (int)str_replace('CMW-URL-', '', $id);
        }
        return $this->urls[$id];
    }

}
class MDSErrors
{
    const MDS_CONNECT_ERROR             = 1;
    const MDS_BACKUP_ERROR              = 2;
    const MDS_PROGRESS_FILE_ERROR       = 3;
    const MDS_PROGRESS_SHMEM_ERROR      = 4;
    const MDS_PROGRESS_SHMEM_CRT_ERROR  = 5;
    const MDS_RESTORE_BACKUP_ERROR      = 6;
    const MDS_NO_SUP_TABLES_ERROR       = 7;
    const MDS_CONFIG_ERROR              = 8;
    const MDS_DB_URLS_ERROR             = 9;
    const MDS_NO_DATABASE               = 10;
    const MDS_PRESCAN_CONFIG_ERROR      = 11;
    const MDS_REPORT_ERROR              = 12;

    const MDS_DROP_CONNECT_ERROR        = 13;

    const MDS_AVD_DB_NOTFOUND           = 14;
    const MDS_AVD_DB_INVALID            = 15;
    const MDS_INVALID_CMS_CONFIG        = 16;
    const MDS_CMS_CONFIG_NOTSUP         = 17;
    const MDS_MULTIPLE_DBS              = 18;
    const MDS_NO_SCANNED                = 19;

    const MDS_CLEANUP_ERROR             = 101;
    const MDS_RESTORE_UPDATE_ERROR      = 102;

    const MESSAGES = [
        self::MDS_CONNECT_ERROR               => 'Can\'t connect to database: %s',
        self::MDS_BACKUP_ERROR                => 'Can\'t create backup file in %s',
        self::MDS_PROGRESS_FILE_ERROR         => 'Can\'t create progress file in %s',
        self::MDS_PROGRESS_SHMEM_ERROR        => 'Can\'t use progress shared memory with key %s',
        self::MDS_PROGRESS_SHMEM_CRT_ERROR    => 'Can\'t create progress shared memory with key %s',
        self::MDS_RESTORE_BACKUP_ERROR        => 'Can\'t open backup file for restore in %s',
        self::MDS_NO_SUP_TABLES_ERROR         => 'Not found any supported tables in db %s in %s@%s',
        self::MDS_CONFIG_ERROR                => 'Can\'t open configuration file in %s',
        self::MDS_DB_URLS_ERROR               => 'Can\'t open urls db file %s',
        self::MDS_DROP_CONNECT_ERROR          => 'Lost connection to database: %s',
        self::MDS_NO_DATABASE                 => 'No database selected. Please, provide database name.',
        self::MDS_PRESCAN_CONFIG_ERROR        => 'Can\'t load prescan config from %s',
        self::MDS_REPORT_ERROR                => 'Can\'t write report to %s',
        self::MDS_CLEANUP_ERROR               => 'Error in cleanup during update table record.',
        self::MDS_RESTORE_UPDATE_ERROR        => 'Error in restore during update table record.',
        self::MDS_AVD_DB_NOTFOUND             => 'Failed loading DB from "%s": DB file not found.',
        self::MDS_AVD_DB_INVALID              => 'Failed loading DB from "%s": invalid DB format.',
        self::MDS_INVALID_CMS_CONFIG          => 'Failed loading CMS config %s',
        self::MDS_CMS_CONFIG_NOTSUP           => 'Can\'t parse config for CMS: %s',
        self::MDS_MULTIPLE_DBS                => 'For multiple DBs we support only scan, please select one db for work.',
        self::MDS_NO_SCANNED                  => 'No database to process.',
    ];

    public static function getErrorMessage($errcode, ...$args) {
        return vsprintf(self::MESSAGES[$errcode] ?? '', ...$args);
    }

}
class MDSException extends Exception
{
    private $_errcode = 0;
    private $_errmsg = '';

    public function __construct($errcode, ...$args)
    {
        $this->_errcode = $errcode;
        $this->_errmsg = MDSErrors::getErrorMessage($errcode, $args);
        parent::__construct($this->_errmsg);
    }

    public function getErrCode()
    {
        return $this->_errcode;
    }

    public function getErrMsg()
    {
        return $this->_errmsg;
    }
}
class MDSDBCredsFromConfig
{
    private $finder;
    private $creds = [];

    public function __construct($finder, $path)
    {
        $res = [];
        $this->finder = $finder;
        foreach ($this->finder->find($path) as $file_config) {
            $config = @file_get_contents($file_config, false, null, 0, 50000);
            if (preg_match('~define\(\s*\'DB_NAME\'\s*,\s*\'([^\']+)\'~msi', $config,$matches)) {
                $res['db_name'] = $matches[1];
            }
            if (preg_match('~define\(\s*\'DB_USER\'\s*,\s*\'([^\']+)\'~msi', $config,$matches)) {
                $res['db_user'] = $matches[1];
            }
            if (preg_match('~define\(\s*\'DB_PASSWORD\'\s*,\s*\'([^\']+)\'~msi', $config,$matches)) {
                $res['db_pass'] = $matches[1];
            }
            if (preg_match('~define\(\s*\'DB_HOST\'\s*,\s*\'([^\']+)\'~msi', $config,$matches)) {
                $host = explode(':', $matches[1]);
                $res['db_host'] = $host[0];
                $res['db_port'] = isset($host[1]) ? (int)$host[1] : 3306;
            }
            if (preg_match('~table_prefix\s*=\s*\'([^\']+)\';~msi', $config,$matches)) {
                $res['db_prefix'] = $matches[1];
            }

            if (isset($res['db_name']) && isset($res['db_user']) && isset($res['db_pass'])
                && isset($res['db_host']) && isset($res['db_port']) && isset($res['db_prefix'])
            ) {
                $this->creds[] = $res;
            }
        }
        $this->creds = array_unique($this->creds, SORT_REGULAR);
    }

    public function getCreds()
    {
        return $this->creds;
    }

    public function printCreds()
    {
        echo 'Found following db credentials: ' . PHP_EOL;
        foreach ($this->creds as $db_cred) {
            echo '--------------------------------------------------------' . PHP_EOL;
            echo 'Host:   ' . $db_cred['db_host']   . PHP_EOL;
            echo 'Port:   ' . $db_cred['db_port']   . PHP_EOL;
            echo 'User:   ' . $db_cred['db_user']   . PHP_EOL;
            echo 'Pass:   ' . $db_cred['db_pass']   . PHP_EOL;
            echo 'Name:   ' . $db_cred['db_name']   . PHP_EOL;
            echo 'Prefix: ' . $db_cred['db_prefix'] . PHP_EOL;
        }
    }

    public function printForXArgs()
    {
        foreach ($this->creds as $db_cred) {
            echo  $db_cred['db_host'] . ';;' . $db_cred['db_port'] . ';;' . $db_cred['db_user'] . ';;' . $db_cred['db_pass'] . ';;' . $db_cred['db_name'] . ';;' . $db_cred['db_prefix'] . PHP_EOL;
        }
    }

}
class MDSCMSConfigFilter
{
    private $followSymlink = true;

    public function __construct()
    {

    }

    private function fileExistsAndNotNull($path)
    {
        return (is_file($path) && file_exists($path) && (filesize($path) > 2048));
    }

    public function needToScan($file, $stat = false, $only_dir = false)
    {
        if (is_dir($file)) {
            return true;
        }
        if ($this->fileExistsAndNotNull($file) && basename($file) === 'wp-config.php') {
            return true;
        }
        return false;
    }

    public function isFollowSymlink()
    {
        return $this->followSymlink;
    }

}

class MDSCHRequest
{

    const API_URL = 'https://api.imunify360.com/api/send-message';
    const DEBUG_API_URL = 'http://127.0.0.1:8888';

    private $timeout = 10;
    private $debug = false;

    /**
     * MDSCHRequest constructor.
     * @param int $timeout
     */
    public function __construct($timeout = 10, $debug = false)
    {
        $this->timeout = $timeout;
        $this->debug = $debug;
    }

    /**
     * @param $data
     * @return bool|array
     */
    public function request($data)
    {
        $result = '';
        $json_data = json_encode($data);

        try {
            $ch = curl_init();
            curl_setopt($ch, CURLOPT_URL, $this->getApiUrl());
            curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
            curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, false);
            curl_setopt($ch, CURLOPT_TIMEOUT, $this->timeout);
            curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, $this->timeout);
            curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
            curl_setopt($ch, CURLOPT_HTTPHEADER, ['Content-Type: application/json']);
            curl_setopt($ch, CURLOPT_POSTFIELDS, $json_data);
            $result = curl_exec($ch);
            curl_close($ch);
        } catch (Exception $e) {
            fwrite(STDERR, 'Warning: [MDS] Curl: ' . $e->getMessage() . PHP_EOL);
            return false;
        }
        return @json_decode($result, true);
    }

    private function getApiUrl()
    {
        return $this->debug ? self::DEBUG_API_URL : self::API_URL;
    }
}
class MDSSendToCH
{
    private $request = null;
    private $report = null;
    private $lic = null;

    public function __construct($request, $lic)
    {
        $this->request = $request;
        $this->lic = $lic;
    }

    public function prepareData($report)
    {
        $this->report = $report;
        $this->array_walk_recursive_delete($this->report, function($value, $key, $userdata) {
            if ($key === 'row_ids' || $key === 'rows_with_error') {
                return true;
            }
            return false;
        });
        $this->report = ['items' => [$this->report]];
    }

    public function send()
    {
        $license = $this->lic->getLicData();
        $data = [
            'method' => 'MDS_SCAN_LIST',
            'license' => $license,
            'payload' => $this->report,
            'server_id' => $license['id'],
        ];
        $res = $this->request->request($data);
        if ($res['status'] === 'ok') {
            return true;
        } else {
            fwrite(STDERR, 'Warning: [MDS] Invalid response: ' . json_encode($res) . PHP_EOL);
            return false;
        }
    }

    /**
     * Remove any elements where the callback returns true
     *
     * @param  array    $array    the array to walk
     * @param  callable $callback callback takes ($value, $key, $userdata)
     * @param  mixed    $userdata additional data passed to the callback.
     * @return array
     */
    private function array_walk_recursive_delete(array &$array, callable $callback, $userdata = null)
    {
        foreach ($array as $key => &$value) {
            if (is_array($value)) {
                $value = $this->array_walk_recursive_delete($value, $callback, $userdata);
            }
            if ($callback($value, $key, $userdata)) {
                unset($array[$key]);
            }
        }
        return $array;
    }
}

class MDSDetachedMode
{
    protected $workdir;
    protected $scan_id;
    protected $pid_file;
    protected $done_file;
    protected $sock_file;
    protected $complete = [
        'scan' => 'MALWARE_SCAN_COMPLETE',
        'cleanup' => 'MALWARE_CLEAN_COMPLETE',
        'restore' => 'MALWARE_RESTORE_COMPLETE'
    ];

    protected $op = null;

    public function __construct($scan_id, $basedir = '/var/imunify360/dbscan/run', $sock_file = '/var/run/defence360agent/generic_sensor.sock.2')
    {
        $this->scan_id  = $scan_id;
        $this->setWorkDir($basedir, $scan_id);
        $this->pid_file     = $this->workdir . '/pid';
        $this->done_file    = $this->workdir . '/done';
        $this->setSocketFile($sock_file);
        $this->savePid();
        $this->checkWorkDir($this->workdir);
    }

    public function getWorkDir()
    {
        return $this->workdir;
    }

    protected function checkWorkDir($workdir)
    {
        if (!file_exists($workdir) && !mkdir($workdir) && !is_dir($workdir)) {
            die('Error! Cannot create workdir ' . $workdir . ' for detached scan.');
        } elseif (file_exists($workdir) && !is_writable($workdir)) {
            die('Error! Workdir ' . $workdir . ' is not writable.');
        } 
    }

    protected function savePid()
    {
        file_put_contents($this->pid_file, strval(getmypid()));
    }

    public function complete()
    {
        @touch($this->done_file);
        $complete = [
            'method'        => 'MALWARE_SCAN_COMPLETE',
            'scan_id'       => $this->scan_id,
            'resource_type' => 'db',
        ];
        if ($this->op && isset($this->complete[$this->op])) {
            $complete['method'] = $this->complete[$this->op];
        }
        $json_complete = json_encode($complete) . "\n";
        $socket = @fsockopen('unix://' . $this->sock_file);
        if (is_resource($socket)) {
            stream_set_blocking($socket, false);
            fwrite($socket, $json_complete);
            fclose($socket);
        }
    }

    public function setOp($op)
    {
        if ($op && isset($this->complete[$op])) {
            $this->op = $op;
        }
    }

    protected function setWorkDir($dir, $scan_id)
    {
        $this->workdir = $dir . '/' . $scan_id;
    }

    protected function setSocketFile($sock)
    {
        $this->sock_file = $sock;
    }
}

class MDSDBCredsFromAVD
{
    protected $dbh;
    
    protected $avd_path_prev    = '/var/imunify360/components_versions.sqlite3';
    protected $avd_path         = '/var/lib/cloudlinux-app-version-detector/components_versions.sqlite3';
    protected $found_apps       = 0;
    private $path_field         = 'real_path';

    public function __construct()
    {
        $path = file_exists($this->avd_path) ? $this->avd_path : (file_exists($this->avd_path_prev) ? $this->avd_path_prev : '');

        if ($path === '') {
            throw new MDSException(MDSErrors::MDS_AVD_DB_NOTFOUND, $this->avd_path);
        }

        $this->openAppDB($path);
        if (!$this->haveTable('apps')) {
            throw new MDSException(MDSErrors::MDS_AVD_DB_INVALID, $this->avd_path);
        }
        if (!$this->haveColumn('apps', $this->path_field)) {
            $this->path_field = 'path';
        }
    }

    public function getCredsFromApps($paths, $apps = null, $recursive = false)
    {
        foreach($this->getApps($paths, $apps, $recursive) as $row) {
            $config = MDSCMSAddonFactory::getCMSConfigInstance($row['title'], $row[$this->path_field]);
            $res = $config->parseConfig();
            $res['app_owner_uid'] = $row['app_uid'] ?? null;
            yield $res;
        }
        $this->dbh = null;
    }

    public function getAppsCount()
    {
        return $this->found_apps;
    }

    public function countApps($paths, $apps = null, $recursive = false)
    {
        list($sql, $params) = $this->generateAppDBQuery($recursive, $apps, $paths);
        $count_sql = 'SELECT COUNT(*) as count FROM (' . $sql . ');';
        $result = $this->execQueryToAppDB($count_sql, $params);
        $this->found_apps = (int)$result->fetchArray(SQLITE3_NUM)[0];
    }

    ////////////////////////////////////////////////////////////////////////////
    
    private function getApps($paths, $apps, $recursive)
    {
        list($sql, $params) = $this->generateAppDBQuery($recursive, $apps, $paths);
        $res = $this->execQueryToAppDB($sql, $params);
        while ($row = $res->fetchArray(SQLITE3_ASSOC)) {
            yield $row;
        }
    }

    private function openAppDB($db)
    {
        $this->dbh = new \SQLite3($db);
    }
    
    private function haveColumn($table_name, $column_name)
    {
        $sql    = 'PRAGMA table_info("' . $table_name . '")';
        $stmt   = $this->dbh->prepare($sql);
        $result = $stmt->execute();
        while ($row = $result->fetchArray(SQLITE3_ASSOC))
        {
            if ($row['name'] == $column_name) {
                return true;
            }
        }
        return false;
    }    
    
    private function haveTable($table_name)
    {
        $sql = 'PRAGMA table_info("' . $table_name . '")';
        $stmt   = $this->dbh->prepare($sql);
        $result = $stmt->execute();
        return (bool)$result->fetchArray();
    }    

    /**
     * @param string $query
     * @param array  $params
     *
     * @return SQLite3Result
     */
    private function execQueryToAppDB(string $query, array $params)
    {
        $stmt  = $this->dbh->prepare($query);
        foreach ($params as $param_name => $param_value)
        {
            $stmt->bindValue($param_name, $param_value);
        }
        return $stmt->execute();
    }

    /**
     * @param $recursive
     * @param $apps
     * @param $paths
     *
     * @return array
     */
    private function generateAppDBQuery($recursive, $apps, $paths): array
    {
        $params = [];
        
        $sql = 'SELECT *'
            . ' FROM apps'
            . ' WHERE (';
        for ($i = 0, $iMax = count($paths); $i < $iMax; $i++) {
            $sql .= $this->path_field . ' ';
            $sql .= $recursive ? 'LIKE ' : '= ';
            $sql .= ':path' . $i;
            $params[':path' . $i] = $recursive ? $paths[$i] . '%' : $paths[$i];
            if ($i !== $iMax - 1) {
                $sql .= ' OR ';
            }
        }

        $sql .= ')';
        
        $sql .= isset($apps) ? ' AND title IN (' : '';
        for ($i = 0, $iMax = count($apps); $i < $iMax; $i++) {
            $sql .= ':app' . $i;
            $params[':app' . $i] = $apps[$i];
            if ($i !== $iMax - 1) {
                $sql .= ', ';
            }
        }
        $sql .= isset($apps) ? ')' : '';
        $sql .= ' GROUP BY ' . $this->path_field . ', title';

        return [$sql, $params];
    }

}

class MDSCMSAddonFactory
{
    public static function getCMSConfigInstance($app, $path)
    {
        $class = 'MDS' . ucfirst(str_replace('_', '', $app)) . 'Config';

        if (!class_exists($class)) {
            throw new MDSException(MDSErrors::MDS_CMS_CONFIG_NOTSUP, $app);
        }
        return new $class($path);
    }
}

class MDSCMSAddon
{
    const CONFIG_FILE = '';
    const MIN_SIZE = '1000';

    protected $app;
    protected $path;

    public function __construct($path)
    {
        if (!file_exists($path . '/' . static::CONFIG_FILE)
            || !is_readable($path . '/' . static::CONFIG_FILE)
            || (filesize($path . '/' . static::CONFIG_FILE) < static::MIN_SIZE)
        ) {
            throw new MDSException(MDSErrors::MDS_INVALID_CMS_CONFIG, $path . '/' . static::CONFIG_FILE);
        }

        $this->path = $path;
    }

    public function parseConfig()
    {

    }

}
class MDSAVDPathFilter
{
    private $ignoreList = [];

    public function __construct($filepath)
    {
        if (!file_exists($filepath) || !is_file($filepath) || !is_readable($filepath)) {
            return;
        }

        $content = file_get_contents($filepath);
        $list = explode("\n", $content);
        foreach ($list as $base64_filepath) {
            if ($base64_filepath !== '') {
                $this->ignoreList[$base64_filepath] = '';
            }
        }
    }

    public function needToScan($file)
    {
        $tree = $this->getTree($file);
        if ($this->pathRelatesTo($tree, $this->ignoreList, true)) {
            return false;
        }
        return true;
    }

    private function getTree($file)
    {
        $tree = [];
        $path = $file;
        while ($path !== '.' && $path !== '/') {
            $path = dirname($path, 1);
            $tree[] = $path;
        }
        $tree[] = $file;
        return $tree;
    }

    private function pathRelatesTo($tree, $pathes, $base64 = false)
    {
        foreach ($tree as $path) {
            if ($base64) {
                $path = base64_encode($path);
            }
            if (isset($pathes[$path])) {
                return true;
            }
        }
        return false;
    }
}

class MDSCollectUrlsRequest
{

    const API_URL = 'https://api.imunify360.com/api/mds/check-urls';
    const DEBUG_API_URL = 'http://127.0.0.1:8888';

    private $timeout = 10;
    private $debug = false;

    /**
     * MDSCollectUrlsRequest constructor.
     * @param int $timeout
     */
    public function __construct($timeout = 10, $debug = false)
    {
        $this->timeout = $timeout;
        $this->debug = $debug;
    }

    /**
     * @param $data
     * @return bool|array
     */
    public function request($data)
    {
        $result = '';
        $json_data = json_encode($data);

        try {
            $ch = curl_init();
            curl_setopt($ch, CURLOPT_URL, $this->getApiUrl());
            curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
            curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, false);
            curl_setopt($ch, CURLOPT_TIMEOUT, $this->timeout);
            curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, $this->timeout);
            curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
            curl_setopt($ch, CURLOPT_HTTPHEADER, ['Content-Type: application/json']);
            curl_setopt($ch, CURLOPT_POSTFIELDS, $json_data);
            $result = curl_exec($ch);
            curl_close($ch);
        } catch (Exception $e) {
            fwrite(STDERR, 'Warning: [MDS] Curl: ' . $e->getMessage() . PHP_EOL);
            return false;
        }
        return @json_decode($result, true);
    }

    private function getApiUrl()
    {
        return $this->debug ? self::DEBUG_API_URL : self::API_URL;
    }
}
class MDSSendUrls
{
    private $request = null;

    public function __construct($request)
    {
        $this->request = $request;
    }

    public function send($urls)
    {
        $data = [
            'urls'      => $urls,
            'source'    => 'MDS',
        ];
        $res = $this->request->request($data);
        if ($res['status'] === 'ok') {
            return true;
        } else {
            fwrite(STDERR, 'Warning: [MDS] Invalid response: ' . json_encode($res) . PHP_EOL);
            return false;
        }
    }
}

class MDSWpcoreConfig extends MDSCMSAddon
{
    const CONFIG_FILE = 'wp-config.php';

    public function parseConfig()
    {
        $res = [];
        $config = @file_get_contents($this->path . '/' . self::CONFIG_FILE, false, null, 0, 50000);
        if (preg_match('~define\(\s*\'DB_NAME\'\s*,\s*\'([^\']+)\'~msi', $config,$matches)) {
            $res['db_name'] = $matches[1];
        }
        if (preg_match('~define\(\s*\'DB_USER\'\s*,\s*\'([^\']+)\'~msi', $config,$matches)) {
            $res['db_user'] = $matches[1];
        }
        if (preg_match('~define\(\s*\'DB_PASSWORD\'\s*,\s*\'([^\']+)\'~msi', $config,$matches)) {
            $res['db_pass'] = $matches[1];
        }
        if (preg_match('~table_prefix\s*=\s*\'([^\']+)\';~msi', $config,$matches)) {
            $res['db_prefix'] = $matches[1];
        }
        if (preg_match('~define\(\s*\'DB_HOST\'\s*,\s*\'([^\']+)\'~msi', $config,$matches)) {
            $host = explode(':', $matches[1]);
            $res['db_host'] = $host[0];
            $res['db_port'] = isset($host[1]) ? (int)$host[1] : 3306;
        }

        if (isset($res['db_name']) && isset($res['db_user']) && isset($res['db_pass']) && isset($res['db_host'])
            && isset($res['db_port']) && isset($res['db_prefix'])
        ) {
            $res['db_app'] = 'wp_core';
            $res['db_path'] = $this->path;
            return $res;
        } else {
            return false;
        }
    }
}
class LoadSignaturesForClean
{
    private $sig_db             = [];
    private $sig_db_meta_info   = [];
    private $sig_db_location    = 'internal';
    private $scan_db            = null;
    public  $_FlexDBShe         = [];

    private $deMapper           = '';

    public function __construct($signature, $avdb)
    {

        $this->sig_db_meta_info = [
            'build-date'    => 'n/a',
            'version'       => 'n/a',
            'release-type'  => 'n/a',
        ];

        if ($signature) {
            $db_raw                 = explode("\n", trim(base64_decode(trim($signature))));
            $this->sig_db_location  = 'external';
        } elseif (file_exists($avdb)) {
            $db_raw                 = explode("\n", trim(@gzinflate(base64_decode(str_rot13(strrev(trim(file_get_contents($avdb))))))));
            $this->sig_db_location  = 'external';
            echo "Loaded External DB\n";
        } else {
            InternalCleanSignatures::init();
            $db_raw = explode("\n", base64_decode(strrev(str_rot13(gzinflate(base64_decode(InternalCleanSignatures::$db))))));
        }
        
        foreach ($db_raw as $line) {
            $line = trim($line);
            if ($line == '') {
                continue;
            }

            $parsed = preg_split("/\t+/", $line);

            if ($parsed[0] == 'System-Data') {
                $meta_info                              = json_decode($parsed[3], true);
                $this->sig_db_meta_info['build-date']   = $meta_info['build-date'];
                $this->sig_db_meta_info['version']      = $meta_info['version'];
                $this->sig_db_meta_info['release-type'] = $meta_info['release-type'];
            } else {
                $db_item['id']          = $parsed[0];
                $db_item['mask_type']   = $parsed[1];

                $db_item['mask_type']   = str_replace('*.', '.*\.', $db_item['mask_type']);
                $db_item['mask_type']   = str_replace('PROCU_ANY', '.*', $db_item['mask_type']);
                $db_item['mask_type']   = str_replace('PROCU_PHP', '\.(suspected|vir|txt|phtml|pht|php\d*|php\..*)$', $db_item['mask_type']);
                $db_item['mask_type']   = str_replace('PROCU_HTML', '\.(htm|html|tpl|inc)$', $db_item['mask_type']);
                $db_item['mask_type']   = str_replace('PROCU_JS', '\.(js)$', $db_item['mask_type']);
                $db_item['mask_type']   = str_replace('PROCU_SS', '.*', $db_item['mask_type']);

                $db_item['sig_type']    = (int)$parsed[2];
                $db_item['sig_match']   = str_replace('~', '\~', trim($parsed[3]));
                $db_item['sig_match']   = str_replace('@<v>@', '\$[a-zA-Z0-9_]+', $db_item['sig_match']);
                $db_item['sig_match']   = str_replace('@<id>@', '[a-zA-Z0-9_]+', $db_item['sig_match']);
                $db_item['sig_match']   = str_replace('@<d>@', '\d+', $db_item['sig_match']);
                $db_item['sig_match']   = str_replace('@<qq>@', '[\'"]', $db_item['sig_match']);
                $db_item['sig_match']   = str_replace('@<q>@', '[\'"]{0,1}', $db_item['sig_match']);
                $db_item['sig_replace'] = trim(@$parsed[4]);

                if ($db_item['sig_match'] == '') {
                    throw new Exception($line);
                }

                $this->sig_db[] = $db_item;
                $this->_FlexDBShe[] = $db_item['sig_match'];  //rescan signs
            }
        }
        LoadSignaturesForScan::optSig($this->_FlexDBShe, false, 'AibolitHelpers::myCheckSum');
        $this->deMapper = @unserialize(@base64_decode($this->deMapper));
    }
    
    public function getDBLocation()
    {
        return $this->sig_db_location;
    }

    public function getDB()
    {
        return $this->sig_db;
    }
    
    public function getDBMetaInfo()
    {
        return $this->sig_db_meta_info;
    }

    public function getDeMapper()
    {
        return is_array($this->deMapper) ? $this->deMapper : false;
    }

    public function getScanDB()
    {
        return $this->scan_db;
    }

    public function setScanDB($db)
    {
        $this->scan_db = $db;
    }
}

class InternalCleanSignatures
{
    public static $db;

    public static function init()
    {
        $i000101010010110010 = '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'; //This variable will be filled by the building script.
        self::$db = $i000101010010110010;
    }
}
class ImLicense
{
    const VERIFY_FIELDS = ['id', 'status', 'group', 'limit', 'token_created_utc', 'token_expire_utc'];
    private $is_valid = false;
    private $raw_lic = [];
    private $valid_sign = '';
    private $pub_key = '';
    private $lic_path = '';
    private $pub_key_path = '';

    public function __construct($lic_path, $pub_key)
    {
        $this->lic_path = $lic_path;
        $this->pub_key_path = $pub_key;

        if (file_exists($lic_path) && filesize($lic_path) > 0 && is_readable($lic_path)) {
            $this->raw_lic = json_decode(file_get_contents($lic_path), true);
        }

        if (file_exists($pub_key) && filesize($pub_key) > 0 && is_readable($pub_key)) {
            $this->pub_key = file_get_contents($pub_key);
        }
        if ($this->isAllFieldsPresent()) {
            $this->findValidSignature();
        }
    }

    public function isValid()
    {
        return $this->is_valid;
    }

    public function getLicData()
    {
        if (!$this->is_valid || $this->valid_sign === '') {
            return false;
        }
        if (is_array($this->raw_lic) && $this->isAllFieldsPresent()) {
            return [
                'id'                => $this->raw_lic['id'],
                'status'            => $this->raw_lic['status'],
                'limit'             => $this->raw_lic['limit'],
                'token_created_utc' => $this->raw_lic['token_created_utc'],
                'token_expire_utc'  => $this->raw_lic['token_expire_utc'],
                'sign'              => $this->valid_sign,
            ];
        }
        return false;
    }

    private function isAllFieldsPresent()
    {
        if (!isset($this->raw_lic['signatures'])) {
            return false;
        }
        if ($this->pub_key === '') {
            return false;
        }
        foreach (self::VERIFY_FIELDS as $field) {
            if (!isset($this->raw_lic[$field])) {
                return false;
            }
        }
        return true;
    }

    private function findValidSignature()
    {
        foreach ($this->raw_lic['signatures'] as $sign) {
            $signature = base64_decode($sign);
            $content = '';
            foreach (self::VERIFY_FIELDS as $field) {
                $content .= $this->raw_lic[$field];
            }
            if (openssl_verify($content, $signature, $this->pub_key, OPENSSL_ALGO_SHA512)) {
                $this->valid_sign = $sign;
                $this->is_valid = true;
                return true;
            }
        }
        return false;
    }
}

class LoadSignaturesForScan
{
    private $sig_db             = [];
    private $sig_db_meta_info   = [];
    private $sig_db_location    = 'internal';

    private $mode;
    private $debug;

    public $_DBShe;
    public $X_DBShe;
    public $_FlexDBShe;
    public $X_FlexDBShe;
    public $XX_FlexDBShe;
    public $_ExceptFlex;
    public $_AdwareSig;
    public $_PhishingSig;
    public $_JSVirSig;
    public $X_JSVirSig;
    public $_SusDB;
    public $_SusDBPrio;
    public $_DeMapper;
    public $_Mnemo;

    public $whiteUrls;
    public $blackUrls;
    public $ownUrl = null;

    private $count;
    private $count_susp;
    private $result = 0;
    private $last_error = '';

    const SIGN_INTERNAL = 1;
    const SIGN_EXTERNAL = 2;
    const SIGN_IMPORT = 3;
    const SIGN_ERROR = 9;

    public function __construct($avdb_file, $mode, $debug)
    {
        $this->mode = $mode;
        $this->debug = $debug;
        $this->sig_db_meta_info = [
            'build-date'    => 'n/a',
            'version'       => 'n/a',
            'release-type'  => 'n/a',
        ];

        if ($avdb_file && file_exists($avdb_file)) {
            $avdb = explode("\n", gzinflate(base64_decode(str_rot13(strrev(trim(file_get_contents($avdb_file)))))));
            $this->sig_db_location  = 'external';

            $this->_DBShe       = explode("\n", base64_decode($avdb[0]));
            $this->X_DBShe      = explode("\n", base64_decode($avdb[1]));
            $this->_FlexDBShe   = explode("\n", base64_decode($avdb[2]));
            $this->X_FlexDBShe  = explode("\n", base64_decode($avdb[3]));
            $this->XX_FlexDBShe = explode("\n", base64_decode($avdb[4]));
            $this->_ExceptFlex  = explode("\n", base64_decode($avdb[5]));
            $this->_AdwareSig   = explode("\n", base64_decode($avdb[6]));
            $this->_PhishingSig = explode("\n", base64_decode($avdb[7]));
            $this->_JSVirSig    = explode("\n", base64_decode($avdb[8]));
            $this->X_JSVirSig   = explode("\n", base64_decode($avdb[9]));
            $this->_SusDB       = explode("\n", base64_decode($avdb[10]));
            $this->_SusDBPrio   = explode("\n", base64_decode($avdb[11]));
            $this->_DeMapper    = array_combine(explode("\n", base64_decode($avdb[12])), explode("\n", base64_decode($avdb[13])));
            $this->_Mnemo       = @array_flip(@array_combine(explode("\n", base64_decode($avdb[14])), explode("\n", base64_decode($avdb[15])))); //TODO: you need to remove array_flip and swap the keys and values in array_combine. Write a test: put the signature base in the tests folder and run a scan with this base on the VIRII folder - the result should not change, since the base is the same

            // get meta information
            $avdb_meta_info = json_decode(base64_decode($avdb[16]), true);

            $this->sig_db_meta_info['build-date'] = $avdb_meta_info ? $avdb_meta_info['build-date'] : 'n/a';
            $this->sig_db_meta_info['version'] = $avdb_meta_info ? $avdb_meta_info['version'] : 'n/a';
            $this->sig_db_meta_info['release-type'] = $avdb_meta_info ? $avdb_meta_info['release-type'] : 'n/a';

            if (count($this->_DBShe) <= 1) {
                $this->_DBShe = [];
            }

            if (count($this->X_DBShe) <= 1) {
                $this->X_DBShe = [];
            }

            if (count($this->_FlexDBShe) <= 1) {
                $this->_FlexDBShe = [];
            }

            if (count($this->X_FlexDBShe) <= 1) {
                $this->X_FlexDBShe = [];
            }

            if (count($this->XX_FlexDBShe) <= 1) {
                $this->XX_FlexDBShe = [];
            }

            if (count($this->_ExceptFlex) <= 1) {
                $this->_ExceptFlex = [];
            }

            if (count($this->_AdwareSig) <= 1) {
                $this->_AdwareSig = [];
            }

            if (count($this->_PhishingSig) <= 1) {
                $this->_PhishingSig = [];
            }

            if (count($this->X_JSVirSig) <= 1) {
                $this->X_JSVirSig = [];
            }

            if (count($this->_JSVirSig) <= 1) {
                $this->_JSVirSig = [];
            }

            if (count($this->_SusDB) <= 1) {
                $this->_SusDB = [];
            }

            if (count($this->_SusDBPrio) <= 1) {
                $this->_SusDBPrio = [];
            }

            $this->result = self::SIGN_EXTERNAL;
        } else {
            InternalSignatures::init();
            $this->_DBShe       = InternalSignatures::$_DBShe;
            $this->X_DBShe      = InternalSignatures::$X_DBShe;
            $this->_FlexDBShe   = InternalSignatures::$_FlexDBShe;
            $this->X_FlexDBShe  = InternalSignatures::$X_FlexDBShe;
            $this->XX_FlexDBShe = InternalSignatures::$XX_FlexDBShe;
            $this->_ExceptFlex  = InternalSignatures::$_ExceptFlex;
            $this->_AdwareSig   = InternalSignatures::$_AdwareSig;
            $this->_PhishingSig = InternalSignatures::$_PhishingSig;
            $this->_JSVirSig    = InternalSignatures::$_JSVirSig;
            $this->X_JSVirSig   = InternalSignatures::$X_JSVirSig;
            $this->_SusDB       = InternalSignatures::$_SusDB;
            $this->_SusDBPrio   = InternalSignatures::$_SusDBPrio;
            $this->_DeMapper    = InternalSignatures::$_DeMapper;
            $this->_Mnemo       = InternalSignatures::$_Mnemo;

            // get meta information
            $avdb_meta_info = InternalSignatures::$db_meta_info;

            $this->sig_db_meta_info['build-date'] = $avdb_meta_info ? $avdb_meta_info['build-date'] : 'n/a';
            $this->sig_db_meta_info['version'] = $avdb_meta_info ? $avdb_meta_info['version'] : 'n/a';
            $this->sig_db_meta_info['release-type'] = $avdb_meta_info ? $avdb_meta_info['release-type'] : 'n/a';

            $this->result = self::SIGN_INTERNAL;
        }

        // use only basic signature subset
        if ($mode < 2) {
            $this->X_FlexDBShe  = [];
            $this->XX_FlexDBShe = [];
            $this->X_JSVirSig   = [];
        }

        // Load custom signatures
        if (file_exists(__DIR__ . '/ai-bolit.sig')) {
            try {
                $s_file = new SplFileObject(__DIR__ . '/ai-bolit.sig');
                $s_file->setFlags(SplFileObject::READ_AHEAD | SplFileObject::SKIP_EMPTY | SplFileObject::DROP_NEW_LINE);
                foreach ($s_file as $line) {
                    $this->_FlexDBShe[] = preg_replace('#\G(?:[^~\\\\]+|\\\\.)*+\K~#', '\\~', $line); // escaping ~
                }

                $this->result = self::SIGN_IMPORT;
                $s_file = null; // file handler is closed
            }
            catch (Exception $e) {
                $this->result = self::SIGN_ERROR;
                $this->last_error = $e->getMessage();
            }
        }

        $this->count = count($this->_JSVirSig) + count($this->X_JSVirSig) + count($this->_DBShe) + count($this->X_DBShe) + count($this->_FlexDBShe) + count($this->X_FlexDBShe) + count($this->XX_FlexDBShe);
        $this->count_susp = $this->count + count($this->_SusDB);

        if (!$debug) {
            $this->OptimizeSignatures($debug);
        }

        $this->_DBShe  = array_map('strtolower', $this->_DBShe);
        $this->X_DBShe = array_map('strtolower', $this->X_DBShe);
    }

    private function OptimizeSignatures($debug)
    {
        ($this->mode == 2) && ($this->_FlexDBShe = array_merge($this->_FlexDBShe, $this->X_FlexDBShe, $this->XX_FlexDBShe));
        ($this->mode == 1) && ($this->_FlexDBShe = array_merge($this->_FlexDBShe, $this->X_FlexDBShe));
        $this->X_FlexDBShe = $this->XX_FlexDBShe = [];

        ($this->mode == 2) && ($this->_JSVirSig = array_merge($this->_JSVirSig, $this->X_JSVirSig));
        $this->X_JSVirSig = [];

        $count = count($this->_FlexDBShe);

        for ($i = 0; $i < $count; $i++) {
            if ($this->_FlexDBShe[$i] == '[a-zA-Z0-9_]+?\(\s*[a-zA-Z0-9_]+?=\s*\)')
                $this->_FlexDBShe[$i] = '\((?<=[a-zA-Z0-9_].)\s*[a-zA-Z0-9_]++=\s*\)';
            if ($this->_FlexDBShe[$i] == '([^\?\s])\({0,1}\.[\+\*]\){0,1}\2[a-z]*e')
                $this->_FlexDBShe[$i] = '(?J)\.[+*](?<=(?<d>[^\?\s])\(..|(?<d>[^\?\s])..)\)?\g{d}[a-z]*e';
            if ($this->_FlexDBShe[$i] == '$[a-zA-Z0-9_]\{\d+\}\s*\.$[a-zA-Z0-9_]\{\d+\}\s*\.$[a-zA-Z0-9_]\{\d+\}\s*\.')
                $this->_FlexDBShe[$i] = '\$[a-zA-Z0-9_]\{\d+\}\s*\.\$[a-zA-Z0-9_]\{\d+\}\s*\.\$[a-zA-Z0-9_]\{\d+\}\s*\.';

            $this->_FlexDBShe[$i] = str_replace('http://.+?/.+?\.php\?a', 'http://[^?\s]++(?<=\.php)\?a', $this->_FlexDBShe[$i]);
            $this->_FlexDBShe[$i] = preg_replace('~\[a-zA-Z0-9_\]\+\K\?~', '+', $this->_FlexDBShe[$i]);
            $this->_FlexDBShe[$i] = preg_replace('~^\\\\[d]\+&@~', '&@(?<=\d..)', $this->_FlexDBShe[$i]);
            $this->_FlexDBShe[$i] = str_replace('\s*[\'"]{0,1}.+?[\'"]{0,1}\s*', '.+?', $this->_FlexDBShe[$i]);
            $this->_FlexDBShe[$i] = str_replace('[\'"]{0,1}.+?[\'"]{0,1}', '.+?', $this->_FlexDBShe[$i]);

            $this->_FlexDBShe[$i] = preg_replace('~^\[\'"\]\{0,1\}\.?|^@\*|^\\\\s\*~', '', $this->_FlexDBShe[$i]);
        }

        self::optSig($this->_FlexDBShe,     $debug, 'AibolitHelpers::myCheckSum');
        self::optSig($this->_JSVirSig,      $debug, 'AibolitHelpers::myCheckSum');
        self::optSig($this->_AdwareSig,     $debug, 'AibolitHelpers::myCheckSum');
        self::optSig($this->_PhishingSig,   $debug, 'AibolitHelpers::myCheckSum');
        self::optSig($this->_SusDB,         $debug, 'AibolitHelpers::myCheckSum');
        //optSig($g_SusDBPrio);
        //optSig($g_ExceptFlex);

        // convert exception rules
        $cnt = count($this->_ExceptFlex);
        for ($i = 0; $i < $cnt; $i++) {
            $this->_ExceptFlex[$i] = trim(Normalization::normalize($this->_ExceptFlex[$i]));
            if ($this->_ExceptFlex[$i] == '')
                unset($this->_ExceptFlex[$i]);
        }

        $this->_ExceptFlex = array_values($this->_ExceptFlex);
    }

    public static function optSig(&$sigs, $debug = false, $func_id = null)
    {
        $sigs = array_unique($sigs);

        // Add SigId
        foreach ($sigs as $k => &$s) {
            if ($func_id && is_callable($func_id)) {
                $id = $func_id($s);
            } else {
                $id = $k;
            }
            $s .= '(?<X' . $id . '>)';
        }
        unset($s);

        $fix = [
            '([^\?\s])\({0,1}\.[\+\*]\){0,1}\2[a-z]*e' => '(?J)\.[+*](?<=(?<d>[^\?\s])\(..|(?<d>[^\?\s])..)\)?\g{d}[a-z]*e',
            'http://.+?/.+?\.php\?a' => 'http://[^?\s]++(?<=\.php)\?a',
            '\s*[\'"]{0,1}.+?[\'"]{0,1}\s*' => '.+?',
            '[\'"]{0,1}.+?[\'"]{0,1}' => '.+?'
        ];

        $sigs = str_replace(array_keys($fix), array_values($fix), $sigs);

        $fix = [
            '~^\\\\[d]\+&@~' => '&@(?<=\d..)',
            '~^((\[\'"\]|\\\\s|@)(\{0,1\}\.?|[?*]))+~' => ''
        ];

        $sigs = preg_replace(array_keys($fix), array_values($fix), $sigs);

        self::optSigCheck($sigs, $debug);

        $tmp = [];
        foreach ($sigs as $i => $s) {
            if (!preg_match('~^(?>(?!\.[*+]|\\\\\d)(?:\\\\.|\[.+?\]|.))+$~', $s)) {
                unset($sigs[$i]);
                $tmp[] = $s;
            }
        }

        usort($sigs, 'strcasecmp');
        $txt = implode("\n", $sigs);

        for ($i = 24; $i >= 1; ($i > 4) ? $i -= 4 : --$i) {
            $txt = preg_replace_callback('#^((?>(?:\\\\.|\\[.+?\\]|[^(\n]|\((?:\\\\.|[^)(\n])++\))(?:[*?+]\+?|\{\d+(?:,\d*)?\}[+?]?|)){' . $i . ',})[^\n]*+(?:\\n\\1(?![{?*+]).+)+#im', 'LoadSignaturesForScan::optMergePrefixes', $txt);
        }

        $sigs = array_merge(explode("\n", $txt), $tmp);

        self::optSigCheck($sigs, $debug);
    }

    private static function optMergePrefixes($m)
    {
        $limit = 8000;

        $prefix     = $m[1];
        $prefix_len = strlen($prefix);

        $len = $prefix_len;
        $r   = [];

        $suffixes = [];
        foreach (explode("\n", $m[0]) as $line) {

            if (strlen($line) > $limit) {
                $r[] = $line;
                continue;
            }

            $s = substr($line, $prefix_len);
            $len += strlen($s);
            if ($len > $limit) {
                if (count($suffixes) == 1) {
                    $r[] = $prefix . $suffixes[0];
                } else {
                    $r[] = $prefix . '(?:' . implode('|', $suffixes) . ')';
                }
                $suffixes = [];
                $len      = $prefix_len + strlen($s);
            }
            $suffixes[] = $s;
        }

        if (!empty($suffixes)) {
            if (count($suffixes) == 1) {
                $r[] = $prefix . $suffixes[0];
            } else {
                $r[] = $prefix . '(?:' . implode('|', $suffixes) . ')';
            }
        }

        return implode("\n", $r);
    }

    private function optMergePrefixes_Old($m)
    {
        $prefix     = $m[1];
        $prefix_len = strlen($prefix);

        $suffixes = [];
        foreach (explode("\n", $m[0]) as $line) {
            $suffixes[] = substr($line, $prefix_len);
        }

        return $prefix . '(?:' . implode('|', $suffixes) . ')';
    }

    /*
     * Checking errors in pattern
     */
    private static function optSigCheck(&$sigs, $debug)
    {
        $result = true;

        foreach ($sigs as $k => $sig) {
            if (trim($sig) == "") {
                if ($debug) {
                    echo ("************>>>>> EMPTY\n     pattern: " . $sig . "\n");
                }
                unset($sigs[$k]);
                $result = false;
            }

            if (@preg_match('~' . $sig . '~smiS', '') === false) {
                $error = error_get_last();
                if ($debug) {
                    echo ("************>>>>> " . $error['message'] . "\n     pattern: " . $sig . "\n");
                }
                unset($sigs[$k]);
                $result = false;
            }
        }

        return $result;
    }

    public static function getSigId($l_Found)
    {
        foreach ($l_Found as $key => &$v) {
            if (is_string($key) && $v[1] != -1 && strlen($key) == 9) {
                return substr($key, 1);
            }
        }

        return null;
    }

    public function setOwnUrl($url)
    {
        if (isset($this->blackUrls)) {
            foreach ($this->blackUrls->getDb() as $black) {
                if (preg_match('~' . $black . '~msi', $url)) {
                    $this->ownUrl = null;
                    return;
                }
            }
        }
        $this->ownUrl = $url;
    }

    public function getOwnUrl()
    {
        return $this->ownUrl;
    }

    public function getDBLocation()
    {
        return $this->sig_db_location;
    }

    public function getDB()
    {
        return $this->sig_db;
    }

    public function getDBMetaInfo()
    {
        return $this->sig_db_meta_info;
    }

    public function getDBMetaInfoVersion()
    {
        return $this->sig_db_meta_info['version'];
    }

    public function getDBCount()
    {
        return $this->count;
    }

    public function getDBCountWithSuspicious()
    {
        return $this->count_susp;
    }

    public function getResult()
    {
        return $this->result;
    }

    public function getLastError()
    {
        return $this->last_error;
    }
}

class InternalSignatures
{
    public static $_DBShe;
    public static $X_DBShe;
    public static $_FlexDBShe;
    public static $X_FlexDBShe;
    public static $XX_FlexDBShe;
    public static $_ExceptFlex;
    public static $_AdwareSig;
    public static $_PhishingSig;
    public static $_JSVirSig;
    public static $X_JSVirSig;
    public static $_SusDB;
    public static $_SusDBPrio;
    public static $_DeMapper;
    public static $_Mnemo;
    public static $db_meta_info;

    public static function init()
    {
        //BEGIN_SIG 19/08/2021 12:52:30
self::$_DBShe = unserialize(gzinflate(/*1629366750*/base64_decode("S7QysKquBQA=")));
self::$X_DBShe = unserialize(gzinflate(/*1629366750*/base64_decode("S7QysKquBQA=")));
self::$_FlexDBShe = unserialize(gzinflate(/*1629366750*/base64_decode("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")));
self::$X_FlexDBShe = unserialize(gzinflate(/*1629366750*/base64_decode("S7QysKquBQA=")));
self::$XX_FlexDBShe = unserialize(gzinflate(/*1629366750*/base64_decode("S7QysKquBQA=")));
self::$_ExceptFlex = unserialize(gzinflate(/*1629366750*/base64_decode("S7QysKquBQA=")));
self::$_AdwareSig = unserialize(gzinflate(/*1629366750*/base64_decode("S7QysKquBQA=")));
self::$_PhishingSig = unserialize(gzinflate(/*1629366750*/base64_decode("S7QysKquBQA=")));
self::$_JSVirSig = unserialize(gzinflate(/*1629366750*/base64_decode("5X0Jc9vG2fBfiZXYIkSKJMBbvJI46SSdpGltp/3el0upIAmJsCiCJagrAv/791y7WICg47QznW/mm8QUjsVij+e+4F949dbFS3hR78cXrtu8OBnE82242U0uR9Py6MHffuEPq+Xx+902XN+o6vU2unu79Ldvo0WgSr6qzuXkm50qhcpRl55y9vPh/TqI5/4G2syU019E8/u7YL1T1cdtuIOLc7g4qPGbRif98MKF13vd3sXJ9f16vgujtYrVY1mV8Cc+q8A/PHLg7wuMiW4OT0/75rhuH15HW3oSDuF3gE9WV8H6ZrfEc4X/OWk3dBungVOgt/QP7+kp1nGKB1f5KXygeJ3MfUVd9sNrHt/QGtq5C13TmINVHPD04b/+fhvs7rdr3ckeV8vD1ep5hatlzcws+8TcnaiFmsKLpnyauVb+jCs8i4L+aF6fuJe51P+DI3Pk6GhrWBdzS9+vyoBxwRq4YA334kSVzJKV9FJVhyfWk861qsLfCg26RnuinNPMSZUPSqdDPqipSZ8fHqtXLj54SkOTLoemO+z4dJgdaZn6OK0O+QR+XuHbXsG/N+mgztVL9rEq/QBmBg/+ykDYHmclc24iRjfrFycMzmfYxhmqSfVsfDLtp5DDN+hBXg9EteHafwhv/B1g0kS5stxTlagkcwP6Uh4+OgRYflV/80aVHsP1Inq0nxqaQx5YCwfWhs0w43pxK709IvcQ3z4pjS8mpydTtSjjn8rYKatpH+5kxywP6SMcvqAKzoCvlQ4OnAp1/Uhd85KZJjgTGmrZAp02jLbbMHRxBL3vlmGsJqe48qcIgYL0k1Mb6/EODKQEk4EOaRKEPvFZhvB1EDJbbb0YuPQnk8uTafkkpXvDk2MnfbnGIB+fnTItOcXL+HpaNaKG8VmI5BD+DOS5kAghNCSqKhTWULDiydB7TlPSR9NHsl/2qJu9jEdWSHOB0xRPC5aPb+BidGExOq10LV7ceqVR3w+rZxaFphstvK4Hr/BI8CB3l7rtQbcNxAS9h9z/DPAe9x7anuC45rlzDW5fxMHubRTdhgH171dmFeBfuGLcz0IAdx08wu93/i7oL1QVHvoQ3vEjcHpjnfKgae0X9HuGb9cH1jU9HJ6KeWEwPAmeNuE2iGHEZeh8F/364a1sXIlbpix3TkNHSrGew6b9+u7Ht9HdJlrjzVLabBtcB9ttsE0Hd3oymsiK1UancGVKIFwAxC5KD169Aytc4ssOyg8v9YrX2o/M5hjaC1i7qfiVeeW2ElQmiy1iG9C3IWIggINj4XJpctl/PX3pVZp1RNHGUDVeq0fljHCZZpPLwRXc7FV6vd5+opIn//y6ft6Da9B8cqmqg1FtiugN+F2NN6sQpoyIDxh2Oj1jElBB9FSEANBFrJzpiwf0YFBTLk8OZRO31xCwLBO+TSbQQV0toOkeDyuTy+kUyZSe4lGZieh2vArnfAwPqj08uTe0CwkG40SChJlQfA8XDTimXAFv4cD52S+yHAIoHQwMKR3+AQ7pjGk6KDw0XRAeQAohnAaMfN4EEZ5dbaLN45oAGiH6dHIJy3RqQDaFeash/APZRWhNSqGlxVW0Cdb6PWkv6bul3ashdUItzFL0D94k3AUaVuHH7jsda+UTZ9R/tlvqaba632ZG2T942TWgSnzQhmgP/Rw+4S8W3z8Acv0UxrtgHWyLh5pfKOqZdgqllh4iFVxhtJK9wsUgLnGGvCDezunCcrfbXNRq92uArkWwBcS/S0/uwnX1Y4zNER+xx5rpksGc5IVG17Dlq/oTCQaaK+chXDhGKcM/YDr02BCh2PBSJChj+HXK/ax4UCapQl6l6c5t8Mw0hmRdF8WFRquXW4aRAcVYRmhImay+IWi8NSnExboFDCV4+sVcT1eUpoRvqOMJCD3/jz9l0CoOVtf62VU092WfcHlyZM+C3iJgaAvoqRmT7lRqTgk3sooXIF9vDAXeReubj2EI116E6o4zZFclQnLrSHBRZHPobSQE1buWkIUSKLLT8jfbrf+MXMCZGs3sLNRyjaxLKHOs673GWQ0FJI3qp0UeYt0HKilcO0Kw47Of/d0SOGR0DwSjJN1OQgZsJ/0hmD1kjl0S8YxYs/08eOXG8yONmaljU2A0tdpNFN2sgnN/7a+ef4M5MO5v58twrQTt0z53R/oEEeX7VYBX4m+fP/g3f/HvAgN5PCEDeiRtiqRCwAQLufG38OxfcNGq4ToOtrtvA9gkWMKgslMOYzPKYj2Q/Qfh9Zb7DxfDEx+6ElI2PKnVJpe1abl27anqcne3UmN/qO/vnlcg/SxCACr/+QKurEGQ6Z8QTatxl7ToHkokyLNt0BXao+nVyT3q2dDnNpzvskv0c8jkGpcp5eh3dLUa7/ztjuQsehOKB92OgV2A2ZW/vrn3b2Cgf/YffLNyZZqdUOltAILxDoTac9yizWONQNWi0DYIecizG25G4QfaMF/dL8wO3W9XGVIgxFGjdSEQbQMQVmXPdT8FvNJ0Qk8JuzGv7Bf0/ClQygsVOUhizrkBZrh4uwxXC/1YOogM6+0frgQtcZZS8k41SCPuIlVj4jKfbKPVFFhVuP4hfAiSEAac/PTBUVW49g2A1vNddB8nvwIs01CJiMGtGCjGFbCpK1VyxpMvpmeDMYjqDa/Sbu5HdEHBdSK4fZSCe0gcAV6QKYpUj+KsBUksm3nEg5FUqJkAa9XntcH11lLWK8uGcbjlrOo2QDVewlPLsz+//+UvhJxxAIT5AaTber0OUisMzxcVm8w6oEQqmAax7bqaVuC0hJK2ApL2SGx+nwI96fCtOgmRGq+qBgocvEpv/BGVDCHeaCOAuTi77bN6+TaKVoFPVhgY3DbaRSTYVOFVe+Bb86Wo7LhOohxoCYSGB2QPZVq2pKEJBYbf10PmMSIPQ7lBJFaUMbhD6Oq0+tLGZejAzz6L12/f/fSBzSvSD3In3hPmhcVsAtYWNAcX+sT13Ws9Sf0v9YE8wO228gYosriA3J4xt8AktAnAAXlLWtgms2wDWQP4R3tWRa25iWNgQ6g8D7eMpREWakTG0fNzXlyyS1LP075WRb7ABd0Tlzbb3hNjiPomBTdc2AVZltBuc1lBgIfX708qY0c08alt8HMnoKHBX9T8naunaTldpgbpka5NTEneHZ7sgqdd7aNNTc8MNY3HF8wy4G2t+r5GBgAXXju+3t4N+YE3cXClGexwoMab5Qa6CObLCF/+1dX779/9/ft3ABc/fPjw16sffnn/4ZRtTmo8erMIrv371Q4x/jHaLj75/Lvv//br9+8/XIGanfZwMsqQ8wZplHU0tr86P0elPL5i3nV+TrTfcJLiyY9giysugNredMtkBRd+j33Wcp3SW5GJdOqyecZcUgzNbLVSrKE4L409gXc5lXbYrEp21XY3Yx1jsPCVJXbCP+IjbAOJ7pHmLcQalMrlnxCIioRhS76l20RE5tFqcvlPg4d74bZ8rYJLpqpy0t7XPsa1j/+6D4AeoX4EdGi50TcBkMa0F9oYSYTSGesFFyFakHyf59gNouQebvFruPcnw7bLpZ+j7XWIqww8RVMNIXNxWbmybu8CkHDmLH7ax7Bd74KHAEjrwcNnlcnlazzHicPpax4JkeoO0EFNpg1dFc3uRW/TJfzwLZldhlsxLOAdwAP8c0Fr1QFq0+khURULWPltxOwUYahKvHOsx9qu8x44ogdik4l5g1YIEd6Y4dAE2iT81DUhh7cP2YabjlX0AuTLw4Kp9PNKzGMlrMSVIDV5T1Y/umj3Ie6wKPdhuLCULYAiYBP71wStB23ScwCd+3h5jDXYnFCV9Y6hcwdJd2YX8++w7EKZ132ENRZTlrFjS0895GtIHYQJ0RqShtXopcr9gdH95ARNUVMNP7gz6qnTSGKHD9vfJB/l0Ps+UVU57vSSZ33oJVvduJUE+morudeHbvKvgt7+lNQc/WqQk6yrBQ0ItrP8BAWDvtE3MwZ8kqoapIB1m/bkn/T8h8bdoGEGLYnsdqAWggrQaJ7gwBs4qogOr/FwTYff42Gc0JLh4Y4Om2bYsGlIU5fUuGu3yB5u6LDu8INl5R35qyE+PxdeDTWGJg3bwJK2qljHJNMxe+eV6hH/LV4pG1JO0v3iDRvjuBt/winc0hy/xcOADlt4+EwT6+HhkNp+55xkjUmlO/82CFHBdgxa2mOV1+sJIpFGWBinV5oo0AHhzhqe8MdDQYbn2CQZo9dm5otCZqPS3TsZzpuyMVZxNCPLShtN3NUaWpk1+hIDEesKSWWlVK6rgra5/eYGYHZySdaRFo4+I7Y7Q8tqn9HNCNOZmwu+0wi4k/ShQrWLnp1Fi2d+Ui9N1dax0PcFsGCLEyRGKFeEhyaJLF495SK/KwuX2y6Z1psN/tMG0u8BYWrCP2TFvUq7A3+alV6HruIZ3UAe4RbKG03vc+BTK2mCjQwbjVa90ugy8ZCHxxeFyPM1032SoMegazyBttG3AXGSOanTkbcnRPvErU/iYCmlVk2SqXrNjEyFKFZTZzCVsym6hmoOmlMzlliNJCQlGPdo5ejJUc0R7pFM00wxTmx42vbtGcEnddRZGNoU9qSbN7j55PJiWsZp1FDPOLewxpyDAr1XNZol3KPdSh23X48FgJHZDZQtbTWbZED0UEf7PchgcPDqzS68oNdO4cF6woYFhANAM2z534eFFsFCy5pXbk4ZZTLrocnuinbrWowWByLeaRTyy2KEsTZW9zG5HIw0tUdrsTj5YifX34FbOefrIfbl6OYO3dX26Wufwl5yDpX0WRKBLtXjlIwbcLLb3ge4UOoFWQCJi7xobSJVoESWBjWke2xOQ0viCMeUWh5TSxYCxtii7irWwBmXyeZotUNNhe2PIiGjCVLuHdghmx0KdmjSYL795bv/4RY/fPj5p5HD5qABdfigxLppvenwNfJ+7cLJz0TzKJoDSTNtLc5YT9XMYzwYePkIRG7YZxpxl8RtUPI/ReFdt4tAA6Qb9wbJt4MHDa/iiBTaI97UbVTofrtCmo1bb/F5nf7U6S5wBjrxpA0wATrv4R/gCnTSlNdRE7moG0pndNakEzMGF6bf8vBSq0VDbcJIiYC1qA/8bSiP7vR4DkAYHNXCq0DJmnIELbkXGEeDeVOT3tfq8cvp12ul0TcUdFB3U9Sd+Oe/qcU0QyoXZPz4/2ihP2fpWnVauvoxeR3B+cXbV4TPA5dvusk3oiw0veRbfdhI3urDZvKdyOI6WABx4iCqKMM1UIyp1qZloUEHEVEsWxeRORNRZCkjcPkfwOCIdJE6SR4w2Hwhey8qy8Xh5SWzsgddiVQLVA9DFvbTMq8cSWmdtu1eyROVZRDeLHdCUyZ1d7p5ogCBPDnMyrooae7JLL5ZJR83CfyG62S+dmrbeU2epzfOou3CuE6we4Ve8cVumb2Uo0VEK1sexaD2MqPfzof/3mjy80bx46UF+uP+QlPSwkE0CpbwP1yYgvmbXbCu5Uc8Vt/JgFHNhDEn9cR1NuMnEoTGhaMns1PXHn3ZXkIYdep9OBhzsr1P4nvDv5yLbr1brx2Yhco0HzRP4FjgnCdjXWA3HbZ+CONwFoLwqLkYKsHhYhGsE56RU8g2Wy0dvFhgL1daDIIROfSWUtXhUVrInUoxVuM0LBml2q22q9WUV7shevLayJhiIG1YOjKNrE0qiJcJlE6jEcr8Mtg0JwN7NLiK26pnx/aJ5me6IRnxbXXIU9ohlGcZc3ZYu3Z0MtpGyvmYMO3z9gqCuVodHXZibPCFgpKGC5csAO3dY4w6bhI8baJwRXFnd46xqaDJKmawzYrura4m9sYWxtM0ki7uMO5FGTXuLvnX0YOEJBOaT3BdkUK+qEPpmHVVkSOLO4clIIbCohUMej33d7SGDrMHZCBIkdEomesl+858wAIyxgYqsy22eCot23pD1QRtaEDg6rGS49AtcXzlXwFAaK5xN7RyPR1091mOKXhXA9YJ1XAX3SPoQWhX2i36w/9AMwexodeFww5fqiPeVBpNfgYaYC/NCvB2vFZvWg97FdElnHGrW2l28H9L2odrLegMhZVKi266dRqKkSDYR6qjbslK0/W0FJoiLmFpp/O63XvdDl63m6/b13jqBa87jdcdOHXxt9PC08bitdd53aQ22LiFp42ZPNVuYLP2Aq/DXXgKO+m87njYOXYF7bv0yJxe16Zbrjzi1alPfdpYZEgQvrs1x4fxZT0aHDwwp/H1Xjd8/bweGTduBPgy77rgfXALGng9Q6FonShxop0lRy+wZY19asSikMoUf0F2yhPHXpb+cBTlATnVkcRkqqJgYtUYAAJZETYAquWhViQVGQ/KRZQqbxhHNIRnjcXO327pQtmlaxUjNGkFVcizW0DA2mQlqmeSSbJ2Dx1kmlGY1aMsQTqjCvpNAaQn6rEyrAM6IxcRBNfQ/oLqMUhgLx6sVhNheJ8V6fRy7DM/OmzfJgx7XrCSUmPNBpQCpFdi+WCjQJsklJZ7ZMtLO7U4y+ymWlSmZe2v0v4lfj9e5a3JEw1yeeHu8au1l6GIiRTuAVlkegURwThMUXxfnZ/n7VhWwL6Tt07BQ49olUdNNQPALAQIWEMzbIlwaCUR4B0noRtDvJe/5VDML28kWyf2KiPSa7iHP+fwz6JH1jP5yLEmW6uaxIPZmY7gJXEgtdr5+YgWwMQat8ng0/KyuREtg50f/8beynX0Nlpfr8I5bL5Cx3ed1QSXbMDvmW+XLGkVzW7X4Ta4jp7inT+LOUSvxZzzeuXfyAu8/gTFnb4wbQpZOZamQWuonjAIWlYOtRVkaEPbMkliG3JOjPsX3wRiOz6mxBzXozABxwqFaZMVp+EVuZa33lhl7DEFPuTqzfcrMoL/hczfxu6N73v9tfqKeLOYecnbhUZqVf7NeWmZ2I2spNLuaGNcHqTb9SyxFYluSMEQLZIA9pWspJe5hZtBy4fbgSv+uAxXgTJPUCgjwoyXqIajiZOOskRZ/oWjyI8GMFoP6045b42PVRndmxKITnjG14cMuASjgCH7PO7b+q4naQoUu5cCNAe+uDmFRB1Xp9Cngr74nNohaE1TIf0jYa3DULq6600Nkh8qU7g/eV2EFZG0gYMy3oEu0u7p2J0D0ke6y24TbudxbTDKOZ7R0xVypEiVfZmP/jZZ+NFq/RgtnNpdNAdEDmfBLvY3tdpFPN7sYFd5KDjs+RbjgLn7AYundgoDiwGgxEg0AJ7k3cLMLgmhOiRRed0MV6SdcwHiSyV96OS1LLzGTnXQZvsHd+pFl1hSaKCQABKCq0G2BkiP1ts+kmDFNhBPHc2adNNECbJKAT0tsxSARHXIp9Jh6icH+soCcofDbDoWo7xQVTFk749A4Z2PLrqIYhfWAALJHCNYq+tg5wCEjiyvBeszqiBcs0MCSLuZ59BNphMFeRd0tg0WwfXVPFpFtPG0e0M9wPs13AzXwcIEnuSll0xQB+ciaV2E8edLaNNm3zY5zIFaA6lLUuc5hnH1iUB+CboWEXN074K2dbUJ57d6aMiaqRctlOUlmOKQmA45tjxPHK9oDiUhE9k5MkJsL4R1lNHRNMN5nKjz/tTytxbHHlJ4Ic8fwMyKLSyIKxQlEuheDvRANADgOldnU3it5t4HuYR9mSXZOclhOlYuzZXEn2brkHuVcxtVEHmQNUqWU/NFOvRKbg4ZqHpV7OOjQWZf6dXNO3Hba9rHo4VT/Y50g12dP6VHLJbUgsRGMuH0urzdNLasVGAbZgoAOnOT9r80zgy+aRlymcM5SZ/svcawo/kTCr2ijHrEqIAmJjRJaWHEOeOockioGckD4gXvkPGn1cz746xRcs4VytwAPTEiGend6B1jEm6PTWRHtvH2S1a6DVr8CISd8cGqcbgKSk8wK4kzRuq3pqs4XEsm7ev5axlCLAnOmN24Zn1EACCDTk9LqthaJ9CVzPZS0kaHxCGvkSdyIgwVqe05/gnKdRHhh8vt+mvvrVtv0a+Hvy4o5297HbrQo18XfhsegkIfBUfWvyhY67MebduP1rWUwfl/5UNg7hZTdJlsToHpCbZax7lUvazqWzFMTdDsc/szUjcC2FEminpINb6fxbutcSvghh5qco0Uu7VrySB4EYqTBarNntbUv/oKIP8c3nPOtB3PrNia4zJzM28F/afxf4yhO2XiSIse4vexKbBxXKTw8oUbtN/93HCyomXJzl2rrwXzZOWly3HM3SPgorfRnmw6NQribNcrnmBv4eLAEF7DdW/P9oe87Rup+T8JJXqcfNC3RQRW2XkWRREc7HywwivHfdSPWwcsvUvWJzRFCPd5iEJK2KCf77Sn3lJ9skQ+DXdlU+oclNrwxrkQ4D4nDoUqEjMwlCMjf6FjHXRIKuWTV3FrYdprWgiMP08DUo+neZgcDybHpxRVynkcIidxsAgPQhPTargOd2YUtBBckaN3VDcUHnhg6dDMLy+UqCNynb+9IeCMcbIcnUK7bst7mqpz/LbknCxe2hQTr32HpdxFih9mYOoz1+pSCgG9hZgYBZTa2JNyMA6332shw6xkG0dXr2sRgWze5DAw+mGXhMJmDlMoawDRbPCK6RVDz/hTziDxFEzxmttpT/AH4JAyV3iEdY0oxCaKiAk5BGzHkDZgo4rkFLW2HEpexjBp+42EaV+qkZlJNiGgS+KiB+BTqqkzA4LqrCYxIqyCi7BrRd0gYExzp0N9bpBfWROdqMfhtMxuj0woUPa0YjnNQKFCxCL/Q+PT71ZAN7QSqm3/uHIMAJzp4TKJJEtXvZkN2cpZmHjylrxqRbNoy+sURvZVZrJsjlpPKcOnXtkjjXi7fd7sop+iaMf5Zu7kckgb6xGd+PXdT5SZIsAGVznmiLDq21U0Myijff8T9sSjTwpaw0C/StT/kmDUZSGxa9GCkfoH1kKo7wtx2hRhcJQu7JG5Tzpui4gPSGOvSPJ1m720MFB8RtJEuDblMXJKQmk84cFigF2/SMQQSjQjcU9cRRqhrQxZlBBkR/AhsXgbAUEQnIPEDIqToOgW2M2kOEShWUWp+wn8Aw3RP7/WYAnn9cZb+tNp0p92L3PG99otbvk9/Wl+x008+uPxxU6dmzT4AWkiz7n8h/v06vY4EMwyGo+eJNm5ULnVohDcdQYltiPhxhZEMmS0PqVN14XWLUQBtHBpS1WZlpDEHTY/KI/H0dOMyCr6k4czXRMEGOAdq8QM6O+Cm++fNoi6r6Zl8U+///nq7V8+GJQkTQFp0SKQYiLztJgIIdCLCZhheBFBwOO4F+YXTZbq8lkZbOEnC+yj5Jav2XNBd8oqAZwHuWgv5XuAN716/eWbGtElGWDDcDiOrcppvegLL5MDgPpOvak943DMU6OhiRu9ZNkiGz50UNok5qI/+vkKFz5I+bq+MRReeZUKoVkdwYrhrO4i8e4CR2m0LVUhGyT5yn7IGLwvNX2+rFV4jSxBjGzNRnBqsRdBhxrp2iipY7bn6oDGT5UGWOD2BUOLW9OGpjVd8HUtS2LlF6GrTesfC21fULP4m0X863aFY0oIa8oH1lBTWSAzYOI0PQ4rouBgm+qtg7vo72Hw+H7nE3XL+5tsKnxAFg9pVsY/T6jC65VavYxx61PVcLYqLYWTWTS0HGXhQJJz0Qr2CmdfzkS04F7zRr+IOwFXnafhcdYGBsnjEiZiQ06QczuIZRSntigPKWiKqExqoCZnBfZU1uuMVJDmylavdjGl/wM1gH5v4qQu/8GZm4kLuGEEIf8K/LBRiXY8EV9FogVGeMyKbjuyBESAey1dRkXNrJIj820QrCnkKk/eJwMSRDwdF2hbwrRxs6CUR0EqCpURQLMqB8poAVfoW1vr6hYWLM9K7yTfRsB+Wd4G15I4bvELR+di0pq/gyZVnY3J6FflChSglRAavkLPkXqAtXnh5ZMAHeURukwU8BzGYsyvTGFFP1MeTczLy2rJW2xWgYdXwEx7mpmikRj6Qk+jjZ+Yik9B9mULQdmtVxfZm+J0OfoBtFfeFRDDc6K/t88HpE4urwTGXJ0TpZ68a3b8hJQHRclP13TYxsMtJah4eOjTVRcP7+hwkUufGlHOVOCQIH5mlP2D0QDl9oR6Y0p35qZhCFKTYG+y6DgN0zzolFmBmYCo+IUJWBbBvdfVdj8tuBsn0kGISWHCrxRNy+ZUy7NFJcpSD3F9f5ium9Hi9EjEu802FPVSKGBaJMr4XhGJtXDHWGPEKYtyZXiFDkVTGfu+Z4R3jcIlhN7V+1209W+CdB0OAwCPp4BdvtExhBJpU2UnZzXj2DQEgpybYg26SCOsqpbj6+TUxiCxJaLthDiYtXsZQ7E4E7DC3Y+74I52CGvD2WGSoG2niQ8+6hWj2uCC5JDefgnUZEibQAGCnMyHy0+JQHYynaPGlphcC9cP0W2QspA3qjGEVV1dYW7dFV6+8skEMjN+WBIgroELXG3ud1fzaL0j60m2gcdDRtGm3fhDI3Zwe582qyjclWjEyuOSRnWSOriEEhHWMwsbkTwLFTPpapL5Cb9uu27RBLzQdK00UWpByaKSTYoXWvU0FzWgC20Y6T+/Vju0g5De0sOkdtzbmY2WWYOKv95dGRMb88fKXidiu/WGTp1MOVvJ5hJGrbANKBUAjRm0eh/dBbslcPBf1qvnX9bzgNRNZhCNlEGkOYzfPv/I1V9MPCQwnXWwxeQZC9CVSekBVjgayI7BLIsULtRdpEXtJuIdm7HJq2LspK7du9YsMN2oT6q2ieWukfzPlRhZSuxn/S6ybE0d4mqzXiYUblv7Ew9sf0vjKhyqBUBKRcMQthTgWfQPGlvcEUku2rUrZH2qpdwJG2SS0ml5TWh4XzdmFmPJVo4EhLw02d1rNyTtr0qlGvmx3E6WHM2ZdRsDOSYtzPI28tKRlaiLpTvDkqjSMFVXsgzSqabK8bIcrQmE05shSjQgKpbYUuwgBUzjdzE0BpGJJLKExDPHPHya9kxxYiypedhDoRRSuzDU6gKwp7knqOtben7/33zn/gRujuANA+lsUAt1hcp62yyTsTgsyzqQp5eBCcusD5ec8eFULuCYsQUA3FC6bN7AcpPMb0KLPKddft5rsRW1JR6WZKVi6zlqoxPhlmf4ECYO8ONoFuV2Ccf/8InjsOcB1gv+pYU86x1dFGyWl6zJbYxUnnos2lhtg5o9RKv7+7vd9pZC3EXyTB3pXGSzTqVsU7M2dJjLwwCwX1DqOS3ofI2JGCGlYGxWiIo11Hr+/J5CjHLFVnu6SpSOqTro3NgNcITmRGenL4ssTUNBo6neIpDhivI4JH2jv4niEFfuwp/FsCK7QEZqRU65XBe2S8oQ1iFyNJ3yciQMSO6ynIYt5PQP52gT8ucdZsob0c4Y6tAFikEg2v3Zru91n1lgPRJDjzG0WoFMe9TEzGui07E6v99iBTzV0nkJ5EnHalX5bPsmGUuRWdQ52JSXy9Uyg2FoOloJ4XOG2JLB1jRlNTnQLK1WTE42ARw93U3Hapaw4HgEzTSOJdamwyXed2DaWqkHHoqMID1Ldx/X5395TlS6rg7ACtpVyehW7b1oVfkdzcojk7SSZD91uhTtUZ/CfiaXT9pGtydrgghX+r1PlnIHmj+5EPhK5cnyIdjmpSULIFXtXMZKWmmaSEOVxOFDsRIUKLREA9BS+1SHVlb9kq2Fy1SmaYojFp9xyhIXrNB2LtV63Yau9U9Y3bST/C1TihXmgzCNNQ0BQelN11dL/zne+fNbkrccygpGiMUlpyW+zEoGhxJdxk68LGs7sQaekkL5YpBKAl5Gz9IcaUZ6CPlwMnlosb8Ngx0WbnLINOwRc1MNrYqJBxPWB2UyUjJiNt2WzJqA9AsSGYveVMmWaqofccaWDhRCpBSDRfggeIG5Rl2SvHAImtIJ+9H0DvkPrsAquN6BYFlWyykNhTbzHJl/Zb95YgmJ+TXwIQkd8GEVl6mlxaLctI4eh3MPaj4lZpPfHcWrTBCBh2Om5G1+dwsdq7SpGc+E63IgFrILTDNflm3kl9wCnANPr3xObKkHQ8fZHZm7wOwuImEhfQS4pyQrkKyiLlXyWn0FcDlRAIlfM5y1EEZQAJgvA3/zES2PzzEQG/9m6zuZh+z2PFWeUdtE18E1IZJN0mxydE0zZ1yZWY68kYonT0qNDdoXIrUFm5Nx2jS1nWkkJDxRs124y7y8hI2ZgO+dg9bbYDXkoKjraLWKHrMNOBJ5Sdh8hnBATgR7DaiwgOtKOTcjZpQJyWhSR4RULZ+1APVA/AP4v40WK8BBS1qwA1y1FGWLIFzTlnx6oNQRNEP358G/7hHCzDthEUE1WopcLsp3RkFBGMMaO8LxzSB/N0vVqY315qLnkoQPlUaQOtm9PTCkVnMbrNzaWCuT2pfmUrFamx+nICMK5qdAxAjNJIfdhOZhZDCPS4pHQYZ9wK+JXeO0AZ3QRJN5Zw7ANUzrlGaLGSsrjj3lx1QY12vkcKe3z3fMEiL8j6QhAURPtqSrzKLdLrpzhB4InWsD6idHSIVjtomgGsAupQ9fpz4eeFOWEiTz0F+FcbL014uZfxMnRC2STbhaJQBVQQJTn0f36DWfmSAV8s0JUQSMHtTgmQXHK7pUqNftkueq2CJocOhA0MorAii/Vin+qsbmSTQs18ZGtiW7wjhcDHWB1eVZQjHIaZe5oo6kt0B/o8lgBIqXKuvkW6xliP4TbVijWsAcd2kcSlb0ysRoW8DM6/1sbAwpKPJ1JN1CjgaUggeiKidwHI2gS80GdcmiEspVqaG9vTh4jmOpCLSNHz1ThWGpw2aaqV+dZ9vQ7pRPEpp3v0NoLBhUs5Te5J0owFprjxt1LgWFY4r4fxhY2jvCLQ+MP6/jpQPDyqHn3//t1x///gco4GcNjM1VODDpoHa/AQxZBIfjk8Fx3aBGzuKUTa5D4Q9+2HqUwknJCkcxHwUh2ZUqmnm25+eyL4lLouqYTlE5sjFrItBcBkEJRJU22b1mVloEuXtOVfkEX4zCl4uKsSbXeTse14rqicfrstZXoHtgFAAfT+mTF5l31gYULtFokzWTnFPyanEDuR4LFb38mr0P/C2Kvo7+MAmA58fYppRmYI5VFs5QfsNFdRq68oYGGZWTN/cZRfTwyyxolsNha/0GRsOlSRulmAZ5Fa2vALuBh48dzHWx2jYwCZFCL0ThZBXFZf0Qfwx94WL8drjOaMz64e9QMIx8Bzp3hHKaBVkg47sJ4t08WgXzXRI8BKtoA7R/5+/imDPUcHPtMmEtWkg1FsFliJ+TgnZTCQMZ8W62yaqQ+PHzes4WjApIUeNUFOYyzFZSoeHJ7fonGDq5VDH+dYZeJxSS0HvnPyYgU5CtkbMOmOYPqVhlxiiWinUHqUIulVQmOqLjKQhlFAbRlGo3sETJs7+crUmJQOtoLaTQNXYEDanpEjWHu/s4nD+r6tNveLNV30tiPYeucpoU5fEq8tToqgzFoY7yXQaqxwyYkdekaL20yQnV6zdfgihn6EBiy5qPj48oZ+KmP4RxECWr6CFoeXVAJst+xu+FPbYFZYwaSDdPqibjYI6oT5piGoOcemSZ4tBIOULgWhq9QUSPsVzFeF/SvvjFni7lVMRxswYLE7OQ2jV0VW2LF0tdit+xaCC6x6nVaUbEo2mnOgHxaOg9kPLm2qqBvo7YEopsk0bJ8GMuJEkNczYW1baKYbRsKweleBovioZasWdQaNK+bPg3V4h22/baqUx6UxqkWELZLs7lNjBjmYmz9BY2iUWZ3SJW57ogtzaVp+K9Bms0gKS2GJZYpJ5zKV4BZ1ZlRzUXEaynKm8iDKEs/xatfUCS5sa/CShQzNFzxaxFL1PyWU8TpYGOjScqa5ONL8a1WhDH/nN8vosW/rMoW+M4DrabxRb0v0s1IlNBt56BemTl7XpBzycW0N+sOfpie481rWW2YpA1PVFGdbuTcRKckRZCw/QtWVUPXSfbofyJnetzPLU+zWEeM/binK7d10aBAzulnaRPNBs1BHvUpOd2sq6Ns8Mhs8heJCgIaSkY/X8+bOrMDL2ZGTjymm5BRkAjJZ1Z5timL0KED8Ea+P0a1J6IgSTe3VlEMr+rxD/ow6259zQL3sMrUOcVeQz83TLY4ida5j68xN9YFgBqQRwN0WHIA2ghIOQGQPV0uZi9BaFF22EmaWV6z1fhb7eBFpFIR7IKeLdslxEqR9ZrOfXEqn5TEFl2tFaPtn65h8V2rBjFkjBJL1fCe/21+pJTL7BEaR/drFUjWtuBgERns5GNTEyo6s/s2QfExyAz62KyvacrVU7lq+9/P8yR18PTIn8BHJAyzP4Xq6SE2FyK9TynyOXhaVLaykupfYlHphF7Ba9RjTSXCa9WU2EL/SX8MEoqs+IixiC/0oB06VCnX1qFMZqos58aUu0qdtmZo6cFv0UUswMmS7QFhhrE2DtiQ9MGQEuysBFnTPUysOKzzlxmKdU+E5TJXBtaBRXOpaj4iM28Fcqq9EcOnaINAW6T5LZWZ+orrkSMKQz//XGhuXnACQMljNF79d0vbz/8z1+/T5BwgvY44xVsmpJ9WeTPIbItehnmQkkRyNyB6KhzfxOqarRe5cmPWmgd2WsdowUt89kc3EegNPEZRpuAqBQ8hHMAgaq/pbM4vFkHCzIYYRQd5bhLiFAqkVif+xTDEtkqqNs/hWt/tXrGMGqMmaVII1A5kXSUvh4aH3EcXe8e6Z0bnwOOqjzSdqqYlwTKs9+/YT/hN9c7E95gheg4VJYsdfR84pNbGOpQYRJXXYOi9j6crRDNUzzAOVDR3T47lLx8+MlRfyz6hcjpivSzkH44khkGUhSgs3IzmAzSJJUOq7tU+rteN7VHGhMSH6cYXmIiyaSEbiOXZYq+jFlq7kx5OFpOtW+agfE6fAoWiTFI9oWho1GTrJts02QDZ86ySX6QsRFMMqbLQ4Oj2Fib/MEBN69mGhWQA8JK+pNEFkPS6VTaH8fGMZT8s188kO8x28e44g/aS8nKwj9UCcSILSZlJrOZgoZlldwFwU2EjtW+NQXOpVuepUPCEbGXh51+31GUPKfF10zM1uzwc88CdXSGgb4OFcfiTNCs7tvkyiq9Ax/G79sa2J5WGL1S01VGgCkfO0ipI19mI03Gz0H2Y4vwkekRJN5Z8tpWYGYO898Whzqk8X6CPm57b9v2KTB2abtuMw1LKmeX41veXjREOy2Pkz1t2sHFUqoYEWmc0VQmxWR/cxAuJVMbZ+2Ma7TJi/gx3DdCSIGqMrTyrOGYejEe5fTKkEV0Ip2rpcQ2gxk3Ovh3qeO6qFCtx1aPxZA/mTxkOKPYQ1sRPbdkL0tXcGqY4VNcAgRehOEA4t6G/cXw8cxHxjSIoy0QqPfMTiAsAe676sws4Z4xcKmvmLUyRlG9Ko6Wj/CE2p+cUqGGdOGEqLW4RAwzAhsYTIBCl6LPS7nzHHjk7uqQGgpCOKw0kG1dOeja6YtVECE0e9cpGMkLxluiq1xkRFkYzjB3ynj/9CQVIT0pLlBQXNCsCglkB8rMGSfNZ0EBYzY9qQRnQQEW7a+8NnYvWFzS1Zg54WA7KFuINMsl4oBlaQOCufavG+BiNDSOz2UE4oCiqYZnKj2HjLYv42tSFH2VsiQXUlLra11zZM+NaA3QfKk5SF0nSE/IOEfSvgwTg/UHNSxVxmHfOE8xQ7d4NQW4ctmIbquZ146OfsDVztKaS8zNgzp7Y2zHb97AFUqm6B/oMyopa29AAoNLgBonXOoJ+Ey8Vmi7jEDFMZ/ySvzVzn8Awd1XSXQDd2ahSkDMSxCeEz9aqYQi/DmBY88WTBgENpUdTrSV58CkdVw74nrCde9QO+odenIxMJPla2dslyUz2jGAv4Sia85hsXdrE8jg0kGDy8YOu0jdwKMCrcN059KejySnFj/sJmEAnPc81glpOIFZo9O8RcPQMlitsB02+FIXc/lj/Q9qGxl/x6SuZdzfJInnAg51/g3coept6O8ec4nMhD6YTqvmKDvc7DBKtK7l+/9CdGguVJHqEPNngYwmk5Pa7JpMsT8DfgyQfOUAaGY/w1kSZpEXmSWUSiOMNKF5eKU58O5bR28Q3nScQ/OFN7+/+nh/t3EsUi9udNZjGvlnJCmlbfMG7KkJ82gNlXcTOblMHXtcHcb4Za7OlwXjlCDTQBhfLKDRKCuaSzGhWUY6l7AYKVk506Y1I3iDyrd5IgEdhD517owj0LSuV4D63CINRORM/4ehTuRgXIrPKF2DvFqWomyGY4KodYwVhZU9okmb6QHiGCURPUjiRCrhyyxp7lyj2G0dFfM5gIJ3wBn7u182CD7ad0j8kyLDdaUXZ5x3n1t7MeD0uHRNJ/EMV3MVhW4yX0X3i2UU74xTRZMYpFCIDujaGKrqGx2JoT9PC5CC68cTx6+p5IV0qjDsNotnmWZZFBBN8Wr/7jjrnzHO4w40rvaLiJsVvBvpF3CtNLe+ynq8sdUQgy0/K44YzVpuojyHg4ktAwfFZTZYjGD3N3khh5Q1QjLogzEO2MabB6t4rHFw9rDwJt/qgtDYFXWOvdb0bcLJqV06AINcxJtcEGyMq8qDtiXwtvnMVGGIgKNBT0uc2ewSsRsstSaL5N1SY1mSt6VBbPvL7GMw36EZBgsZ/nWLTt/ds3kRWg2x4I56Y0H5i5aoraSXCVsCxZON6W2v1MPICJSmMoGVQ2iKtJhMG9FzLgewzi+pnymTsUhfFeLiXCyftvn7zA2bo2dCRDMxksydyMLApgXLrtBFu4Lhchn+Rq2AAvZBhF6eadqXEr5+yvyQzT+8onRODpoVzk1lhNmwmUvwoijpdNMyGaz0fZohC/QNXShSIFzFQ6GFLilJQ3ylqZH0oBcfA4hd+aKnS9/WEpFV+0In8vnC4XBoKlpqoZPyxMyg/F00s9XAhsj8HLQxS+OtcTaUwmUFsRAAWt9hobCiFgPifiJ/p2UpCBnoK5h5LDtNhjpO47bR491BoQCjv3uFhjITvMFqSgrsRxOoJaimzLDfKEpZpfle4HodD1OD07IJo+TgRqkU0hwZEYMYer5kgUuVjht1Vk5zLGm1ZtIgXeSEpbJJn+VAdGlYbE88jHChEJL8w6RhN2S9IjxRwnBmfri4ZxUD9Ij1TcJr6EhGn1dnj0KmQ3hDNgh0yN1lI65IY6upRS2N6GPjD3mFpI6RbAqGi9pKLJU8xjBD+QJk8PiFDpg/BXJEXmUMZpzfIpVJ4FK8CzanldOb8JSqFlR3cCU1a5jhwr0XfkNP8pjSUjOD92/f/fjXD1LVqMnVz/7+7Xv9BQ/4fwQSBH4+jREoW2IIxx8/zJEzq2rwRJovvYqqBjdQKjZvopBKPKB4ZzyaRTssTTDgJ1yTncQNmvUmyD9/ifB71n+KAOsHNRlmm75gnftEm3XPBMvHpL0M88IcOptGqeTGGkwFpEJMSklNXL3Dl/BISXJo6s+ZpzM0jfmzbOHCWqVMItvnfrItW/X3lRWQvOBvxx2WfPhmAbd+9tcALVtKpfxxDUrzavWnaIvFqnQVJmtJjHOs+rQJWW7PfB8QP6BNXdD7eAXI3tIwWwV3vpzNMJA9hj9f0nrxHW6O7A/N2oVlrFJhiMswgBQ3FXPrj+tZ9PQTffGoOvbjzZMaj9cTVR1OxcjO3XOiArr6a4uF1o3haOCXdOlvhIOEhmSXRhpngq9NOIv4540jKev6h2amyCsXUvrDvdACidLMI8YgAJ5MW0eEYHiovKTV2x8PAW0RwP8w8b+ezm8nQWO6SDaPazwYb8cLIJqzZ+6Z/CH4jQC9ayRD3IaT+CvOa+KHlxO/afcUYB9nMxS4tALURNQwW28CLGwDheRPpuZ5S7U4xn14mPxhHywAgHX8qPwh0uzgJlwnIJ2isfMuWmDKyYelv74FtaiMocnLMghTO1SSsCg0V7kd1O5XGh5KS7VwRmjSOMuFgH0pzmUJUPBHeuTOeLDRlgsMrgnvbnRRCWQQnBZzNl/5sR3XKTvFvc2ACt/+6z7aBSP9KAqM0Zr0duspTjHe+Vv0e6WXr2YrmCPpB9ShOHwlzGxQW0fE3uBFW8E1pPGdBq/e0h2JRtVjGGn6eRjRmztLU1UHcKW25BWAdaRuqTIpfVxWopYxDScFSZrBNljf3Pir4LYNTbYSj9k07ts1Z5waG4xwSMs1W+MpUHXQNvqGMSjVTn/wdfmZ4vh6yde59m9Rbr+j70oxUHVN8Dsuyypc3x5NpEpDD+00IyuRNxN9SBcwFmoeJfOYoxCpGM7K6pmIfbwMAu1/KnJSwdOyFLWRsSS8SXkRy0I4yCtitxbAWePk2TZ0Ips12z8wJJB17CF9YcwiBfGZxxbJBONeqqqh7bB2cZoc9IcmaewEzvhiXIP/CoeQr4jOy0HaV6dpCB+2GgBJfjAW2tmfzePpjV5K5WSQ2tMz+7fGqYOo4IV6tOaC/m6FVzH5AjL4lil0mkZKFALQgZfzeB5X4d6dnqQG63T3LDDP5XUJdTf5hWIhM/q0pf5sos395h8kofx1G0p4JWYtHIgvoNuvtbLDaQ0VXga2iXetPRwYdnK4efXCzSPPuBU/9Ed2bHL5ODVLdbBtpoDUKPMpdE4j4gl0tGL470zg69cW+IlWZKDP+Y/nc5oLtelLZROybaA1gbWgsnzyAUt9kEWodPA9oiOT59pPTR0wNdDO8S9KWJTFGTkDrOVhuzeAX1MKFh2SYG1/6ME5Dt6gy4Hcu6r92lo/d96m7nnV0mos/2koSdlTXNbVqoi+2UY34eLiu//zI37V48PWX8fEiao/h/NthDE68IatvwjJRgSy8Xb3lj5xsdvydDk+AQXSmR8Hh6ymVICMVlYi1gZ/vMpuTz2LmGPHIqNM4jFNevQIyr2LB+i5Rh4dxwnwJtM6Q22L4uElMJnLWhITlimUjgXOW7H6MLqCCeirZvSONXzR1QqZFI7fB10onPurJOVYEuoPc6SNOz0xVr8qwf7dKrHZ8egPcBmZVA5tKGU6JclUypKLe5H+Z0V60Pe5tU4I5093q/VBzo8Toy/jQrOYoyCt3AxAw+K1pTzfyIJd0VHRuPulrkY0KDHhoDqBdiJ5g5pdvDINbVHIUlbdA+CsCQiafMtcuuVm6W/vONfSSVunAMsrx8WtTPJbnBMjUwvlW+wIBvbN/W4JN0NYl/KfJdlCF+EytVMKpMtFwKuq3b0sYJJwhTF8Y/Wqr50/nxAHj/NLng5/UY9LAI4X0fDWvz137hewILvzNIlbOAO65CnhqFkR/xH5tDgLtGmjYz722k4OwxAK9zP6NpI7F9fkgtkZLltaPK75A33Mi1oVflJsUoaWS60tLvAmOo/E0aPGdbUjLewKNPUrUnI7ekjWY2pGWhKHTax2lD42Eg+2eN2kwApFX5SoI0/HXckBlp6o0E42ZGpcCxyNrd+kLIVwMIOAqb+lzDyaWEuqBU/mjwtKq+bE4IQShpfRKngP2gxqtbVpWbNoOD5L+fLFl1zoiKzoohn9LiQKwMuoMNJH15sTCJcgWSq96WJGnfpqJikrV7PgtwMbQIOoHwm8UvPiK6CZtxP3vDktaswGeFON66uFvwvqyOGH/F4SVdpdoW+2EZbqDXKPoKf+ul393ecPO0m4C4bL3EWzUAJeTOqiFX4al3SYrCPOMv0QrjWZn1zLZSzhbJ5+q/7WiGqmFmPOjnw1NF/6pDBXy4ORd25TjpyOcKwypGJYvoef3K3ksE/C8nlpumKdAYC+38bR9gKF1FLmCeIcJmvRGQerpT+/RWvcOthZhmHogKfAPaPM0Kae/evrEEgNxrQhIJV+gMdFxkbssGoWzAGMgq0zUm7KDTj5zOM6ih6lpQIUb7VnEr9cgXUXlSPlxfhLEuVHP6Yvcm8DWdexJgAmTZ45hjH7THbLzTWiTXQ/XyYT/346v00e1w5ZFaCv2TN/qGPG43FNngHhiRWCq2YlQQknG/qNt35999OwlDGw6RoJmNfMPkqddp34i7tw7dit7LRAXdwgF6dhR9QwtLEkI0tjsSUSA8jVHQer61JqYncOE8ea5CehxkJ1W1pMb4q3XDUsOTm1MSsdD+xxLUjPvThJP81mOUd1aEXqnZw4cLGkbKTHjfrhu/e4T8E1DDBBWBwnO/9uE4ydBY5k9qw9H/aXnxaIdLJ3jVTg+dzoc6s6e7qW9jfFrBj0VBiyKl6mjtvDVGD1KMWzWLxoo6KK8aKznIdS5R1Gafi5Nkqqhy+nZfrwru33a1T0MXmtOCjTdFsxLhb/t+efIn+hAzSAPTW5MdMLT0o4ZpKcUCTLfdXHNofrUMV+qmyp4u8gi8fDY6cNu6OotgQgFLlsHCZEWHjQEarzqO8ljvJ0nKVoxuxPzH0DDaDU0EAdNKfrSPEroSPSqShA+J9puXNJnDKfEcB4Qq4QKbWaACOoSicQI65ITolidf2Rl/3/BQ==")));
self::$X_JSVirSig = unserialize(gzinflate(/*1629366750*/base64_decode("S7QysKquBQA=")));
self::$_SusDB = unserialize(gzinflate(/*1629366750*/base64_decode("HUu7DsIwEPuXTKRDQiuV4QJ0YOEHmAhDaSM4Kb1ESWkG4N+5Ivkh23IPDbwRtiZDW4PY5yFhnI82V0uf7LOakNzqBya5wnoKSGdcnFWXzNNdGISa77sWBGi96aCUYpXsrk25cWLQy3s3fkIaY3I5R6SHtGoI01r5f2cVuVlqYb4/")));
self::$_SusDBPrio = unserialize(gzinflate(/*1629366750*/base64_decode("S7QysKquBQA=")));
self::$_Mnemo = unserialize(gzinflate(/*1629366750*/base64_decode("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")));
self::$_DeMapper = unserialize(base64_decode("YTo1OntzOjEwOiJ3aXphcmQucGhwIjtzOjM3OiJjbGFzcyBXZWxjb21lU3RlcCBleHRlbmRzIENXaXphcmRTdGVwIjtzOjE3OiJ1cGRhdGVfY2xpZW50LnBocCI7czozNzoieyBDVXBkYXRlQ2xpZW50OjpBZGRNZXNzYWdlMkxvZygiZXhlYyI7czoxMToiaW5jbHVkZS5waHAiO3M6NDg6IkdMT0JBTFNbIlVTRVIiXS0+SXNBdXRob3JpemVkKCkgJiYgJGFyQXV0aFJlc3VsdCI7czo5OiJzdGFydC5waHAiO3M6NjA6IkJYX1JPT1QuJy9tb2R1bGVzL21haW4vY2xhc3Nlcy9nZW5lcmFsL3VwZGF0ZV9kYl91cGRhdGVyLnBocCI7czoxMDoiaGVscGVyLnBocCI7czo1ODoiSlBsdWdpbkhlbHBlcjo6Z2V0UGx1Z2luKCJzeXN0ZW0iLCJvbmVjbGlja2NoZWNrb3V0X3ZtMyIpOyI7fQ=="));
self::$db_meta_info = unserialize(base64_decode("YTozOntzOjEwOiJidWlsZC1kYXRlIjtzOjEwOiIxNjI5Mjc1NDEwIjtzOjc6InZlcnNpb24iO3M6MTM6IjIwMjEwODE4LTYxNzgiO3M6MTI6InJlbGVhc2UtdHlwZSI7czoxMDoicHJvZHVjdGlvbiI7fQ=="));

//END_SIG
    }
}

class AibolitHelpers
{
    /**
     * Format bytes to human readable
     *
     * @param int $bytes
     *
     * @return string
     */
    public static function bytes2Human($bytes)
    {
        if ($bytes < 1024) {
            return $bytes . ' b';
        } elseif (($kb = $bytes / 1024) < 1024) {
            return number_format($kb, 2) . ' Kb';
        } elseif (($mb = $kb / 1024) < 1024) {
            return number_format($mb, 2) . ' Mb';
        } elseif (($gb = $mb / 1024) < 1024) {
            return number_format($gb, 2) . ' Gb';
        } else {
            return number_format($gb / 1024, 2) . 'Tb';
        }
    }

    /**
     * Seconds to human readable
     * @param int $seconds
     * @return string
     */
    public static function seconds2Human($seconds)
    {
        $r        = '';
        $_seconds = floor($seconds);
        $ms       = $seconds - $_seconds;
        $seconds  = $_seconds;
        if ($hours = floor($seconds / 3600)) {
            $r .= $hours . ' h ';
            $seconds %= 3600;
        }

        if ($minutes = floor($seconds / 60)) {
            $r .= $minutes . ' m ';
            $seconds %= 60;
        }

        if ($minutes < 3) {
            $r .= ' ' . (string)($seconds + ($ms > 0 ? round($ms) : 0)) . ' s';
        }

        return $r;
    }

    /**
     * Get bytes from shorthand byte values (1M, 1G...)
     * @param int|string $val
     * @return int
     */
    public static function getBytes($val)
    {
        $val  = trim($val);
        $last = strtolower($val[strlen($val) - 1]);
        $val  = preg_replace('~\D~', '', $val);
        switch ($last) {
            case 't':
                $val *= 1024;
            case 'g':
                $val *= 1024;
            case 'm':
                $val *= 1024;
            case 'k':
                $val *= 1024;
        }
        return intval($val);
    }

    /**
     * Convert dangerous chars to html entities
     *
     * @param        $par_Str
     * @param string $addPrefix
     * @param string $noPrefix
     * @param bool   $replace_path
     *
     * @return string
     */
    public static function makeSafeFn($par_Str, $addPrefix = '', $noPrefix = '', $replace_path = false)
    {
        if ($replace_path) {
            $lines = explode("\n", $par_Str);
            array_walk($lines, static function(&$n) use ($addPrefix, $noPrefix) {
                $n = $addPrefix . str_replace($noPrefix, '', $n);
            });

            $par_Str = implode("\n", $lines);
        }

        return htmlspecialchars($par_Str, ENT_SUBSTITUTE | ENT_QUOTES);
    }


    public static function myCheckSum($str)
    {
        return hash('crc32b', $str);
    }

}

class Finder
{
    const MAX_ALLOWED_PHP_HTML_IN_DIR = 600;

    private $sym_links              = [];
    private $skipped_folders        = [];
    private $doorways               = [];
    private $big_files              = [];
    private $big_elf_files          = [];

    private $collect_skipped        = false;
    private $collect_symLinks       = false;
    private $collect_doorways       = false;
    private $collect_bigfiles       = false;
    private $collect_bigelffiles    = false;

    private $total_dir_counter      = 0;
    private $total_files_counter    = 0;
    private $checked_hashes         = [];

    private $initial_dir            = '';
    private $initial_level          = null;
    private $level_limit            = null;

    private $filter;
    private $total                  = 0;

    public function __construct($filter = null, $level_limit = null)
    {
        $this->filter = $filter;
        $this->level_limit = $level_limit;
    }

    private function linkResolve($path)
    {
        return realpath($path);
    }

    private function resolve($path, $follow_symlinks)
    {
        if (!$follow_symlinks || !is_link($path)) {
            return $path;
        }
        return $this->linkResolve($path);
    }

    private function isPathCheckedAlready($path)
    {
        $root_hash = crc32($path);
        if (isset($this->checked_hashes[$root_hash])) {
            return true;
        }
        $this->checked_hashes[$root_hash] = '';
        return false;
    }

    private function walk($path, $follow_symlinks)
    {
        $level = substr_count($path, '/');
        if (isset($this->level_limit) && (($level - $this->initial_level + 1) > $this->level_limit)) {
            return;
        }
        $l_DirCounter          = 0;
        $l_DoorwayFilesCounter = 0;

        if ($follow_symlinks && $this->isPathCheckedAlready($path)) {
            return;
        }

        # will not iterate dir, if it should be ignored
        if (!$this->filter->needToScan($path, false, true)) {
            if ($this->collect_skipped) {
                $this->skipped_folders[] = $path;
            }
            return;
        }
        $dirh = @opendir($path);
        if ($dirh === false) {
            return;
        }

        while (($entry = readdir($dirh)) !== false) {
            if ($entry == '.' || $entry == '..') {
                continue;
            }
            $entry = $path . DIRECTORY_SEPARATOR . $entry;
            if (is_link($entry)) {

                if ($this->collect_symLinks) {
                    $this->sym_links[] = $entry;
                }

                if (!$follow_symlinks) {
                    continue;
                }
                $real_path = $this->resolve($entry, true);
            } else {
                $real_path = $entry;
            }
            if (is_dir($entry)) {
                $l_DirCounter++;
                if ($this->collect_doorways && $l_DirCounter > self::MAX_ALLOWED_PHP_HTML_IN_DIR) {
                    $this->doorways[]  = $path;
                    $l_DirCounter = -655360;
                }
                $this->total_dir_counter++;
                yield from $this->walk($real_path, $follow_symlinks);
            } else if (is_file($entry)) {
                $stat = stat($entry);
                if (!$stat) {
                    continue;
                }
                if ($this->collect_doorways && is_callable([$this->filter, 'checkShortExt']) && $this->filter->checkShortExt($entry)) {
                    $l_DoorwayFilesCounter++;
                    if ($l_DoorwayFilesCounter > self::MAX_ALLOWED_PHP_HTML_IN_DIR) {
                        $this->doorways[]           = $path;
                        $l_DoorwayFilesCounter = -655360;
                    }
                }
                if ($follow_symlinks && $this->isPathCheckedAlready($real_path)) {
                    continue;
                }
                if ($this->collect_bigfiles && is_callable([$this->filter, 'checkIsBig']) && $this->filter->checkIsBig($real_path)) {
                    $this->big_files[] = $real_path;
                }
                if ($this->collect_bigelffiles
                    && is_callable([$this->filter, 'checkIsBig']) && $this->filter->checkIsBig($real_path)
                    && is_callable([$this->filter, 'checkIsElf']) && $this->filter->checkIsElf($real_path)
                    && $this->filter->needToScan($real_path, false, false, ['check_size_range'])
                ) {
                    $this->big_elf_files[] = $real_path;
                }
                $need_to_scan = $this->filter->needToScan($real_path, $stat);
                $this->total_files_counter = $need_to_scan ? $this->total_files_counter + 1 : $this->total_files_counter;
                $this->total++;
                 if (class_exists('Progress')) {
                     Progress::setCurrentFile($real_path);
                     Progress::setFilesTotal($this->total_files_counter);
                     Progress::updateList($this->total);
                }
                if ($need_to_scan) {
                    yield $real_path;
                }
            }
        }
        closedir($dirh);
    }

    private function expandPath($path, $follow_symlinks)
    {
        if ($path) {
            if (is_dir($path)) {
                yield from $this->walk($path, $follow_symlinks);
            } else {
                if ($this->collect_bigfiles && is_callable([$this->filter, 'checkIsBig']) && $this->filter->checkIsBig($path)) {
                    $this->big_files[] = $path;
                    if ($this->collect_bigelffiles && is_callable([$this->filter, 'checkIsElf']) && $this->filter->checkIsElf($path)
                        && $this->filter->needToScan($path, false, false, ['check_size_range'])) {
                        $this->big_elf_files[] = $path;
                    }
                }
                $need_to_scan = $this->filter->needToScan($path);
                if ($need_to_scan) {
                    yield $path;
                }
            }
        }
    }

    public function find($target)
    {
        $started = microtime(true);

        if ($target === '/') {
            $target = '/*';
        }
        if (is_string($target) && substr($target, -1) == DIRECTORY_SEPARATOR) {
            $target = substr($target, 0, -1);
        }

        if (is_callable([$this->filter, 'getGenerated']) && !$this->filter->getGenerated()
            && is_callable([$this->filter, 'generateCheckers'])
        ) {
            $this->filter->generateCheckers();
        }

        if (class_exists('Progress')) {
            Progress::setStage(Progress::STAGE_LIST);
        }

        # We shouldn't use iglob for list of paths,
        # cause they cannot contain * or regexp
        # but can contain invalid sequence e.g. [9-0]
        $paths = is_array($target) ? $target : new GlobIterator($target, FilesystemIterator::CURRENT_AS_PATHNAME);
        foreach ($paths as $path) {
            $this->initial_dir = realpath($path);
            $this->initial_level = substr_count($this->initial_dir, '/');
            $path = $this->linkResolve($path);
            yield from $this->expandPath($path, $this->filter->isFollowSymlink());
        }

        if (class_exists('PerfomanceStats')) {
            PerfomanceStats::addPerfomanceItem(PerfomanceStats::FINDER_STAT, microtime(true) - $started);
        }
    }

    private function convertTemplatesToRegexp($templates)
    {
        return '~(' . str_replace([',', '.', '*'], ['|', '\\.', '.*'], $templates) . ')~i';
    }

    public function setLevelLimit($level)
    {
        $this->level_limit = $level;
    }

    public function getSymlinks()
    {
        return $this->sym_links;
    }

    public function getBigFiles()
    {
        return $this->big_files;
    }

    public function getBigElfFiles()
    {
        return $this->big_elf_files;
    }

    public function setCollectDoorways($flag)
    {
        $this->collect_doorways = $flag;
    }

    public function setCollectBigElfs($flag)
    {
        $this->collect_bigelffiles = $flag;
    }

    public function setCollectSymlinks($flag)
    {
        $this->collect_symLinks = $flag;
    }

    public function setCollectSkipped($flag)
    {
        $this->collect_skipped = $flag;
    }

    public function setCollectBigFiles($flag)
    {
        $this->collect_bigfiles = $flag;
    }

    public function getDoorways()
    {
        return $this->doorways;
    }

    public function skippedDirs()
    {
        return $this->skipped_folders;
    }

    public function getTotalDirs()
    {
        return $this->total_dir_counter;
    }

    public function getTotalFiles()
    {
        return $this->total_files_counter;
    }

    public function getFilter()
    {
        return $this->filter;
    }
}
class StringToStreamWrapper {

    const WRAPPER_NAME = 'var';

    private static $_content;
    private $_position;

    /**
     * Prepare a new memory stream with the specified content
     * @return string
     */
    public static function prepare($content)
    {
        if (!in_array(self::WRAPPER_NAME, stream_get_wrappers())) {
            stream_wrapper_register(self::WRAPPER_NAME, get_class());
        }
        self::$_content = $content;
    }

    public function stream_open($path, $mode, $options, &$opened_path)
    {
        $this->_position = 0;
        return true;
    }

    public function stream_read($count)
    {
        $ret = substr(self::$_content, $this->_position, $count);
        $this->_position += strlen($ret);
        return $ret;
    }

    public function stream_stat()
    {
        return [];
    }

    public function stream_eof()
    {
        return $this->_position >= strlen(self::$_content);
    }

    public function stream_set_option($option , $arg1, $arg2 )
    {
        return true;
    }
}

class Normalization
{
    const MAX_ITERATION = 10;

    private static $confusables = "YToxNTY1OntzOjM6IuKAqCI7czoxOiIgIjtzOjM6IuKAqSI7czoxOiIgIjtzOjM6IuGagCI7czoxOiIgIjtzOjM6IuKAgCI7czoxOiIgIjtzOjM6IuKAgSI7czoxOiIgIjtzOjM6IuKAgiI7czoxOiIgIjtzOjM6IuKAgyI7czoxOiIgIjtzOjM6IuKAhCI7czoxOiIgIjtzOjM6IuKAhSI7czoxOiIgIjtzOjM6IuKAhiI7czoxOiIgIjtzOjM6IuKAiCI7czoxOiIgIjtzOjM6IuKAiSI7czoxOiIgIjtzOjM6IuKAiiI7czoxOiIgIjtzOjM6IuKBnyI7czoxOiIgIjtzOjI6IsKgIjtzOjE6IiAiO3M6Mzoi4oCHIjtzOjE6IiAiO3M6Mzoi4oCvIjtzOjE6IiAiO3M6Mjoiw4IiO3M6MToiICI7czoyOiLfuiI7czoxOiJfIjtzOjM6Iu+5jSI7czoxOiJfIjtzOjM6Iu+5jiI7czoxOiJfIjtzOjM6Iu+5jyI7czoxOiJfIjtzOjM6IuKAkCI7czoxOiItIjtzOjM6IuKAkSI7czoxOiItIjtzOjM6IuKAkiI7czoxOiItIjtzOjM6IuKAkyI7czoxOiItIjtzOjM6Iu+5mCI7czoxOiItIjtzOjI6ItuUIjtzOjE6Ii0iO3M6Mzoi4oGDIjtzOjE6Ii0iO3M6Mjoiy5ciO3M6MToiLSI7czozOiLiiJIiO3M6MToiLSI7czozOiLinpYiO3M6MToiLSI7czozOiLisroiO3M6MToiLSI7czoyOiLYjSI7czoxOiIsIjtzOjI6ItmrIjtzOjE6IiwiO3M6Mzoi4oCaIjtzOjE6IiwiO3M6MjoiwrgiO3M6MToiLCI7czozOiLqk7kiO3M6MToiLCI7czoyOiLNviI7czoxOiI7IjtzOjM6IuCkgyI7czoxOiI6IjtzOjM6IuCqgyI7czoxOiI6IjtzOjM6Iu+8miI7czoxOiI6IjtzOjI6ItaJIjtzOjE6IjoiO3M6Mjoi3IMiO3M6MToiOiI7czoyOiLchCI7czoxOiI6IjtzOjM6IuGbrCI7czoxOiI6IjtzOjM6Iu+4sCI7czoxOiI6IjtzOjM6IuGggyI7czoxOiI6IjtzOjM6IuGgiSI7czoxOiI6IjtzOjM6IuKBmiI7czoxOiI6IjtzOjI6IteDIjtzOjE6IjoiO3M6Mjoiy7giO3M6MToiOiI7czozOiLqnokiO3M6MToiOiI7czozOiLiiLYiO3M6MToiOiI7czoyOiLLkCI7czoxOiI6IjtzOjM6IuqTvSI7czoxOiI6IjtzOjM6Iu+8gSI7czoxOiIhIjtzOjI6IseDIjtzOjE6IiEiO3M6Mzoi4rWRIjtzOjE6IiEiO3M6MjoiypQiO3M6MToiPyI7czoyOiLJgSI7czoxOiI/IjtzOjM6IuClvSI7czoxOiI/IjtzOjM6IuGOriI7czoxOiI/IjtzOjM6IuqbqyI7czoxOiI/IjtzOjQ6IvCdha0iO3M6MToiLiI7czozOiLigKQiO3M6MToiLiI7czoyOiLcgSI7czoxOiIuIjtzOjI6ItyCIjtzOjE6Ii4iO3M6Mzoi6piOIjtzOjE6Ii4iO3M6NDoi8JCpkCI7czoxOiIuIjtzOjI6ItmgIjtzOjE6Ii4iO3M6Mjoi27AiO3M6MToiLiI7czozOiLqk7giO3M6MToiLiI7czozOiLjg7siO3M6MToityI7czozOiLvvaUiO3M6MToityI7czozOiLhm6siO3M6MToityI7czoyOiLOhyI7czoxOiK3IjtzOjM6IuK4sSI7czoxOiK3IjtzOjQ6IvCQhIEiO3M6MToityI7czozOiLigKIiO3M6MToityI7czozOiLigKciO3M6MToityI7czozOiLiiJkiO3M6MToityI7czozOiLii4UiO3M6MToityI7czozOiLqno8iO3M6MToityI7czozOiLhkKciO3M6MToityI7czoyOiLVnSI7czoxOiInIjtzOjM6Iu+8hyI7czoxOiInIjtzOjM6IuKAmCI7czoxOiInIjtzOjM6IuKAmSI7czoxOiInIjtzOjM6IuKAmyI7czoxOiInIjtzOjM6IuKAsiI7czoxOiInIjtzOjM6IuKAtSI7czoxOiInIjtzOjI6ItWaIjtzOjE6IiciO3M6Mjoi17MiO3M6MToiJyI7czoxOiJgIjtzOjE6IiciO3M6Mzoi4b+vIjtzOjE6IiciO3M6Mzoi772AIjtzOjE6IiciO3M6MjoiwrQiO3M6MToiJyI7czoyOiLOhCI7czoxOiInIjtzOjM6IuG/vSI7czoxOiInIjtzOjM6IuG+vSI7czoxOiInIjtzOjM6IuG+vyI7czoxOiInIjtzOjM6IuG/viI7czoxOiInIjtzOjI6Isq5IjtzOjE6IiciO3M6MjoizbQiO3M6MToiJyI7czoyOiLLiCI7czoxOiInIjtzOjI6IsuKIjtzOjE6IiciO3M6Mjoiy4siO3M6MToiJyI7czoyOiLLtCI7czoxOiInIjtzOjI6Isq7IjtzOjE6IiciO3M6Mjoiyr0iO3M6MToiJyI7czoyOiLKvCI7czoxOiInIjtzOjI6Isq+IjtzOjE6IiciO3M6Mzoi6p6MIjtzOjE6IiciO3M6Mjoi15kiO3M6MToiJyI7czoyOiLftCI7czoxOiInIjtzOjI6It+1IjtzOjE6IiciO3M6Mzoi4ZGKIjtzOjE6IiciO3M6Mzoi4ZuMIjtzOjE6IiciO3M6NDoi8Ja9kSI7czoxOiInIjtzOjQ6IvCWvZIiO3M6MToiJyI7czozOiLvvLsiO3M6MToiKCI7czozOiLinagiO3M6MToiKCI7czozOiLinbIiO3M6MToiKCI7czozOiLjgJQiO3M6MToiKCI7czozOiLvtL4iO3M6MToiKCI7czozOiLvvL0iO3M6MToiKSI7czozOiLinakiO3M6MToiKSI7czozOiLinbMiO3M6MToiKSI7czozOiLjgJUiO3M6MToiKSI7czozOiLvtL8iO3M6MToiKSI7czozOiLinbQiO3M6MToieyI7czo0OiLwnYSUIjtzOjE6InsiO3M6Mzoi4p21IjtzOjE6In0iO3M6Mzoi4ri/IjtzOjE6IrYiO3M6Mzoi4oGOIjtzOjE6IioiO3M6Mjoi2a0iO3M6MToiKiI7czozOiLiiJciO3M6MToiKiI7czo0OiLwkIyfIjtzOjE6IioiO3M6Mzoi4Zy1IjtzOjE6Ii8iO3M6Mzoi4oGBIjtzOjE6Ii8iO3M6Mzoi4oiVIjtzOjE6Ii8iO3M6Mzoi4oGEIjtzOjE6Ii8iO3M6Mzoi4pWxIjtzOjE6Ii8iO3M6Mzoi4p+LIjtzOjE6Ii8iO3M6Mzoi4qe4IjtzOjE6Ii8iO3M6NDoi8J2IuiI7czoxOiIvIjtzOjM6IuOHkyI7czoxOiIvIjtzOjM6IuOAsyI7czoxOiIvIjtzOjM6IuKzhiI7czoxOiIvIjtzOjM6IuODjiI7czoxOiIvIjtzOjM6IuS4vyI7czoxOiIvIjtzOjM6IuK8gyI7czoxOiIvIjtzOjM6Iu+8vCI7czoxOiJcIjtzOjM6Iu+5qCI7czoxOiJcIjtzOjM6IuKIliI7czoxOiJcIjtzOjM6IuKfjSI7czoxOiJcIjtzOjM6IuKntSI7czoxOiJcIjtzOjM6IuKnuSI7czoxOiJcIjtzOjQ6IvCdiI8iO3M6MToiXCI7czo0OiLwnYi7IjtzOjE6IlwiO3M6Mzoi44eUIjtzOjE6IlwiO3M6Mzoi5Li2IjtzOjE6IlwiO3M6Mzoi4ryCIjtzOjE6IlwiO3M6Mzoi6p24IjtzOjE6IiYiO3M6Mjoiy4QiO3M6MToiXiI7czoyOiLLhiI7czoxOiJeIjtzOjM6IuK4sCI7czoxOiKwIjtzOjI6IsuaIjtzOjE6IrAiO3M6Mzoi4oiYIjtzOjE6IrAiO3M6Mzoi4peLIjtzOjE6IrAiO3M6Mzoi4pemIjtzOjE6IrAiO3M6Mzoi4pK4IjtzOjE6IqkiO3M6Mzoi4pOHIjtzOjE6Iq4iO3M6Mzoi4ZutIjtzOjE6IisiO3M6Mzoi4p6VIjtzOjE6IisiO3M6NDoi8JCKmyI7czoxOiIrIjtzOjM6IuKelyI7czoxOiL3IjtzOjM6IuKAuSI7czoxOiI8IjtzOjM6IuKdriI7czoxOiI8IjtzOjI6IsuCIjtzOjE6IjwiO3M6NDoi8J2ItiI7czoxOiI8IjtzOjM6IuGQuCI7czoxOiI8IjtzOjM6IuGasiI7czoxOiI8IjtzOjM6IuGQgCI7czoxOiI9IjtzOjM6IuK5gCI7czoxOiI9IjtzOjM6IuOCoCI7czoxOiI9IjtzOjM6IuqTvyI7czoxOiI9IjtzOjM6IuKAuiI7czoxOiI+IjtzOjM6IuKdryI7czoxOiI+IjtzOjI6IsuDIjtzOjE6Ij4iO3M6NDoi8J2ItyI7czoxOiI+IjtzOjM6IuGQsyI7czoxOiI+IjtzOjQ6IvCWvL8iO3M6MToiPiI7czozOiLigZMiO3M6MToifiI7czoyOiLLnCI7czoxOiJ+IjtzOjM6IuG/gCI7czoxOiJ+IjtzOjM6IuKIvCI7czoxOiJ+IjtzOjM6IuKCpCI7czoxOiKjIjtzOjQ6IvCdn5AiO3M6MToiMiI7czo0OiLwnZ+aIjtzOjE6IjIiO3M6NDoi8J2fpCI7czoxOiIyIjtzOjQ6IvCdn64iO3M6MToiMiI7czo0OiLwnZ+4IjtzOjE6IjIiO3M6Mzoi6p2aIjtzOjE6IjIiO3M6MjoixqciO3M6MToiMiI7czoyOiLPqCI7czoxOiIyIjtzOjM6IuqZhCI7czoxOiIyIjtzOjM6IuGSvyI7czoxOiIyIjtzOjM6IuqbryI7czoxOiIyIjtzOjQ6IvCdiIYiO3M6MToiMyI7czo0OiLwnZ+RIjtzOjE6IjMiO3M6NDoi8J2fmyI7czoxOiIzIjtzOjQ6IvCdn6UiO3M6MToiMyI7czo0OiLwnZ+vIjtzOjE6IjMiO3M6NDoi8J2fuSI7czoxOiIzIjtzOjM6IuqeqyI7czoxOiIzIjtzOjI6IsicIjtzOjE6IjMiO3M6MjoixrciO3M6MToiMyI7czozOiLqnaoiO3M6MToiMyI7czozOiLis4wiO3M6MToiMyI7czoyOiLQlyI7czoxOiIzIjtzOjI6ItOgIjtzOjE6IjMiO3M6NDoi8Ja8uyI7czoxOiIzIjtzOjQ6IvCRo4oiO3M6MToiMyI7czo0OiLwnZ+SIjtzOjE6IjQiO3M6NDoi8J2fnCI7czoxOiI0IjtzOjQ6IvCdn6YiO3M6MToiNCI7czo0OiLwnZ+wIjtzOjE6IjQiO3M6NDoi8J2fuiI7czoxOiI0IjtzOjM6IuGPjiI7czoxOiI0IjtzOjQ6IvCRoq8iO3M6MToiNCI7czo0OiLwnZ+TIjtzOjE6IjUiO3M6NDoi8J2fnSI7czoxOiI1IjtzOjQ6IvCdn6ciO3M6MToiNSI7czo0OiLwnZ+xIjtzOjE6IjUiO3M6NDoi8J2fuyI7czoxOiI1IjtzOjI6Isa8IjtzOjE6IjUiO3M6NDoi8JGiuyI7czoxOiI1IjtzOjQ6IvCdn5QiO3M6MToiNiI7czo0OiLwnZ+eIjtzOjE6IjYiO3M6NDoi8J2fqCI7czoxOiI2IjtzOjQ6IvCdn7IiO3M6MToiNiI7czo0OiLwnZ+8IjtzOjE6IjYiO3M6Mzoi4rOSIjtzOjE6IjYiO3M6Mjoi0LEiO3M6MToiNiI7czozOiLhj64iO3M6MToiNiI7czo0OiLwkaOVIjtzOjE6IjYiO3M6NDoi8J2IkiI7czoxOiI3IjtzOjQ6IvCdn5UiO3M6MToiNyI7czo0OiLwnZ+fIjtzOjE6IjciO3M6NDoi8J2fqSI7czoxOiI3IjtzOjQ6IvCdn7MiO3M6MToiNyI7czo0OiLwnZ+9IjtzOjE6IjciO3M6NDoi8JCTkiI7czoxOiI3IjtzOjQ6IvCRo4YiO3M6MToiNyI7czozOiLgrIMiO3M6MToiOCI7czozOiLgp6oiO3M6MToiOCI7czozOiLgqaoiO3M6MToiOCI7czo0OiLwnqOLIjtzOjE6IjgiO3M6NDoi8J2fliI7czoxOiI4IjtzOjQ6IvCdn6AiO3M6MToiOCI7czo0OiLwnZ+qIjtzOjE6IjgiO3M6NDoi8J2ftCI7czoxOiI4IjtzOjQ6IvCdn74iO3M6MToiOCI7czoyOiLIoyI7czoxOiI4IjtzOjI6IsiiIjtzOjE6IjgiO3M6NDoi8JCMmiI7czoxOiI4IjtzOjM6IuCppyI7czoxOiI5IjtzOjM6IuCtqCI7czoxOiI5IjtzOjM6IuCnrSI7czoxOiI5IjtzOjM6IuC1rSI7czoxOiI5IjtzOjQ6IvCdn5ciO3M6MToiOSI7czo0OiLwnZ+hIjtzOjE6IjkiO3M6NDoi8J2fqyI7czoxOiI5IjtzOjQ6IvCdn7UiO3M6MToiOSI7czo0OiLwnZ+/IjtzOjE6IjkiO3M6Mzoi6p2uIjtzOjE6IjkiO3M6Mzoi4rOKIjtzOjE6IjkiO3M6NDoi8JGjjCI7czoxOiI5IjtzOjQ6IvCRoqwiO3M6MToiOSI7czo0OiLwkaOWIjtzOjE6IjkiO3M6Mzoi4o26IjtzOjE6ImEiO3M6Mzoi772BIjtzOjE6ImEiO3M6NDoi8J2QmiI7czoxOiJhIjtzOjQ6IvCdkY4iO3M6MToiYSI7czo0OiLwnZKCIjtzOjE6ImEiO3M6NDoi8J2StiI7czoxOiJhIjtzOjQ6IvCdk6oiO3M6MToiYSI7czo0OiLwnZSeIjtzOjE6ImEiO3M6NDoi8J2VkiI7czoxOiJhIjtzOjQ6IvCdloYiO3M6MToiYSI7czo0OiLwnZa6IjtzOjE6ImEiO3M6NDoi8J2XriI7czoxOiJhIjtzOjQ6IvCdmKIiO3M6MToiYSI7czo0OiLwnZmWIjtzOjE6ImEiO3M6NDoi8J2aiiI7czoxOiJhIjtzOjI6IsmRIjtzOjE6ImEiO3M6MjoizrEiO3M6MToiYSI7czo0OiLwnZuCIjtzOjE6ImEiO3M6NDoi8J2bvCI7czoxOiJhIjtzOjQ6IvCdnLYiO3M6MToiYSI7czo0OiLwnZ2wIjtzOjE6ImEiO3M6NDoi8J2eqiI7czoxOiJhIjtzOjI6ItCwIjtzOjE6ImEiO3M6Mzoi77yhIjtzOjE6IkEiO3M6NDoi8J2QgCI7czoxOiJBIjtzOjQ6IvCdkLQiO3M6MToiQSI7czo0OiLwnZGoIjtzOjE6IkEiO3M6NDoi8J2SnCI7czoxOiJBIjtzOjQ6IvCdk5AiO3M6MToiQSI7czo0OiLwnZSEIjtzOjE6IkEiO3M6NDoi8J2UuCI7czoxOiJBIjtzOjQ6IvCdlawiO3M6MToiQSI7czo0OiLwnZagIjtzOjE6IkEiO3M6NDoi8J2XlCI7czoxOiJBIjtzOjQ6IvCdmIgiO3M6MToiQSI7czo0OiLwnZi8IjtzOjE6IkEiO3M6NDoi8J2ZsCI7czoxOiJBIjtzOjI6Is6RIjtzOjE6IkEiO3M6NDoi8J2aqCI7czoxOiJBIjtzOjQ6IvCdm6IiO3M6MToiQSI7czo0OiLwnZycIjtzOjE6IkEiO3M6NDoi8J2dliI7czoxOiJBIjtzOjQ6IvCdnpAiO3M6MToiQSI7czoyOiLQkCI7czoxOiJBIjtzOjM6IuGOqiI7czoxOiJBIjtzOjM6IuGXhSI7czoxOiJBIjtzOjM6IuqTriI7czoxOiJBIjtzOjQ6IvCWvYAiO3M6MToiQSI7czo0OiLwkIqgIjtzOjE6IkEiO3M6MjoiyKciO3M6MToi5SI7czoyOiLIpiI7czoxOiLFIjtzOjQ6IvCdkJsiO3M6MToiYiI7czo0OiLwnZGPIjtzOjE6ImIiO3M6NDoi8J2SgyI7czoxOiJiIjtzOjQ6IvCdkrciO3M6MToiYiI7czo0OiLwnZOrIjtzOjE6ImIiO3M6NDoi8J2UnyI7czoxOiJiIjtzOjQ6IvCdlZMiO3M6MToiYiI7czo0OiLwnZaHIjtzOjE6ImIiO3M6NDoi8J2WuyI7czoxOiJiIjtzOjQ6IvCdl68iO3M6MToiYiI7czo0OiLwnZijIjtzOjE6ImIiO3M6NDoi8J2ZlyI7czoxOiJiIjtzOjQ6IvCdmosiO3M6MToiYiI7czoyOiLGhCI7czoxOiJiIjtzOjI6ItCsIjtzOjE6ImIiO3M6Mzoi4Y+PIjtzOjE6ImIiO3M6Mzoi4ZGyIjtzOjE6ImIiO3M6Mzoi4ZavIjtzOjE6ImIiO3M6Mzoi77yiIjtzOjE6IkIiO3M6Mzoi4oSsIjtzOjE6IkIiO3M6NDoi8J2QgSI7czoxOiJCIjtzOjQ6IvCdkLUiO3M6MToiQiI7czo0OiLwnZGpIjtzOjE6IkIiO3M6NDoi8J2TkSI7czoxOiJCIjtzOjQ6IvCdlIUiO3M6MToiQiI7czo0OiLwnZS5IjtzOjE6IkIiO3M6NDoi8J2VrSI7czoxOiJCIjtzOjQ6IvCdlqEiO3M6MToiQiI7czo0OiLwnZeVIjtzOjE6IkIiO3M6NDoi8J2YiSI7czoxOiJCIjtzOjQ6IvCdmL0iO3M6MToiQiI7czo0OiLwnZmxIjtzOjE6IkIiO3M6Mzoi6p60IjtzOjE6IkIiO3M6MjoizpIiO3M6MToiQiI7czo0OiLwnZqpIjtzOjE6IkIiO3M6NDoi8J2boyI7czoxOiJCIjtzOjQ6IvCdnJ0iO3M6MToiQiI7czo0OiLwnZ2XIjtzOjE6IkIiO3M6NDoi8J2ekSI7czoxOiJCIjtzOjI6ItCSIjtzOjE6IkIiO3M6Mzoi4Y+0IjtzOjE6IkIiO3M6Mzoi4Ze3IjtzOjE6IkIiO3M6Mzoi6pOQIjtzOjE6IkIiO3M6NDoi8JCKgiI7czoxOiJCIjtzOjQ6IvCQiqEiO3M6MToiQiI7czo0OiLwkIyBIjtzOjE6IkIiO3M6Mzoi772DIjtzOjE6ImMiO3M6Mzoi4oW9IjtzOjE6ImMiO3M6NDoi8J2QnCI7czoxOiJjIjtzOjQ6IvCdkZAiO3M6MToiYyI7czo0OiLwnZKEIjtzOjE6ImMiO3M6NDoi8J2SuCI7czoxOiJjIjtzOjQ6IvCdk6wiO3M6MToiYyI7czo0OiLwnZSgIjtzOjE6ImMiO3M6NDoi8J2VlCI7czoxOiJjIjtzOjQ6IvCdlogiO3M6MToiYyI7czo0OiLwnZa8IjtzOjE6ImMiO3M6NDoi8J2XsCI7czoxOiJjIjtzOjQ6IvCdmKQiO3M6MToiYyI7czo0OiLwnZmYIjtzOjE6ImMiO3M6NDoi8J2ajCI7czoxOiJjIjtzOjM6IuG0hCI7czoxOiJjIjtzOjI6Is+yIjtzOjE6ImMiO3M6Mzoi4rKlIjtzOjE6ImMiO3M6Mjoi0YEiO3M6MToiYyI7czozOiLqrq8iO3M6MToiYyI7czo0OiLwkJC9IjtzOjE6ImMiO3M6NDoi8J+djCI7czoxOiJDIjtzOjQ6IvCRo7IiO3M6MToiQyI7czo0OiLwkaOpIjtzOjE6IkMiO3M6Mzoi77yjIjtzOjE6IkMiO3M6Mzoi4oWtIjtzOjE6IkMiO3M6Mzoi4oSCIjtzOjE6IkMiO3M6Mzoi4oStIjtzOjE6IkMiO3M6NDoi8J2QgiI7czoxOiJDIjtzOjQ6IvCdkLYiO3M6MToiQyI7czo0OiLwnZGqIjtzOjE6IkMiO3M6NDoi8J2SniI7czoxOiJDIjtzOjQ6IvCdk5IiO3M6MToiQyI7czo0OiLwnZWuIjtzOjE6IkMiO3M6NDoi8J2WoiI7czoxOiJDIjtzOjQ6IvCdl5YiO3M6MToiQyI7czo0OiLwnZiKIjtzOjE6IkMiO3M6NDoi8J2YviI7czoxOiJDIjtzOjQ6IvCdmbIiO3M6MToiQyI7czoyOiLPuSI7czoxOiJDIjtzOjM6IuKypCI7czoxOiJDIjtzOjI6ItChIjtzOjE6IkMiO3M6Mzoi4Y+fIjtzOjE6IkMiO3M6Mzoi6pOaIjtzOjE6IkMiO3M6NDoi8JCKoiI7czoxOiJDIjtzOjQ6IvCQjIIiO3M6MToiQyI7czo0OiLwkJCVIjtzOjE6IkMiO3M6NDoi8JCUnCI7czoxOiJDIjtzOjM6IuKFviI7czoxOiJkIjtzOjM6IuKFhiI7czoxOiJkIjtzOjQ6IvCdkJ0iO3M6MToiZCI7czo0OiLwnZGRIjtzOjE6ImQiO3M6NDoi8J2ShSI7czoxOiJkIjtzOjQ6IvCdkrkiO3M6MToiZCI7czo0OiLwnZOtIjtzOjE6ImQiO3M6NDoi8J2UoSI7czoxOiJkIjtzOjQ6IvCdlZUiO3M6MToiZCI7czo0OiLwnZaJIjtzOjE6ImQiO3M6NDoi8J2WvSI7czoxOiJkIjtzOjQ6IvCdl7EiO3M6MToiZCI7czo0OiLwnZilIjtzOjE6ImQiO3M6NDoi8J2ZmSI7czoxOiJkIjtzOjQ6IvCdmo0iO3M6MToiZCI7czoyOiLUgSI7czoxOiJkIjtzOjM6IuGPpyI7czoxOiJkIjtzOjM6IuGRryI7czoxOiJkIjtzOjM6IuqTkiI7czoxOiJkIjtzOjM6IuKFriI7czoxOiJEIjtzOjM6IuKFhSI7czoxOiJEIjtzOjQ6IvCdkIMiO3M6MToiRCI7czo0OiLwnZC3IjtzOjE6IkQiO3M6NDoi8J2RqyI7czoxOiJEIjtzOjQ6IvCdkp8iO3M6MToiRCI7czo0OiLwnZOTIjtzOjE6IkQiO3M6NDoi8J2UhyI7czoxOiJEIjtzOjQ6IvCdlLsiO3M6MToiRCI7czo0OiLwnZWvIjtzOjE6IkQiO3M6NDoi8J2WoyI7czoxOiJEIjtzOjQ6IvCdl5ciO3M6MToiRCI7czo0OiLwnZiLIjtzOjE6IkQiO3M6NDoi8J2YvyI7czoxOiJEIjtzOjQ6IvCdmbMiO3M6MToiRCI7czozOiLhjqAiO3M6MToiRCI7czozOiLhl54iO3M6MToiRCI7czozOiLhl6oiO3M6MToiRCI7czozOiLqk5MiO3M6MToiRCI7czozOiLihK4iO3M6MToiZSI7czozOiLvvYUiO3M6MToiZSI7czozOiLihK8iO3M6MToiZSI7czozOiLihYciO3M6MToiZSI7czo0OiLwnZCeIjtzOjE6ImUiO3M6NDoi8J2RkiI7czoxOiJlIjtzOjQ6IvCdkoYiO3M6MToiZSI7czo0OiLwnZOuIjtzOjE6ImUiO3M6NDoi8J2UoiI7czoxOiJlIjtzOjQ6IvCdlZYiO3M6MToiZSI7czo0OiLwnZaKIjtzOjE6ImUiO3M6NDoi8J2WviI7czoxOiJlIjtzOjQ6IvCdl7IiO3M6MToiZSI7czo0OiLwnZimIjtzOjE6ImUiO3M6NDoi8J2ZmiI7czoxOiJlIjtzOjQ6IvCdmo4iO3M6MToiZSI7czozOiLqrLIiO3M6MToiZSI7czoyOiLQtSI7czoxOiJlIjtzOjI6ItK9IjtzOjE6ImUiO3M6Mjoiw6kiO3M6MToiZSI7czozOiLii78iO3M6MToiRSI7czozOiLvvKUiO3M6MToiRSI7czozOiLihLAiO3M6MToiRSI7czo0OiLwnZCEIjtzOjE6IkUiO3M6NDoi8J2QuCI7czoxOiJFIjtzOjQ6IvCdkawiO3M6MToiRSI7czo0OiLwnZOUIjtzOjE6IkUiO3M6NDoi8J2UiCI7czoxOiJFIjtzOjQ6IvCdlLwiO3M6MToiRSI7czo0OiLwnZWwIjtzOjE6IkUiO3M6NDoi8J2WpCI7czoxOiJFIjtzOjQ6IvCdl5giO3M6MToiRSI7czo0OiLwnZiMIjtzOjE6IkUiO3M6NDoi8J2ZgCI7czoxOiJFIjtzOjQ6IvCdmbQiO3M6MToiRSI7czoyOiLOlSI7czoxOiJFIjtzOjQ6IvCdmqwiO3M6MToiRSI7czo0OiLwnZumIjtzOjE6IkUiO3M6NDoi8J2coCI7czoxOiJFIjtzOjQ6IvCdnZoiO3M6MToiRSI7czo0OiLwnZ6UIjtzOjE6IkUiO3M6Mjoi0JUiO3M6MToiRSI7czozOiLitLkiO3M6MToiRSI7czozOiLhjqwiO3M6MToiRSI7czozOiLqk7AiO3M6MToiRSI7czo0OiLwkaKmIjtzOjE6IkUiO3M6NDoi8JGiriI7czoxOiJFIjtzOjQ6IvCQioYiO3M6MToiRSI7czo0OiLwnZCfIjtzOjE6ImYiO3M6NDoi8J2RkyI7czoxOiJmIjtzOjQ6IvCdkociO3M6MToiZiI7czo0OiLwnZK7IjtzOjE6ImYiO3M6NDoi8J2TryI7czoxOiJmIjtzOjQ6IvCdlKMiO3M6MToiZiI7czo0OiLwnZWXIjtzOjE6ImYiO3M6NDoi8J2WiyI7czoxOiJmIjtzOjQ6IvCdlr8iO3M6MToiZiI7czo0OiLwnZezIjtzOjE6ImYiO3M6NDoi8J2YpyI7czoxOiJmIjtzOjQ6IvCdmZsiO3M6MToiZiI7czo0OiLwnZqPIjtzOjE6ImYiO3M6Mzoi6qy1IjtzOjE6ImYiO3M6Mzoi6p6ZIjtzOjE6ImYiO3M6Mjoixb8iO3M6MToiZiI7czozOiLhup0iO3M6MToiZiI7czoyOiLWhCI7czoxOiJmIjtzOjQ6IvCdiJMiO3M6MToiRiI7czozOiLihLEiO3M6MToiRiI7czo0OiLwnZCFIjtzOjE6IkYiO3M6NDoi8J2QuSI7czoxOiJGIjtzOjQ6IvCdka0iO3M6MToiRiI7czo0OiLwnZOVIjtzOjE6IkYiO3M6NDoi8J2UiSI7czoxOiJGIjtzOjQ6IvCdlL0iO3M6MToiRiI7czo0OiLwnZWxIjtzOjE6IkYiO3M6NDoi8J2WpSI7czoxOiJGIjtzOjQ6IvCdl5kiO3M6MToiRiI7czo0OiLwnZiNIjtzOjE6IkYiO3M6NDoi8J2ZgSI7czoxOiJGIjtzOjQ6IvCdmbUiO3M6MToiRiI7czozOiLqnpgiO3M6MToiRiI7czoyOiLPnCI7czoxOiJGIjtzOjQ6IvCdn4oiO3M6MToiRiI7czozOiLhlrQiO3M6MToiRiI7czozOiLqk50iO3M6MToiRiI7czo0OiLwkaOCIjtzOjE6IkYiO3M6NDoi8JGioiI7czoxOiJGIjtzOjQ6IvCQiociO3M6MToiRiI7czo0OiLwkIqlIjtzOjE6IkYiO3M6NDoi8JCUpSI7czoxOiJGIjtzOjM6Iu+9hyI7czoxOiJnIjtzOjM6IuKEiiI7czoxOiJnIjtzOjQ6IvCdkKAiO3M6MToiZyI7czo0OiLwnZGUIjtzOjE6ImciO3M6NDoi8J2SiCI7czoxOiJnIjtzOjQ6IvCdk7AiO3M6MToiZyI7czo0OiLwnZSkIjtzOjE6ImciO3M6NDoi8J2VmCI7czoxOiJnIjtzOjQ6IvCdlowiO3M6MToiZyI7czo0OiLwnZeAIjtzOjE6ImciO3M6NDoi8J2XtCI7czoxOiJnIjtzOjQ6IvCdmKgiO3M6MToiZyI7czo0OiLwnZmcIjtzOjE6ImciO3M6NDoi8J2akCI7czoxOiJnIjtzOjI6IsmhIjtzOjE6ImciO3M6Mzoi4baDIjtzOjE6ImciO3M6Mjoixo0iO3M6MToiZyI7czoyOiLWgSI7czoxOiJnIjtzOjQ6IvCdkIYiO3M6MToiRyI7czo0OiLwnZC6IjtzOjE6IkciO3M6NDoi8J2RriI7czoxOiJHIjtzOjQ6IvCdkqIiO3M6MToiRyI7czo0OiLwnZOWIjtzOjE6IkciO3M6NDoi8J2UiiI7czoxOiJHIjtzOjQ6IvCdlL4iO3M6MToiRyI7czo0OiLwnZWyIjtzOjE6IkciO3M6NDoi8J2WpiI7czoxOiJHIjtzOjQ6IvCdl5oiO3M6MToiRyI7czo0OiLwnZiOIjtzOjE6IkciO3M6NDoi8J2ZgiI7czoxOiJHIjtzOjQ6IvCdmbYiO3M6MToiRyI7czoyOiLUjCI7czoxOiJHIjtzOjM6IuGPgCI7czoxOiJHIjtzOjM6IuGPsyI7czoxOiJHIjtzOjM6IuqTliI7czoxOiJHIjtzOjM6Iu+9iCI7czoxOiJoIjtzOjM6IuKEjiI7czoxOiJoIjtzOjQ6IvCdkKEiO3M6MToiaCI7czo0OiLwnZKJIjtzOjE6ImgiO3M6NDoi8J2SvSI7czoxOiJoIjtzOjQ6IvCdk7EiO3M6MToiaCI7czo0OiLwnZSlIjtzOjE6ImgiO3M6NDoi8J2VmSI7czoxOiJoIjtzOjQ6IvCdlo0iO3M6MToiaCI7czo0OiLwnZeBIjtzOjE6ImgiO3M6NDoi8J2XtSI7czoxOiJoIjtzOjQ6IvCdmKkiO3M6MToiaCI7czo0OiLwnZmdIjtzOjE6ImgiO3M6NDoi8J2akSI7czoxOiJoIjtzOjI6ItK7IjtzOjE6ImgiO3M6Mjoi1bAiO3M6MToiaCI7czozOiLhj4IiO3M6MToiaCI7czozOiLvvKgiO3M6MToiSCI7czozOiLihIsiO3M6MToiSCI7czozOiLihIwiO3M6MToiSCI7czozOiLihI0iO3M6MToiSCI7czo0OiLwnZCHIjtzOjE6IkgiO3M6NDoi8J2QuyI7czoxOiJIIjtzOjQ6IvCdka8iO3M6MToiSCI7czo0OiLwnZOXIjtzOjE6IkgiO3M6NDoi8J2VsyI7czoxOiJIIjtzOjQ6IvCdlqciO3M6MToiSCI7czo0OiLwnZebIjtzOjE6IkgiO3M6NDoi8J2YjyI7czoxOiJIIjtzOjQ6IvCdmYMiO3M6MToiSCI7czo0OiLwnZm3IjtzOjE6IkgiO3M6MjoizpciO3M6MToiSCI7czo0OiLwnZquIjtzOjE6IkgiO3M6NDoi8J2bqCI7czoxOiJIIjtzOjQ6IvCdnKIiO3M6MToiSCI7czo0OiLwnZ2cIjtzOjE6IkgiO3M6NDoi8J2eliI7czoxOiJIIjtzOjM6IuKyjiI7czoxOiJIIjtzOjI6ItCdIjtzOjE6IkgiO3M6Mzoi4Y67IjtzOjE6IkgiO3M6Mzoi4ZW8IjtzOjE6IkgiO3M6Mzoi6pOnIjtzOjE6IkgiO3M6NDoi8JCLjyI7czoxOiJIIjtzOjI6IsubIjtzOjE6ImkiO3M6Mzoi4o2zIjtzOjE6ImkiO3M6Mzoi772JIjtzOjE6ImkiO3M6Mzoi4oWwIjtzOjE6ImkiO3M6Mzoi4oS5IjtzOjE6ImkiO3M6Mzoi4oWIIjtzOjE6ImkiO3M6NDoi8J2QoiI7czoxOiJpIjtzOjQ6IvCdkZYiO3M6MToiaSI7czo0OiLwnZKKIjtzOjE6ImkiO3M6NDoi8J2SviI7czoxOiJpIjtzOjQ6IvCdk7IiO3M6MToiaSI7czo0OiLwnZSmIjtzOjE6ImkiO3M6NDoi8J2VmiI7czoxOiJpIjtzOjQ6IvCdlo4iO3M6MToiaSI7czo0OiLwnZeCIjtzOjE6ImkiO3M6NDoi8J2XtiI7czoxOiJpIjtzOjQ6IvCdmKoiO3M6MToiaSI7czo0OiLwnZmeIjtzOjE6ImkiO3M6NDoi8J2akiI7czoxOiJpIjtzOjI6IsSxIjtzOjE6ImkiO3M6NDoi8J2apCI7czoxOiJpIjtzOjI6IsmqIjtzOjE6ImkiO3M6MjoiyakiO3M6MToiaSI7czoyOiLOuSI7czoxOiJpIjtzOjM6IuG+viI7czoxOiJpIjtzOjI6Is26IjtzOjE6ImkiO3M6NDoi8J2biiI7czoxOiJpIjtzOjQ6IvCdnIQiO3M6MToiaSI7czo0OiLwnZy+IjtzOjE6ImkiO3M6NDoi8J2duCI7czoxOiJpIjtzOjQ6IvCdnrIiO3M6MToiaSI7czoyOiLRliI7czoxOiJpIjtzOjM6IuqZhyI7czoxOiJpIjtzOjI6ItOPIjtzOjE6ImkiO3M6Mzoi6q21IjtzOjE6ImkiO3M6Mzoi4Y6lIjtzOjE6ImkiO3M6NDoi8JGjgyI7czoxOiJpIjtzOjI6IsOtIjtzOjE6ImkiO3M6Mzoi772KIjtzOjE6ImoiO3M6Mzoi4oWJIjtzOjE6ImoiO3M6NDoi8J2QoyI7czoxOiJqIjtzOjQ6IvCdkZciO3M6MToiaiI7czo0OiLwnZKLIjtzOjE6ImoiO3M6NDoi8J2SvyI7czoxOiJqIjtzOjQ6IvCdk7MiO3M6MToiaiI7czo0OiLwnZSnIjtzOjE6ImoiO3M6NDoi8J2VmyI7czoxOiJqIjtzOjQ6IvCdlo8iO3M6MToiaiI7czo0OiLwnZeDIjtzOjE6ImoiO3M6NDoi8J2XtyI7czoxOiJqIjtzOjQ6IvCdmKsiO3M6MToiaiI7czo0OiLwnZmfIjtzOjE6ImoiO3M6NDoi8J2akyI7czoxOiJqIjtzOjI6Is+zIjtzOjE6ImoiO3M6Mjoi0ZgiO3M6MToiaiI7czozOiLvvKoiO3M6MToiSiI7czo0OiLwnZCJIjtzOjE6IkoiO3M6NDoi8J2QvSI7czoxOiJKIjtzOjQ6IvCdkbEiO3M6MToiSiI7czo0OiLwnZKlIjtzOjE6IkoiO3M6NDoi8J2TmSI7czoxOiJKIjtzOjQ6IvCdlI0iO3M6MToiSiI7czo0OiLwnZWBIjtzOjE6IkoiO3M6NDoi8J2VtSI7czoxOiJKIjtzOjQ6IvCdlqkiO3M6MToiSiI7czo0OiLwnZedIjtzOjE6IkoiO3M6NDoi8J2YkSI7czoxOiJKIjtzOjQ6IvCdmYUiO3M6MToiSiI7czo0OiLwnZm5IjtzOjE6IkoiO3M6Mzoi6p6yIjtzOjE6IkoiO3M6Mjoizb8iO3M6MToiSiI7czoyOiLQiCI7czoxOiJKIjtzOjM6IuGOqyI7czoxOiJKIjtzOjM6IuGSjSI7czoxOiJKIjtzOjM6IuqTmSI7czoxOiJKIjtzOjQ6IvCdkKQiO3M6MToiayI7czo0OiLwnZGYIjtzOjE6ImsiO3M6NDoi8J2SjCI7czoxOiJrIjtzOjQ6IvCdk4AiO3M6MToiayI7czo0OiLwnZO0IjtzOjE6ImsiO3M6NDoi8J2UqCI7czoxOiJrIjtzOjQ6IvCdlZwiO3M6MToiayI7czo0OiLwnZaQIjtzOjE6ImsiO3M6NDoi8J2XhCI7czoxOiJrIjtzOjQ6IvCdl7giO3M6MToiayI7czo0OiLwnZisIjtzOjE6ImsiO3M6NDoi8J2ZoCI7czoxOiJrIjtzOjQ6IvCdmpQiO3M6MToiayI7czozOiLihKoiO3M6MToiSyI7czozOiLvvKsiO3M6MToiSyI7czo0OiLwnZCKIjtzOjE6IksiO3M6NDoi8J2QviI7czoxOiJLIjtzOjQ6IvCdkbIiO3M6MToiSyI7czo0OiLwnZKmIjtzOjE6IksiO3M6NDoi8J2TmiI7czoxOiJLIjtzOjQ6IvCdlI4iO3M6MToiSyI7czo0OiLwnZWCIjtzOjE6IksiO3M6NDoi8J2VtiI7czoxOiJLIjtzOjQ6IvCdlqoiO3M6MToiSyI7czo0OiLwnZeeIjtzOjE6IksiO3M6NDoi8J2YkiI7czoxOiJLIjtzOjQ6IvCdmYYiO3M6MToiSyI7czo0OiLwnZm6IjtzOjE6IksiO3M6MjoizpoiO3M6MToiSyI7czo0OiLwnZqxIjtzOjE6IksiO3M6NDoi8J2bqyI7czoxOiJLIjtzOjQ6IvCdnKUiO3M6MToiSyI7czo0OiLwnZ2fIjtzOjE6IksiO3M6NDoi8J2emSI7czoxOiJLIjtzOjM6IuKylCI7czoxOiJLIjtzOjI6ItCaIjtzOjE6IksiO3M6Mzoi4Y+mIjtzOjE6IksiO3M6Mzoi4ZuVIjtzOjE6IksiO3M6Mzoi6pOXIjtzOjE6IksiO3M6NDoi8JCUmCI7czoxOiJLIjtzOjI6IteAIjtzOjE6ImwiO3M6Mzoi4oijIjtzOjE6ImwiO3M6Mzoi4o+9IjtzOjE6ImwiO3M6Mzoi77+oIjtzOjE6ImwiO2k6MTtzOjE6ImwiO3M6Mjoi2aEiO3M6MToibCI7czoyOiLbsSI7czoxOiJsIjtzOjQ6IvCQjKAiO3M6MToibCI7czo0OiLwnqOHIjtzOjE6ImwiO3M6NDoi8J2fjyI7czoxOiJsIjtzOjQ6IvCdn5kiO3M6MToibCI7czo0OiLwnZ+jIjtzOjE6ImwiO3M6NDoi8J2frSI7czoxOiJsIjtzOjQ6IvCdn7ciO3M6MToibCI7czozOiLvvKkiO3M6MToibCI7czozOiLihaAiO3M6MToibCI7czozOiLihJAiO3M6MToibCI7czozOiLihJEiO3M6MToibCI7czo0OiLwnZCIIjtzOjE6ImwiO3M6NDoi8J2QvCI7czoxOiJsIjtzOjQ6IvCdkbAiO3M6MToibCI7czo0OiLwnZOYIjtzOjE6ImwiO3M6NDoi8J2VgCI7czoxOiJsIjtzOjQ6IvCdlbQiO3M6MToibCI7czo0OiLwnZaoIjtzOjE6ImwiO3M6NDoi8J2XnCI7czoxOiJsIjtzOjQ6IvCdmJAiO3M6MToibCI7czo0OiLwnZmEIjtzOjE6ImwiO3M6NDoi8J2ZuCI7czoxOiJsIjtzOjI6IsaWIjtzOjE6ImwiO3M6Mzoi772MIjtzOjE6ImwiO3M6Mzoi4oW8IjtzOjE6ImwiO3M6Mzoi4oSTIjtzOjE6ImwiO3M6NDoi8J2QpSI7czoxOiJsIjtzOjQ6IvCdkZkiO3M6MToibCI7czo0OiLwnZKNIjtzOjE6ImwiO3M6NDoi8J2TgSI7czoxOiJsIjtzOjQ6IvCdk7UiO3M6MToibCI7czo0OiLwnZSpIjtzOjE6ImwiO3M6NDoi8J2VnSI7czoxOiJsIjtzOjQ6IvCdlpEiO3M6MToibCI7czo0OiLwnZeFIjtzOjE6ImwiO3M6NDoi8J2XuSI7czoxOiJsIjtzOjQ6IvCdmK0iO3M6MToibCI7czo0OiLwnZmhIjtzOjE6ImwiO3M6NDoi8J2alSI7czoxOiJsIjtzOjI6IseAIjtzOjE6ImwiO3M6MjoizpkiO3M6MToibCI7czo0OiLwnZqwIjtzOjE6ImwiO3M6NDoi8J2bqiI7czoxOiJsIjtzOjQ6IvCdnKQiO3M6MToibCI7czo0OiLwnZ2eIjtzOjE6ImwiO3M6NDoi8J2emCI7czoxOiJsIjtzOjM6IuKykiI7czoxOiJsIjtzOjI6ItCGIjtzOjE6ImwiO3M6Mjoi04AiO3M6MToibCI7czoyOiLXlSI7czoxOiJsIjtzOjI6ItefIjtzOjE6ImwiO3M6Mjoi2KciO3M6MToibCI7czo0OiLwnriAIjtzOjE6ImwiO3M6NDoi8J66gCI7czoxOiJsIjtzOjM6Iu+6jiI7czoxOiJsIjtzOjM6Iu+6jSI7czoxOiJsIjtzOjI6It+KIjtzOjE6ImwiO3M6Mzoi4rWPIjtzOjE6ImwiO3M6Mzoi4ZuBIjtzOjE6ImwiO3M6Mzoi6pOyIjtzOjE6ImwiO3M6NDoi8Ja8qCI7czoxOiJsIjtzOjQ6IvCQiooiO3M6MToibCI7czo0OiLwkIyJIjtzOjE6ImwiO3M6NDoi8J2IqiI7czoxOiJMIjtzOjM6IuKFrCI7czoxOiJMIjtzOjM6IuKEkiI7czoxOiJMIjtzOjQ6IvCdkIsiO3M6MToiTCI7czo0OiLwnZC/IjtzOjE6IkwiO3M6NDoi8J2RsyI7czoxOiJMIjtzOjQ6IvCdk5siO3M6MToiTCI7czo0OiLwnZSPIjtzOjE6IkwiO3M6NDoi8J2VgyI7czoxOiJMIjtzOjQ6IvCdlbciO3M6MToiTCI7czo0OiLwnZarIjtzOjE6IkwiO3M6NDoi8J2XnyI7czoxOiJMIjtzOjQ6IvCdmJMiO3M6MToiTCI7czo0OiLwnZmHIjtzOjE6IkwiO3M6NDoi8J2ZuyI7czoxOiJMIjtzOjM6IuKzkCI7czoxOiJMIjtzOjM6IuGPniI7czoxOiJMIjtzOjM6IuGSqiI7czoxOiJMIjtzOjM6IuqToSI7czoxOiJMIjtzOjQ6IvCWvJYiO3M6MToiTCI7czo0OiLwkaKjIjtzOjE6IkwiO3M6NDoi8JGisiI7czoxOiJMIjtzOjQ6IvCQkJsiO3M6MToiTCI7czo0OiLwkJSmIjtzOjE6IkwiO3M6Mzoi77ytIjtzOjE6Ik0iO3M6Mzoi4oWvIjtzOjE6Ik0iO3M6Mzoi4oSzIjtzOjE6Ik0iO3M6NDoi8J2QjCI7czoxOiJNIjtzOjQ6IvCdkYAiO3M6MToiTSI7czo0OiLwnZG0IjtzOjE6Ik0iO3M6NDoi8J2TnCI7czoxOiJNIjtzOjQ6IvCdlJAiO3M6MToiTSI7czo0OiLwnZWEIjtzOjE6Ik0iO3M6NDoi8J2VuCI7czoxOiJNIjtzOjQ6IvCdlqwiO3M6MToiTSI7czo0OiLwnZegIjtzOjE6Ik0iO3M6NDoi8J2YlCI7czoxOiJNIjtzOjQ6IvCdmYgiO3M6MToiTSI7czo0OiLwnZm8IjtzOjE6Ik0iO3M6MjoizpwiO3M6MToiTSI7czo0OiLwnZqzIjtzOjE6Ik0iO3M6NDoi8J2brSI7czoxOiJNIjtzOjQ6IvCdnKciO3M6MToiTSI7czo0OiLwnZ2hIjtzOjE6Ik0iO3M6NDoi8J2emyI7czoxOiJNIjtzOjI6Is+6IjtzOjE6Ik0iO3M6Mzoi4rKYIjtzOjE6Ik0iO3M6Mjoi0JwiO3M6MToiTSI7czozOiLhjrciO3M6MToiTSI7czozOiLhl7AiO3M6MToiTSI7czozOiLhm5YiO3M6MToiTSI7czozOiLqk58iO3M6MToiTSI7czo0OiLwkIqwIjtzOjE6Ik0iO3M6NDoi8JCMkSI7czoxOiJNIjtzOjQ6IvCdkKciO3M6MToibiI7czo0OiLwnZGbIjtzOjE6Im4iO3M6NDoi8J2SjyI7czoxOiJuIjtzOjQ6IvCdk4MiO3M6MToibiI7czo0OiLwnZO3IjtzOjE6Im4iO3M6NDoi8J2UqyI7czoxOiJuIjtzOjQ6IvCdlZ8iO3M6MToibiI7czo0OiLwnZaTIjtzOjE6Im4iO3M6NDoi8J2XhyI7czoxOiJuIjtzOjQ6IvCdl7siO3M6MToibiI7czo0OiLwnZivIjtzOjE6Im4iO3M6NDoi8J2ZoyI7czoxOiJuIjtzOjQ6IvCdmpciO3M6MToibiI7czoyOiLVuCI7czoxOiJuIjtzOjI6ItW8IjtzOjE6Im4iO3M6MjoiybQiO3M6MToibiI7czozOiLvvK4iO3M6MToiTiI7czozOiLihJUiO3M6MToiTiI7czo0OiLwnZCNIjtzOjE6Ik4iO3M6NDoi8J2RgSI7czoxOiJOIjtzOjQ6IvCdkbUiO3M6MToiTiI7czo0OiLwnZKpIjtzOjE6Ik4iO3M6NDoi8J2TnSI7czoxOiJOIjtzOjQ6IvCdlJEiO3M6MToiTiI7czo0OiLwnZW5IjtzOjE6Ik4iO3M6NDoi8J2WrSI7czoxOiJOIjtzOjQ6IvCdl6EiO3M6MToiTiI7czo0OiLwnZiVIjtzOjE6Ik4iO3M6NDoi8J2ZiSI7czoxOiJOIjtzOjQ6IvCdmb0iO3M6MToiTiI7czoyOiLOnSI7czoxOiJOIjtzOjQ6IvCdmrQiO3M6MToiTiI7czo0OiLwnZuuIjtzOjE6Ik4iO3M6NDoi8J2cqCI7czoxOiJOIjtzOjQ6IvCdnaIiO3M6MToiTiI7czo0OiLwnZ6cIjtzOjE6Ik4iO3M6Mzoi4rKaIjtzOjE6Ik4iO3M6Mzoi6pOgIjtzOjE6Ik4iO3M6NDoi8JCUkyI7czoxOiJOIjtzOjM6IuCwgiI7czoxOiJvIjtzOjM6IuCygiI7czoxOiJvIjtzOjM6IuC0giI7czoxOiJvIjtzOjM6IuC2giI7czoxOiJvIjtzOjM6IuClpiI7czoxOiJvIjtzOjM6IuCppiI7czoxOiJvIjtzOjM6IuCrpiI7czoxOiJvIjtzOjM6IuCvpiI7czoxOiJvIjtzOjM6IuCxpiI7czoxOiJvIjtzOjM6IuCzpiI7czoxOiJvIjtzOjM6IuC1piI7czoxOiJvIjtzOjM6IuC5kCI7czoxOiJvIjtzOjM6IuC7kCI7czoxOiJvIjtzOjM6IuGBgCI7czoxOiJvIjtzOjI6ItmlIjtzOjE6Im8iO3M6Mjoi27UiO3M6MToibyI7czozOiLvvY8iO3M6MToibyI7czozOiLihLQiO3M6MToibyI7czo0OiLwnZCoIjtzOjE6Im8iO3M6NDoi8J2RnCI7czoxOiJvIjtzOjQ6IvCdkpAiO3M6MToibyI7czo0OiLwnZO4IjtzOjE6Im8iO3M6NDoi8J2UrCI7czoxOiJvIjtzOjQ6IvCdlaAiO3M6MToibyI7czo0OiLwnZaUIjtzOjE6Im8iO3M6NDoi8J2XiCI7czoxOiJvIjtzOjQ6IvCdl7wiO3M6MToibyI7czo0OiLwnZiwIjtzOjE6Im8iO3M6NDoi8J2ZpCI7czoxOiJvIjtzOjQ6IvCdmpgiO3M6MToibyI7czozOiLhtI8iO3M6MToibyI7czozOiLhtJEiO3M6MToibyI7czozOiLqrL0iO3M6MToibyI7czoyOiLOvyI7czoxOiJvIjtzOjQ6IvCdm5AiO3M6MToibyI7czo0OiLwnZyKIjtzOjE6Im8iO3M6NDoi8J2dhCI7czoxOiJvIjtzOjQ6IvCdnb4iO3M6MToibyI7czo0OiLwnZ64IjtzOjE6Im8iO3M6Mjoiz4MiO3M6MToibyI7czo0OiLwnZuUIjtzOjE6Im8iO3M6NDoi8J2cjiI7czoxOiJvIjtzOjQ6IvCdnYgiO3M6MToibyI7czo0OiLwnZ6CIjtzOjE6Im8iO3M6NDoi8J2evCI7czoxOiJvIjtzOjM6IuKynyI7czoxOiJvIjtzOjI6ItC+IjtzOjE6Im8iO3M6Mzoi4YO/IjtzOjE6Im8iO3M6Mjoi1oUiO3M6MToibyI7czoyOiLXoSI7czoxOiJvIjtzOjI6ItmHIjtzOjE6Im8iO3M6NDoi8J64pCI7czoxOiJvIjtzOjQ6IvCeuaQiO3M6MToibyI7czo0OiLwnrqEIjtzOjE6Im8iO3M6Mzoi77urIjtzOjE6Im8iO3M6Mzoi77usIjtzOjE6Im8iO3M6Mzoi77uqIjtzOjE6Im8iO3M6Mzoi77upIjtzOjE6Im8iO3M6Mjoi2r4iO3M6MToibyI7czozOiLvrqwiO3M6MToibyI7czozOiLvrq0iO3M6MToibyI7czozOiLvrqsiO3M6MToibyI7czozOiLvrqoiO3M6MToibyI7czoyOiLbgSI7czoxOiJvIjtzOjM6Iu+uqCI7czoxOiJvIjtzOjM6Iu+uqSI7czoxOiJvIjtzOjM6Iu+upyI7czoxOiJvIjtzOjM6Iu+upiI7czoxOiJvIjtzOjI6ItuVIjtzOjE6Im8iO3M6Mzoi4LSgIjtzOjE6Im8iO3M6Mzoi4YCdIjtzOjE6Im8iO3M6NDoi8JCTqiI7czoxOiJvIjtzOjQ6IvCRo4giO3M6MToibyI7czo0OiLwkaOXIjtzOjE6Im8iO3M6NDoi8JCQrCI7czoxOiJvIjtpOjA7czoxOiJPIjtzOjI6It+AIjtzOjE6Ik8iO3M6Mzoi4KemIjtzOjE6Ik8iO3M6Mzoi4K2mIjtzOjE6Ik8iO3M6Mzoi44CHIjtzOjE6Ik8iO3M6NDoi8JGTkCI7czoxOiJPIjtzOjQ6IvCRo6AiO3M6MToiTyI7czo0OiLwnZ+OIjtzOjE6Ik8iO3M6NDoi8J2fmCI7czoxOiJPIjtzOjQ6IvCdn6IiO3M6MToiTyI7czo0OiLwnZ+sIjtzOjE6Ik8iO3M6NDoi8J2ftiI7czoxOiJPIjtzOjM6Iu+8ryI7czoxOiJPIjtzOjQ6IvCdkI4iO3M6MToiTyI7czo0OiLwnZGCIjtzOjE6Ik8iO3M6NDoi8J2RtiI7czoxOiJPIjtzOjQ6IvCdkqoiO3M6MToiTyI7czo0OiLwnZOeIjtzOjE6Ik8iO3M6NDoi8J2UkiI7czoxOiJPIjtzOjQ6IvCdlYYiO3M6MToiTyI7czo0OiLwnZW6IjtzOjE6Ik8iO3M6NDoi8J2WriI7czoxOiJPIjtzOjQ6IvCdl6IiO3M6MToiTyI7czo0OiLwnZiWIjtzOjE6Ik8iO3M6NDoi8J2ZiiI7czoxOiJPIjtzOjQ6IvCdmb4iO3M6MToiTyI7czoyOiLOnyI7czoxOiJPIjtzOjQ6IvCdmrYiO3M6MToiTyI7czo0OiLwnZuwIjtzOjE6Ik8iO3M6NDoi8J2cqiI7czoxOiJPIjtzOjQ6IvCdnaQiO3M6MToiTyI7czo0OiLwnZ6eIjtzOjE6Ik8iO3M6Mzoi4rKeIjtzOjE6Ik8iO3M6Mjoi0J4iO3M6MToiTyI7czoyOiLVlSI7czoxOiJPIjtzOjM6IuK1lCI7czoxOiJPIjtzOjM6IuGLkCI7czoxOiJPIjtzOjM6IuCsoCI7czoxOiJPIjtzOjQ6IvCQk4IiO3M6MToiTyI7czozOiLqk7MiO3M6MToiTyI7czo0OiLwkaK1IjtzOjE6Ik8iO3M6NDoi8JCKkiI7czoxOiJPIjtzOjQ6IvCQiqsiO3M6MToiTyI7czo0OiLwkJCEIjtzOjE6Ik8iO3M6NDoi8JCUliI7czoxOiJPIjtzOjM6IuKBsCI7czoxOiK6IjtzOjM6IuG1kiI7czoxOiK6IjtzOjI6IsWQIjtzOjE6ItYiO3M6Mzoi4o20IjtzOjE6InAiO3M6Mzoi772QIjtzOjE6InAiO3M6NDoi8J2QqSI7czoxOiJwIjtzOjQ6IvCdkZ0iO3M6MToicCI7czo0OiLwnZKRIjtzOjE6InAiO3M6NDoi8J2ThSI7czoxOiJwIjtzOjQ6IvCdk7kiO3M6MToicCI7czo0OiLwnZStIjtzOjE6InAiO3M6NDoi8J2VoSI7czoxOiJwIjtzOjQ6IvCdlpUiO3M6MToicCI7czo0OiLwnZeJIjtzOjE6InAiO3M6NDoi8J2XvSI7czoxOiJwIjtzOjQ6IvCdmLEiO3M6MToicCI7czo0OiLwnZmlIjtzOjE6InAiO3M6NDoi8J2amSI7czoxOiJwIjtzOjI6Is+BIjtzOjE6InAiO3M6Mjoiz7EiO3M6MToicCI7czo0OiLwnZuSIjtzOjE6InAiO3M6NDoi8J2boCI7czoxOiJwIjtzOjQ6IvCdnIwiO3M6MToicCI7czo0OiLwnZyaIjtzOjE6InAiO3M6NDoi8J2dhiI7czoxOiJwIjtzOjQ6IvCdnZQiO3M6MToicCI7czo0OiLwnZ6AIjtzOjE6InAiO3M6NDoi8J2ejiI7czoxOiJwIjtzOjQ6IvCdnroiO3M6MToicCI7czo0OiLwnZ+IIjtzOjE6InAiO3M6Mzoi4rKjIjtzOjE6InAiO3M6Mjoi0YAiO3M6MToicCI7czozOiLvvLAiO3M6MToiUCI7czozOiLihJkiO3M6MToiUCI7czo0OiLwnZCPIjtzOjE6IlAiO3M6NDoi8J2RgyI7czoxOiJQIjtzOjQ6IvCdkbciO3M6MToiUCI7czo0OiLwnZKrIjtzOjE6IlAiO3M6NDoi8J2TnyI7czoxOiJQIjtzOjQ6IvCdlJMiO3M6MToiUCI7czo0OiLwnZW7IjtzOjE6IlAiO3M6NDoi8J2WryI7czoxOiJQIjtzOjQ6IvCdl6MiO3M6MToiUCI7czo0OiLwnZiXIjtzOjE6IlAiO3M6NDoi8J2ZiyI7czoxOiJQIjtzOjQ6IvCdmb8iO3M6MToiUCI7czoyOiLOoSI7czoxOiJQIjtzOjQ6IvCdmrgiO3M6MToiUCI7czo0OiLwnZuyIjtzOjE6IlAiO3M6NDoi8J2crCI7czoxOiJQIjtzOjQ6IvCdnaYiO3M6MToiUCI7czo0OiLwnZ6gIjtzOjE6IlAiO3M6Mzoi4rKiIjtzOjE6IlAiO3M6Mjoi0KAiO3M6MToiUCI7czozOiLhj6IiO3M6MToiUCI7czozOiLhka0iO3M6MToiUCI7czozOiLqk5EiO3M6MToiUCI7czo0OiLwkIqVIjtzOjE6IlAiO3M6NDoi8J2QqiI7czoxOiJxIjtzOjQ6IvCdkZ4iO3M6MToicSI7czo0OiLwnZKSIjtzOjE6InEiO3M6NDoi8J2ThiI7czoxOiJxIjtzOjQ6IvCdk7oiO3M6MToicSI7czo0OiLwnZSuIjtzOjE6InEiO3M6NDoi8J2VoiI7czoxOiJxIjtzOjQ6IvCdlpYiO3M6MToicSI7czo0OiLwnZeKIjtzOjE6InEiO3M6NDoi8J2XviI7czoxOiJxIjtzOjQ6IvCdmLIiO3M6MToicSI7czo0OiLwnZmmIjtzOjE6InEiO3M6NDoi8J2amiI7czoxOiJxIjtzOjI6ItSbIjtzOjE6InEiO3M6Mjoi1aMiO3M6MToicSI7czoyOiLVpiI7czoxOiJxIjtzOjM6IuKEmiI7czoxOiJRIjtzOjQ6IvCdkJAiO3M6MToiUSI7czo0OiLwnZGEIjtzOjE6IlEiO3M6NDoi8J2RuCI7czoxOiJRIjtzOjQ6IvCdkqwiO3M6MToiUSI7czo0OiLwnZOgIjtzOjE6IlEiO3M6NDoi8J2UlCI7czoxOiJRIjtzOjQ6IvCdlbwiO3M6MToiUSI7czo0OiLwnZawIjtzOjE6IlEiO3M6NDoi8J2XpCI7czoxOiJRIjtzOjQ6IvCdmJgiO3M6MToiUSI7czo0OiLwnZmMIjtzOjE6IlEiO3M6NDoi8J2agCI7czoxOiJRIjtzOjM6IuK1lSI7czoxOiJRIjtzOjQ6IvCdkKsiO3M6MToiciI7czo0OiLwnZGfIjtzOjE6InIiO3M6NDoi8J2SkyI7czoxOiJyIjtzOjQ6IvCdk4ciO3M6MToiciI7czo0OiLwnZO7IjtzOjE6InIiO3M6NDoi8J2UryI7czoxOiJyIjtzOjQ6IvCdlaMiO3M6MToiciI7czo0OiLwnZaXIjtzOjE6InIiO3M6NDoi8J2XiyI7czoxOiJyIjtzOjQ6IvCdl78iO3M6MToiciI7czo0OiLwnZizIjtzOjE6InIiO3M6NDoi8J2ZpyI7czoxOiJyIjtzOjQ6IvCdmpsiO3M6MToiciI7czozOiLqrYciO3M6MToiciI7czozOiLqrYgiO3M6MToiciI7czozOiLhtKYiO3M6MToiciI7czozOiLisoUiO3M6MToiciI7czoyOiLQsyI7czoxOiJyIjtzOjM6IuqugSI7czoxOiJyIjtzOjI6IsqAIjtzOjE6InIiO3M6NDoi8J2IliI7czoxOiJSIjtzOjM6IuKEmyI7czoxOiJSIjtzOjM6IuKEnCI7czoxOiJSIjtzOjM6IuKEnSI7czoxOiJSIjtzOjQ6IvCdkJEiO3M6MToiUiI7czo0OiLwnZGFIjtzOjE6IlIiO3M6NDoi8J2RuSI7czoxOiJSIjtzOjQ6IvCdk6EiO3M6MToiUiI7czo0OiLwnZW9IjtzOjE6IlIiO3M6NDoi8J2WsSI7czoxOiJSIjtzOjQ6IvCdl6UiO3M6MToiUiI7czo0OiLwnZiZIjtzOjE6IlIiO3M6NDoi8J2ZjSI7czoxOiJSIjtzOjQ6IvCdmoEiO3M6MToiUiI7czoyOiLGpiI7czoxOiJSIjtzOjM6IuGOoSI7czoxOiJSIjtzOjM6IuGPkiI7czoxOiJSIjtzOjQ6IvCQkrQiO3M6MToiUiI7czozOiLhlociO3M6MToiUiI7czozOiLqk6MiO3M6MToiUiI7czo0OiLwlry1IjtzOjE6IlIiO3M6Mzoi772TIjtzOjE6InMiO3M6NDoi8J2QrCI7czoxOiJzIjtzOjQ6IvCdkaAiO3M6MToicyI7czo0OiLwnZKUIjtzOjE6InMiO3M6NDoi8J2TiCI7czoxOiJzIjtzOjQ6IvCdk7wiO3M6MToicyI7czo0OiLwnZSwIjtzOjE6InMiO3M6NDoi8J2VpCI7czoxOiJzIjtzOjQ6IvCdlpgiO3M6MToicyI7czo0OiLwnZeMIjtzOjE6InMiO3M6NDoi8J2YgCI7czoxOiJzIjtzOjQ6IvCdmLQiO3M6MToicyI7czo0OiLwnZmoIjtzOjE6InMiO3M6NDoi8J2anCI7czoxOiJzIjtzOjM6IuqcsSI7czoxOiJzIjtzOjI6Isa9IjtzOjE6InMiO3M6Mjoi0ZUiO3M6MToicyI7czozOiLqrqoiO3M6MToicyI7czo0OiLwkaOBIjtzOjE6InMiO3M6NDoi8JCRiCI7czoxOiJzIjtzOjM6Iu+8syI7czoxOiJTIjtzOjQ6IvCdkJIiO3M6MToiUyI7czo0OiLwnZGGIjtzOjE6IlMiO3M6NDoi8J2RuiI7czoxOiJTIjtzOjQ6IvCdkq4iO3M6MToiUyI7czo0OiLwnZOiIjtzOjE6IlMiO3M6NDoi8J2UliI7czoxOiJTIjtzOjQ6IvCdlYoiO3M6MToiUyI7czo0OiLwnZW+IjtzOjE6IlMiO3M6NDoi8J2WsiI7czoxOiJTIjtzOjQ6IvCdl6YiO3M6MToiUyI7czo0OiLwnZiaIjtzOjE6IlMiO3M6NDoi8J2ZjiI7czoxOiJTIjtzOjQ6IvCdmoIiO3M6MToiUyI7czoyOiLQhSI7czoxOiJTIjtzOjI6ItWPIjtzOjE6IlMiO3M6Mzoi4Y+VIjtzOjE6IlMiO3M6Mzoi4Y+aIjtzOjE6IlMiO3M6Mzoi6pOiIjtzOjE6IlMiO3M6NDoi8Ja8uiI7czoxOiJTIjtzOjQ6IvCQipYiO3M6MToiUyI7czo0OiLwkJCgIjtzOjE6IlMiO3M6Mzoi6p61IjtzOjE6It8iO3M6MjoizrIiO3M6MToi3yI7czoyOiLPkCI7czoxOiLfIjtzOjQ6IvCdm4MiO3M6MToi3yI7czo0OiLwnZu9IjtzOjE6It8iO3M6NDoi8J2ctyI7czoxOiLfIjtzOjQ6IvCdnbEiO3M6MToi3yI7czo0OiLwnZ6rIjtzOjE6It8iO3M6Mzoi4Y+wIjtzOjE6It8iO3M6NDoi8J2QrSI7czoxOiJ0IjtzOjQ6IvCdkaEiO3M6MToidCI7czo0OiLwnZKVIjtzOjE6InQiO3M6NDoi8J2TiSI7czoxOiJ0IjtzOjQ6IvCdk70iO3M6MToidCI7czo0OiLwnZSxIjtzOjE6InQiO3M6NDoi8J2VpSI7czoxOiJ0IjtzOjQ6IvCdlpkiO3M6MToidCI7czo0OiLwnZeNIjtzOjE6InQiO3M6NDoi8J2YgSI7czoxOiJ0IjtzOjQ6IvCdmLUiO3M6MToidCI7czo0OiLwnZmpIjtzOjE6InQiO3M6NDoi8J2anSI7czoxOiJ0IjtzOjM6IuG0myI7czoxOiJ0IjtzOjM6IuKKpCI7czoxOiJUIjtzOjM6IuKfmSI7czoxOiJUIjtzOjQ6IvCfnagiO3M6MToiVCI7czozOiLvvLQiO3M6MToiVCI7czo0OiLwnZCTIjtzOjE6IlQiO3M6NDoi8J2RhyI7czoxOiJUIjtzOjQ6IvCdkbsiO3M6MToiVCI7czo0OiLwnZKvIjtzOjE6IlQiO3M6NDoi8J2ToyI7czoxOiJUIjtzOjQ6IvCdlJciO3M6MToiVCI7czo0OiLwnZWLIjtzOjE6IlQiO3M6NDoi8J2VvyI7czoxOiJUIjtzOjQ6IvCdlrMiO3M6MToiVCI7czo0OiLwnZenIjtzOjE6IlQiO3M6NDoi8J2YmyI7czoxOiJUIjtzOjQ6IvCdmY8iO3M6MToiVCI7czo0OiLwnZqDIjtzOjE6IlQiO3M6MjoizqQiO3M6MToiVCI7czo0OiLwnZq7IjtzOjE6IlQiO3M6NDoi8J2btSI7czoxOiJUIjtzOjQ6IvCdnK8iO3M6MToiVCI7czo0OiLwnZ2pIjtzOjE6IlQiO3M6NDoi8J2eoyI7czoxOiJUIjtzOjM6IuKypiI7czoxOiJUIjtzOjI6ItCiIjtzOjE6IlQiO3M6Mzoi4Y6iIjtzOjE6IlQiO3M6Mzoi6pOUIjtzOjE6IlQiO3M6NDoi8Ja8iiI7czoxOiJUIjtzOjQ6IvCRorwiO3M6MToiVCI7czo0OiLwkIqXIjtzOjE6IlQiO3M6NDoi8JCKsSI7czoxOiJUIjtzOjQ6IvCQjJUiO3M6MToiVCI7czo0OiLwnZCuIjtzOjE6InUiO3M6NDoi8J2RoiI7czoxOiJ1IjtzOjQ6IvCdkpYiO3M6MToidSI7czo0OiLwnZOKIjtzOjE6InUiO3M6NDoi8J2TviI7czoxOiJ1IjtzOjQ6IvCdlLIiO3M6MToidSI7czo0OiLwnZWmIjtzOjE6InUiO3M6NDoi8J2WmiI7czoxOiJ1IjtzOjQ6IvCdl44iO3M6MToidSI7czo0OiLwnZiCIjtzOjE6InUiO3M6NDoi8J2YtiI7czoxOiJ1IjtzOjQ6IvCdmaoiO3M6MToidSI7czo0OiLwnZqeIjtzOjE6InUiO3M6Mzoi6p6fIjtzOjE6InUiO3M6Mzoi4bScIjtzOjE6InUiO3M6Mzoi6q2OIjtzOjE6InUiO3M6Mzoi6q2SIjtzOjE6InUiO3M6MjoiyosiO3M6MToidSI7czoyOiLPhSI7czoxOiJ1IjtzOjQ6IvCdm5YiO3M6MToidSI7czo0OiLwnZyQIjtzOjE6InUiO3M6NDoi8J2diiI7czoxOiJ1IjtzOjQ6IvCdnoQiO3M6MToidSI7czo0OiLwnZ6+IjtzOjE6InUiO3M6Mjoi1b0iO3M6MToidSI7czo0OiLwkJO2IjtzOjE6InUiO3M6NDoi8JGjmCI7czoxOiJ1IjtzOjM6IuKIqiI7czoxOiJVIjtzOjM6IuKLgyI7czoxOiJVIjtzOjQ6IvCdkJQiO3M6MToiVSI7czo0OiLwnZGIIjtzOjE6IlUiO3M6NDoi8J2RvCI7czoxOiJVIjtzOjQ6IvCdkrAiO3M6MToiVSI7czo0OiLwnZOkIjtzOjE6IlUiO3M6NDoi8J2UmCI7czoxOiJVIjtzOjQ6IvCdlYwiO3M6MToiVSI7czo0OiLwnZaAIjtzOjE6IlUiO3M6NDoi8J2WtCI7czoxOiJVIjtzOjQ6IvCdl6giO3M6MToiVSI7czo0OiLwnZicIjtzOjE6IlUiO3M6NDoi8J2ZkCI7czoxOiJVIjtzOjQ6IvCdmoQiO3M6MToiVSI7czoyOiLVjSI7czoxOiJVIjtzOjM6IuGIgCI7czoxOiJVIjtzOjQ6IvCQk44iO3M6MToiVSI7czozOiLhkYwiO3M6MToiVSI7czozOiLqk7QiO3M6MToiVSI7czo0OiLwlr2CIjtzOjE6IlUiO3M6NDoi8JGiuCI7czoxOiJVIjtzOjM6IuKIqCI7czoxOiJ2IjtzOjM6IuKLgSI7czoxOiJ2IjtzOjM6Iu+9liI7czoxOiJ2IjtzOjM6IuKFtCI7czoxOiJ2IjtzOjQ6IvCdkK8iO3M6MToidiI7czo0OiLwnZGjIjtzOjE6InYiO3M6NDoi8J2SlyI7czoxOiJ2IjtzOjQ6IvCdk4siO3M6MToidiI7czo0OiLwnZO/IjtzOjE6InYiO3M6NDoi8J2UsyI7czoxOiJ2IjtzOjQ6IvCdlaciO3M6MToidiI7czo0OiLwnZabIjtzOjE6InYiO3M6NDoi8J2XjyI7czoxOiJ2IjtzOjQ6IvCdmIMiO3M6MToidiI7czo0OiLwnZi3IjtzOjE6InYiO3M6NDoi8J2ZqyI7czoxOiJ2IjtzOjQ6IvCdmp8iO3M6MToidiI7czozOiLhtKAiO3M6MToidiI7czoyOiLOvSI7czoxOiJ2IjtzOjQ6IvCdm44iO3M6MToidiI7czo0OiLwnZyIIjtzOjE6InYiO3M6NDoi8J2dgiI7czoxOiJ2IjtzOjQ6IvCdnbwiO3M6MToidiI7czo0OiLwnZ62IjtzOjE6InYiO3M6Mjoi0bUiO3M6MToidiI7czoyOiLXmCI7czoxOiJ2IjtzOjQ6IvCRnIYiO3M6MToidiI7czozOiLqrqkiO3M6MToidiI7czo0OiLwkaOAIjtzOjE6InYiO3M6NDoi8J2IjSI7czoxOiJWIjtzOjI6ItmnIjtzOjE6IlYiO3M6Mjoi27ciO3M6MToiViI7czozOiLihaQiO3M6MToiViI7czo0OiLwnZCVIjtzOjE6IlYiO3M6NDoi8J2RiSI7czoxOiJWIjtzOjQ6IvCdkb0iO3M6MToiViI7czo0OiLwnZKxIjtzOjE6IlYiO3M6NDoi8J2TpSI7czoxOiJWIjtzOjQ6IvCdlJkiO3M6MToiViI7czo0OiLwnZWNIjtzOjE6IlYiO3M6NDoi8J2WgSI7czoxOiJWIjtzOjQ6IvCdlrUiO3M6MToiViI7czo0OiLwnZepIjtzOjE6IlYiO3M6NDoi8J2YnSI7czoxOiJWIjtzOjQ6IvCdmZEiO3M6MToiViI7czo0OiLwnZqFIjtzOjE6IlYiO3M6Mjoi0bQiO3M6MToiViI7czozOiLitLgiO3M6MToiViI7czozOiLhj5kiO3M6MToiViI7czozOiLhkK8iO3M6MToiViI7czozOiLqm58iO3M6MToiViI7czozOiLqk6YiO3M6MToiViI7czo0OiLwlryIIjtzOjE6IlYiO3M6NDoi8JGioCI7czoxOiJWIjtzOjQ6IvCQlJ0iO3M6MToiViI7czoyOiLJryI7czoxOiJ3IjtzOjQ6IvCdkLAiO3M6MToidyI7czo0OiLwnZGkIjtzOjE6InciO3M6NDoi8J2SmCI7czoxOiJ3IjtzOjQ6IvCdk4wiO3M6MToidyI7czo0OiLwnZSAIjtzOjE6InciO3M6NDoi8J2UtCI7czoxOiJ3IjtzOjQ6IvCdlagiO3M6MToidyI7czo0OiLwnZacIjtzOjE6InciO3M6NDoi8J2XkCI7czoxOiJ3IjtzOjQ6IvCdmIQiO3M6MToidyI7czo0OiLwnZi4IjtzOjE6InciO3M6NDoi8J2ZrCI7czoxOiJ3IjtzOjQ6IvCdmqAiO3M6MToidyI7czozOiLhtKEiO3M6MToidyI7czoyOiLRoSI7czoxOiJ3IjtzOjI6ItSdIjtzOjE6InciO3M6Mjoi1aEiO3M6MToidyI7czo0OiLwkZyKIjtzOjE6InciO3M6NDoi8JGcjiI7czoxOiJ3IjtzOjQ6IvCRnI8iO3M6MToidyI7czozOiLqroMiO3M6MToidyI7czo0OiLwkaOvIjtzOjE6IlciO3M6NDoi8JGjpiI7czoxOiJXIjtzOjQ6IvCdkJYiO3M6MToiVyI7czo0OiLwnZGKIjtzOjE6IlciO3M6NDoi8J2RviI7czoxOiJXIjtzOjQ6IvCdkrIiO3M6MToiVyI7czo0OiLwnZOmIjtzOjE6IlciO3M6NDoi8J2UmiI7czoxOiJXIjtzOjQ6IvCdlY4iO3M6MToiVyI7czo0OiLwnZaCIjtzOjE6IlciO3M6NDoi8J2WtiI7czoxOiJXIjtzOjQ6IvCdl6oiO3M6MToiVyI7czo0OiLwnZieIjtzOjE6IlciO3M6NDoi8J2ZkiI7czoxOiJXIjtzOjQ6IvCdmoYiO3M6MToiVyI7czoyOiLUnCI7czoxOiJXIjtzOjM6IuGOsyI7czoxOiJXIjtzOjM6IuGPlCI7czoxOiJXIjtzOjM6IuqTqiI7czoxOiJXIjtzOjM6IuGZriI7czoxOiJ4IjtzOjI6IsOXIjtzOjE6IngiO3M6Mzoi4qSrIjtzOjE6IngiO3M6Mzoi4qSsIjtzOjE6IngiO3M6Mzoi4qivIjtzOjE6IngiO3M6Mzoi772YIjtzOjE6IngiO3M6Mzoi4oW5IjtzOjE6IngiO3M6NDoi8J2QsSI7czoxOiJ4IjtzOjQ6IvCdkaUiO3M6MToieCI7czo0OiLwnZKZIjtzOjE6IngiO3M6NDoi8J2TjSI7czoxOiJ4IjtzOjQ6IvCdlIEiO3M6MToieCI7czo0OiLwnZS1IjtzOjE6IngiO3M6NDoi8J2VqSI7czoxOiJ4IjtzOjQ6IvCdlp0iO3M6MToieCI7czo0OiLwnZeRIjtzOjE6IngiO3M6NDoi8J2YhSI7czoxOiJ4IjtzOjQ6IvCdmLkiO3M6MToieCI7czo0OiLwnZmtIjtzOjE6IngiO3M6NDoi8J2aoSI7czoxOiJ4IjtzOjI6ItGFIjtzOjE6IngiO3M6Mzoi4ZWBIjtzOjE6IngiO3M6Mzoi4ZW9IjtzOjE6IngiO3M6Mzoi4ZmtIjtzOjE6IlgiO3M6Mzoi4pWzIjtzOjE6IlgiO3M6NDoi8JCMoiI7czoxOiJYIjtzOjQ6IvCRo6wiO3M6MToiWCI7czozOiLvvLgiO3M6MToiWCI7czozOiLihakiO3M6MToiWCI7czo0OiLwnZCXIjtzOjE6IlgiO3M6NDoi8J2RiyI7czoxOiJYIjtzOjQ6IvCdkb8iO3M6MToiWCI7czo0OiLwnZKzIjtzOjE6IlgiO3M6NDoi8J2TpyI7czoxOiJYIjtzOjQ6IvCdlJsiO3M6MToiWCI7czo0OiLwnZWPIjtzOjE6IlgiO3M6NDoi8J2WgyI7czoxOiJYIjtzOjQ6IvCdlrciO3M6MToiWCI7czo0OiLwnZerIjtzOjE6IlgiO3M6NDoi8J2YnyI7czoxOiJYIjtzOjQ6IvCdmZMiO3M6MToiWCI7czo0OiLwnZqHIjtzOjE6IlgiO3M6Mzoi6p6zIjtzOjE6IlgiO3M6MjoizqciO3M6MToiWCI7czo0OiLwnZq+IjtzOjE6IlgiO3M6NDoi8J2buCI7czoxOiJYIjtzOjQ6IvCdnLIiO3M6MToiWCI7czo0OiLwnZ2sIjtzOjE6IlgiO3M6NDoi8J2epiI7czoxOiJYIjtzOjM6IuKyrCI7czoxOiJYIjtzOjI6ItClIjtzOjE6IlgiO3M6Mzoi4rWdIjtzOjE6IlgiO3M6Mzoi4Zq3IjtzOjE6IlgiO3M6Mzoi6pOrIjtzOjE6IlgiO3M6NDoi8JCKkCI7czoxOiJYIjtzOjQ6IvCQirQiO3M6MToiWCI7czo0OiLwkIyXIjtzOjE6IlgiO3M6NDoi8JCUpyI7czoxOiJYIjtzOjI6IsmjIjtzOjE6InkiO3M6Mzoi4baMIjtzOjE6InkiO3M6Mzoi772ZIjtzOjE6InkiO3M6NDoi8J2QsiI7czoxOiJ5IjtzOjQ6IvCdkaYiO3M6MToieSI7czo0OiLwnZKaIjtzOjE6InkiO3M6NDoi8J2TjiI7czoxOiJ5IjtzOjQ6IvCdlIIiO3M6MToieSI7czo0OiLwnZS2IjtzOjE6InkiO3M6NDoi8J2VqiI7czoxOiJ5IjtzOjQ6IvCdlp4iO3M6MToieSI7czo0OiLwnZeSIjtzOjE6InkiO3M6NDoi8J2YhiI7czoxOiJ5IjtzOjQ6IvCdmLoiO3M6MToieSI7czo0OiLwnZmuIjtzOjE6InkiO3M6NDoi8J2aoiI7czoxOiJ5IjtzOjI6IsqPIjtzOjE6InkiO3M6Mzoi4bu/IjtzOjE6InkiO3M6Mzoi6q2aIjtzOjE6InkiO3M6MjoizrMiO3M6MToieSI7czozOiLihL0iO3M6MToieSI7czo0OiLwnZuEIjtzOjE6InkiO3M6NDoi8J2bviI7czoxOiJ5IjtzOjQ6IvCdnLgiO3M6MToieSI7czo0OiLwnZ2yIjtzOjE6InkiO3M6NDoi8J2erCI7czoxOiJ5IjtzOjI6ItGDIjtzOjE6InkiO3M6Mjoi0q8iO3M6MToieSI7czozOiLhg6ciO3M6MToieSI7czo0OiLwkaOcIjtzOjE6InkiO3M6Mzoi77y5IjtzOjE6IlkiO3M6NDoi8J2QmCI7czoxOiJZIjtzOjQ6IvCdkYwiO3M6MToiWSI7czo0OiLwnZKAIjtzOjE6IlkiO3M6NDoi8J2StCI7czoxOiJZIjtzOjQ6IvCdk6giO3M6MToiWSI7czo0OiLwnZScIjtzOjE6IlkiO3M6NDoi8J2VkCI7czoxOiJZIjtzOjQ6IvCdloQiO3M6MToiWSI7czo0OiLwnZa4IjtzOjE6IlkiO3M6NDoi8J2XrCI7czoxOiJZIjtzOjQ6IvCdmKAiO3M6MToiWSI7czo0OiLwnZmUIjtzOjE6IlkiO3M6NDoi8J2aiCI7czoxOiJZIjtzOjI6Is6lIjtzOjE6IlkiO3M6Mjoiz5IiO3M6MToiWSI7czo0OiLwnZq8IjtzOjE6IlkiO3M6NDoi8J2btiI7czoxOiJZIjtzOjQ6IvCdnLAiO3M6MToiWSI7czo0OiLwnZ2qIjtzOjE6IlkiO3M6NDoi8J2epCI7czoxOiJZIjtzOjM6IuKyqCI7czoxOiJZIjtzOjI6ItCjIjtzOjE6IlkiO3M6Mjoi0q4iO3M6MToiWSI7czozOiLhjqkiO3M6MToiWSI7czozOiLhjr0iO3M6MToiWSI7czozOiLqk6wiO3M6MToiWSI7czo0OiLwlr2DIjtzOjE6IlkiO3M6NDoi8JGipCI7czoxOiJZIjtzOjQ6IvCQirIiO3M6MToiWSI7czo0OiLwnZCzIjtzOjE6InoiO3M6NDoi8J2RpyI7czoxOiJ6IjtzOjQ6IvCdkpsiO3M6MToieiI7czo0OiLwnZOPIjtzOjE6InoiO3M6NDoi8J2UgyI7czoxOiJ6IjtzOjQ6IvCdlLciO3M6MToieiI7czo0OiLwnZWrIjtzOjE6InoiO3M6NDoi8J2WnyI7czoxOiJ6IjtzOjQ6IvCdl5MiO3M6MToieiI7czo0OiLwnZiHIjtzOjE6InoiO3M6NDoi8J2YuyI7czoxOiJ6IjtzOjQ6IvCdma8iO3M6MToieiI7czo0OiLwnZqjIjtzOjE6InoiO3M6Mzoi4bSiIjtzOjE6InoiO3M6Mzoi6q6TIjtzOjE6InoiO3M6NDoi8JGjhCI7czoxOiJ6IjtzOjQ6IvCQi7UiO3M6MToiWiI7czo0OiLwkaOlIjtzOjE6IloiO3M6Mzoi77y6IjtzOjE6IloiO3M6Mzoi4oSkIjtzOjE6IloiO3M6Mzoi4oSoIjtzOjE6IloiO3M6NDoi8J2QmSI7czoxOiJaIjtzOjQ6IvCdkY0iO3M6MToiWiI7czo0OiLwnZKBIjtzOjE6IloiO3M6NDoi8J2StSI7czoxOiJaIjtzOjQ6IvCdk6kiO3M6MToiWiI7czo0OiLwnZaFIjtzOjE6IloiO3M6NDoi8J2WuSI7czoxOiJaIjtzOjQ6IvCdl60iO3M6MToiWiI7czo0OiLwnZihIjtzOjE6IloiO3M6NDoi8J2ZlSI7czoxOiJaIjtzOjQ6IvCdmokiO3M6MToiWiI7czoyOiLOliI7czoxOiJaIjtzOjQ6IvCdmq0iO3M6MToiWiI7czo0OiLwnZunIjtzOjE6IloiO3M6NDoi8J2coSI7czoxOiJaIjtzOjQ6IvCdnZsiO3M6MToiWiI7czo0OiLwnZ6VIjtzOjE6IloiO3M6Mzoi4Y+DIjtzOjE6IloiO3M6Mzoi6pOcIjtzOjE6IloiO3M6NDoi8JGiqSI7czoxOiJaIjtzOjI6Isa/IjtzOjE6Iv4iO3M6Mjoiz7giO3M6MToi/iI7czoyOiLPtyI7czoxOiLeIjtzOjQ6IvCQk4QiO3M6MToi3iI7fQ==";

    private static function need_skip($string, $i)
    {
        $chars = " @\r\n\t";
        if (isset($string[$i]) && strpos($chars, $string[$i]) !== false) {
            $i++;
            return $i;
        }
        return false;
    }

    private static function match_shortopen_tag($string, $i, $needle, $j)
    {
        $pos_needle = false;
        $pos_string = false;
        if ((isset($needle[$j - 2]) && isset($string[$i - 2]))
            && (($needle[$j - 2] == '<') && ($string[$i - 2] == '<'))
            && (isset($needle[$j - 1]) && isset($string[$i - 1]))
            && ($needle[$j - 1] == '?' && $string[$i - 1] == '?')
        ) {
            $pos_needle = $j;
            $pos_string = $i;
        }
        if ($pos_needle && (isset($needle[$pos_needle]) && $needle[$pos_needle] == 'p')
            && (isset($needle[$pos_needle + 1]) && $needle[$pos_needle + 1] == 'h')
            && (isset($needle[$pos_needle + 2]) && $needle[$pos_needle + 2] == 'p')
        ) {
            $pos_needle = $pos_needle + 3;
        }

        if ($pos_string && (isset($string[$pos_string]) && $string[$pos_string] == 'p')
            && (isset($string[$pos_string + 1]) && $string[$pos_string + 1] == 'h')
            && (isset($string[$pos_string + 2]) && $string[$pos_string + 2] == 'p')
        ) {

            $pos_string = $pos_string + 3;
        }
        return [$pos_needle, $pos_string];
    }

    public static function unescape($string, $save_length = false) {
        if (strpos($string, '\\\'') === false && strpos($string, '\\"') === false && strpos($string, '\\/') === false) {
            return $string;
        }
        $strippedStr = stripcslashes($string);
        if (!$save_length) {
            return $strippedStr;
        } else {
            $strippedStr = self::extend_string_with_spaces($string, $strippedStr);
            return $strippedStr;
        }
    }

    public static function strip_whitespace($string, $save_length = false)
    {
        StringToStreamWrapper::prepare($string);
        $strippedStr = @php_strip_whitespace(StringToStreamWrapper::WRAPPER_NAME . '://');

        if (!$save_length) {
            return $strippedStr;
        } else {
            $strippedStr = self::extend_string_with_spaces($string, $strippedStr);
            return $strippedStr;
        }
    }

    public static function normalize($string, $save_length = false)
    {
        $search  = [ ' ;', ' =', ' ,', ' .', ' (', ' )', ' {', ' }', '; ', '= ', ', ', '. '
            , '( ', '( ', '{ ', '} ', ' !', ' >', ' <', ' _', '_ ', '< ',  '> ', ' $', ' %', '% '
            , '# ', ' #', '^ ', ' ^', ' &', '& ', ' ?', '? '];
        $replace = [  ';',  '=',  ',',  '.',  '(',  ')',  '{',  '}', ';',  '=',  ',',  '.'
            ,  '(',   ')', '{',  '}',   '!',  '>',  '<',  '_', '_',  '<',   '>',   '$',  '%', '%'
            ,  '#',   '#', '^',   '^',  '&', '&',   '?', '?'];

        $bad_chars = ['配', '内'];
        $string = str_replace($bad_chars, ' ', $string);
        $string = str_replace("\xEF\xBB\xBF", '   ', $string); //BOM

        $last_char = $string[-1] ?? '';

        if (!$save_length) {
            $string = str_replace('@', '', $string);
            $string = preg_replace('~\s+~msi', ' ', $string);
            $string = str_replace($search, $replace, $string);
            if (in_array($last_char, ["\r", "\n"]) && isset($string[-1]) && $string[-1] !== $last_char) {
                $string .= $last_char;
            }
        }

        $string = preg_replace_callback('~\bchr\(\s*([0-9a-fA-FxX\^]+)\s*\)~', function($m) use ($save_length) {
            if (strpos($m[1], '^') !== false) {
                $m[1] = Helpers::calc($m[1]);
            }
            if ($save_length) {
                return str_pad("'" . @chr(intval($m[1], 0)) . "'", strlen($m[0]), ' ');
            } else {
                return "'" . @chr(intval($m[1], 0)) . "'";
            }
        }, $string);

        $pattern = '~%([0-9a-fA-F]{2})~';
        if ($save_length && preg_match('~%25(%[0-9a-fA-F]{2}){2}(%25)?~ms', $string)) {
            $pattern = (isset($m[2]) && $m[2] !== '') ? '~%\s{0,2}([0-9a-fA-F\s]{2,6})~' : '~%\s{0,2}([0-9a-fA-F]{2})~';
        }

        for ($i = 0; $i < 2; $i++) {
            $string = preg_replace_callback($pattern, function($m) use ($save_length) {
                if ($save_length) {
                    return str_pad(chr(@hexdec($m[1])), strlen($m[0]), ' ');
                } else {
                    return @chr(hexdec($m[1]));
                }
            }, $string);
        }

        $iter = 0;
        $regexpHtmlAmp = '/\&[#\w ]{2,20} {0,2}; {0,2}/i';
        while ($iter < self::MAX_ITERATION && preg_match($regexpHtmlAmp, $string)) {
            $string = preg_replace_callback($regexpHtmlAmp, function ($m) use ($save_length) {
                if ($save_length) {
                    if (strpos($m[0], '  ') !== false) {
                        $m[0] = str_pad(str_replace(' ', '', $m[0]), strlen($m[0]));
                    }
                    $string = $m[0] == '&nbsp;' ? ' ' : $m[0];
                    return str_pad(@html_entity_decode($string, ENT_QUOTES | ENT_HTML5), strlen($m[0]), ' ', STR_PAD_LEFT);
                } else {
                    $string = $m[0] == '&nbsp;' ? ' ' : $m[0];
                    return @html_entity_decode($string, ENT_QUOTES | ENT_HTML5);
                }
            }, $string);
            $iter++;
        }
        
        $string = preg_replace_callback('/\\\\(?:x(?<hex>[a-fA-F0-9]{1,2})|(?<oct>[0-9]{2,3}))/i', function($m) use ($save_length) {
            $is_oct     = isset($m['oct']);
            $full_str   = $m[0];
            $value      = $is_oct ? $m['oct'] : $m['hex'];
            if ($save_length) {
                if ($is_oct) {
                    return str_pad(@chr(octdec($value)), strlen($full_str), ' ');
                }
                return str_pad(chr(@hexdec($value)), strlen($full_str), ' ');
            } else {
                if ($is_oct) {
                    return @chr(octdec($value));
                }
                return @chr(hexdec($value));
            }
        }, $string);
        
        $string = self::concatenate_strings($string, $save_length);

        $string = preg_replace_callback('~<title[^>]{0,99}>\s*\K(.{0,300}?)(?=<\/title>)~mis', function($m) use ($save_length) {
            if(preg_match('~(?:\w[^\x00-\x7F]{1,9}|[^\x00-\x7F]{1,9}\w)~', $m[1])) {
                return self::HomoglyphNormalize($m[1]);
            }
            return $m[1];
        }, $string);

        $string = preg_replace_callback('~<\?p\s+h\s+p~msi', function ($m) {
            return str_pad('<?php', strlen($m[0]), ' ');
        }, $string);

        if (!$save_length) {
            $string = str_replace('<?php', '<?php ', $string);
            $string = preg_replace('~\s+~msi', ' ', $string);
        } else {
            $string = str_replace('<?php', '<?   ', $string);
        }

        return $string;
    }
    
    public static function get_end_of_extended_length($string_normalized, $string_orig, $start_pos)
    {
        if (strlen($string_normalized) == $start_pos + 1) {
            return $start_pos;
        }
        for ($i = $start_pos + 1, $iMax = strlen($string_normalized); $i < $iMax; $i++) {
            if ($string_orig[$i] === '\\' || $string_normalized[$i] !== ' ' || $string_orig[$i] === ' ') {
                break;
            }
        }
        return $i - 1;
    }

    public static function string_pos($string, $needle, $unescape = false)
    {
        $j      = 0;
        $skip   = false;
        $start  = false;
        $end    = 0;
        $last_tag = [false, false];

        $string_strip_whitespace = self::strip_whitespace($string, true);

        $string = preg_replace_callback('~(<%3f|%253c%3f|%3c%3f)(php)?~msi', function ($m) {
            $ret = (isset($m[2]) && $m[2] !== '') ? '<?php' : '<?';
            return str_pad($ret, strlen($m[0]), ' ');
        }, $string_strip_whitespace);

        $string = preg_replace_callback('~(?:%3f>|%3f%253e|%3f%3e)~msi', function ($m) {
            return str_pad('?>', strlen($m[0]),  ' ', STR_PAD_LEFT);
        }, $string);

        $string = self::normalize($string, true);
        $needle = self::normalize($needle, false);
        
        if ($unescape) {
            $string = self::unescape($string, true);
            $string = self::normalize($string, true);
        }

        $needle = self::concatenate_strings($needle, true);

        for ($i = 0, $iMax = strlen($string); $i < $iMax; $i++) {
            if(trim($string[$i]) === '' && trim($needle[$j]) === '') {
                $string[$i] = $needle[$j] = ' ';
            }
            if ($string[$i] == $needle[$j]) {
                if ($j == 0) {
                    $start = $i;
                } elseif ($j == strlen($needle) - 1) {
                    $end = self::get_end_of_extended_length($string, $string_strip_whitespace, $i);
                    return [$start, $end];
                }
                $j++;
            } else {
                $match_php_tag = self::match_shortopen_tag($string, $i, $needle, $j);
                if ($match_php_tag[0] !== false && ($last_tag[0] !== $match_php_tag[0])) {
                    $j = $match_php_tag[0];
                }
                if ($match_php_tag[1] !== false && ($last_tag[1] !== $match_php_tag[1])) {
                    $i = $match_php_tag[1] - 1;
                }
                $last_tag = $match_php_tag;
                if ($match_php_tag[0] !== false || ($match_php_tag[1] !== false && (!empty($last_tag)))) {
                    continue;
                }
                $skip = self::need_skip($string, $i);
                if ($skip !== false && $start !== false) {
                    $i = $skip - 1;
                } else {
                    $j = 0;
                }
            }
        }
        return false;
    }

    private static function concatenate_strings($string, $save_length)
    {
        $string = preg_replace_callback('/[\'"]\s*?[\+\.]+\s*?[\'"]/smi', function($m) use ($save_length) {
            if ($save_length) {
                return str_repeat(' ', strlen($m[0]));
            } else {
                return '';
            }
        }, $string);
        return $string;
    }

    private static function HomoglyphNormalize($str)
    {
        if (!is_array(self::$confusables)) {
            self::$confusables = @unserialize(@base64_decode(self::$confusables));
        }
        return str_replace(array_keys(self::$confusables), array_values(self::$confusables), $str);
    }

    private static function extend_string_with_spaces($string, $strippedStr)
    {
        $in_comment_ml = false;
        $in_comment_nl = false;
        $iMax = strlen($string);
        $jMax = strlen($strippedStr);

        if ($iMax === $jMax) {
            return $string;
        }

        $newStr = '';
        $j = 0;

        for ($i = 0; $i < $iMax; $i++) {
            if (isset($strippedStr[$j]) && trim($string[$i]) === trim($strippedStr[$j]) && !$in_comment_ml && !$in_comment_nl) {
                $newStr .= $string[$i];
                $j++;
            } else if ((trim($string[$i]) === '/' && trim($string[$i + 1]) === '*') && !$in_comment_ml && !$in_comment_nl) {
                $in_comment_ml = true;
                $newStr .= ' ';
            } else if ((trim($string[$i]) === '*' && trim($string[$i + 1]) === '/') && $in_comment_ml) {
                $in_comment_ml = false;
                $newStr .= ' ';
            } else if ((trim($string[$i]) === '/' && trim($string[$i + 1]) === '/') && !$in_comment_nl && !$in_comment_ml) {
                $in_comment_nl = true;
                $newStr .= ' ';
            } else if ($string[$i] === "\n" && $in_comment_nl) {
                $in_comment_nl = false;
                $newStr .= ' ';
            } else if ($string[$i] === '?' && $string[$i + 1] === '>' && $in_comment_nl) {
                $in_comment_nl = false;
                $newStr .= $string[$i];
                $j++;
            } else if ((isset($strippedStr[$j]) && trim($string[$i]) !== trim($strippedStr[$j])) && ($in_comment_ml || $in_comment_nl)) {
                $newStr .= ' ';
            } else {
                $newStr .= ' ';
            }
        }
        return $newStr;
    }

    /**
     * @param array $confusables
     */
    public static function setConfusables(array $confusables)
    {
        self::$confusables = $confusables;
    }
}

class Encoding
{
    // Unicode BOM is U+FEFF, but after encoded, it will look like this.

    const UTF32_BIG_ENDIAN_BOM = "\x00\x00\xFE\xFF";
    const UTF32_LITTLE_ENDIAN_BOM = "\xFF\xFE\x00\x00";
    const UTF16_BIG_ENDIAN_BOM = "\xFE\xFF";
    const UTF16_LITTLE_ENDIAN_BOM = "\xFF\xFE";
    const UTF8_BOM = "\xEF\xBB\xBF";

    public static function detectUTFEncoding($text)
    {
        $first2 = substr($text, 0, 2);
        $first3 = substr($text, 0, 3);
        $first4 = substr($text, 0, 4);

        if ($first3 == self::UTF8_BOM) {
            return 'UTF-8';
        } elseif ($first4 == self::UTF32_BIG_ENDIAN_BOM) {
            return 'UTF-32BE';
        } elseif ($first4 == self::UTF32_LITTLE_ENDIAN_BOM) {
            return 'UTF-32LE';
        } elseif ($first2 == self::UTF16_BIG_ENDIAN_BOM) {
            return 'UTF-16BE';
        } elseif ($first2 == self::UTF16_LITTLE_ENDIAN_BOM) {
            return 'UTF-16LE';
        }
        return false;
    }

    public static function iconvSupported()
    {
        return (function_exists('iconv') && is_callable('iconv'));
    }

    public static function convertToCp1251($from, $str)
    {
        $ret = @iconv($from, 'CP1251//TRANSLIT', $str);
        if ($ret === false) {
            $ret = @iconv($from, 'CP1251//IGNORE', $str);
        }
        return $ret;
    }

    public static function convertToUTF8($from, $str)
    {
        return @iconv($from, 'UTF-8//IGNORE', $str);
    }
}
/**
 * Class SharedMem work with shared-memory
 */
class SharedMem
{

    private $instance = null;

    /**
     * SharedMem constructor.
     * @param int $key
     * @param string $mode
     * @param int $permissions
     * @param int $size
     */
    public function __construct(int $key , string $mode , int $permissions , int $size)
    {
        $this->instance = shmop_open($key, $mode, $permissions, $size);
    }

    /**
     * @param int $offset
     * @param int $size
     * @param bool $trim
     * @param bool $json
     * @return false|mixed|string
     */
    public function read(int $offset, int $size, bool $trim = true, bool $json = true)
    {
        $res = shmop_read($this->instance, $offset, $size);
        if ($trim) {
            $res = rtrim($res, "\0");
        }
        if ($json) {
            $res = json_decode($res, true);
        }
        return $res;
    }

    /**
     * @param string $data
     * @return int
     */
    public function write(array $data): int
    {
        shmop_write($this->instance, str_repeat("\0", shmop_size($this->instance)), 0);
        if (function_exists('json_encode')) {
            $res = shmop_write($this->instance, json_encode($data), 0);
        } else {
            $res = shmop_write($this->instance, serialize($data), 0);
        }
        return $res;
    }

    /**
     * @return int
     */
    public function getSize(): int
    {
        return shmop_size($this->instance);
    }

    /**
     * @return bool
     */
    public function delete(): bool
    {
        return shmop_delete($this->instance);
    }

    /**
     * @param bool $delete
     */
    public function close(bool $delete = false)
    {
        if ($delete) {
            shmop_delete($this->instance);
        }

        if (version_compare(phpversion('shmop'), '8.0.0', '<')) {
            shmop_close($this->instance);
        }

        $this->instance = null;
    }

    /**
     * @return bool
     */
    public function isValid()
    {
        if (version_compare(phpversion('shmop'), '8.0.0', '>=')) {
            return is_object($this->instance);
        }

        return is_resource($this->instance);
    }

    /**
     * @return false|resource|Shmop
     */
    public function getInstance()
    {
        return $this->instance;
    }
}

class ScanUnit
{
    public static function QCR_ScanContent($checkers, $l_Unwrapped, $l_Content, $signs, $debug = null, $precheck = null, $processResult = null, &$return = null)
    {
        $smart_skipped = false;
        $flag = false;
        foreach ($checkers as $checker => $full) {
            $l_pos = 0;
            $l_SignId = '';
            if (isset($precheck) && is_callable($precheck)) {
                if (!$precheck($checker, $l_Unwrapped) && ($full && !$precheck($checker, $l_Content))) {
                    $smart_skipped = true;
                    continue;
                }
            }
            $flag = ScanCheckers::{$checker}($l_Unwrapped, $l_pos, $l_SignId, $signs, $debug);
            if ($flag && isset($processResult) && is_callable($processResult)) {
                $processResult($checker, $l_Unwrapped, $l_pos, $l_SignId, $return);
            }

            if (!$flag && $full) {
                $flag = ScanCheckers::{$checker}($l_Content, $l_pos, $l_SignId, $signs, $debug);
                if ($flag && isset($processResult) && is_callable($processResult)) {
                    $processResult($checker, $l_Content, $l_pos, $l_SignId, $return);
                }
            }
            if ($flag) {
                return true;
            }
        }
        if (!$flag && $smart_skipped) {
            $return = [RapidScanStorageRecord::RX_SKIPPED_SMART, '', ''];
        }
        return false;
    }

    public static function Rescan($content, $signs, $debug = null, $deobfuscate = false, $processResult = null, &$return = null)
    {
        $checkers['CriticalPHP'] = true;
        $l_Unwrapped = Normalization::strip_whitespace($content);
        $l_UnicodeContent = Encoding::detectUTFEncoding($content);
        if ($l_UnicodeContent !== false) {
            if (Encoding::iconvSupported()) {
                $l_Unwrapped = Encoding::convertToCp1251($l_UnicodeContent, $l_Unwrapped);
            }
        }

        if ($deobfuscate) {
            $l_DeobfObj = new Deobfuscator($l_Unwrapped, $content);
            $l_DeobfType = $l_DeobfObj->getObfuscateType($l_Unwrapped);
        }

        if (isset($l_DeobfType) && $l_DeobfType != '') {
            $l_Unwrapped = $l_DeobfObj->deobfuscate();
        }

        $l_Unwrapped = Normalization::normalize($l_Unwrapped);
        return self::QCR_ScanContent($checkers, $l_Unwrapped, $content, $signs);
    }
}

class ScanCheckers
{
    const URL_GRAB = '~(?:https?:)?\/\/(?:www\.)?[-a-zA-Z0-9@:%._\+\~#=]{2,256}\.[a-z]{2,4}\b(?:[-a-zA-Z0-9@:%_\+.\~#?&/=]*)~msi';

    public static function WarningPHP($l_Content, &$l_Pos, &$l_SigId, $signs, $debug = null)
    {
        foreach ($signs->_SusDB as $l_Item) {
            if (preg_match('~' . $l_Item . '~smiS', $l_Content, $l_Found, PREG_OFFSET_CAPTURE)) {
                if (!self::CheckException($l_Content, $l_Found, $signs)) {
                    $l_Pos   = $l_Found[0][1];
                    $l_SigId = LoadSignaturesForScan::getSigId($l_Found);
                    return true;
                }
            }
        }
        return false;
    }

    ////////////////////////////////////////////////////////////////////////////
    public static function Adware($l_Content, &$l_Pos, &$l_SigId, $signs, $debug = null)
    {
        $l_Res = false;

        foreach ($signs->_AdwareSig as $l_Item) {
            $offset = 0;
            while (preg_match('~' . $l_Item . '~smi', $l_Content, $l_Found, PREG_OFFSET_CAPTURE, $offset)) {
                if (!self::CheckException($l_Content, $l_Found, $signs)) {
                    $l_Pos = $l_Found[0][1];
                    $l_SigId = 'adware';
                    return true;
                }

                $offset = $l_Found[0][1] + 1;
            }
        }

        return $l_Res;
    }

    ////////////////////////////////////////////////////////////////////////////
    public static function CheckException(&$l_Content, &$l_Found, $signs, $debug = null)
    {
        if (!(isset($signs->_ExceptFlex) && is_array($signs->_ExceptFlex))) {
            return false;
        }
        $l_FoundStrPlus = substr($l_Content, max($l_Found[0][1] - 10, 0), 70);

        foreach ($signs->_ExceptFlex as $l_ExceptItem) {
            if (@preg_match('~' . $l_ExceptItem . '~smi', $l_FoundStrPlus, $l_Detected)) {
                return true;
            }
        }

        return false;
    }

    ////////////////////////////////////////////////////////////////////////////
    public static function Phishing($l_Content, &$l_Pos, &$l_SigId, $signs, $debug = null)
    {
        $l_Res = false;

        foreach ($signs->_PhishingSig as $l_Item) {
            $offset = 0;
            while (preg_match('~' . $l_Item . '~smi', $l_Content, $l_Found, PREG_OFFSET_CAPTURE, $offset)) {
                if (!self::CheckException($l_Content, $l_Found, $signs)) {
                    $l_Pos   = $l_Found[0][1];
                    $l_SigId = LoadSignaturesForScan::getSigId($l_Found);

                    if (is_object($debug) && $debug->getDebugMode() == true) {
                        echo "Phis: $l_Content matched [$l_Item] in $l_Pos\n";
                    }

                    return $l_Pos;
                }
                $offset = $l_Found[0][1] + 1;

            }
        }

        return $l_Res;
    }

    ////////////////////////////////////////////////////////////////////////////
    public static function CriticalJS($l_Content, &$l_Pos, &$l_SigId, $signs, $debug = null)
    {
        $l_Res = false;

        foreach ($signs->_JSVirSig as $l_Item) {
            $offset = 0;
            if (is_object($debug) && $debug->getDebugPerfomance() == true) {
                $stat_start = microtime(true);
            }
            $time = microtime(true);
            $res = preg_match('~' . $l_Item . '~smi', $l_Content, $l_Found, PREG_OFFSET_CAPTURE, $offset);
            if (class_exists('PerfomanceStats')) {
                PerfomanceStats::addPerfomanceItem(PerfomanceStats::PCRE_SCAN_STAT, microtime(true) - $time);
            }
            while ($res) {
                if (!self::CheckException($l_Content, $l_Found, $signs)) {
                    $l_Pos   = $l_Found[0][1];
                    $l_SigId = LoadSignaturesForScan::getSigId($l_Found);

                    if (is_object($debug) && $debug->getDebugMode() == true) {
                        echo "JS: $l_Content matched [$l_Item] in $l_Pos\n";
                    }

                    $l_Res = true;
                    break;
                }

                $offset = $l_Found[0][1] + 1;
                $time = microtime(true);
                $res = preg_match('~' . $l_Item . '~smi', $l_Content, $l_Found, PREG_OFFSET_CAPTURE, $offset);
                if (class_exists('PerfomanceStats')) {
                    PerfomanceStats::addPerfomanceItem(PerfomanceStats::PCRE_SCAN_STAT, microtime(true) - $time);
                }
            }

            if (is_object($debug) && $debug->getDebugPerfomance() == true) {
                $stat_stop = microtime(true);
                $debug->addPerfomanceItem($l_Item, $stat_stop - $stat_start);
            }

        }

        return $l_Res;
    }

    public static function CriticalJS_PARA($l_Content, &$l_Pos, &$l_SigId, $signs, $debug = null)
    {
        foreach ($signs->X_JSVirSig as $l_Item) {
            if (is_object($debug) && $debug->getDebugPerfomance() == true) {
                $stat_start = microtime(true);
            }

            if (preg_match('~' . $l_Item . '~smi', $l_Content, $l_Found, PREG_OFFSET_CAPTURE)) {
                if (!self::CheckException($l_Content, $l_Found, $signs)) {
                    $l_Pos   = $l_Found[0][1];
                    //$l_SigId = myCheckSum($l_Item);
                    $l_SigId = LoadSignaturesForScan::getSigId($l_Found);

                    if (is_object($debug) && $debug->getDebugMode() == true) {
                        echo "JS PARA: $l_Content matched [$l_Item] in $l_Pos\n";
                    }
                    return true;
                }
            }

            if (is_object($debug) && $debug->getDebugPerfomance() == true) {
                $stat_stop = microtime(true);
                $debug->addPerfomanceItem($l_Item, $stat_stop - $stat_start);
            }
        }
        return false;
    }

    ////////////////////////////////////////////////////////////////////////////
    public static function CriticalPHPGIF($l_Content, &$l_Pos, &$l_SigId, $signs, $debug = null)
    {
        if (strpos($l_Content, 'GIF89') === 0) {
            $l_Pos = 0;
            $l_SigId = 'GIF';
            if (is_object($debug) && $debug->getDebugMode() == true) {
                echo "CRIT 6: $l_Content matched [GIF] in $l_Pos\n";
            }

            return true;
        }
        return false;
    }

    public static function CriticalPHPUploader($l_Content, &$l_Pos, &$l_SigId, $signs, $debug = null)
    {
        // detect uploaders / droppers
        $l_Found = null;
        if ((strlen($l_Content) < 2048) && ((($l_Pos = strpos($l_Content, 'multipart/form-data')) > 0) || (($l_Pos = strpos($l_Content, '$_FILE[') > 0)) || (($l_Pos = strpos($l_Content, 'move_uploaded_file')) > 0) || (preg_match('|\bcopy\s*\(|smi', $l_Content, $l_Found, PREG_OFFSET_CAPTURE)))) {
            if ($l_Found != null) {
                $l_Pos = $l_Found[0][1];
                $l_SigId = 'uploader';
            }
            if (is_object($debug) && $debug->getDebugMode() == true) {
                echo "CRIT 7: $l_Content matched [uploader] in $l_Pos\n";
            }

            return true;
        }
    }

    public static function CriticalPHP_3($l_Content, &$l_Pos, &$l_SigId, $signs, $debug = null)
    {
        foreach ($signs->X_FlexDBShe as $l_Item) {
            if (is_object($debug) && $debug->getDebugPerfomance() == true) {
                $stat_start = microtime(true);
            }

            if (preg_match('~' . $l_Item . '~smiS', $l_Content, $l_Found, PREG_OFFSET_CAPTURE)) {
                if (!self::CheckException($l_Content, $l_Found, $signs)) {
                    $l_Pos   = $l_Found[0][1];
                    $l_SigId = LoadSignaturesForScan::getSigId($l_Found);

                    if (is_object($debug) && $debug->getDebugMode() == true) {
                        echo "CRIT 3: $l_Content matched [$l_Item] in $l_Pos\n";
                    }

                    return true;
                }
            }

            if (is_object($debug) && $debug->getDebugPerfomance() == true) {
                $stat_stop = microtime(true);
                $debug->addPerfomanceItem($l_Item, $stat_stop - $stat_start);
            }
        }
        return false;
    }

    public static function CriticalPHP_2($l_Content, &$l_Pos, &$l_SigId, $signs, $debug = null)
    {
        foreach ($signs->XX_FlexDBShe as $l_Item) {
            if (is_object($debug) && $debug->getDebugPerfomance() == true) {
                $stat_start = microtime(true);
            }

            if (preg_match('~' . $l_Item . '~smiS', $l_Content, $l_Found, PREG_OFFSET_CAPTURE)) {
                if (!self::CheckException($l_Content, $l_Found, $signs)) {
                    $l_Pos   = $l_Found[0][1];
                    $l_SigId = LoadSignaturesForScan::getSigId($l_Found);

                    if (is_object($debug) && $debug->getDebugMode() == true) {
                        echo "CRIT 2: $l_Content matched [$l_Item] in $l_Pos\n";
                    }

                    return true;
                }
            }

            if (is_object($debug) && $debug->getDebugPerfomance() == true) {
                $stat_stop = microtime(true);
                $debug->addPerfomanceItem($l_Item, $stat_stop - $stat_start);
            }
        }
        return false;
    }

    public static function CriticalPHP_4($l_Content, &$l_Pos, &$l_SigId, $signs, $debug = null)
    {
        $l_Content_lo = strtolower($l_Content);

        foreach ($signs->_DBShe as $l_Item) {
            $l_Pos = strpos($l_Content_lo, $l_Item);
            if ($l_Pos !== false) {
                $l_SigId = AibolitHelpers::myCheckSum($l_Item);

                if (is_object($debug) && $debug->getDebugMode() == true) {
                    echo "CRIT 4: $l_Content matched [$l_Item] in $l_Pos\n";
                }

                return true;
            }
        }
        return false;
    }

    public static function CriticalPHP_5($l_Content, &$l_Pos, &$l_SigId, $signs, $debug = null)
    {
        $l_Content_lo = strtolower($l_Content);

        foreach ($signs->X_DBShe as $l_Item) {
            $l_Pos = strpos($l_Content_lo, $l_Item);
            if ($l_Pos !== false) {
                $l_SigId = AibolitHelpers::myCheckSum($l_Item);

                if (is_object($debug) && $debug->getDebugMode() == true) {
                    echo "CRIT 5: $l_Content matched [$l_Item] in $l_Pos\n";
                }

                return true;
            }
        }
        return false;
    }

    public static function CriticalPHP($l_Content, &$l_Pos, &$l_SigId, $signs, $debug = null)
    {
        foreach ($signs->_FlexDBShe as $l_Item) {
            $offset = 0;

            if (is_object($debug) && $debug->getDebugPerfomance() == true) {
                $stat_start = microtime(true);
            }
            $time = microtime(true);
            $res = preg_match('~' . $l_Item . '~smiS', $l_Content, $l_Found, PREG_OFFSET_CAPTURE, $offset);
            if (class_exists('PerfomanceStats')) {
                PerfomanceStats::addPerfomanceItem(PerfomanceStats::PCRE_SCAN_STAT, microtime(true) - $time);
            }
            while ($res) {
                if (!self::CheckException($l_Content, $l_Found, $signs)) {
                    $l_Pos   = $l_Found[0][1];
                    //$l_SigId = myCheckSum($l_Item);
                    $l_SigId = LoadSignaturesForScan::getSigId($l_Found);

                    if (is_object($debug) && $debug->getDebugMode() == true) {
                        echo "CRIT 1: $l_Content matched [$l_Item] in $l_Pos\n";
                    }

                    return true;
                }

                $offset = $l_Found[0][1] + 1;
                $time = microtime(true);
                $res = preg_match('~' . $l_Item . '~smiS', $l_Content, $l_Found, PREG_OFFSET_CAPTURE, $offset);
                if (class_exists('PerfomanceStats')) {
                    PerfomanceStats::addPerfomanceItem(PerfomanceStats::PCRE_SCAN_STAT, microtime(true) - $time);
                }
            }
            if (is_object($debug) && $debug->getDebugPerfomance() == true) {
                $stat_stop = microtime(true);
                $debug->addPerfomanceItem($l_Item, $stat_stop - $stat_start);
            }

        }

        return false;
    }

    public static function isOwnUrl($url, $own_domain)
    {
        if (!isset($own_domain)) {
            return false;
        }
        return (bool)preg_match('~^(http(s)?:)?//(www\.)?' . preg_quote($own_domain, '~') . '~msi', $url);
    }

    public static function isUrlInList($url, $list)
    {
        if (isset($list)) {
            foreach ($list as $item) {
                if (preg_match('~' . $item . '~msiS', $url, $id, PREG_OFFSET_CAPTURE)) {
                    return $id;
                }
            }
        }

        return false;
    }

    public static function UrlChecker($l_Content, &$l_Pos, &$l_SigId, $signs, $debug = null)
    {
        $l_Pos      = [];
        $l_SigId    = [];
        $offset     = 0;
        
        while (preg_match(self::URL_GRAB, $l_Content, $l_Found, PREG_OFFSET_CAPTURE, $offset)) {
            if (!self::isOwnUrl($l_Found[0][0], $signs->getOwnUrl())
                && (isset($signs->whiteUrls) && !self::isUrlInList($l_Found[0][0], $signs->whiteUrls->getDb()))
            ) {
                if ($id = self::isUrlInList($l_Found[0][0], $signs->blackUrls->getDb())) {
                    $l_Pos['black'][] = $l_Found[0][1];
                    $l_SigId['black'][] = $signs->blackUrls->getSig($id);
                } else {
                    $l_Pos['unk'][] = $l_Found[0][1];
                    $l_SigId['unk'][] = $l_Found[0][0];
                }
            }
            $offset = $l_Found[0][1] + strlen($l_Found[0][0]);
        }
        return !empty($l_Pos);
    }
}class Helpers
{
    const REGEXP_BASE64_DECODE = '~base64_decode\s*\(\s*[\'"]([^\'"]*)[\'"]\s*\)~mis';
    const GOTO_MAX_HOPS        = 1000;
    
    public static function normalize($string, $save_length = false)
    {
        $search  = [ ' ;', ' =', ' ,', ' .', ' (', ' )', ' {', ' }', '; ', '= ', ', ', '. '
        , '( ', '( ', '{ ', '} ', ' !', ' >', ' <', ' _', '_ ', '< ',  '> ', ' $', ' %', '% '
        , '# ', ' #', '^ ', ' ^', ' &', '& ', ' ?', '? '];
        $replace = [  ';',  '=',  ',',  '.',  '(',  ')',  '{',  '}', ';',  '=',  ',',  '.'
        ,  '(',   ')', '{',  '}',   '!',  '>',  '<',  '_', '_',  '<',   '>',   '$',  '%', '%'
        ,  '#',   '#', '^',   '^',  '&', '&',   '?', '?'];

        if (!$save_length) {
            $string = str_replace('@', '', $string);
            $string = preg_replace('~\s+~smi', ' ', $string);
            $string = str_replace($search, $replace, $string);
        }

        $string = preg_replace_callback('~\bchr\(\s*([0-9a-fA-FxX\^]+)\s*\)~', static function($m) use ($save_length) {
            if (strpos($m[1], '^') !== false) {
                $m[1] = Helpers::calc($m[1]);
            }
            if ($save_length) {
                return str_pad("'" . @chr(intval($m[1], 0)) . "'", strlen($m[0]), ' ');
            } else {
                return "'" . @chr(intval($m[1], 0)) . "'";
            }
        }, $string);

        $string = preg_replace_callback('/\&\#([0-9]{1,3});/i', static function($m) use ($save_length) {
            if ($save_length) {
                return str_pad(@chr((int)$m[1]), strlen($m[0]), ' ');
            } else {
                return @chr((int)$m[1]);
            }
        }, $string);

        $string = preg_replace_callback('/\\\\(?:x(?<hex>[a-fA-F0-9]{1,2})|(?<oct>[0-9]{1,3}))/i', function($m) use ($save_length) {
            $is_oct     = isset($m['oct']);
            $full_str   = $m[0];
            $value      = $is_oct ? $m['oct'] : $m['hex'];
            if ($save_length) {
                if ($is_oct) {
                    return str_pad(@chr(octdec($value)), strlen($full_str), ' ');
                }
                return str_pad(chr(@hexdec($value)), strlen($full_str), ' ');
            } else {
                if ($is_oct) {
                    return @chr(octdec($value));
                }
                return @chr(hexdec($value));
            }
        }, $string);

        $string = preg_replace_callback('/[\'"]\s*?\.+\s*?[\'"]/smi', static function($m) use ($save_length) {
            if ($save_length) {
                return str_repeat(' ', strlen($m[0]));
            } else {
                return '';
            }
        }, $string);

        $string = preg_replace_callback('/[\'"]\s*?\++\s*?[\'"]/smi', static function($m) use ($save_length) {
            if ($save_length) {
                return str_repeat(' ', strlen($m[0]));
            } else {
                return '';
            }
        }, $string);

        if (!$save_length) {
            $string = str_replace('<?php', '<?php ', $string);
            $string = preg_replace('~\s+~', ' ', $string);
        }

        return $string;
    }

    public static function format($source)
    {
        $t_count = 0;
        $in_object = false;
        $in_at = false;
        $in_php = false;
        $in_for = false;
        $in_comp = false;
        $in_quote = false;
        $in_var = false;

        if (!defined('T_ML_COMMENT')) {
            define('T_ML_COMMENT', T_COMMENT);
        }

        $result = '';
        @$tokens = token_get_all($source);
        foreach ($tokens as $token) {
            if (is_string($token)) {
                $token = trim($token);
                if ($token == '{') {
                    if ($in_for) {
                        $in_for = false;
                    }
                    if (!$in_quote && !$in_var) {
                        $t_count++;
                        $result = rtrim($result) . ' ' . $token . "\n" . str_repeat('    ', $t_count);
                    } else {
                        $result = rtrim($result) . $token;
                    }
                } elseif ($token == '$') {
                    $in_var = true;
                    $result .= $token;
                } elseif ($token == '}') {
                    if (!$in_quote && !$in_var) {
                        $new_line = true;
                        $t_count--;
                        if ($t_count < 0) {
                            $t_count = 0;
                        }
                        $result = rtrim($result) . "\n" . str_repeat('    ', $t_count) .
                            $token . "\n" . @str_repeat('    ', $t_count);
                    } else {
                        $result = rtrim($result) . $token;
                    }
                    if ($in_var) {
                        $in_var = false;
                    }
                } elseif ($token == ';') {
                    if ($in_comp) {
                        $in_comp = false;
                    }
                    if ($in_for) {
                        $result .= $token . ' ';
                    } else {
                        $result .= $token . "\n" . str_repeat('    ', $t_count);
                    }
                } elseif ($token == ':') {
                    if ($in_comp) {
                        $result .= ' ' . $token . ' ';
                    } else {
                        $result .= $token . "\n" . str_repeat('    ', $t_count);
                    }
                } elseif ($token == '(') {
                    $result .= ' ' . $token;
                } elseif ($token == ')') {
                    $result .= $token;
                } elseif ($token == '@') {
                    $in_at = true;
                    $result .= $token;
                } elseif ($token == '.') {
                    $result .= ' ' . $token . ' ';
                } elseif ($token == '=') {
                    $result .= ' ' . $token . ' ';
                } elseif ($token == '?') {
                    $in_comp = true;
                    $result .= ' ' . $token . ' ';
                } elseif ($token == '"') {
                    if ($in_quote) {
                        $in_quote = false;
                    } else {
                        $in_quote = true;
                    }
                    $result .= $token;
                } else {
                    $result .= $token;
                }
            } else {
                list($id, $text) = $token;
                switch ($id) {
                    case T_OPEN_TAG:
                    case T_OPEN_TAG_WITH_ECHO:
                        $in_php = true;
                        $result .= trim($text) . "\n";
                        break;
                    case T_CLOSE_TAG:
                        $in_php = false;
                        $result .= trim($text);
                        break;
                    case T_FOR:
                        $in_for = true;
                        $result .= trim($text);
                        break;
                    case T_OBJECT_OPERATOR:
                        $result .= trim($text);
                        $in_object = true;
                        break;

                    case T_ENCAPSED_AND_WHITESPACE:
                    case T_WHITESPACE:
                        $result .= trim($text);
                        break;
                    case T_RETURN:
                        $result = rtrim($result) . "\n" . str_repeat('    ', $t_count) . trim($text) . ' ';
                        break;
                    case T_ELSE:
                    case T_ELSEIF:
                        $result = rtrim($result) . ' ' . trim($text) . ' ';
                        break;
                    case T_CASE:
                    case T_DEFAULT:
                        $result = rtrim($result) . "\n" . str_repeat('    ', $t_count - 1) . trim($text) . ' ';
                        break;
                    case T_FUNCTION:
                    case T_CLASS:
                        $result .= "\n" . str_repeat('    ', $t_count) . trim($text) . ' ';
                        break;
                    case T_AND_EQUAL:
                    case T_AS:
                    case T_BOOLEAN_AND:
                    case T_BOOLEAN_OR:
                    case T_CONCAT_EQUAL:
                    case T_DIV_EQUAL:
                    case T_DOUBLE_ARROW:
                    case T_IS_EQUAL:
                    case T_IS_GREATER_OR_EQUAL:
                    case T_IS_IDENTICAL:
                    case T_IS_NOT_EQUAL:
                    case T_IS_NOT_IDENTICAL:
                    case T_LOGICAL_AND:
                    case T_LOGICAL_OR:
                    case T_LOGICAL_XOR:
                    case T_MINUS_EQUAL:
                    case T_MOD_EQUAL:
                    case T_MUL_EQUAL:
                    case T_OR_EQUAL:
                    case T_PLUS_EQUAL:
                    case T_SL:
                    case T_SL_EQUAL:
                    case T_SR:
                    case T_SR_EQUAL:
                    case T_START_HEREDOC:
                    case T_XOR_EQUAL:
                        $result = rtrim($result) . ' ' . trim($text) . ' ';
                        break;
                    case T_COMMENT:
                        $result = rtrim($result) . "\n" . str_repeat('    ', $t_count) . trim($text) . ' ';
                        break;
                    case T_ML_COMMENT:
                        $result = rtrim($result) . "\n";
                        $lines = explode("\n", $text);
                        foreach ($lines as $line) {
                            $result .= str_repeat('    ', $t_count) . trim($line);
                        }
                        $result .= "\n";
                        break;
                    case T_INLINE_HTML:
                        $result .= $text;
                        break;
                    default:
                        $result .= trim($text);
                        break;
                }
            }
        }
        return $result;
    }

    public static function replaceCreateFunction($str)
    {
        $hangs = 20;
        $str = stripcslashes($str);
        while (strpos($str, 'create_function') !== false && $hangs--) {
            $start_pos = strpos($str, 'create_function');
            $end_pos = 0;
            $brackets = 0;
            $started = false;
            $opened = 0;
            $closed = 0;
            for ($i = $start_pos, $iMax = strlen($str); $i < $iMax; $i++) {
                if ($str[$i] === '(') {
                    $started = true;
                    $brackets++;
                    $opened++;
                } else if ($str[$i] === ')') {
                    $closed++;
                    $brackets--;
                }
                if ($brackets == 0 && $started) {
                    $end_pos = $i + 1;
                    break;
                }
            }

            $cr_func = substr($str, $start_pos, $end_pos - $start_pos);
            $func = implode('function(', explode('create_function(\'', $cr_func, 2));
            $func = implode(') {', explode('\',\'', $func, 2));
            $func = substr($func, 0, -2) . '}';
            $str = str_replace($cr_func, $func, $str);
        }
        return $str;
    }

    public static function calc($expr)
    {
        if (is_array($expr)) {
            $expr = $expr[0];
        }
        preg_match('~(chr|min|max|round)?\(([^\)]+)\)~msi', $expr, $expr_arr);
        if (@$expr_arr[1] == 'min' || @$expr_arr[1] == 'max') {
            return $expr_arr[1](explode(',', $expr_arr[2]));
        } elseif (@$expr_arr[1] == 'chr') {
            if ($expr_arr[2][0] === '(') {
                $expr_arr[2] = substr($expr_arr[2], 1);
            }
            $expr_arr[2] = self::calc($expr_arr[2]);
            return $expr_arr[1]((int)$expr_arr[2]);
        } elseif (@$expr_arr[1] == 'round') {
            $expr_arr[2] = self::calc($expr_arr[2]);
            return $expr_arr[1]($expr_arr[2]);
        } else {
            preg_match_all('~([\d\.a-fx]+)([\*\/\-\+\^\|\&])?~', $expr, $expr_arr);
            foreach ($expr_arr[1] as &$expr_arg) {
                if (strpos($expr_arg, "0x") !== false) {
                    $expr = str_replace($expr_arg, hexdec($expr_arg), $expr);
                    $expr_arg = hexdec($expr_arg);
                } else if ($expr_arg[0] === '0' && (strlen($expr_arg) > 1) && (strpos($expr_arg, '.') === false)) {
                    $expr = str_replace($expr_arg, octdec($expr_arg), $expr);
                    $expr_arg = octdec($expr_arg);
                }
            }
            if (in_array('*', $expr_arr[2]) !== false) {
                $pos = array_search('*', $expr_arr[2]);
                $res = $expr_arr[1][$pos] * $expr_arr[1][$pos + 1];
                $pos_subst = strpos($expr, $expr_arr[1][$pos] . '*' . $expr_arr[1][$pos + 1]);
                $expr = substr_replace($expr, $res, $pos_subst, strlen($expr_arr[1][$pos] . '*' . $expr_arr[1][$pos + 1]));
                $expr = self::calc($expr);
            } elseif (in_array('/', $expr_arr[2]) !== false) {
                $pos = array_search('/', $expr_arr[2]);
                $res = $expr_arr[1][$pos] / $expr_arr[1][$pos + 1];
                $pos_subst = strpos($expr, $expr_arr[1][$pos] . '/' . $expr_arr[1][$pos + 1]);
                $expr = substr_replace($expr, $res, $pos_subst, strlen($expr_arr[1][$pos] . '/' . $expr_arr[1][$pos + 1]));
                $expr = self::calc($expr);
            } elseif (in_array('-', $expr_arr[2]) !== false) {
                $pos = array_search('-', $expr_arr[2]);
                $res = $expr_arr[1][$pos] - $expr_arr[1][$pos + 1];
                $pos_subst = strpos($expr, $expr_arr[1][$pos] . '-' . $expr_arr[1][$pos + 1]);
                $expr = substr_replace($expr, $res, $pos_subst, strlen($expr_arr[1][$pos] . '-' . $expr_arr[1][$pos + 1]));
                $expr = self::calc($expr);
            } elseif (in_array('+', $expr_arr[2]) !== false) {
                $pos = array_search('+', $expr_arr[2]);
                $res = $expr_arr[1][$pos] + $expr_arr[1][$pos + 1];
                $pos_subst = strpos($expr, $expr_arr[1][$pos] . '+' . $expr_arr[1][$pos + 1]);
                $expr = substr_replace($expr, $res, $pos_subst, strlen($expr_arr[1][$pos] . '+' . $expr_arr[1][$pos + 1]));
                $expr = self::calc($expr);
            } elseif (in_array('^', $expr_arr[2]) !== false) {
                $pos = array_search('^', $expr_arr[2]);
                $res = (int)$expr_arr[1][$pos] ^ (int)$expr_arr[1][$pos + 1];
                $pos_subst = strpos($expr, $expr_arr[1][$pos] . '^' . $expr_arr[1][$pos + 1]);
                $expr = substr_replace($expr, $res, $pos_subst, strlen($expr_arr[1][$pos] . '^' . $expr_arr[1][$pos + 1]));
                $expr = self::calc($expr);
            } elseif (in_array('|', $expr_arr[2]) !== false) {
                $pos = array_search('|', $expr_arr[2]);
                $res = $expr_arr[1][$pos] | $expr_arr[1][$pos + 1];
                $pos_subst = strpos($expr, $expr_arr[1][$pos] . '|' . $expr_arr[1][$pos + 1]);
                $expr = substr_replace($expr, $res, $pos_subst, strlen($expr_arr[1][$pos] . '|' . $expr_arr[1][$pos + 1]));
                $expr = self::calc($expr);
            } elseif (in_array('&', $expr_arr[2]) !== false) {
                $pos = array_search('&', $expr_arr[2]);
                $res = $expr_arr[1][$pos] & $expr_arr[1][$pos + 1];
                $pos_subst = strpos($expr, $expr_arr[1][$pos] . '&' . $expr_arr[1][$pos + 1]);
                $expr = substr_replace($expr, $res, $pos_subst, strlen($expr_arr[1][$pos] . '&' . $expr_arr[1][$pos + 1]));
                $expr = self::calc($expr);
            } else {
                return $expr;
            }

            return $expr;
        }
    }

    public static function getEvalCode($string)
    {
        preg_match("/eval\(([^\)]+)\)/msi", $string, $matches);
        return (empty($matches)) ? '' : end($matches);
    }

    /**
     * @param string $content
     *
     * @return string
     */
    public static function unwrapGoto(&$content): string
    {

        /*
        $label_num = 0;
        $label_name = 'tmp_spec_label';

        $replaceVars = [];

        $content = preg_replace_callback('~goto ([^\w;]+);~msi', function ($m) use (&$replaceVars, &$label_num, $label_name) {
            $label_num++;
            $newName = $label_name . $label_num;
            $replaceVars[] = [$m[1], $newName];
            return 'goto ' . $newName . '; ';
        }, $content);

        if (!empty($replaceVars)) {
            foreach ($replaceVars as $replaceVar) {
                $content = str_replace($replaceVar[0], $replaceVar[1], $content);
            }
        }

        $content = preg_replace_callback('~(if\s*(\([^)(]*+(?:(?2)[^)(]*)*+\))\s*)(goto\s*(?:\w+);)~msi', function($m) {
            return $m[1] . ' { ' . $m[3] . ' } ';
        }, $content);
        */

        preg_match_all('~goto\s?(\w+);~msi', $content, $gotoMatches, PREG_SET_ORDER);
        $gotoCount = count($gotoMatches);
        if (!$gotoCount || ($gotoCount <= 0 && $gotoCount > self::GOTO_MAX_HOPS)) {
            return $content;
        }

        $label_num = 0;
        $label_name = 'tmp_label';

        $res      = '';
        $hops     = self::GOTO_MAX_HOPS;
        if (preg_match('~(.*?)(?:goto\s\w+;|\w+:)~msi', $content, $m)) {
            $res .= trim($m[1]) . PHP_EOL;
        }

        if (preg_match('~\w{1,99}:\s*(<\?php)~msi', $content, $m, PREG_OFFSET_CAPTURE)) {
            $orig = substr($content, 0, $m[1][1]);
            $content = str_replace('<?php ' . $orig, '', $content);
        }

        $content = preg_replace_callback('~(?<!: )\}\s*goto\s*\w+;~mis', function($m) use (&$label_num, $label_name) {
            $label_num++;
            return $label_name . $label_num . ': ' . $m[0];
        }, $content);

        //try to match all if's conditions it can be if or loop
        preg_match_all('~(\w+):\s*if\s*(\([^)(]*+(?:(?2)[^)(]*)*+\))\s*\{\s*goto\s*(\w+); (' . $label_name . '\d+):\s*\}\s*goto\s*(\w+);~mis', $content, $conds, PREG_SET_ORDER);
        foreach ($conds as $cond) {
            preg_match('~\w+:\s*(\w+):\s*goto\s*' . $cond[1] . '~msi', $content, $while);
            preg_match('~' . $cond[5] . ':\s*(\w+):\s*goto\s*(\w+);~msi', $content, $do);
            preg_match('~(\w+):\s*' . $cond[3] . ':\s*goto\s*(\w+);~msi', $content, $m);
            preg_match('~(\w+):\s*goto\s*(\w+); goto\s*' . $m[1] . ';~msi', $content, $ifelse);
            preg_match('~(\w+):\s*\w+:\s*goto\s*' . $cond[1] . ';~msi', $content, $m);
            preg_match('~(\w+):\s*\w+:\s*goto\s*' . $m[1] . ';~msi', $content, $m);
            preg_match('~(\w+):\s*' . $ifelse[2] . ': goto\s*(\w+);~msi', $content, $m);

            if (!empty($m) && ($m[2] === $cond[1])) { // if goto in last match point to this if statement - we have a loop, otherwise - if-else
                $ifelse = [];
            }

            if (empty($do) && empty($ifelse)) { //reverse conditions except do while & if else
                if ($cond[2][1] === '!') {
                    $cond[2] = substr_replace($cond[2], '', 1, 1);
                } else {
                    $cond[2] = '(!' . $cond[2] . ')';
                }
            }

            if (!empty($ifelse)) {
                $content = str_replace($cond[0],
                    $cond[1] . ': if ' . $cond[2] . ' { goto ' . $cond[3] . '; ' . $cond[4] . ': ' . '} else { goto ' . $cond[5] . ';',
                    $content);
                preg_match('~(\w+):\s*(' . $ifelse[2] . '):\s*goto\s*(\w+);~msi', $content, $m2);
                $content = str_replace($m2[0],
                    $m2[1] . ': goto ' . $cond[4] . '; ' . $m2[2] . ': } goto ' . $m2[3] . ';', $content);
            } elseif (!empty($do)) {
                preg_match('~(\w+):\s*(' . $cond[3] . '):\s*goto\s*~msi', $content, $match);
                $tmp = $cond[0];
                $content = str_replace($match[0], $match[1] . ': do { goto ' . $match[2] . '; ' . $match[2] . ': goto ', $content);
                $cond[0] = $cond[1] . ': } while ' . $cond[2] . '; goto ' . $cond[5] . ';';
                $content = str_replace($tmp, $cond[0], $content);
            } else if (!empty($while)) { //loop change if to while, reverse condition, exchange labels; in last goto $tmp_labelN
                preg_match('~\w+:\s*goto\s*(' . $while[1] . ')~msi', $content, $match);
                $content = str_replace($match[0], str_replace($match[1], $cond[4], $match[0]), $content);
                $content = str_replace($cond[0], $cond[1] . ': ' . 'while (' . $cond[2] . ') {' . 'goto ' . $cond[5] . '; ' . $cond[4] . ': } goto ' . $cond[3] . ';', $content);
            } else { //just if - need to reverse condition and exchange labels; in last need goto to $tmp_labelN
                $tmp = $cond[0];
                $cond[0] = $cond[1] . ': ' . 'if ' . $cond[2] . ' { goto ' . $cond[5] . '; ' . $cond[4] . ': } goto ' . $cond[3] . ';';
                $content = str_replace($tmp, $cond[0], $content);
                preg_match('~(\w+):\s*(' . $cond[3] . '):\s*goto\s*(\w+)~msi', $content, $match);
                $content = str_replace($match[0], $match[1] . ': goto ' . $cond[4] . '; ' . $match[2] . ': goto ' . $match[3], $content);
            }
        }
        $nextGotoPos = 0;
        while ($nextGotoPos !== false && $hops > 0 && preg_match('~goto\s(\w+);~msi',
                substr($content, $nextGotoPos),
                $gotoNameMatch,
                PREG_OFFSET_CAPTURE)) {
            $gotoNameStr    = $gotoNameMatch[1][0] . ':';
            $gotoNameStrLen = strlen($gotoNameStr);
            $gotoPos        = strpos($content, $gotoNameStr);
            $nextGotoPos    = strpos($content, 'goto ', $gotoPos);
            $cutUntilPos    = ($nextGotoPos - $gotoPos) - $gotoNameStrLen;

            $substr = '';

            if ($nextGotoPos) {
                $substr = substr($content, $gotoPos + $gotoNameStrLen, $cutUntilPos);
            } else {
                $substr = substr($content, $gotoPos + $gotoNameStrLen);
            }

            $piece = trim($substr);
            $piece === '' ?: $res .= $piece . ' ';
            $hops--;
        }
        $res = preg_replace('~\w{1,20}:~msi', '', $res);
        $res = stripcslashes($res);
        return $res;
    }

    public static function getTextInsideQuotes($string)
    {
        if (preg_match_all('/("(.*)")/msi', $string, $matches)) {
            $array = end($matches);
            return @end($array);
        }

        if (preg_match_all('/\((\'(.*)\')/msi', $string, $matches)) {
            $array = end($matches);
            return @end($array);
        }

        return '';
    }

    public static function getNeedles($string)
    {
        preg_match_all("/'(.*?)'/msi", $string, $matches);

        return (empty($matches)) ? [] : $matches[1];
    }

    public static function getHexValues($string)
    {
        preg_match_all('/0x[a-fA-F0-9]{1,8}/msi', $string, $matches);
        return (empty($matches)) ? [] : $matches[0];
    }

    public static function formatPHP($string)
    {
        $string = str_replace('<?php', '', $string);
        $string = str_replace('?>', '', $string);
        $string = str_replace(PHP_EOL, "", $string);
        $string = str_replace(";", ";\n", $string);
        $string = str_replace("}", "}\n", $string);
        return $string;
    }
    
    public static function prepareArray($string)
    {
        $string = rtrim($string, ',');
        $array_string = Helpers::normalize($string);
        $list_str = explode(',', $array_string);
        $result = [];
        foreach ($list_str as $element) {
            $key = null;
            $value = $element;
            if (strpos($element, '=>') !== false) {
                list($key, $value) = explode('=>', $element);
            }
            $key = is_null($key) ? $key : trim($key, '\'"');
            $value = is_null($value) ? $value : trim($value, '\'"');
            
            if (is_null($key)) {
                $result[] = $value;
            }
            else {
                $result[$key] = $value;
            }
        }
        return $result;
    }    

    public static function detect_utf_encoding($text)
    {
        $first2 = substr($text, 0, 2);
        $first3 = substr($text, 0, 3);
        $first4 = substr($text, 0, 4);

        if ($first4 == chr(0x00) . chr(0x00) . chr(0xFE) . chr(0xFF)) {
            return 'UTF-32BE';
        } elseif ($first4 == chr(0xFF) . chr(0xFE) . chr(0x00) . chr(0x00)) {
            return 'UTF-32LE';
        } elseif ($first2 == chr(0xFE) . chr(0xFF)) {
            return 'UTF-16BE';
        } elseif ($first2 == chr(0xFF) . chr(0xFE)) {
            return 'UTF-16LE';
        }

        return false;
    }

    //from sample_16
    public static function someDecoder($str)
    {
        $str = base64_decode($str);
        $TC9A16C47DA8EEE87 = 0;
        $TA7FB8B0A1C0E2E9E = 0;
        $T17D35BB9DF7A47E4 = 0;
        $T65CE9F6823D588A7 = (ord($str[1]) << 8) + ord($str[2]);
        $i = 3;
        $T77605D5F26DD5248 = 0;
        $block = 16;
        $T7C7E72B89B83E235 = "";
        $T43D5686285035C13 = "";
        $len = strlen($str);

        $T6BBC58A3B5B11DC4 = 0;

        for (; $i < $len;) {
            if ($block == 0) {
                $T65CE9F6823D588A7 = (ord($str[$i++]) << 8);
                $T65CE9F6823D588A7 += ord($str[$i++]);
                $block = 16;
            }
            if ($T65CE9F6823D588A7 & 0x8000) {
                $TC9A16C47DA8EEE87 = (ord($str[$i++]) << 4);
                $TC9A16C47DA8EEE87 += (ord($str[$i]) >> 4);
                if ($TC9A16C47DA8EEE87) {
                    $TA7FB8B0A1C0E2E9E = (ord($str[$i++]) & 0x0F) + 3;
                    for ($T17D35BB9DF7A47E4 = 0; $T17D35BB9DF7A47E4 < $TA7FB8B0A1C0E2E9E; $T17D35BB9DF7A47E4++) {
                        $T7C7E72B89B83E235[$T77605D5F26DD5248 + $T17D35BB9DF7A47E4] =
                            $T7C7E72B89B83E235[$T77605D5F26DD5248 - $TC9A16C47DA8EEE87 + $T17D35BB9DF7A47E4];
                    }
                    $T77605D5F26DD5248 += $TA7FB8B0A1C0E2E9E;
                } else {
                    $TA7FB8B0A1C0E2E9E = (ord($str[$i++]) << 8);
                    $TA7FB8B0A1C0E2E9E += ord($str[$i++]) + 16;
                    for ($T17D35BB9DF7A47E4 = 0; $T17D35BB9DF7A47E4 < $TA7FB8B0A1C0E2E9E;
                         $T7C7E72B89B83E235[$T77605D5F26DD5248 + $T17D35BB9DF7A47E4++] = $str[$i]) {
                    }
                    $i++;
                    $T77605D5F26DD5248 += $TA7FB8B0A1C0E2E9E;
                }
            } else {
                $T7C7E72B89B83E235[$T77605D5F26DD5248++] = $str[$i++];
            }
            $T65CE9F6823D588A7 <<= 1;
            $block--;
            if ($i == $len) {
                $T43D5686285035C13 = $T7C7E72B89B83E235;
                if (is_array($T43D5686285035C13)) {
                    $T43D5686285035C13 = implode($T43D5686285035C13);
                }
                $T43D5686285035C13 = "?" . ">" . $T43D5686285035C13;
                return $T43D5686285035C13;
            }
        }
    }

    public static function someDecoder2($WWAcmoxRAZq, $sBtUiFZaz)   //sample_05
    {
        $JYekrRTYM = str_rot13(gzinflate(str_rot13(base64_decode('y8svKCwqLiktK6+orFdZV0FWWljPyMzKzsmNNzQyNjE1M7ewNAAA'))));
        if ($WWAcmoxRAZq == 'asedferg456789034689gd') {
            $cEerbvwKPI = $JYekrRTYM[18] . $JYekrRTYM[19] . $JYekrRTYM[17] . $JYekrRTYM[17] . $JYekrRTYM[4] . $JYekrRTYM[21];
            return $cEerbvwKPI($sBtUiFZaz);
        } elseif ($WWAcmoxRAZq == 'zfcxdrtgyu678954ftyuip') {
            $JWTDeUKphI = $JYekrRTYM[1] . $JYekrRTYM[0] . $JYekrRTYM[18] . $JYekrRTYM[4] . $JYekrRTYM[32] .
                $JYekrRTYM[30] . $JYekrRTYM[26] . $JYekrRTYM[3] . $JYekrRTYM[4] . $JYekrRTYM[2] . $JYekrRTYM[14] .
                $JYekrRTYM[3] . $JYekrRTYM[4];
            return $JWTDeUKphI($sBtUiFZaz);
        } elseif ($WWAcmoxRAZq == 'gyurt456cdfewqzswexcd7890df') {
            $rezmMBMev = $JYekrRTYM[6] . $JYekrRTYM[25] . $JYekrRTYM[8] . $JYekrRTYM[13] . $JYekrRTYM[5] . $JYekrRTYM[11] . $JYekrRTYM[0] . $JYekrRTYM[19] . $JYekrRTYM[4];
            return $rezmMBMev($sBtUiFZaz);
        } elseif ($WWAcmoxRAZq == 'zcdfer45dferrttuihvs4321890mj') {
            $WbbQXOQbH = $JYekrRTYM[18] . $JYekrRTYM[19] . $JYekrRTYM[17] . $JYekrRTYM[26] . $JYekrRTYM[17] . $JYekrRTYM[14] . $JYekrRTYM[19] . $JYekrRTYM[27] . $JYekrRTYM[29];
            return $WbbQXOQbH($sBtUiFZaz);
        } elseif ($WWAcmoxRAZq == 'zsedrtre4565fbghgrtyrssdxv456') {
            $jPnPLPZcMHgH = $JYekrRTYM[2] . $JYekrRTYM[14] . $JYekrRTYM[13] . $JYekrRTYM[21] . $JYekrRTYM[4] . $JYekrRTYM[17] . $JYekrRTYM[19] . $JYekrRTYM[26] . $JYekrRTYM[20] . $JYekrRTYM[20] . $JYekrRTYM[3] . $JYekrRTYM[4] . $JYekrRTYM[2] . $JYekrRTYM[14] . $JYekrRTYM[3] . $JYekrRTYM[4];
            return $jPnPLPZcMHgH($sBtUiFZaz);
        }
    }

    public static function someDecoder3($str)
    {
        $l = base64_decode($str);
        $lllllll = 0;
        $lllll = 3;
        $llllll = (ord($l[1]) << 8) + ord($l[2]);
        $lllllllll = 16;
        $llllllll = [];
        for ($lllllMax = strlen($l); $lllll < $lllllMax;) {
            if ($lllllllll == 0) {
                $llllll = (ord($l[$lllll++]) << 8);
                $llllll+= ord($l[$lllll++]);
                $lllllllll = 16;
            }
            if ($llllll & 0x8000) {
                $lll = (ord($l[$lllll++]) << 4);
                $lll+= (ord($l[$lllll]) >> 4);
                if ($lll) {
                    $ll = (ord($l[$lllll++]) & 0x0f) + 3;
                    for ($llll = 0;$llll < $ll;$llll++) $llllllll[$lllllll + $llll] = $llllllll[$lllllll - $lll + $llll];
                    $lllllll+= $ll;
                } else {
                    $ll = (ord($l[$lllll++]) << 8);
                    $ll+= ord($l[$lllll++]) + 16;
                    for ($llll = 0;$llll < $ll;$llllllll[$lllllll + $llll++] = ord($l[$lllll]));
                    $lllll++;
                    $lllllll+= $ll;
                }
            } else {
                $llllllll[$lllllll++] = ord($l[$lllll++]);
            }
            $llllll <<= 1;
            $lllllllll--;
        }
        $lllll = 0;
        $lllllllll="?".chr(62);
        $llllllllll = "";
        for (;$lllll < $lllllll;) {
            $llllllllll.= chr($llllllll[$lllll++] ^ 0x07);
        }
        $lllllllll.=$llllllllll.chr(60)."?";
        return $lllllllll;
    }

    public static function PHPJiaMi_decoder($str, $md5, $rand, $lower_range = '')
    {
        $md5_xor = md5($md5);
        $lower_range = !$lower_range ? ord($rand) : $lower_range;
        $layer1 = '';
        for ($i=0, $iMax = strlen($str); $i < $iMax; $i++) {
            $layer1 .= ord($str[$i]) < 245 ? ((ord($str[$i]) > $lower_range && ord($str[$i]) < 245) ? chr(ord($str[$i]) / 2) : $str[$i]) : '';
        }
        $layer1 = base64_decode($layer1);
        $result = '';
        $j = $len_md5_xor = strlen($md5_xor);
        for ($i=0, $iMax = strlen($layer1); $i < $iMax; $i++) {
            $j = $j ? $j : $len_md5_xor;
            $j--;
            $result .= $layer1[$i] ^ $md5_xor[$j];
        }
        return $result;
    }

    public static function someDecoder4($ae, $key)
    {
        $at = [];
        for ($i = 0, $iMax = strlen($key); $i < $iMax; $i++) {
            if ((int)$key[$i] > 0) {
                $at[$i] = $key[$i];
            }
        }
        $at = array_values($at);
        $str = "";
        for ($i = 0, $iMax = count($ae); $i < $iMax; $i++) {
            if ($i < count($ae) - 1) {
                $str .= str_replace(md5($at[$i]), "", $ae[$i]);
            } else {
                $str .= $ae[$i];
            }
        }
        return $str;
    }

    public static function OELoveDecoder($arg1, $arg2 = '')
    {
        if (empty($arg1)) {
            return '';
        }
        $arg1 = base64_decode($arg1);
        if ($arg2 == '') return ~$arg1;
        //if ($arg2 == '-1') @271552362217();
        $len = strlen($arg1);
        $arg2 = str_pad($arg2, $len, $arg2);
        return $arg2 ^ $arg1;
    }

    public static function decodeEvalFuncBinary($input)
    {
        if (empty($input)) {
            return;
        }
        $keyStr = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";
        $chr1 = $chr2 = $chr3 = "";
        $enc1 = $enc2 = $enc3 = $enc4 = "";
        $i = 0;
        $output = "";
        $input = preg_replace("[^A-Za-z0-9\+\/\=]", "", $input);
        do {
            $enc1 = strpos($keyStr, substr($input, $i++, 1));
            $enc2 = strpos($keyStr, substr($input, $i++, 1));
            $enc3 = strpos($keyStr, substr($input, $i++, 1));
            $enc4 = strpos($keyStr, substr($input, $i++, 1));
            $chr1 = ($enc1 << 2) | ($enc2 >> 4);
            $chr2 = (($enc2 & 15) << 4) | ($enc3 >> 2);
            $chr3 = (($enc3 & 3) << 6) | $enc4;
            $output .= chr($chr1);
            if ($enc3 !== 64) {
                $output .= chr($chr2);
            }
            if ($enc4 !== 64) {
                $output .= chr($chr3);
            }
            $chr1 = $chr2 = $chr3 = "";
            $enc1 = $enc2 = $enc3 = $enc4 = "";
        } while ($i < strlen($input));

        return $output;
    }

    public static function decodeFileGetContentsWithFunc($data, $key)
    {
        $out_data = "";

        for ($i = 0; $i < strlen($data);) {
            for ($j = 0; $j < strlen($key) && $i < strlen($data); $j++, $i++) {
                $out_data .= chr(ord($data[$i]) ^ ord($key[$j]));
            }
        }

        return $out_data;
    }

    public static function stripsquoteslashes($str)
    {
        $res = '';
        for ($i = 0, $iMax = strlen($str); $i < $iMax; $i++) {
            if (isset($str[$i+1]) && ($str[$i] == '\\' && ($str[$i+1] == '\\' || $str[$i+1] == '\''))) {
                continue;
            } else {
                $res .= $str[$i];
            }
        }
        return $res;
    }

    public static function isSafeFunc($str)
    {
        $safeFuncs = [
            'base64_decode', 'gzinflate', 'gzdecode', 'gzuncompress', 'strrev', 'strlen',
            'str_rot13', 'urldecode', 'rawurldecode', 'stripslashes', 'chr',
            'htmlspecialchars_decode', 'convert_uudecode','pack', 'ord',
            'str_repeat', 'sprintf', 'str_replace', 'strtr', 'hex2bin', 'unserialize'
        ];
        return in_array(strtolower($str), $safeFuncs);

    }

    public static function aanKFMDigitsDecode($digits)
    {
        $res = '';
        $len = ceil(strlen($digits) / 3) * 3;
        $cipher = str_pad($digits, $len, '0', STR_PAD_LEFT);
        for ($i = 0; $i < (strlen($cipher) / 3);$i++) {
            $res .= chr(substr($cipher, $i * 3, 3));
        }
        return $res;
    }

    public static function obf20200414_1_decrypt($data, $key)
    {
        $key = md5($key);
        $x = 0;
        $data = base64_decode($data);
        $len = strlen($data);
        $l = strlen($key);
        $char = '';
        for ($i = 0; $i < $len; $i++) {
            if ($x === $l) {
                $x = 0;
            }
            $char .= substr($key, $x, 1);
            $x++;
        }
        $str = '';
        for ($i = 0; $i < $len; $i++) {
            if (ord(substr($data, $i, 1)) < ord(substr($char, $i, 1))) {
                $str .= chr((ord(substr($data, $i, 1)) + 256) - ord(substr($char, $i, 1)));
            } else {
                $str .= chr(ord(substr($data, $i, 1)) - ord(substr($char, $i, 1)));
            }
        }
        return $str;
    }

    public static function Xtea_decrypt($text, $key)
    {
        $_key = '';
        $cbc = 1;

        if(is_array($key)) {
            $_key = $key;
        } else if(isset($key) && !empty($key)) {
            $_key = self::_str2long(str_pad($key, 16, $key));
        } else {
            $_key = [0, 0, 0, 0];
        }

        $plain = [];
        $cipher = self::_str2long(base64_decode($text));

        if($cbc == 1) {
            $i = 2;
        } else {
            $i = 0;
        }

        for ($i, $iMax = count($cipher); $i < $iMax; $i += 2) {
            $return = self::block_decrypt($cipher[$i], $cipher[$i+1], $_key);
            if($cbc == 1) {
                $plain[] = [$return[0] ^ $cipher[$i - 2], $return[1] ^ $cipher[$i - 1]];
            } else {
                $plain[] = $return;
            }
        }

        $output = "";
        for($i = 0, $iMax = count($plain); $i < $iMax; $i++) {
            $output .= self::_long2str($plain[$i][0]);
            $output .= self::_long2str($plain[$i][1]);
        }

        return $output;
    }

    public static function calculateMathStr($task)
    {
        $res = $task;

        while (preg_match('~\(?(\d+)\s?([+\-*\/])\s?(\d+)\)?~', $res, $subMatch)) {
            if (count($subMatch) === 4) {
                list($subSearch, $number_1, $operator, $number_2) = $subMatch;
                $res = str_replace($subSearch, self::calc("$number_1$operator$number_2"), $res);
            } else {
                return $res;
            }
        }

        return $res;
    }

    public static function decrypt_T_func($l)
    {
        $x2 = 256;
        $W2 = 8;
        $cY = [];
        $I3 = 0;
        $C4 = 0;
        for ($bs = 0, $bsMax = strlen($l); $bs < $bsMax; $bs++) {
            $I3 = ($I3 << 8) + ord($l[$bs]);
            $C4 += 8;
            if ($C4 >= $W2) {
                $C4 -= $W2;
                $cY[] = $I3 >> $C4;
                $I3 &= (1 << $C4) - 1;
                $x2++;
                if ($x2 >> $W2) {
                    $W2++;
                }
            }
        }
        $K5 = range("\x0", "\377");
        $UH = '';
        foreach ($cY as $bs => $xd) {
            if (!isset($K5[$xd])) {
                $iU = $Co . $Co[0];
            } else {
                $iU = $K5[$xd];
            }
            $UH .= $iU;
            if ($bs) {
                $K5[] = $Co . $iU[0];
            }
            $Co = $iU;
        }
        return $UH;
    }

    public static function getDecryptKeyForTinkleShell($size)
    {
        $bx = md5(base64_encode($size));
        $len = strlen($bx);
        $arr = [];
        for ($i = 0; $i < $len; $i++) {
            $arr[] = substr($bx, $i, 1);
        }
        $arr = array_unique($arr);
        $newstr = "";
        foreach ($arr as $k => $v) {
            $newstr .= $v;
        }
        if (strlen($newstr) < 9) {
            if (strpos($newstr, 'A') === false) {
                $newstr .= 'A';
            }
            if (strpos($newstr, 'B') === false) {
                $newstr .= 'B';
            }
            if (strpos($newstr, 'C') === false) {
                $newstr .= 'C';
            }
            if (strpos($newstr, 'D') === false) {
                $newstr .= 'D';
            }
            if (strpos($newstr, 'E') === false) {
                $newstr .= 'E';
            }
            if (strpos($newstr, 'F') === false) {
                $newstr .= 'F';
            }
            if (strpos($newstr, 'G') === false) {
                $newstr .= 'G';
            }
        }

       return strtoupper($newstr);
    }

    /**
     * For 4 args
     * @param array $arr
     *
     * @return string
     */
    public static function decodeEvalCreateFunc_1(array $arr) : string
    {
        $args = $arr;

        for ($i = 0; $i < 4; $i++) {
            for ($j = 0, $jMax = strlen($args[$i]); $j < $jMax; $j++) {
                $args[$i][$j] = chr(ord($args[$i][$j]) - ($i ? $args[$j xor $j] : 1));
            }
            if ($i === 2 && self::isSafeFunc($args[1]) && self::isSafeFunc($args[2])) {
                $args[3] = @$args[1](@$args[2]($args[3]));
            }
        }

        return $args[3];
    }

    /**
     * For 3 args
     * @param array $arr
     *
     * @return string
     */
    public static function decodeEvalCreateFunc_2(array $arr) : string
    {
        $args = $arr;

        for ($i = 0; $i < 3; $i++) {
            for ($j = 0, $jMax = strlen($args[$i]); $j < $jMax; $j++) {
                $args[$i][$j] = chr(ord($args[$i][$j]) - 1);
            }
            if ($i === 1 && self::isSafeFunc($args[0]) && self::isSafeFunc($args[1])) {
                $args[2] = @$args[0](@$args[1]($args[2]));
            }
        }

        return $args[2];
    }

    public static function decodeACharCustom($encoded)
    {
        $result = '';
        $i = 0;
        $len = strlen($encoded);
        while ($i < $len) {
            if ($encoded[$i] === ' ') {
                $result .= ' ';
            } else if ($encoded[$i] === '!') {
                $result .= chr((ord($encoded[$i + 1]) - ord('A')) * 16 + (ord($encoded[$i + 2]) - ord('a')));
                $i += 2;
            } else {
                $result .= chr (ord($encoded[$i]) + 1);
            }
            $i++;
        }
        return $result;
    }

    /**
     * @param string $key
     * @param string $data
     *
     * @return string
     */
    public static function decodeFuncVars(string $key, string $data): string
    {
        $hakfku = $data;
        $keyLen = strlen($key);
        $dataLen = strlen($hakfku);
        $res = "";
        for ($i = 0; $i < $dataLen;) {
            for ($j = 0; ($j < $keyLen && $i < $dataLen); $j++, $i++) {
                $res .= $hakfku[$i] ^ $key[$j];
            }
        }

        return $res;
    }

    /**
     * @param string $data
     * @param string $key
     *
     * @return string
     */
    public static function decodeEvalFileContentBySize(string $data, string $key): string
    {
        $res = '';
        $key = md5($key) . md5($key . $key);
        $key_len = strlen($key);
        $data_len = strlen($data);
        for ($i = 0; $i < $data_len; $i++) {
            $res .= chr(ord($data[$i]) ^ ord($key[$i % $key_len]));
        }

        return $res;
    }

    public static function decodeClassDecryptedWithKey(string $data, int $num, string $key): string
    {
        function CTL($start, &$data, &$data_long)
        {
            $n = strlen($data);
            $tmp = unpack('N*', $data);
            $j = $start;
            foreach ($tmp as $value) $data_long[$j++] = $value;
            return $j;
        }

        function LtoC($l)
        {
            return pack('N', $l);
        }

        function add($i1, $i2)
        {
            $result = 0.0;
            foreach (func_get_args() as $value) {
                if (0.0 > $value) {
                    $value -= 1.0 + 0xffffffff;
                }
                $result += $value;
            }
            if (0xffffffff < $result || -0xffffffff > $result) {
                $result = fmod($result, 0xffffffff + 1);
            }
            if (0x7fffffff < $result) {
                $result -= 0xffffffff + 1.0;
            } elseif (-0x80000000 > $result) {
                $result += 0xffffffff + 1.0;
            }
            return $result;
        }

        function delg($y, $z, &$w, &$k, $num)
        {
            $sum = 0xC6EF3720;
            $klhys = 0x9E3779B9;
            $n = $num;
            while ($n-- > 0) {
                $z = add($z, -(add($y << 4 ^ rsLT($y, 5), $y) ^ add($sum, $k[rsLT($sum, 11) & 3])));
                $sum = add($sum, -$klhys);
                $y = add($y, -(add($z << 4 ^ rsLT($z, 5), $z) ^ add($sum, $k[$sum & 3])));
            }
            $w[0] = $y;
            $w[1] = $z;
        }

        function rsLT($integer, $n)
        {
            if (0xffffffff < $integer || -0xffffffff > $integer) {
                $integer = fmod($integer, 0xffffffff + 1);
            }
            if (0x7fffffff < $integer) {
                $integer -= 0xffffffff + 1.0;
            } elseif (-0x80000000 > $integer) {
                $integer += 0xffffffff + 1.0;
            }
            if (0 > $integer) {
                $integer &= 0x7fffffff;
                $integer >>= $n;
                $integer |= 1 << (31 - $n);
            } else {
                $integer >>= $n;
            }
            return $integer;
        }

        function resize(&$data, $size, $nonull = false)
        {
            $n = strlen($data);
            $nmod = $n % $size;
            if (0 == $nmod) $nmod = $size;
            if ($nmod > 0) {
                if ($nonull) {
                    for ($i = $n; $i < $n - $nmod + $size; ++$i) {
                        $data[$i] = $data[$i % $n];
                    }
                } else {
                    for ($i = $n; $i < $n - $nmod + $size; ++$i) {
                        $data[$i] = chr(0);
                    }
                }
            }
            return $n;
        }

        $ncdL = CTL(0, $data, $enc_data_long);
        resize($key, 16, true);
        $n_key_long = CTL(0, $key, $key_long);
        $data = '';
        $w = array(0, 0);
        $j = 0;
        $len = 0;
        $k = array(0, 0, 0, 0);
        $pos = 0;
        for ($i = 0; $i < $ncdL; $i += 2) {
            if ($j + 4 <= $n_key_long) {
                $k[0] = $key_long[$j];
                $k[1] = $key_long[$j + 1];
                $k[2] = $key_long[$j + 2];
                $k[3] = $key_long[$j + 3];
            } else {
                $k[0] = $key_long[$j % $n_key_long];
                $k[1] = $key_long[($j + 1) % $n_key_long];
                $k[2] = $key_long[($j + 2) % $n_key_long];
                $k[3] = $key_long[($j + 3) % $n_key_long];
            }
            $j = ($j + 4) % $n_key_long;
            delg($enc_data_long[$i], $enc_data_long[$i + 1], $w, $k, $num);
            if (0 == $i) {
                $len = $w[0];
                if (4 <= $len) {
                    $data .= LtoC($w[1]);
                } else {
                    $data .= substr(LtoC($w[1]), 0, $len % 4);
                }
            } else {
                $pos = ($i - 1) * 4;
                if ($pos + 4 <= $len) {
                    $data .= LtoC($w[0]);
                    if ($pos + 8 <= $len) {
                        $data .= LtoC($w[1]);
                    } elseif ($pos + 4 < $len) {
                        $data .= substr(LtoC($w[1]), 0, $len % 4);
                    }
                } else {
                    $data .= substr(LtoC($w[0]), 0, $len % 4);
                }
            }
        }
        return $data;
    }

    /**
     * @param $string
     * @param $amount
     *
     * @return string
     */
    public static function rotencode($string, $amount)
    {
        $key = substr($string, 0, 1);
        if (strlen($string) == 1) {
            return chr(ord($key) + $amount);
        } else {
            return chr(ord($key) + $amount) . self::rotencode(
                    substr($string, 1, strlen($string) - 1),
                    $amount);
        }
    }

    /**
     * @param $a
     * @param $b
     *
     * @return string
     */
    public static function decodefuncDictVars($a, $b)
    {
        $c = preg_split("//", $a, -1, PREG_SPLIT_NO_EMPTY);
        foreach ($c as $d => $e) {
            $c[$d] = chr(ord($e) + $b);
        }
        $res = implode("", $c);

        return $res;
    }

    public static function codelock_dec($codelock_v)
    {
        switch ($codelock_v) {
            case "A":
                $dv = 0;
            break;
            case "B":
                $dv = 1;
            break;
            case "C":
                $dv = 2;
            break;
            case "D":
                $dv = 3;
            break;
            case "E":
                $dv = 4;
            break;
            case "F":
                $dv = 5;
            break;
            case "G":
                $dv = 6;
            break;
            case "H":
                $dv = 7;
            break;
            case "I":
                $dv = 8;
            break;
            case "J":
                $dv = 9;
            break;
            case "K":
                $dv = 10;
            break;
            case "L":
                $dv = 11;
            break;
            case "M":
                $dv = 12;
            break;
            case "N":
                $dv = 13;
            break;
            case "O":
                $dv = 14;
            break;
            case "P":
                $dv = 15;
            break;
            case "Q":
                $dv = 16;
            break;
            case "R":
                $dv = 17;
            break;
            case "S":
                $dv = 18;
            break;
            case "T":
                $dv = 19;
            break;
            case "U":
                $dv = 20;
            break;
            case "V":
                $dv = 21;
            break;
            case "W":
                $dv = 22;
            break;
            case "X":
                $dv = 23;
            break;
            case "Y":
                $dv = 24;
            break;
            case "Z":
                $dv = 25;
            break;
            case "a":
                $dv = 26;
            break;
            case "b":
                $dv = 27;
            break;
            case "c":
                $dv = 28;
            break;
            case "d":
                $dv = 29;
            break;
            case "e":
                $dv = 30;
            break;
            case "f":
                $dv = 31;
            break;
            case "g":
                $dv = 32;
            break;
            case "h":
                $dv = 33;
            break;
            case "i":
                $dv = 34;
            break;
            case "j":
                $dv = 35;
            break;
            case "k":
                $dv = 36;
            break;
            case "l":
                $dv = 37;
            break;
            case "m":
                $dv = 38;
            break;
            case "n":
                $dv = 39;
            break;
            case "o":
                $dv = 40;
            break;
            case "p":
                $dv = 41;
            break;
            case "q":
                $dv = 42;
            break;
            case "r":
                $dv = 43;
            break;
            case "s":
                $dv = 44;
            break;
            case "t":
                $dv = 45;
            break;
            case "u":
                $dv = 46;
            break;
            case "v":
                $dv = 47;
            break;
            case "w":
                $dv = 48;
            break;
            case "x":
                $dv = 49;
            break;
            case "y":
                $dv = 50;
            break;
            case "z":
                $dv = 51;
            break;
            case "0":
                $dv = 52;
            break;
            case "1":
                $dv = 53;
            break;
            case "2":
                $dv = 54;
            break;
            case "3":
                $dv = 55;
            break;
            case "4":
                $dv = 56;
            break;
            case "5":
                $dv = 57;
            break;
            case "6":
                $dv = 58;
            break;
            case "7":
                $dv = 59;
            break;
            case "8":
                $dv = 60;
            break;
            case "9":
                $dv = 61;
            break;
            case "+":
                $dv = 62;
            break;
            case "/":
                $dv = 63;
            break;
            case "=":
                $dv = 64;
            break;
            default:
                $dv = 0;
            break;
        }
        return $dv;
    }

    public static function codelock_run($ciph, $key)
    {
        $m = 0;
        $abc = "";
        for ($i = 0, $iMax = strlen($ciph); $i < $iMax; $i++) {
            $c = substr($ciph, $i, 1);
            $dv = Helpers::codelock_dec($c);
            $dv = ($dv - $m) / 4;
            $fb = decbin($dv);
            while (strlen($fb) < 4) {
                $fb = "0" . $fb;
            }
            $abc = $abc . $fb;
            $m++;
            if ($m > 3) {
                $m = 0;
            }
        }
        $kl = 0;
        $pd = "";
        for ($j = 0, $jMax = strlen($abc); $j < $jMax; $j = $j + 8) {
            $c = substr($abc, $j, 8);
            $k = substr($key, $kl, 1);
            $dc = bindec($c);
            $dc = $dc - strlen($key);
            $c = chr($dc);
            $kl++;
            if ($kl >= strlen($key)) {
                $kl = 0;
            }
            $dc = ord($c) ^ ord($k);
            $p = chr($dc);
            $pd = $pd . $p;
        }
        return $pd;
    }

    public static function codelock_dec_int($codelock_decint_code, $codelock_calc_key)
    {
        if ($codelock_calc_key !== "") {
            $codelock_calc_key = base64_encode($codelock_calc_key);
            $codelock_k1 = substr($codelock_calc_key, 0, 1);
            $codelock_k2 = substr($codelock_calc_key, 1, 1);
            $codelock_k3 = substr($codelock_calc_key, 2, 1);
            $codelock_decint_code = str_replace("$", "$codelock_k1", $codelock_decint_code);
            $codelock_decint_code = str_replace("(", "$codelock_k2", $codelock_decint_code);
            $codelock_decint_code = str_replace(")", "$codelock_k3", $codelock_decint_code);
        }
        $codelock_decint_code = base64_decode($codelock_decint_code);
        return $codelock_decint_code;
    }

    /**
     * @param string $dictionary
     * @param string $content
     *
     * @return array
     */
    public static function getVarsFromDictionary($dictionary, $content) : array
    {
        $vars = [];

        preg_match_all('~(\$(?:[^\w]+|\w+)\s*=(\s?\.?\s?\$(?:[^\w]+|\w+)[{\[]\d+[\]}])+)~msi', $content, $concatMatches);
        for ($i = 0; $iMax = count($concatMatches[0]), $i <= $iMax; $i++) {
            preg_match_all('~(\$(?:[^\w]+|\w+)(=))?(\s?(\.?)\s?\$(?:[^\w]+|\w+)[{\[](\d+)[\]}])~msi',
                $concatMatches[0][$i], $varMatches);
            for ($j = 0; $jMax = count($varMatches[0]), $j < $jMax; $j++) {
                $varName = substr($varMatches[1][0], 0, -1);
                $value = $dictionary[(int)$varMatches[5][$j]] ?? '';

                if ($varMatches[2][$j] === '=') {
                    $vars[$varName] = $value;
                } else {
                    $vars[$varName] .= $value;
                }
            }
        }

        return $vars;
    }

    /**
     * @param array  $vars
     * @param string $content
     *
     * @return array
     */
    public static function getVarsFromDictionaryDynamically(array &$vars = [], string $content = ''): array
    {
        preg_match_all('~(\$\w+)(\.)?\s?=\s?(?:\$\w+[{\[]?\d+[}\]]?\.?)+;~msi', $content, $varsMatches, PREG_SET_ORDER);
        foreach ($varsMatches as $varsMatch) {
            preg_match_all('~(\$\w+)[{\[]?(\d+)?[}\]]?~msi', $varsMatch[0], $subVarsMatches, PREG_SET_ORDER);
            $concat = '';
            foreach ($subVarsMatches as $subVarsMatch) {
                if (isset($subVarsMatch[2])) {
                    $concat .= $vars[$subVarsMatch[1]][(int)$subVarsMatch[2]] ?? '';
                } else if ($varsMatch[1] !== $subVarsMatch[1]) {
                    $concat .= $vars[$subVarsMatch[1]];
                }
            }
            if (isset($vars[$varsMatch[1]])) {
                $vars[$varsMatch[1]] .= $concat;
            } else {
                $vars[$varsMatch[1]] = $concat;
            }
        }

        return $vars;
    }

    /**
     * @param string $str
     * @return string
     */
    public static function concatVariableValues($str) : string
    {
        preg_match_all('/\$\w+\s?(\.?)=\s?"([\w=\+\/]+)"/', $str, $concatVars);

        $strVar = "";

        foreach ($concatVars[2] as $index => $concatVar) {
            if ($concatVars[1][$index] === '.') {
                $strVar .= $concatVar;
            } else {
                $strVar = $concatVar;
            }
        }

        return $strVar;
    }

    /**
     * Concats simple str without variable
     *
     * @param string $str
     * @return string
     */
    public static function concatStr($str) : string
    {
        preg_match_all('~(\.?)\s?[\'"]([\w=\+/%&();]+)[\'"]\s?~msi', $str, $concatStrings);

        $strVar = "";

        foreach ($concatStrings[2] as $index => $concatString) {
            if ($concatStrings[1][$index] === '.') {
                $strVar .= $concatString;
            } else {
                $strVar = $concatString;
            }
        }

        return $strVar;
    }

    /**
     * Concats simple strings without variable in content globally
     *
     * @param string $str
     * @return string
     */
    public static function concatStringsInContent($str) : string
    {
        $strVar = preg_replace_callback('~(?:[\'"][\w=();]*[\'"]\.?){2,}~msi', static function ($m) {
            return '\'' . self::concatStr($m[0]) . '\'';
        }, $str);

        return $strVar;
    }

    /**
     * @param $dictionaryVar
     * @param $dictionaryValue
     * @param $str
     *
     * @return string
     */
    public static function replaceVarsFromDictionary($dictionaryVar, $dictionaryValue, $str) : string
    {

        $result = $str;
        $result = preg_replace_callback('~(?:(\$(?:GLOBALS\[[\'"])?\w+(?:[\'"]\])?)[\[{][\'"]?(\d+)[\'"]?[\]}]\s?(\.)?\s?)~smi',
            function ($match) use ($dictionaryValue, $dictionaryVar) {
                if ($match[1] !== $dictionaryVar && !isset($dictionaryValue[(int)$match[2]])) {
                    return $match[0];
                }
                $lastChar = $match[3] ?? '';
                $value = $dictionaryValue[(int)$match[2]];
                $value = str_replace(['\'', '.'], ['@@quote@@', '@@dot@@'], $value);
                return '\'' . $value . '\'' . $lastChar;
            },
            $result
        );
        $result = str_replace('\'.\'', '', $result);
        $result = str_replace(['@@quote@@', '@@dot@@'], ['\\\'', '.'], $result);
        return $result;
    }

    /**
     * @param string $arrayName
     * @param array  $array
     * @param string $str
     *
     * @return string
     */
    public static function replaceVarsByArrayName(string $arrayName, array $array, string $str): string
    {
        $result = preg_replace_callback('~\s?(\$\w+)\s?\[\s?(\d+)\s?\]\s?~msi',
            function ($match) use ($array, $arrayName) {
                if ($match[1] !== $arrayName) {
                    return $match[0];
                }
                return $array[$match[2]] ?? $match[0];
            },
            $str
        );

        return $result;
    }

    /**
     * Collects simple or concated vars from str
     * @param string $str
     * @param string $trimQuote
     * @param array $vars
     * @param bool $remove
     *
     * @return array
     */
    public static function collectVars(&$str, string $trimQuote = '"', &$vars = [], $remove = false) : array
    {
        if (!is_string($str)) {
            return $vars;
        }
        preg_match_all('~(\$\w+)\s?(\.)?=\s?([\'"].*?[\'"]);~msi', $str, $matches);

        foreach ($matches[1] as $index => $match) {
            $varName = $match;
            $varValue = str_replace("$trimQuote.$trimQuote", '', $matches[3][$index]);
            $varValue = stripcslashes(trim($varValue, $trimQuote));
            if ($matches[2][$index] !== '.') {
                $vars[$varName] = $varValue;
            } else {
                $vars[$varName] .= $varValue;
            }
        }
        if ($remove) {
            $str = str_replace($matches[0], '', $str);
        }

        return $vars;
    }

    /**
     * Collects concated variable vars or str from str
     * @param string $str
     * @param string $trimQuote
     * @param array $vars
     * @param bool $remove
     *
     */
    public static function collectConcatedVars(&$str, string $trimQuote = '"', &$vars = [], $remove = false): array
    {
        if (!is_string($str)) {
            return $vars;
        }
        preg_match_all('~(\$\w+)\s?(\.)?=((?:\s?\.?\s?(?:[\'"][^"\']+[\'"]|\$\w{1,50}))+);~msi', $str, $matches, PREG_SET_ORDER);

        foreach ($matches as $match) {
            $varName = $match[1];
            $varValue = '';

            preg_match_all('~[\'"]([^"\']+)[\'"]|(\$\w{1,50})~msi', $match[3], $varsMatch, PREG_SET_ORDER);
            foreach ($varsMatch as $varMatch) {

                if ($varMatch[1] !== '') {
                    $varValue .= $varMatch[1];
                } else {
                    $varValue .= $vars[$varMatch[2]] ?? '';
                }

                $varValue = str_replace("$trimQuote.$trimQuote", '', $varValue);
                $varValue = stripcslashes(trim($varValue, $trimQuote));
            }

            if ($match[2] !== '.') {
                $vars[$varName] = $varValue;
            } else {
                $vars[$varName] .= $varValue;
            }

            if ($remove) {
                $str = str_replace($match[0], '', $str);
            }
        }

        return $vars;
    }

    /**
     * Collects simple or concated str
     * @param string $str
     * @param string $trimQuote
     *
     * @return string
     */
    public static function collectStr($str, string $trimQuote = '"') : string
    {
        preg_match('~["\'\w%=\.\+\/]+~msi', $str, $match);

        $str = str_replace("$trimQuote.$trimQuote", '', $match[0]);
        $str = trim($str, $trimQuote);

        return $str;
    }

    /**
     * Collects function wrapped vars with one arg from str
     * ex. var1 = base64_decode(str1); var2 = gzinflate(str2); and etc.
     *
     * @param string $str
     *
     * @return array
     */
    public static function collectFuncVars(string &$str, &$vars = [], $quotes = true, $delete = false): array
    {
        preg_match_all('~(\$\w+)\s*=\s*(\w+)\([\'"]([\w+/=]+)[\'"](?:,\s*[\'"]([\w+/=]*)[\'"],\s*[\'"]([\w+/=]+)[\'"])?\);~msi', $str, $matches, PREG_SET_ORDER);

        foreach ($matches as $match) {
            $func = $match[2];
            $param1 = $match[3];
            $param2 = $match[4];
            $param3 = $match[5];

            if (self::isSafeFunc($func)) {
                if ($func === 'str_replace') {
                    $ret = @$func($param1, $param2, $param3);
                } else {
                    $ret = @$func($param1);
                }
            }
            $vars[$match[1]] = self::isSafeFunc($ret) ? $ret : ($quotes ? "'$ret'" : $ret);

            if ($delete) {
                $str = str_replace($match[0], '', $str);
            }
        }

        return $vars;
    }

    /**
     * @param array  $vars
     * @param string $str
     *
     * @return string
     */
    public static function replaceVarsFromArray(array $vars, string $str, bool $isFunc = false, $toStr = false) : string
    {
        $result = $str;

        uksort($vars, static function($a, $b) {
            return strlen($b) <=> strlen($a);
        });
        foreach ($vars as $name => $value) {
            $sub_name = substr($name, 1);
            $result = preg_replace_callback('~{?(@)?\${?[\'"]?GLOBALS[\'"]?}?\[[\'"](\w+)[\'"]\]}?~msi',
                function ($m) use ($value, $sub_name) {
                    if ($m[2] !== $sub_name) {
                        return $m[0];
                    }
                    return $m[1] . $value;
                }, $result);

            if (!is_string($value)) {
                continue;
            }
            $result = str_replace(['{' . $name . '}', $name . '('], [$value, trim($value, '\'"') . '('],
                $result);

            if (!$isFunc && !$toStr) {
                $result = str_replace($name, $value, $result);
            } else if ($toStr) {
                $result = str_replace($name, "'$value'", $result);
            }

        }

        return $result;
    }

    /**
     * @param $str
     * @return array
     */
    public static function collectVarsChars($str)
    {
        $vars = [];
        preg_match_all('~(\$\w+)=\'(\w)\';~msi', $str, $matches, PREG_SET_ORDER);
        foreach ($matches as $m) {
            $vars[$m[1]] = $m[2];
        }
        return $vars;
    }

    /**
     * Removes duplicated string variables after replacing
     *
     * @param string $str
     *
     * @return string
     */
    public static function removeDuplicatedStrVars($str) : string
    {
        return preg_replace('~[\'"]?([^\'"]+)[\'"]?\s?=\s?[\'"]?\1[\'"]?;~msi','', $str);
    }

    /**
     * @param $chars
     * @param $str
     * @return array
     */
    public static function assembleStrings($chars, $str)
    {
        $vars = [];
        array_walk($chars, static function(&$x) {
            $x = "'$x'";
        });
        $parts = explode(';', $str);
        foreach ($parts as &$part) {
            $vals = explode('=', $part);
            $part = str_replace($vals[1], strtr($vals[1], $chars), $part);
        }
        $str = implode(';', $parts);
        $vars = self::collectVars($str, '\'');
        return $vars;
    }

    public static function replaceBase64Decode($str, $quote = '\'')
    {
        return preg_replace_callback(self::REGEXP_BASE64_DECODE, static function ($m) use ($quote) {
            return $quote . base64_decode($m[1]) . $quote;
        }, $str);
    }
    
    public static function replaceMinMaxRound($string, $max_iterations = 15)
    {
        $i = 0;
        $regexp_for_multi_min_max_round = '~(?:min|max|round)\(\s*\d+[\.\,\|\s\|+\|\-\|\*\|\/]([\d\s\.\,\+\-\*\/]+)?\)~msi';
        while (preg_match($regexp_for_multi_min_max_round, $string) && $i < $max_iterations) {
            $string = preg_replace_callback($regexp_for_multi_min_max_round, ['Helpers','calc'], $string);
            $i++;
        }
        
        $regexp_for_single_min_max_round = '~(?:min|max|round)\(\s*\d+\s*\)~msi';
        while (preg_match($regexp_for_single_min_max_round, $string) && $i < $max_iterations) {
            $string = preg_replace_callback($regexp_for_single_min_max_round, ['Helpers','calc'], $string);
            $i++;
        }
        
        $regexp_for_brackets = '~\(\s*\d+[\.\|\s\|+\|\-\|\*\|\/]([\d\s\.\+\-\*\/]+)?\)~msi';
        while (preg_match($regexp_for_brackets, $string) && $i < $max_iterations) {
            $string = preg_replace_callback($regexp_for_brackets, ['Helpers','calc'], $string);
            $i++;
        }
        
        return $string;
    }

    public static function xorWithKey($encrypted, $key)
    {
        $res = '';
        for ($i = 0, $iMax = strlen($encrypted); $i < $iMax; ) {
            for ($j = 0; $j < strlen($key) && $i < strlen($encrypted); $j++, $i++) {
                $res .= $encrypted[$i] ^ $key[$j];
            }
        }
        return $res;
    }

    public static function dictionarySampleDecode($string)
    {
        $str1 = substr($string, 0, 5);
        $str2 = substr($string, 7, -7);
        $str3 = substr($string, -5);
        return gzinflate(base64_decode($str1 . $str2 . $str3));
    }

    public static function unserialize(&$string)
    {
        $type = substr($string, 0, 2);
        $string = substr($string, 2);
        switch ($type) {
            case 'N;':
                return null;
            case 'b:':
                list($ret, $string) = explode(';', $string, 2);
                return (bool)(int)$ret;
            case 'i:':
                list($ret, $string) = explode(';', $string, 2);
                return (int)$ret;
            case 'd:':
                list($ret, $string) = explode(';', $string, 2);
                return (float)$ret;
            case 's:':
                list($length, $string) = explode(':', $string, 2);
                $length = (int) $length;
                if (($length > strlen($string) - 3) || ($string[0] !== '"') || (substr($string, $length + 1, 2) !== '";')) {
                    return '';
                }
                $ret = substr($string, 1, $length);
                $string = substr($string, $length + 3);
                return $ret;
            case 'a:':
                $ret = [];
                list($length, $string) = explode(':', $string, 2);
                if ($string[0] !== '{') {
                    return '';
                }
                $length = (int) $length;
                $string = substr($string, 1);
                for ($i= 0; $i < $length; $i++) {
                    $ret[self::unserialize($string)] = self::unserialize($string);
                }
                if ($string === '') {
                    return $ret;
                }
                $end = substr($string, 0, 2);
                if ($end !== '' && $end !== '};' && $end !== '}' && $end !== '}}') {
                    return '';
                }
                $string = substr($string, 2);
                return $ret;
            case 'O:':
                list($length, $string) = explode(':', $string, 2);
                $length = (int) $length;
                $string = substr($string, $length + 3);
                list($length, $string) = explode(':', $string, 2);
                $string = preg_replace('~{([^{}]*+(?:(?R)[^{}]*)*+)}~msi', '', $string);
                return '';
            default:
                return '';
        }
    }

    public static function deobfuscatorIO_string($string, $key)
    {
        $m = [];
        $n = 0;
        $p = '';
        $string = base64_decode($string);
        for ($i = 0, $iMax = strlen($string); $i < $iMax; $i++) {
            if ($string[$i] === "\xC3") {
                $inc = 64;
                continue;
            } else if ($string[$i] === "\xC2") {
                continue;
            }
            $p .= chr(ord($string[$i]) + $inc);
            $inc = 0;
        }
        $string = $p;
        $p = '';
        for ($i = 0; $i < 256; $i++) {
            $m[$i] = $i;
        }
        for ($i = 0; $i < 256; $i++) {
            $n = ($n + $m[$i] + ord($key[$i % strlen($key)])) % 256;
            $o = $m[$i];
            $m[$i] = $m[$n];
            $m[$n] = $o;
        }
        $r = 0;
        $n = 0;
        for ($i = 0, $iMax = strlen($string); $i < $iMax; $i++) {
            $r = ($r + 1) % 256;
            $n = ($n + $m[$r]) % 256;
            $o = $m[$r];
            $m[$r] = $m[$n];
            $m[$n] = $o;
            $p .= chr(ord($string[$i]) ^ $m[($m[$r] + $m[$n]) % 256]);
        }
        return $p;
    }

    public static function joomlaInjectDecoder($params, $op, $delta)
    {
        $params = explode(',', $params);
        $params = array_reverse($params);
        for ($i = 1, $iMax = count($params); $i < $iMax; $i++) {
            if ($i !== 0 ) {
                $params[$i] = substr($params[$i], 1, -1);
            }
            for ($j = 0, $jMax = strlen($params[$i]); $j < $jMax; $j++) {
                $tmp = ord($params[$i][$j]);
                if ($op === '-') {
                    $tmp = $tmp - $delta;

                } else if ($op === '+') {
                    $tmp = $tmp + $delta;
                }
                $params[$i][$j] = chr($tmp);
            }
            if ($i === 0) {
                break;
            }
            if (self::isSafeFunc($params[$i])) {
                $params[0] = $params[$i]($params[0]);
            }
            if ($i === $iMax - 1) {
                $i = -1;
            }
        }
        return $params[0];
    }

    public static function jsPackerUnbaser($int, $radix)
    {
        if ($int < $radix) {
            $ret = '';
        } else {
            $ret = self::jsPackerUnbaser((int)($int / $radix), $radix);
        }

        if (($int = $int % $radix) > 35) {
            $ret .= chr($int + 29);
        } else {
            $ret .= base_convert((string)$int, 10, 36);
        }
        return $ret;
    }

    public static function jsObjectDecodeIndexToString($int)
    {
        $ret = base_convert((string)$int, 10, 36);
        $ret = preg_replace_callback('~[0-9]~', function ($m) {
            return chr((int)$m[0] + 65);
        }, $ret);
        return $ret;
    }

    public static function jsObjectStringDecoder($r, $t, $encoded)
    {
        $ret = '';
        $i = 1;
        for ($f = 0, $fMax = strlen($encoded); $f < $fMax; $f++) {
            $o = strpos($r, $encoded[$f]);
            if (in_array($encoded[$f], $t)) {
                $i = 0;
            }
            if ($o !== false) {
                $ret .= chr($i * strlen($r) + $o);
                $i = 1;
            }
        }
        return $ret;
    }

    /**
     * Post processing after deobfuscation
     *
     * @param string $deobfuscated
     *
     * @return string
     */
    public static function postProcess($deobfuscated) : string
    {
        $deobfuscated = preg_replace_callback('~"[\w\\\\\s=;_<>&/\.-]+"~msi', static function ($matches) {
            return preg_match('~\\\\x[2-7][0-9a-f]|\\\\1[0-2][0-9]|\\\\[3-9][0-9]|\\\\0[0-4][0-9]|\\\\1[0-7][0-9]~msi', $matches[0]) ? stripcslashes($matches[0]) : $matches[0];
        }, $deobfuscated);

        $deobfuscated = preg_replace_callback('~echo\s*"((.*?[^\\\\])??((\\\\\\\\)+)?+)"~msi', static function ($matches) {
            return preg_match('~\\\\x[2-7][0-9a-f]|\\\\1[0-2][0-9]|\\\\[3-9][0-9]|\\\\0[0-4][0-9]|\\\\1[0-7][0-9]~msi', $matches[0]) ? stripcslashes($matches[0]) : $matches[0];
        }, $deobfuscated);

        preg_match_all('~(global\s*(\$[\w_]+);)\2\s*=\s*"[^"]+";~msi', $deobfuscated, $matches, PREG_SET_ORDER);
        foreach ($matches as $match) {
            $deobfuscated = str_replace($match[0], '', $deobfuscated);
            $deobfuscated = str_replace($match[1], '', $deobfuscated);
        }

        preg_match_all('~\$\{"GLOBALS"\}\[[\'"](\w+)[\'"]\]=["\'](\w+)[\'"];~msi', $deobfuscated, $matches, PREG_SET_ORDER);
        foreach ($matches as $match) {
            $deobfuscated = preg_replace_callback('~\$\{\$\{"GLOBALS"\}\[[\'"](\w+)[\'"]\]\}~msi', static function ($matches) use ($match) {
                if ($matches[1] !== $match[1]) {
                    return $matches[0];
                }
                return '$' . $match[2];
            }, $deobfuscated);
            $deobfuscated = str_replace($match[0], '', $deobfuscated);
        }

        if (strpos($deobfuscated, '${$') !== false) {
            preg_match_all('~\$\{(\$\w+)\}~msi', $deobfuscated, $matches);
            preg_match_all('~(\$\w+)\s*=\s*["\'](\w+)[\'"];~msi', $deobfuscated, $matches2);
            $replace_to = [];
            foreach ($matches[1] as $k => $match) {
                $index = array_search($match, $matches2[1]);
                if ($index !== false) {
                    $replace_to[] = '$' . $matches2[2][$index];
                } else {
                    unset($matches[0][$k]);
                }
            }
            if (!empty($replace_to)) {
                $deobfuscated = str_replace($matches[0], $replace_to, $deobfuscated);
            }
        }

        if (strpos($deobfuscated, 'chr(')) {
            $deobfuscated = preg_replace_callback('~chr\((\d+)\)~msi', static function ($matches) {
                return "'" . chr($matches[1]) . "'";
            }, $deobfuscated);
        }
        return $deobfuscated;
    }

    private static function block_decrypt($y, $z, $key)
    {
        $delta = 0x9e3779b9;
        $sum = 0xC6EF3720;
        $n = 32;

        for ($i = 0; $i < 32; $i++) {
            $z = self::_add($z, -(self::_add($y << 4 ^ self::_rshift($y, 5), $y)
                ^ self::_add($sum, $key[self::_rshift($sum, 11) & 3])));
            $sum = self::_add($sum, -$delta);
            $y = self::_add($y, -(self::_add($z << 4 ^ self::_rshift($z, 5), $z)
                ^ self::_add($sum, $key[$sum & 3])));

        }
        return [$y, $z];
    }

    private static function _rshift($integer, $n)
    {
        if (0xffffffff < $integer || -0xffffffff > $integer) {
            $integer = fmod($integer, 0xffffffff + 1);
        }

        if (0x7fffffff < $integer) {
            $integer -= 0xffffffff + 1.0;
        } else if (-0x80000000 > $integer) {
            $integer += 0xffffffff + 1.0;
        }

        if (0 > $integer) {
            $integer &= 0x7fffffff;
            $integer >>= $n;
            $integer |= 1 << (31 - $n);
        } else {
            $integer >>= $n;
        }
        return $integer;
    }

    private static function _add($i1, $i2)
    {
        $result = 0.0;

        foreach (func_get_args() as $value) {
            if (0.0 > $value) {
                $value -= 1.0 + 0xffffffff;
            }
            $result += $value;
        }

        if (0xffffffff < $result || -0xffffffff > $result) {
            $result = fmod($result, 0xffffffff + 1);
        }

        if (0x7fffffff < $result) {
            $result -= 0xffffffff + 1.0;
        } else if (-0x80000000 > $result) {
            $result += 0xffffffff + 1.0;
        }
        return $result;
    }

    private static function _str2long($data)
    {
        $tmp = unpack('N*', $data);
        $data_long = [];
        $j = 0;

        foreach ($tmp as $value) $data_long[$j++] = $value;
        return $data_long;
    }

    private static function _long2str($l){
        return pack('N', $l);
    }

    ///////////////////////////////////////////////////////////////////////////
}

class MathCalc {
    const ELEMENT_TYPE_OPERATION            = 'operation';
    const ELEMENT_TYPE_NUMBER               = 'number';
    const ELEMENT_TYPE_SIMPLE_PARENTHESES   = 'simple_parentheses';
    
    const ELEMENT       = 'element';
    const ELEMENT_TYPE  = 'type';
    
    const REGEXP_VALUE      = '[0-9]*\.[0-9]+|[1-9][0-9]*|0(?:x[\da-f]+|b[01]+|[0-7]+)|0';
    const REGEXP_OPERATION  = '\+|\-|/|\*\*|\*|%|&|\||\^|\~|<<|>>';
    const REGEXP_VALUE_SIGN = '\-|\+';
    
    private static $math_operations_order = [];
    
    public static function calcRawString($raw_string, $max_iterations = 10)
    {
        self::loadMathOperationsOrder();
        
        $iterations = 0;
        do {
            $old_string = $raw_string;
            $raw_string = self::calcRawStringOnePassWithParentheses($raw_string);
            $raw_string = FuncCalc::calcFuncInRawStringOnePassWithParentheses($raw_string);
            if ($raw_string == $old_string) {
                break;
            }
            $iterations++;
        } while($iterations < $max_iterations);

        $iterations = 0;
        do {
            $old_string = $raw_string;
            $raw_string = self::calcRawStringOnePassWithoutParentheses($raw_string);
            if ($raw_string == $old_string) {
                break;
            }
            $iterations++;
        } while($iterations < $max_iterations);
        
        return $raw_string;
    }
    
    public static function calcRawStringOnePassWithParentheses($raw_string)
    {
        self::loadMathOperationsOrder();
        $regexp_find_simple_math_operations = '('
                . '\s*(?:\(\s*[+-]?\s*(?:' . self::REGEXP_VALUE . ')\s*\))\s*'
                . '|'
                . '\s*(?:' . self::REGEXP_VALUE . ')\s*'
                . '|'
                . '\s*(?:' . self::REGEXP_OPERATION . ')\s*'
                . ')+';
        $regexp_find_math_operations_inside_brackets    = '\(' . $regexp_find_simple_math_operations . '\)';
        return preg_replace_callback('~' . $regexp_find_math_operations_inside_brackets . '~mis', function($matches) {
            $original = $matches[0];
            $math_string = substr($original, 1, strlen($original) - 2);
            if (self::haveOnlyValue($math_string) || self::haveOnlyOperation($math_string)) {
                return $original;
            }
            try {
                $result = self::calcSimpleMath($math_string);
            }
            catch (\Exception $e) {
                return $original;
            }
            return '(' . $result . ')';
        }, $raw_string);
    }
    
    public static function calcRawStringOnePassWithoutParentheses($raw_string)
    {
        self::loadMathOperationsOrder();
        $regexp_find_simple_math_operations = '(?:'
                . '\s*?(?:\(\s*[+-]?\s*(?:' . self::REGEXP_VALUE . ')\s*\))\s*?'
                . '|'
                . '\s*?(?:' . self::REGEXP_VALUE . ')\s*?'
                . '|'
                . '\s*?(?:' . self::REGEXP_OPERATION . ')\s*?'
                . ')+';
        return preg_replace_callback('~(\s*)(' . $regexp_find_simple_math_operations . ')(\s*)~mis', function($matches){
            $begin          = $matches[1];
            $math_string    = $matches[2];
            $end            = $matches[3];
            $original       = $begin . $math_string . $end;
            
            if (self::haveOnlyValueWithParentheses($math_string) || self::haveOnlyOperationWithParentheses($math_string)) {
                return $original;
            }
            if (self::haveOnlyValue($math_string)) {
                return $original;
            }
            if (self::haveOnlyOperation($math_string)) {
                return $original;
            }
            
            try {
                $result = self::calcSimpleMath($math_string);
            }
            catch (\Exception $e) {
                return $original;
            }
            
            return $begin . $result . $end;
        }, $raw_string);
    }
    
    ////////////////////////////////////////////////////////////////////////////
    
    private static function loadMathOperationsOrder()
    {
        if (!empty(self::$math_operations_order)) {
            return;
        }
        
        self::$math_operations_order = [
            [
                '**' => [
                    'elements' => [-1, +1],
                    'func' => function($a, $b) {
                        return $a ** $b;
                    },
                ],
            ],
            [
                '~' => [
                    'elements' => [+1],
                    'func' => function($a) {
                        return ~$a;
                    },
                ],
            ],
            [
                '*' => [
                    'elements' => [-1, +1],
                    'func' => function($a, $b) {
                        return $a * $b;
                    },
                ],
                '/' => [
                    'elements' => [-1, +1],
                    'func' => function($a, $b) {
                        if ($b == 0) {
                            throw new Exception('Division by zero');
                        }
                        return $a / $b;
                    },
                ],
                '%' => [
                    'elements' => [-1, +1],
                    'func' => function($a, $b) {
                        if ($b == 0) {
                            throw new Exception('Division by zero');
                        }
                        return $a % $b;
                    },
                ],
            ],
            [
                '+' => [
                    'elements' => [-1, +1],
                    'func' => function($a, $b) {
                        return $a + $b;
                    },
                ],
                '-' => [
                    'elements' => [-1, +1],
                    'func' => function($a, $b) {
                        return $a - $b;
                    },
                ],
            ],
            [
                '<<' => [
                    'elements' => [-1, +1],
                    'func' => function($a, $b) {
                        return $a << $b;
                    },
                ],
                '>>' => [
                    'elements' => [-1, +1],
                    'func' => function($a, $b) {
                        return $a >> $b;
                    },
                ],
            ],
            [
                '&' => [
                    'elements' => [-1, +1],
                    'func' => function($a, $b) {
                        return $a & $b;
                    },
                ],
            ],
            [
                '^' => [
                    'elements' => [-1, +1],
                    'func' => function($a, $b) {
                        return $a ^ $b;
                    },
                ],
            ],
            [
                '|' => [
                    'elements' => [-1, +1],
                    'func' => function($a, $b) {
                        return $a | $b;
                    },
                ],
            ],
        ];        
    }

    private static function haveOnlyValue($string)
    {
        return preg_match('~^\s*[+-]?\s*(?:' . self::REGEXP_VALUE . ')\s*$~mis', $string);
    }

    private static function haveOnlyOperation($string)
    {
        return preg_match('~^(\s*(?:' . self::REGEXP_OPERATION . ')\s*)+$~mis', $string);
    }
    
    private static function haveOnlyValueWithParentheses($string)
    {
        return preg_match('~^\s*(?:\(\s*[+-]?\s*(?:' . self::REGEXP_VALUE . ')\s*\))\s*$~mis', $string);
    }

    private static function haveOnlyOperationWithParentheses($string)
    {
        return preg_match('~^\s*(?:\(\s*(?:' . self::REGEXP_OPERATION . ')\s*\))\s*$~mis', $string);
    }
    
    private static function calcSimpleMath($string, $max_iterations = 30)
    {
        
        $input_string = $string;
        $input_string = str_replace(' ', '', $input_string);
        $input_string = str_replace(['+-', '-+'], '-', $input_string);
        $input_string = str_replace(['--', '++'], '+', $input_string);
        
        $regexp_find_simple_math_operations = '('
                . '(?<' . self::ELEMENT_TYPE_SIMPLE_PARENTHESES . '>\(\s*[+-]?\s*(?:' . self::REGEXP_VALUE . ')\s*\))\s*'
                . '|'
                . '(?<' . self::ELEMENT_TYPE_NUMBER . '>' . self::REGEXP_VALUE . ')'
                . '|'
                . '(?<' . self::ELEMENT_TYPE_OPERATION . '>' . self::REGEXP_OPERATION . ')'
                . ')';
        if (!preg_match_all('~'.$regexp_find_simple_math_operations.'~mis', $input_string, $matches)) {
            return $string;
        }
        
        $math_array = [];
        foreach ($matches[0] as $index => $element) {
            if ($element === $matches[self::ELEMENT_TYPE_OPERATION][$index]) {
                $type = self::ELEMENT_TYPE_OPERATION;
            }
            elseif ($element === $matches[self::ELEMENT_TYPE_NUMBER][$index]) {
                $type       = self::ELEMENT_TYPE_NUMBER;
                $k = $element;
                $element    = self::convertNum($element);
            }
            elseif ($element === $matches[self::ELEMENT_TYPE_SIMPLE_PARENTHESES][$index]) {
                $type = self::ELEMENT_TYPE_NUMBER;
                $element = self::convertNum(trim($element, '()'));
            }
            else {
                throw new Exception();
            }
            
            $math_array[] = [
                self::ELEMENT       => $element,
                self::ELEMENT_TYPE  => $type,
            ];
        }
        
        if ($math_array[0][self::ELEMENT_TYPE] == self::ELEMENT_TYPE_OPERATION 
            && $math_array[0][self::ELEMENT] == '-' 
            && $math_array[1][self::ELEMENT_TYPE] == self::ELEMENT_TYPE_NUMBER
        ) {
            unset($math_array[0]);
            $math_array[1][self::ELEMENT] *= -1;
            $math_array = array_values($math_array);
        }
        
        $changed = false;
        foreach (self::$math_operations_order as $level => $operations) {
            $iterations = 0;
            do {
                $interrupted = false;
                foreach ($math_array as $index => &$element) {
                    if ($element[self::ELEMENT_TYPE] != self::ELEMENT_TYPE_OPERATION) {
                        continue;
                    }
                    
                    if (!isset($operations[$element[self::ELEMENT]])) {
                        continue;
                    }
                    
                    $func_params    = $operations[$element[self::ELEMENT]];
                    $val1_offset    = $func_params['elements'][0];
                    $val2_offset    = isset($func_params['elements'][1]) ? $func_params['elements'][1] : null;
                    $val1_index     = $index + $val1_offset;
                    $val2_index     = $index + $val2_offset;
                    
                    if(!isset($math_array[$val1_index])) {
                        continue;
                    }
                    
                    $val1 = $math_array[$val1_index][self::ELEMENT];
                    
                    if (is_null($val2_offset)) {
                        try {
                            $result = $func_params['func']($val1);
                        }
                        catch (\Exception $e) {
                            continue;
                        }
                        $element[self::ELEMENT] = $result;
                    }
                    else {
                        if (!isset($math_array[$val2_index])) {
                            continue;
                        }
                        $val2 = $math_array[$val2_index][self::ELEMENT];
                        
                        try {
                            $result = $func_params['func']($val1, $val2);
                        }
                        catch (\Exception $e) {
                            throw new \Exception('');
                        }
                        $element[self::ELEMENT] = $result;
                    }
                    $element[self::ELEMENT_TYPE] = self::ELEMENT_TYPE_NUMBER;
                    
                    unset($math_array[$val1_index]);
                    if (!is_null($val2_offset)) {
                        unset($math_array[$val2_index]);
                    }
                    $changed        = true;
                    $interrupted    = true;
                    break;
                }
                unset($element);
                $math_array = array_values($math_array);
                $iterations++;
                if ($iterations >= $max_iterations) {
                    return $string;
                }
            } while ($interrupted);
        }

        if (!$changed) {
            return $string;
        }
        
        $return_value = '';
        foreach ($math_array as $element) {
            $return_value .= $element[self::ELEMENT];
        }
        return $return_value;
    }
    
    private static function convertNum(string $string) 
    {
        if(stripos($string, '0x') === 0) {
            return (float)hexdec($string);
        }
        elseif(stripos($string, '0b') === 0) {
            return (float)bindec($string);
        }
        elseif(stripos($string, '0.') === 0) {
            return (float)$string;
        }
        elseif ($string !== '0' && substr($string, 0, 1) == '0') {
            return (float)octdec($string);
        }
        return (float)$string;
    }
}


class FuncCalc {
    
    private static $functions = [];
    private static $functions_regexp = '';

    public static function calcFuncInRawStringOnePassWithParentheses($raw_string)
    {
        if (empty(self::$functions)) {
            self::loadFunctions();
        }
        
        $regexp_find_functions = '(?:'
                . '('.self::$functions_regexp.')'
                . '\s*\(([^)]+)\)'
                . ')+';
        
        return preg_replace_callback('~' . $regexp_find_functions . '~mis', function($matches) {
            $name   = $matches[1];
            $params = $matches[2];
            return self::calcFunction($name, $params);
        }, $raw_string);        
    }
    
    ////////////////////////////////////////////////////////////////////////////
    
    private static function calcFunction($name, $params) {
        $result             = "$name($params)";
        $name_lower         = strtolower($name);
        $function_otions    = isset(self::$functions[$name_lower]) ? self::$functions[$name_lower] : false;
        if (!$function_otions) {
            return $result;
        }
        
        $params_array = explode(',', $params);
        $params_array = array_map('trim', $params_array);
        
        try {
            return $function_otions['func'](...$params_array);
        } catch (Exception $ex) {
            return $result;
        }
    }

    private static function loadFunctions()
    {
        self::$functions = [
            'min' => [
                'func' => function(...$a) {
                    return min($a);
                },
            ],
            'max' => [
                'func' => function(...$a) {
                    return max($a);
                },
            ],
            'round' => [
                'func' => function($a, $b = 0) {
                    return round($a, $b);
                },
            ],
            'abs' => [
                'func' => function($a) {
                    return abs($a);
                },
            ],
        ];
        self::$functions_regexp = implode('|', array_keys(self::$functions));
    }
    
}
    



///////////////////////////////////////////////////////////////////////////

function parseArgs($argv)
{
    array_shift($argv);
    $o = [];
    foreach ($argv as $a) {
        if (substr($a, 0, 2) == '--') {
            $eq = strpos($a, '=');
            if ($eq !== false) {
                $o[substr($a, 2, $eq - 2)] = substr($a, $eq + 1);
            } else {
                $k = substr($a, 2);
                if (!isset($o[$k])) {
                    $o[$k] = true;
                }
            }
        } else {
            if (strpos($a, '-') === 0) {
                if (substr($a, 2, 1) === '=') {
                    $o[substr($a, 1, 1)] = substr($a, 3);
                } else {
                    foreach (str_split(substr($a, 1)) as $k) {
                        if (!isset($o[$k])) {
                            $o[$k] = true;
                        }
                    }
                }
            } else {
                $o[] = $a;
            }
        }
    }
    return $o;
}


////////////////////////////////////////////////////////////////////////////////////////////////////////
// cli handler
if (!defined('AIBOLIT_START_TIME') && !defined('PROCU_CLEAN_DB') && @strpos(__FILE__, @$argv[0])!==false) {
    set_time_limit(0);
    ini_set('max_execution_time', '900000');
    ini_set('realpath_cache_size', '16M');
    ini_set('realpath_cache_ttl', '1200');
    ini_set('pcre.backtrack_limit', '1000000');
    ini_set('pcre.recursion_limit', '12500');
    ini_set('pcre.jit', '1');
    $options = parseArgs($argv);
    $str = php_strip_whitespace($options[0]);
    $str2 = file_get_contents($options[0]);
    $l_UnicodeContent = Helpers::detect_utf_encoding($str);
    $l_UnicodeContent2 = Helpers::detect_utf_encoding($str2);
    if ($l_UnicodeContent !== false) {
        if (function_exists('iconv')) {
            $str = iconv($l_UnicodeContent, "UTF-8", $str);
            $str2 = iconv($l_UnicodeContent2, "UTF-8", $str2);
        }
    }
    $d = new Deobfuscator($str, $str2);
    $start = microtime(true);
    $deobf_type = $d->getObfuscateType($str);
    if ($deobf_type != '') {
        $str = $d->deobfuscate();
    }
    $code = $str;
    if (isset($options['prettyprint'])) {
        $code = Helpers::normalize($code);
        $code = Helpers::format($code);
    }
    if ($l_UnicodeContent !== false) {
        if (function_exists('iconv')) {
            $code = iconv('UTF-8', $l_UnicodeContent . '//IGNORE', $code);
        }
    }
    echo $code;
    echo "\n";
    //echo 'Execution time: ' . round(microtime(true) - $start, 4) . ' sec.';
}

class Deobfuscator
{
    private static $signatures = [
        [
            'full' => '~(\$\w+)=(\'[^\']+\');\s*eval\(gzinflate\(str_rot13\((\$_D)\(\1\)+;~msi',
            'id' => 'undefinedDFunc',
        ],
        [
            'full' => '~(\$[\w_]{1,50})\s*=\s*\[\s*base64_decode\s*\(\s*[\'"]([\w=]+)[\'"]\s*\)\s*,\s*([^;]{2,200})\]\s*;\s*(if\s*[^}]+}\s*else\s*{[^}]+}\s*function\s\w+[^}]+})~msi',
            'id' => 'base64Array',
        ],
        [
            'full' => '~for\((\$\w{1,40})=\d+,(\$\w+)=\'([^\$]+)\',(\$\w+)=\'\';@?ord\(\2\[\1\]\);\1\+\+\)\{if\(\1<\d+\)\{(\$\w+)\[\2\[\1\]\]=\1;\}else\{\$\w+\.\=@?chr\(\(\5\[\2\[\1\]\]<<\d+\)\+\(\5\[\2\[\+\+\1\]\]\)\);\}\}\s*.{0,500}eval\(\4\);(if\(isset\(\$_(GET|REQUEST|POST|COOKIE)\[[\'"][^\'"]+[\'"]\]\)\)\{[^}]+;\})?~msi',
            'fast' => '~for\((\$\w{1,40})=\d+,(\$\w+)=\'([^\$]+)\',(\$\w+)=\'\';@?ord\(\2\[\1\]\);\1\+\+\)\{if\(\1<\d+\)\{(\$\w+)\[\2\[\1\]\]=\1;\}else\{\$\w+\.\=@?chr\(\(\5\[\2\[\1\]\]<<\d+\)\+\(\5\[\2\[\+\+\1\]\]\)\);\}\}\s*.{0,500}eval\(\4\);~msi',
            'id'   => 'parenthesesString',
        ],
        [
            'full' => '~\$codelock_rfiled=dirname\(__FILE__\);(?:\s*\$codelock_fixpath=\'\';)?\s*if\s*\(\$codelock_file\s*==\s*\'\'\)\s*\{\s*echo\s*"[^"]+";\s*die\(\);\s*\}\s*else\s*\{\}\s*\$codelock_lock="([^"]+)";\s*eval\((gzinflate\()?base64_decode\(\$codelock_lock\)\)\)?;\s*return;\s*\?>\s*([\w\+\/=\$\)\(]+)~msi',
            'id' => 'codeLockDecoder',
        ],
        [
            'full' => '~error_reporting\(0\);\s*set_time_limit\(0\);\s*session_start\(\);\s*\$\w+\s*=\s*"[^"]+";(\s*function\s*(\w+)\((\$\w+)\)\{\s*@?((?:\w+\()+)\3(\)+);\s*}\s*(\$\w+)="([^"]+)";\s*\2\(\6\);)~msi',
            'id' => 'agustus1945',
        ],
        [
            'full' => '~(?:\$\w+\s*=\s*"[^"]*"(?:\.\$\w+)?;\s*)+(\$\w+)=(?:\$\w+\.?)+;\s*eval\(str_rot13\(gzinflate\(str_rot13\(base64_decode\(\(\1\)\)\)\)\)\);~msi',
            'id' => 'R4C',
        ],
        [
            'full' => '~(?:\$[^;\s]+\s*=\s*\d;\s*[^;\s]+:\s*if\s*\([^\)]+\)+\s*\{\s*goto\s*[^;\s]+;\s*\}\s*\$[^;\s]+[^:]+:\s*[^;]+;\s*)?goto [^;\s]+;\s*([^;\s]+:\s*([^;\s]+:\s*)?.*?goto\s*[^;\s]+;\s*(}\s*goto\s*[^;\s]+;)?(goto\s*[^;\s]+;)?\s*)+[^;\s]+:\s*[^;>]+;(\s*goto\s*[^;\s]+;\s*[^;\s]+:\s*[^;\s]+:\s*|(?:\s*die;\s*}\s*)?\s*goto\s*[^;\s]+;\s*[^;\s]+:\s*\}?)?(?:(?:.*?goto\s*\w{1,50};)?(?:\s*\w{1,50}:\s?)+)?~msi',
            'fast' => '~goto [^;\s]+;\s*([^;\s]+:\s*([^;\s]+:\s*)?.*?goto\s*[^;\s]+;\s*(}\s*goto\s*[^;\s]+;)?(goto\s*[^;\s]+;)?\s*)+[^;\s]+:\s*[^;]+(?:;|\?>)~msi',
            'id' => 'goto',
        ],
        [
            'full' => '~\$\w+\s=\sfile_get_contents\(base64_decode\(["\'][^"\']+["\']\)\s\.\sbase64_decode\(["\'][^"\']+[\'"]\)\s\.\s\$\w+\s\.\s["\'][^\'"]+["\']\s\.\s\$_SERVER\[["\'][^\'"]+[\'"]\]\s\.\s["\'][^"\']+["\']\s\.\s\$_SERVER\[["\'][^"\']+["\']\]\);.*?\s\$\w+\s=\sbase64_decode\(["\'][^"\']+["\']\);\s.*?\s@unlink\(\$_SERVER\[["\'][^"\']+["\']\]\);~msi',
            'id' => 'gotoBase64Decode',
        ],
        [
            'full' => '~(?:\$\w{1,50}\s?=\s?(?:str_rot13\(\$\w{1,50}\)|[\'"][^"\']+[\'"]|base64_decode\("(?:{\$\w{1,50}})+"\));\s*)+(\$\w{1,50})\s?=\s?base64_decode\("((?:{\$\w{1,50}})+)"\);\s?eval\(\1\);~msi',
            'id' => 'gotoStrRot13Vars',
        ],
        [
            'full' => '~(\$\{"GLOBALS"\}\["\w+"\])\s*=\s*"\w+";\s*(?:\$\{"GLOBALS"\}\["(\w+)"\]\s*=\s*"\w+";\s*)+.*?;\s*\$\{\1\}\s*=\s*[\"\'][^;]+[\"\'];\s*exec\(\$\w+\);\s*echo\s*"[^"]+";\s*\}\s*\}~msi',
            'id' => 'gotoShell',
        ],
        [
            'full' => '~(?:\$\w+\s*=\s*\'[^\']++\';\s*)*eval\(base64_decode\(substr\("(?:[^"]++)",(?:\d+),(?:-?\d+)\)\.base64_decode\(strrev\("[^"]++"(?:\.(?:substr\("(?:[^"]++)",(?:\d++),(?:-?\d++)\)|"(?:[^"]+)"))++\)\)\)\);(?:\$\w+\s*=\s*\'[^\']++\';\s*)*~msi',
            'id'   => 'substrEmpty',
        ],
        [
            'full' => '~function\s{0,50}(\w+)\((\$\w+)\)\s{0,50}\{\s{0,50}\2\s{0,50}=\s{0,50}substr\(\2,\s{0,50}\(int\)\s{0,50}\(?hex2bin\(([\'"])([0-9a-f]+)\3\)\)\)?;\s{0,50}\2\s{0,50}=\s{0,50}substr\(\2,\s{0,50}\(int\)\s{0,50}\(?hex2bin\(([\'"])([0-9a-f]+)\5\)\)?,\s{0,50}\(int\)\s{0,50}\(?hex2bin\(([\'"])([0-9a-f]+)\7\)\)\)?;\s{0,50}return\s{0,50}\2;\s{0,50}\}\s{0,50}(\$\w+)\s{0,50}=\s{0,50}([\'"])[^\'"]+\10;\s{0,50}(\$\w+)\s{0,50}=\s{0,50}[\'"]base64_decode[\'"];\s{0,50}function\s{0,50}\w+\((\$\w+)\)\s{0,50}{\s{0,50}global\s{0,50}\9;\s{0,50}global\s{0,50}\11;\s{0,50}return\s{0,50}strrev\(gzinflate\(\11\(\1\(\12\)\)\)\);\s{0,50}\}\s{0,50}(?:(?:eval\()+\w+\(([\'"]))?([^\'"]+)\13\)+;~msi',
            'id'   => 'Obf_20200522_1',
        ],
        [
            'full' => '~(\$auth_pass\s*=\s*"[^"]+";\s*(?:/\*[^\*]+\*/\s*)?)\$__="";((?:\$__=\$__\."[^"]+";\s*)+)\$\w+=\$__;function\s*(\w+)\((\$\w+),\s*(\$\w+)\)\{\s*for\((\$\w+)=0;\6<strlen\(\4\);\)\s*for\((\$\w+)=0;\7<strlen\(\5\);\7\+\+,\s*\6\+\+\)\s*(\$\w+)\s*\.=\s*\4\{\6\}\s*\^\s*\5\{\7\};\s*return\s*\8;\s*\};(\$\w+)=base64_decode\(\9\);\$__=\3\(\9,"([^"]+)"\);\$_=create_function\("",\$__\);\$_\(\);~msi',
            'id' => 'b64xoredkey',
        ],
        [
            'full' => '~(eval\(gzinflate\(base64_decode\("([^"]+)"\)\)\);\s*)((?:eval\((?:\$\w+\()+"[^"]+"\)+;\s*)+)~msi',
            'id' => 'linesCond',
        ],
        [
            'full' => '~(\$\w+)\s*=\s*\'[\'.error_reporting]+;\s*\1\(0\);((?:\s*\$\w+\s*=\s*[\'abcdefgilnorstz64_.]+;)+)((?:\s*\$\w+\s*=\s*\'[^;]+\';)+)((?:\s*\$\w+\()+)(\$\w+)[\s\)]+;\s*die\(\);~mis',
            'id'   => 'blackScorpShell',
        ],
        [
            'full' => '~(?(DEFINE)(?\'c\'(?:/\*\w+\*/)*))(\$\w+)\s*=\s*basename(?&c)\((?&c)trim(?&c)\((?&c)preg_replace(?&c)\((?&c)rawurldecode(?&c)\((?&c)"[%0-9A-F\.]+"(?&c)\)(?&c),\s*\'\',\s*__FILE__(?&c)\)(?&c)\)(?&c)\)(?&c);(\$\w+)\s*=\s*"([%\w\.\-\~]+)";(?:(\$\w+)=[^;]+;\5(?&c)\((?&c)\'\',\s*\'};\'\s*\.\s*(?&c)\()?(?:eval(?&c)\()?(?&c)rawurldecode(?&c)\((?&c)\3(?&c)\)(?&c)\s*\^\s*substr(?&c)\((?&c)str_repeat(?&c)\((?&c)\2,\s*(?&c)\((?&c)strlen(?&c)\((?&c)\3(?&c)\)(?&c)/strlen(?&c)\((?&c)\2(?&c)\)(?&c)\)(?&c)\s*\+\s*1(?&c)\)(?&c),\s*0,(?&c)\s*strlen(?&c)\((?&c)\3(?&c)\)(?&c)\)(?&c)\)(?:(?&c)\s*\.\s*\'{\'(?&c)\))?(?&c);~msi',
            'id'   => 'xorFName',
        ],
        [
            'full' => '~(\$\w{1,40})=base64_decode\(\'[^\']+\'\);(\$\w+)=base64_decode\(\'[^\']+\'\);(\$\w+)=base64_decode\(\'([^\']+)\'\);eval\(\1\(gzuncompress\(\2\(\3\)\)\)\);~msi',
            'id'   => 'phpMess',
        ],
        [
            'full' => '~(\$\w{1,40})\s*=\s*\"([^\"]+)\";\s*\$\w+\s*=\s*\$\w+\(\1,\"[^\"]+\",\"[^\"]+\"\);\s*\$\w+\(\"[^\"]+\",\"[^\"]+\",\"\.\"\);~msi',
            'id'   => 'pregReplaceSample05',
        ],
        [
            'full' => '~(\$\w{1,40})\s*=\s*\w+\(\'.+?\'\);\s*(\$\w+)\s*=\s*\w+\(\'.+?\'\);\s*(\$\w+)\s*=\s*\"([^\"]+)\";\s*(\$\w+)\s*=\s*.+?;\s*\2\(\5,\"[^\']+\'\3\'[^\"]+\",\"\.\"\);~msi',
            'id'   => 'pregReplaceB64',
        ],
        [
            'full' => '~preg_replace\([\'"]/\(\.\*\)/e[\'"],[\'"]([^\'"]+)[\'"],\s?NULL\);~msi',
            'id'   => 'pregReplaceStr',
        ],
        [
            'full' => '~(\$\w{1,40})\s*=\s*\'([^\']+)\';\s*\1\s*=\s*gzinflate\s*\(base64_decode\s*\(\1\)\);\s*\1\s*=\s*str_replace\s*\(\"__FILE__\",\"\'\$\w+\'\",\1\);\s*eval\s*\(\1\);~msi',
            'id'   => 'GBE',
        ],
        [
            'full' => '~(\$GLOBALS\[\s*[\'"]_+\w{1,60}[\'"]\s*\])\s*=\s*\s*array\s*\(\s*base64_decode\s*\(.+?((.+?\1\[\d+\]).+?)+[^;]+;(\s*include\(\$_\d+\);)?}?((.+?_+\d+\(\d+\))+[^;]+;)?(.*?(\$[a-z]+).+\8_\d+;)?(echo\s*\$\w+;})?}?(?:unset.*?[^}]+})?~msi',
            'fast' => '~\$GLOBALS\[\s*[\'"]_+\w{1,60}[\'"]\s*\]\s*=\s*\s*array\s*\(\s*base64_decode\s*\(~msi',
            'id'   => 'Bitrix',
        ],
        [
            'full' => '~\$\w{1,40}\s*=\s*(__FILE__|__LINE__);\s*\$\w{1,40}\s*=\s*(\d+);\s*eval(\s*\()+\$?\w+\s*\([\'"][^\'"]+[\'"](\s*\))+;\s*return\s*;\s*\?>(.+)~msi',
            'id'   => 'B64inHTML',
        ],
        [
            'full' => '~<\?php\s+(?:/[*/].*?)?(?:\$[O0]*=__FILE__;\s*)?(\$[O0]*)=urldecode\(\'([%a-f0-9]+)\'\);(\$(GLOBALS\[\')?[O0]*(\'\])?=(\d+);)?(.*?)(\$(GLOBALS\[\')?[O0]*(\'\])?\.?=(\$(GLOBALS\[\')?[O0]*(\'\])?([{\[]\d+[}\]])?\.?)+;)+([^\?]+)\?\>[\s\w\~=/+\\\\^{`%|@[}]+~msi',
            'fast' => '~(\$[O0]*)=urldecode\(\'([%a-f0-9]+)\'\);(\$(GLOBALS\[\')?[O0]*(\'\])?=(\d+);)?(.*?)(\$(GLOBALS\[\')?[O0]*(\'\])?\.?=(\$(GLOBALS\[\')?[O0]*(\'\])?([{\[]\d+[}\]])?\.?)+;)+([^\?]+)\?\>[\s\w\~=/+\\\\^{`%|@[}]+~msi',
            'id'   => 'LockIt',
        ],
        [
            'full' => '~(\$\w{1,40})\s*=\s*\"(\\\\142|\\\\x62)[0-9a-fx\\\\]+";\s*@?eval\s*\(\1\s*\([^\)]+\)+\s*;~msi',
            'fast' => '~(\$\w{1,40})\s*=\s*\"(\\\\142|\\\\x62)[0-9a-fx\\\\]+";\s*@?eval\s*\(\1\s*\(~msi',
            'id'   => 'FOPO',
        ],
        [
            'full' => '~\$_F=__FILE__;\$_X=\'([^\']+\');eval\([^\)]+\)+;~msi',
            'fast' => '~\$_F=__FILE__;\$_X=\'([^\']+\');eval\(~ms',
            'id'   => 'ByteRun',
        ],
        [
            'full' => '~(\$\w{1,40}=\'[^\']+\';\s*)+(\$[\w{1,40}]+)=(urldecode|base64_decode){0,1}\(?[\'"]([\w+%=-]+)[\'"]\)?;((\$\w+)=[^;]+;)+[^\(]+\(\'Content-Type.*?;\${"[^"]+"}\["[\\\\x0-9a-f]+"\]\(\);~msi',
            'id'   => 'Urldecode',
        ],
        [
            'full' => '~(\$[\w{1,40}]+)\s?=\s?(urldecode|base64_decode)\(?[\'"]([\w+%=\-/\\\\\*]+)[\'"]\);(\s*\$\w+\.?\s?=\s?((?:\$\w+\s*\.\s*)?\$\w+[{\[]\d+[}\]]\s*[\.;]?\s*)+)+((\$\w+=["\']([^\'"]+)[\'"];\s*eval\(\'\?>\'\.[\$\w\(\)\*\d,\s]+);|(eval\(\s*\$\w+\([\'"]([^\'"]+)[\'"][)\s]+;)|header\(\'[^\']+\'\);(?:\$\w+=\${[^}]+}\[[^\]]+\]\(\'.*?\'?;}?\'\);)+\${[^}]+}\[[^\]]+\]\(\);)~msi',
            'id'   => 'UrlDecode2',
        ],
        [
            'full' => '~(?:\$\w{1,40}\s?=\s?[\'"]?[\d\w]+[\'"]?;\s*)*()(?|(?:(\$\w{1,40})=[\'"]([^\'"]+)[\'"];\s*)+(?:global\s*\$\w+;\s*)?(\$[\w{1,40}]+)=urldecode\(\2\);|(\$\w{1,40})=urldecode\([\'"]([^\'"]+)[\'"]\);function\s*\w+\([^{]+\{global\s*(\$\w+);)\s*.+?\4(?:.{1,1000}\4[{\[]\d+[}\]]\.?)+?.*?(?:function\s*(\w+)\(\$\w+\s*=\s*\'\'\)\{global\s*\4;@.+\5\(\);|function\s*\w+\(\$\w+,\s*\$\w+,\s*\$\w+\)\s*\{\$\w+\s*[^)]+\)[^}]+;\}|header\((?:\4[\[\{]\d+[\]\}]\.?)+\);})~msi',
            'id'   => 'UrlDecode3',
        ],
        [
            'full' => '~(?:@?session_start\(\);)?(?:@?(?:set_time_limit|error_reporting)\(\d+\);){1,2}(?:ini_set\(base64_decode\([\'"][^\'"]+[\'"]\)|@\$\w{1,50}=\$_POST\[base64_decode\([\'"][^\'"]+[\'"]\)\];|if\((?:\w{1,50}\(\)\){foreach\(\$_POST\s{0,50}as\s{0,50}\$\w{1,50}=>\$\w{1,50}\)|\$_GET|!empty\(\$_SERVER\[))(?:.*?base64_decode\([\'"][^\'"]+[\'"]\)+\.?){1,200}\]?(?:\)\)|;})?(?:;return\s?\$\w{1,50};})?;?~msi',
            'id' => 'manyBase64DecodeContent',
        ],
        [
            'full' => '~echo\s{0,50}base64_decode\(\'[^\']+\'\);\s{0,50}echo\s{0,50}base64_decode\(\'[^\']+\'\)\.php_uname\(\)\.base64_decode\(\'[^\']+\'\);.*?else\s{0,50}{\s{0,50}echo\s{0,50}base64_decode\(\'[^\']+\'\);\s{0,50}}}}~msi',
            'id' => 'manyBase64DecodeContent',
        ],
        [
            'full' => '~{(\$\w{1,100})\s?=(?:\s?base64_decode\(\'[^\']+\'\)\.?)+;(\$\w{1,100})\s?=\s?\1\(base64_decode\(\'[^\']+\'\),(?:\s?base64_decode\(\'[^\']+\'\)\.?)+\);\2\(base64_decode\(\'([^\']+)\'\)\);exit;}~msi',
            'id' => 'manyBase64DecodeContent',
        ],
        [
            'full' => '~eval\(base64_decode\(\'[^\']+\'\)\.file_get_contents\(base64_decode\(\'[^\']+\'\)\)\);~msi',
            'id' => 'manyBase64DecodeContent',
        ],
        [
            'full' => '~\$\w{1,50}\s?=\s?\$\w{1,50}->get\(base64_decode\([\'"][^\'"]+[\'"]\)(?:.*?base64_decode\([\'"][^\'"]+[\'"]\)){1,200}\)\s?\)\s?{~msi',
            'id' => 'manyBase64DecodeContent',
        ],
        [
            'full' => '~explode\(\"\*\*\*\",\s*\$\w+\);\s*eval\(eval\(\"return strrev\(base64_decode\([^\)]+\)+;~msi',
            'fast' => '~explode\(\"\*\*\*\",\s*\$\w+\);\s*eval\(eval\(\"return strrev\(base64_decode\(~msi',
            'id'   => 'cobra',
        ],
        [
            'full' => '~\$[O0]+=\(base64_decode\(strtr\(fread\(\$[O0]+,(\d+)\),\'([^\']+)\',\'([^\']+)\'\)\)\);eval\([^\)]+\)+;~msi',
            'fast' => '~\$[O0]+=\(base64_decode\(strtr\(fread\(\$[O0]+,(\d+)\),\'([^\']+)\',\'([^\']+)\'\)\)\);eval\(~msi',
            'id'   => 'strtrFread',
        ],
        [
            'full' => '~if\s*\(\!extension_loaded\(\'IonCube_loader\'\)\).+pack\(\"H\*\",\s*\$__ln\(\"/\[A-Z,\\\\r,\\\\n\]/\",\s*\"\",\s*substr\(\$__lp,\s*([0-9a-fx]+\-[0-9a-fx]+)\)\)\)[^\?]+\?\>\s*[0-9a-z\r\n]+~msi',
            'fast' => '~IonCube_loader~ms',
            'id'   => 'FakeIonCube',
        ],
        [
            'full' => '~(\$\w{1,40})="([\w\]\[\<\&\*\_+=/]{300,})";\$\w+=\$\w+\(\1,"([\w\]\[\<\&\*\_+=/]+)","([\w\]\[\<\&\*\_+=/]+)"\);~msi',
            'id'   => 'strtrBase64',
        ],
        [
            'full' => '~\$\w+\s*=\s*array\((\'[^\']+\',?)+\);\s*.+?(\$_\w{1,40}\[\w+\])\s*=\s*explode\(\'([^\']+)\',\s*\'([^\']+)\'\);.+?(\2\[[a-fx\d]+\])\(\);(.+?\2)+.+}~msi',
            'fast' => '~(\$_\w{1,40}\[\w+\])\s*=\s*explode\(\'([^\']+)\',\s*\'([^\']+)\'\);.+?(\1\[[a-fx\d]+\])\(\);~msi',
            'id'   => 'explodeSubst',
        ],
        [
            'full' => '~(\$[\w{1,40}]+)\s*=\s*\'([\w+%=\-\#\\\\\'\*]+)\';(\$[\w+]+)\s*=\s*Array\(\);(\3\[\]\s*=\s*(\1\[\d+\]\.?)+;+)+(.+\3)[^}]+}~msi',
            'fast' => '~(\$[\w{1,40}]+)\s*=\s*\'([\w+%=\-\#\\\\\'\*]+)\';(\$[\w+]+)\s*=\s*Array\(\);(\3\[\]\s*=\s*(\1\[\d+\]\.?)+;+)+~msi',
            'id'   => 'subst',
        ],
        [
            'full' => '~if\s{0,50}\(!(?:function_exists|\$\W{1,50})\(\"([\w\W]{1,50})\"\)\)\s{0,50}{\s{0,50}function \1\(.+?eval\(\1\(\"([^\"]+)\"\)\);~msi',
            'fast' => '~if\s{0,50}\(!(?:function_exists|\$\W{1,50})\(\"([\w\W]{1,50})\"\)\)\s{0,50}{\s{0,50}function \1\(.+?eval\(\1\(\"[^\"]+\"\)\);~msi',
            'id'   => 'decoder',
        ],
        [
            'full' => '~(\$\w{1,40})\s*=\s*\"riny\(\"\.(\$\w+)\(\"base64_decode\"\);\s*(\$\w+)\s*=\s*\2\(\1\.\'\("([^"]+)"\)\);\'\);\s*\$\w+\(\3\);~msi',
            'id'   => 'GBZ',
        ],
        [
            'full' => '~\$\w+\s*=\s*\d+;\s*\$GLOBALS\[\'[^\']+\'\]\s*=\s*Array\(\);\s*global\s*\$\w+;(\$\w{1,40})\s*=\s*\$GLOBALS;\$\{"\\\\x[a-z0-9\\\\]+"\}\[(\'\w+\')\]\s*=\s*\"(([^\"\\\\]|\\\\.)*)\";\1\[(\1\[\2\]\[\d+\].?).+?exit\(\);\}+~msi',
            'fast' => '~(\$\w{1,40})\s*=\s*\$GLOBALS;\$\{"\\\\x[a-z0-9\\\\]+"\}\[(\'\w+\')\]\s*=\s*\"(([^\"\\\\]|\\\\.)*)\";\1\[(\1\[\2\]\[\d+\].?)~msi',
            'id'   => 'globalsArray',
        ],
        [
            'full' => '~(\${(["\w\\\\]+)}\[["\w\\\\]+\]=["\w\\\\]+;)+((\${\${(["\w\\\\]+)}\[["\w\\\\]+\]}).?=((urldecode\(["%\w]+\);)|(\${\${["\w\\\\]+}\[["\w\\\\]+\]}{\d+}.?)+;))+eval\(\${\${["\w\\\\]+}\[["\w\\\\]+\]}\(["\w+=]+\)\);~msi',
            'id'   => 'xbrangwolf',
        ],
        [
            'full' => '~(\$\w{1,40})\s*=\s*\'(\\\\.|[^\']){0,100}\';\s*\$\w+\s*=\s*\'(\\\\.|[^\']){0,100}\'\^\1;[^)]+\)+;\s*\$\w+\(\);~msi',
            'fast' => '~(\$\w{1,40})\s*=\s*\'(\\\\.|[^\']){0,100}\';\s*\$\w+\s*=\s*\'(\\\\.|[^\']){0,100}\'\^\1;~msi',
            'id'   => 'xoredVar',
        ],
        [
            'full' => '~(?:(?:\$\w+=\'[^\']+\';\s*)+(?:\$\w+=\'[^\']+\'\^\'[^\']+\';\s*)+.{0,50})?\$\w{1,40}=\'[^\']{0,100}(?:\'\^\')?[^\']*\';(?:\$\w{1,40}=\w{1,3};)?(?:\$\w{1,40}=\'[^\']+(?:\'\^\')?[^\']*\';)+\w{1,40};(?:.{0,6000}?)if\(\$\w{1,40}==\$\w{1,40}\(\$\w{1,40}\)\){(?:.{0,6000}?)(\$\w+)=\$\w+\(\$\w+,\$\w+\);\1\(\'[^\']+\',\'[^\']+\'\);}.{0,300}\$\w{1,40}\(\'[^\']{0,100}\',\'[^\']{0,100}\'\)(?:.{0,300}\s*;\s*\'[^\']+\';){0,2}~msi',
            'fast' => '~\$\w{1,40}=\'[^\']{0,100}(?:\'\^\')[^\']*\';(?:\$\w{1,40}=\'[^\']+(?:\'\^\')?[^\']*\';)+~msi',
            'id'   => 'xoredVar',
        ],
        [
            'full' => '~(\$\w+)=fopen\(__FILE__,\'r\'\);(\$\w+)=fread\(\1,filesize\(__FILE__\)\);fclose\(\1\);(\$\w+)=explode\(hex2bin\(\'([^\']+)\'\),\2\)\[(\d)\];(\$\w+)=\[\];for\((\$\w+)=0;\7<strlen\(\3\);\7\+\+\)\6\[\]=ord\(\3\[\7\]\)\s*xor\s*\7;eval\(hex2bin\(base64_decode\(implode\(array_map\(hex2bin\(\'([^\']+)\'\),\6\)\)\)\)\);__halt_compiler\(\);\w+~msi',
            'id' => 'D5',
        ],
        [
            'full' => '~(\$\w{1,40})\s*=\s*\'([^\']*)\';\s*(\$\w{1,40})\s*=\s*explode\s*\((chr\s*\(\s*\(\d+\-\d+\)\)),substr\s*\(\1,\s*\((\d+\-\d+)\),\s*\(\s*(\d+\-\d+)\)\)\);\s*(\$\w{1,40})\s*=\s*\3\[\d+\]\s*\(\3\[\s*\(\d+\-\d+\)\]\);\s*(\$\w{1,40})\s*=\s*\3\[\d+\]\s*\(\3\[\s*\(\d+\-\d+\)\]\);\s*if\s*\(!function_exists\s*\(\'([^\']*)\'\)\)\s*\{\s*function\s*\9\s*\(.+\1\s*=\s*\$\w+[+\-\*]\d+;~msi',
            'fast' => '~(\$\w{1,40})\s=\s\'([^\']*)\';\s(\$\w{1,40})=explode\((chr\(\(\d+\-\d+\)\)),substr\(\1,\((\d+\-\d+)\),\((\d+\-\d+)\)\)\);\s(\$\w{1,40})\s=\s\3\[\d+\]\(\3\[\(\d+\-\d+\)\]\);\s(\$\w{1,40})\s=\s\3\[\d+\]\(\3\[\(\d+\-\d+\)\]\);\sif\s\(!function_exists\(\'([^\']*)\'\)\)\s\{\sfunction\s*\9\(~msi',
            'id'   => 'arrayOffsets',
        ],
        [
            'full' => '~(\$\w+)\s?=\s?[\'"](.*?)[\'"];\s?(\$\w+)\s?=\s?explode\(chr\(+(\d+\s?[-+]\s?\d+)\)+,\s?[\'"]((?:\d+,?)+)[\'"]\);\s?(\$\w+)\s?=\s?substr\(\1,\s?\(+(\d+\s?[-+]\s?\d+)\),\s?\(+(\d+\s?[-+]\s?\d+)\)\);\s?if\s?\(!function_exists\([\'"](\w+)[\'"]\)\)\s?{\s?function\s?\9\((\$\w+),\s?(\$\w+)\)\s?{\s?(\$\w+)\s?=\s?NULL;\s?for\s?\((\$\w+)\s?=\s0;\s?\13\s?<\s?\(sizeof\(\10\)\s?/\s?(\d+)\);\s?\13\+\+\)\s?{\s?\12\s?\.=\s?substr\(\11,\s?\10\[\(\13\s?\*\s?(\d+)\)\],\s?\10\[\(\13\s?\*\s?(\d+)\)\s?\+\s?(\d+)\]\);\s?}\s?return\s?\12;\s?}\s;\s?}\s?(\$\w+)\s?=\s?[\'"](.*?eval\(str_replace\(chr\(\(+(\d+\s?[-+]\s?\d+)\)\),\s?chr\(\(+(\d+\s?[-+]\s?\d+)\)\),\s?\9\(\3,\1\)\)\);.*?)[\'"];\s?(\$\w+)\s?=\s?substr\(\1,\s?\(+(\d+\s?[-+]\s?\d+)\),\s?\(+(\d+\s?[-+]\s?\d+)\)\);\s?\22\(\6,\s?\18,\s?NULL\);\s?\22\s?=\s?\18;\s?\22\s?=\s?\(+(\d+\s?[-+]\s?\d+)\);\s?\$\w+\s?=\s?\$\w+\s?\-\s?\d+;~msi',
            'fast' => '~(\$\w+)\s?=\s?[\'"](.*?)[\'"];\s?(\$\w+)\s?=\s?explode\(chr\(+(\d+\s?[-+]\s?\d+)\)+,\s?[\'"]((?:\d+,?)+)[\'"]\);\s?(\$\w+)\s?=\s?substr\(\1,\s?\(+(\d+\s?[-+]\s?\d+)\),\s?\(+(\d+\s?[-+]\s?\d+)\)\);\s?if\s?\(!function_exists\([\'"](\w+)[\'"]\)\)\s?{\s?function\s?\9\((\$\w+),\s?(\$\w+)\)\s?{\s?(\$\w+)\s?=\s?NULL;\s?for\s?\((\$\w+)\s?=\s0;\s?\13\s?<\s?\(sizeof\(\10\)\s?/\s?(\d+)\);\s?\13\+\+\)\s?{\s?\12\s?\.=\s?substr\(\11,\s?\10\[\(\13\s?\*\s?(\d+)\)\],\s?\10\[\(\13\s?\*\s?(\d+)\)\s?\+\s?(\d+)\]\);\s?}\s?return\s?\12;\s?}\s;\s?}\s?(\$\w+)\s?=\s?[\'"]([^\'"]+)[\'"];\s?(\$\w+)\s?=\s?substr\(\1,\s?\(+(\d+\s?[-+]\s?\d+)\),\s?\(+(\d+\s?[-+]\s?\d+)\)\);\s?\20\(\6,\s?\18,\s?NULL\);\s?\20\s?=\s?\18;\s?\20\s?=\s?\(+(\d+\s?[-+]\s?\d+)\);\s?\$\w+\s?=\s?\$\w+\s?\-\s?\d+;~msi',
            'id'   => 'arrayOffsetsEval',
        ],
        [
            'full' => '~(\$\w{1,50}\s*=\s*array\((\'\d+\',?)+\);)+\$\w{1,40}=\"([^\"]+)\";if\s*\(!function_exists\(\"\w{1,50}\"\)\)\s*\{\s*function\s*[^\}]+\}\s*return\s*\$\w+;\}[^}]+}~msi',
            'fast' => '~(\$\w{1,50}=\s*array\((\'\d+\',?)+\);)+\$\w{1,40}=\"[^\"]+\";if\s*\(!function_exists\(\"\w{1,50}\"\)\)\{\s*function ~msi',
            'id'   => 'obfB64',
        ],
        [
            'full' => '~if\(\!function_exists\(\'findsysfolder\'\)\){function findsysfolder\(\$fld\).+\$REXISTHEDOG4FBI=\'([^\']+)\';\$\w+=\'[^\']+\';\s*eval\(\w+\(\'([^\']+)\',\$REXISTHEDOG4FBI\)\);~msi',
            'fast' => '~if\(!function_exists\(\'findsysfolder\'\)\){function findsysfolder\(\$fld\)\{\$fld1=dirname\(\$fld\);\$fld=\$fld1\.\'/scopbin\';clearstatcache\(\);if\(!is_dir\(\$fld\)\)return findsysfolder\(\$fld1\);else return \$fld;\}\}require_once\(findsysfolder\(__FILE__\)\.\'/911006\.php\'\);~msi',
            'id'   => 'sourceCop',
        ],
        [
            'full' => '~function\s*(\w{1,40})\s*\(\s*(\$\w{1,40})\s*,\s*(\$\w{1,40})\s*\)\s*\{\s*(\$\w{1,40})\s*=\s*str_rot13\s*\(\s*gzinflate\s*\(\s*str_rot13\s*\(\s*base64_decode\s*\(\s*[\'"][^\'"]*[\'"]\s*\)\s*\)\s*\)\s*\)\s*;\s*(if\s*\(\s*\$\w+\s*==[\'"][^\'"]*[\'"]\s*\)\s*\{\s*(\$\w{1,40})\s*=(\$\w+[\{\[]\d+[\}\]]\.?)+;return\s*(\$\w+)\(\3\);\s*\}\s*else\s*)+\s*if\s*\(\s*\$\w+\s*==[\'"][^\'"]*[\'"]\s*\)\s*\{\s*return\s*eval\(\3\);\s*\}\s*\};\s*(\$\w{1,40})\s*=\s*[\'"][^\'"]*[\'"];(\s*\9\([\'"][^\'"]*[\'"],)+\s*[\'"][^\'"]*[\'"]\s*\)+;~msi',
            'id'   => 'webshellObf',

        ],
        [
            'full' => '~(\$\w{1,40})=\'([^\'\\\\]|.*?)\';\s*((\$\w{1,40})=(\1\[\d+].?)+;\s*)+(\$\w{1,40})=\'\';\s*(\$\w{1,40})\(\6,\$\w{1,40}\.\"([^\"]+)\"\.\$\w{1,40}\.\4\);~msi',
            'fast' => '~(\$\w{1,40})=\'([^\\\\\']|.*?)\';\s*((\$\w{1,40})=(\1\[\d+].?)+;\s*)+(\$\w{1,40})=\'\';~msi',
            'id'   => 'substCreateFunc',
        ],
        [
            'full' => '~@error_reporting\(0\);\s*@ini_set\(\'error_log\',NULL\);\s*@ini_set\(\'log_errors\',0\);\s*@ini_set\(\'display_errors\',\s*0\);\s*@(\$\w+)="[create_function"\.]+;\s*(\$\w+)=\1\("([^"]+)","[eval\."]+\(\'\?>\'\.[base64_decode"\.]+\(\3\)\);"\);\s*\2\("([^"]+)"\);exit;~msi',
            'id'   => 'Obf_20200507_2',
        ],
        [
            'full' => '~\$\w+=([create_function"\'.]+);\s?\$\w+=\$\w+\([\'"]\\\\?\$\w+[\'"],((?:[\'"][eval]{0,4}[\'"]\.?)+)\.([\'"](\([\'"]\?>[\'"]\.)\w+[\'"]\.[^)\\\\]+)\\\\?\$\w+\)+;[\'"]\);\s?\$\w+\([\'"]([\w\+=\\\\\'"%/]+)[\'"]\);~msi',
            'id'   => 'createFunc',
        ],
        [
            'full' => '~(?(DEFINE)(?\'foreach\'(?:/\*\w+\*/)?\s*foreach\(\[[\d,]+\]\s*as\s*\$\w+\)\s*\{\s*\$\w+\s*\.=\s*\$\w+\[\$\w+\];\s*\}\s*(?:/\*\w+\*/)?\s*))(\$\w+)\s*=\s*"([^"]+)";\s*\$\w+\s*=\s*"";(?P>foreach)if\(isset\(\$_REQUEST\s*(?:/\*\w+\*/)?\["\$\w+"\]\)+\{\s*\$\w+\s*=\s*\$_REQUEST\s*(?:/\*\w+\*/)?\["\$\w+"\];(?:\s*\$\w+\s*=\s*"";\s*)+(?P>foreach)+\$\w+\s*=\s*\$\w+\([create_function\'\.]+\);\s*\$\w+\s*=\s*\$\w+\("",\s*\$\w+\(\$\w+\)\);\s*\$\w+\(\);\s*(?:exit\(\);)?\s*}~msi',
            'fast' => '~(?(DEFINE)(?\'foreach\'(?:/\*\w+\*/)?\s*foreach\(\[[\d,]+\]\s*as\s*\$\w+\)\s*\{\s*\$\w+\s*\.=\s*\$\w+\[\$\w+\];\s*\}\s*(?:/\*\w+\*/)?\s*))(\$\w+)\s*=\s*"([^"]+)";\s*\$\w+\s*=\s*"";(?P>foreach)if\(isset\(\$_REQUEST\s*(?:/\*\w+\*/)?\["\$\w+"\]\)+\{\s*\$\w+\s*=\s*\$_REQUEST\s*(?:/\*\w+\*/)?\["\$\w+"\];(?:\s*\$\w+\s*=\s*"";\s*)+(?P>foreach)+\$\w+\s*=\s*\$\w+\([create_function\'\.]+\);\s*\$\w+\s*=\s*\$\w+\("",\s*\$\w+\(\$\w+\)\);\s*\$\w+\(\);~msi',
            'id'   => 'forEach',
        ],
        [
            'full' => '~\$\w+\s*=\s*base64_decode\s*\([\'"][^\'"]+[\'"]\);\s*if\s*\(!function_exists\s*\("rotencode"\)\).{0,1000}eval\s*\(\$\w+\s*\(base64_decode\s*\([\'"][^"\']+[\'"]\)+;~msi',
            'id'   => 'PHPMyLicense',
        ],
        [
            'full' => '~(\$\w{1,40})\s*=\s*file\(__FILE__\);\s*if\(!function_exists\(\"([^\"]*)\"\)\)\{function\s*\2\((\$\w{1,40}),(\$\w{1,40})=\d+\)\{(\$\w{1,40})=implode\(\"[^\"]*\",\3\);(\$\w{1,40})=array\((\d+),(\d+),(\d+)\);if\(\4==0\)\s*(\$\w{1,40})=substr\(\5,\6\[\d+\],\6\[\d+\]\);elseif\(\4==1\)\s*\10=substr\(\5,\6\[\d+\]\+\6\[\d+\],\6\[\d+\]\);else\s*\10=trim\(substr\(\5,\6\[\d+\]\+\6\[\d+\]\+\6\[\d+\]\)\);return\s*\(\10\);\}\}\s*eval\(base64_decode\(\2\(\1\)\)\);\s*eval\(\w{1,40}\(\2\(\1\s*,\s*2\)\s*,\s*\2\(\1\s*,\s*1\)\)\);\s*__halt_compiler\(\);\s*[\w\+\=/]+~msi',
            'fast' => '~(\$\w{1,40})\s*=\s*file\(__FILE__\);\s*if\(!function_exists\(\"([^\"]*)\"\)\)\{function\s*\2\((\$\w{1,40}),(\$\w{1,40})=\d+\)\{(\$\w{1,40})=implode\(\"[^\"]*\",\3\);(\$\w{1,40})=array\((\d+),(\d+),(\d+)\);if\(\4==0\)\s*(\$\w{1,40})=substr\(\5,\6\[\d+\],\6\[\d+\]\);elseif\(\4==1\)\s*\10=substr\(\5,\6\[\d+\]\+\6\[\d+\],\6\[\d+\]\);else\s*\10=trim\(substr\(\5,\6\[\d+\]\+\6\[\d+\]\+\6\[\d+\]\)\);return\s*\(\10\);\}\}\s*eval\(base64_decode\(\2\(\1\)\)\);\s*eval\(\w{1,40}\(\2\(\1\s*,\s*2\)\s*,\s*\2\(\1\s*,\s*1\)\)\);\s*__halt_compiler\(\);~msi',
            'id'   => 'zeura',
        ],
        [
            'full' => '~<\?php\s*(\$\w{1,40})\s*=\s*file\(__FILE__\);\s*function\s(\w{1,50})\((\$\w{1,50}),(\$\w{1,50})\){(\$\w{1,50})=array\(\d+,\d+,\d+,(\d+)\);if\(\4==\d+\){(\$\w{1,50})=substr\(\3,\5\[0\]\+\5\[1\],\5\[2\]\);}elseif\(\4==\d+\){\7=substr\(\3,\5\[0\],\5\[1\]\);}elseif\(\4==\d+\){\7=trim\(substr\(\3,\5\[0\]\+\5\[1\]\+\5\[2\]\)\);}return\7;}eval\(base64_decode\(\2\(\1\[0\],\d+\)\)\);eval\(\w{1,50}\(\2\(\1\[0\],\d+\),\2\(\1\[0\],41\),\1\)\);__halt_compiler\(\);[\w+=/]+~msi',
            'fast' => '~<\?php\s*(\$\w{1,40})\s*=\s*file\(__FILE__\);\s*function\s(\w{1,50})\((\$\w{1,50}),(\$\w{1,50})\){(\$\w{1,50})=array\(\d+,\d+,\d+,(\d+)\);if\(\4==\d+\){(\$\w{1,50})=substr\(\3,\5\[0\]\+\5\[1\],\5\[2\]\);}elseif\(\4==\d+\){\7=substr\(\3,\5\[0\],\5\[1\]\);}elseif\(\4==\d+\){\7=trim\(substr\(\3,\5\[0\]\+\5\[1\]\+\5\[2\]\)\);}return\7;}eval\(base64_decode\(\2\(\1\[0\],\d+\)\)\);eval\(\w{1,50}\(\2\(\1\[0\],\d+\),\2\(\1\[0\],41\),\1\)\);__halt_compiler\(\);~msi',
            'id'   => 'zeuraFourArgs',
        ],
        [
            'full' => '~(<\?php\s*/\* This file is protected by copyright law and provided under.*?\*/(?:\s*/\*.*?\*/\s*)+\$_[0O]+="(\w+)";.*?\$_[0O]+=__FILE__;.*?\$\w+=str_replace\("\\\\n","",\$\w+\);\$\w+=str_replace\("\\\\r","",\$\w+\);.*?function\s\w+\(\$\w+,\$\w+\){\$\w+=md5\(\$\w+\)\.md5\(\$\w+\.\$\w+\);.*?\$\w+=strlen\(\$\w+\);for\(\$\w+=0;\$\w+<strlen\(\$\w+\);\$\w+\+\+\){\$\w+\.=\s?chr\(ord\(\$\w+\[\$\w+\]\)\^ord\(\$\w+\[\$\w+%\$\w+\]\)\);}return\s\$\w+;}eval\(\w+\(\w+\("([^"]+)"\),\$\w+\)\);eval\(\w+\(\$\w+\)\);exit\(\);\?)>[^"\']+~msi',
            'id'   => 'evalFileContentBySize',
        ],
        [
            'full' => '~<\?php\s*(eval(?:\(\w+)+\((substr\(file_get_contents\(__FILE__\),\s?(\d+)\))\)+;)\s*__halt_compiler\(\);\s*[\w+/]+~msi',
            'id' => 'evalFileContentOffset',
        ],
        [
            'full' => '~(\$\w+)\s*=\s*base64_decode\(((?:(?|[\'"][\w=]+[\'"]|chr\(\d+\))\.?)+)\);(\$\w+)\s*=\s*base64_decode\(((?:(?|[\'"][\w=]+[\'"]|chr\(\d+\))\.?)+)\);(\$\w+)\s*=\s*base64_decode\(((?:(?|[\'"][\w=]+[\'"]|chr\(\d+\))\.)[^;]+)\);(\1\((\(-(\d+)-\(-\9\)\))\);@set_time_limit\((\(-(\d+)-\(-\11\)\))\);)eval\(base64_decode\(((?:(?|[\'"]\d+[\'"]|chr\(\d+\))\.?)+)\)\.gzinflate\(str_rot13\(\3\(\5\){4};~msi',
            'fast' => '~@set_time_limit\((\(-(\d+)-\(-\2\)\))\);eval\(base64_decode\(((?:(?|[\'"]\d+[\'"]|chr\(\d+\))\.?)+)\)\.gzinflate\(str_rot13\(\$\w+\(\$\w+\){4};~msi',
            'id'   => 'evalConcatedVars',
        ],
        [
            'full' => '~(\$\{"[\\\\x47c2153fGLOBALS]+"\}\["[\w\\\\]+"\]="[\w\\\\]+";(\$\w+="\w+";)?){5,}.+\$\{"[\\\\x47c2153fGLOBALS]+"\}\["[\w\\\\]+"\].+?}+(?:exit;}+if\(@?file_exists\("[^"]+"\)+{include\("[^"]+"\);\}|==\(string\)\$\{\$\w+\}\)\s*\{\$\w+="[^"]+";\$\w+="[^"]+";\$\{\$\w+\}\.=\$\{\$\w+\};break;\}+eval\("[^"]+"\.gzinflate\(base64_decode\(\$\{\$\{"[^"]+"\}\["[^"]+"\]\}\)+;)?~msi',
            'id'   => 'Obf_20200618_1',
        ],
        [
            'full' => '~(\$\w+\s?=\s?(\w+)\(\'\d+\'\);\s*)+\$\w+\s?=\s?new\s?\$\w+\(\2\(\'(\d+)\'\)+;\s?error_reporting\(0\);\s?eval\(\$\w+\(\$\w+->\$\w+\("([^"]+)"\)+;.+?function \2.+?return\s\$\w+;\s}~msi',
            'id'   => 'aanKFM',
        ],
        [
            'full' => '~error_reporting\(\d\);@?set_time_limit\(\d\);(\$\w{1,50})\s?=\s?[\'"]([^\'"]+)[\'"];(\$\w{1,50})\s?=\s?[\'"]([^\'"]+)[\'"];(\$\w{1,50})\s?=\s?[\'"]([^\'"]{0,100})[\'"];(\$\w{1,50}\s?=\s?[\'"][^\'"]{0,500}[\'"];)eval\(gzinflate\(base64_decode\(\3\)\)\);rebirth\(\);eval\(gzinflate\(base64_decode\(hate\(\1,\5\){4};~msi',
            'fast' => '~error_reporting\(\d\);@?set_time_limit\(\d\);(\$\w{1,50})\s?=\s?[\'"]([^\'"]+)[\'"];(\$\w{1,50})\s?=\s?[\'"]([^\'"]+)[\'"];(\$\w{1,50})\s?=\s?[\'"]([^\'"]{0,100})[\'"];(\$\w{1,50}\s?=\s?[\'"][^\'"]{0,500}[\'"];)eval\(gzinflate\(base64_decode\(\$\w{1,50}\)\)\);rebirth\(\);eval\(gzinflate\(base64_decode\(hate\(\$\w{1,50},\$\w{1,50}\){4};~msi',
            'id' => 'evalLoveHateFuncs',
        ],
        [
            'full' => '~function\s?(\w+)\(\){\s?(\$\w+)\s?=\s?[\'"]([^\'"]+)[\'"];\s?\2\s?=\s?str_rot13\(\2\);\s?(\w+)\(\2\);\s?}\s?function\s?\4\((\$\w+)\){\s?(?:global\s?\$\w+;\s?)?\5\s?=\s?pack\([\'"]H\*[\'"],\5\);\s?(\$\w+)\s?=\s?[\'"]{2};\s?eval\(((?:\6|\5)\.?)+\);\s?}\s?\1\(\);~msi',
            'id'   => 'evalPackStrrot',
        ],
        [
            'full' => '~error_reporting\(\d\);(?:\$\w+=[\'"]\w+[\'"];)?ini_set\([\'"]\w+[\'"],\d\);eval\(base64_decode\([\'"]([\w\+=]+)[\'"]\)\);\$\w+=str_split\([\'"]([}\w|,[=\'\.;\]&]+)[\'"]\);\$\w+=[\'"]{2};foreach\(\$\w+\s{0,50}as\s{0,50}\$\w+\){foreach\((\$\w+)\s{0,50}as\s{0,50}\$\w+\s{0,50}=>\s{0,50}\$\w+\){(?:\$\w+=[\'"]\w+[\'"];\$\w+=[\'"]\w+[\'"];)?if\(\$\w+\s{0,50}==\s{0,50}\(string\)\$\w+\){(?:\$\w+=[\'"]\w+[\'"];\$\w+=[\'"]\w+[\'"];)?\$\w+\s{0,50}\.=\s{0,50}\$\w+;break;}}}eval\([\'"]\?>[\'"]\.gzinflate\(base64_decode\(\$\w+\)\)\);~msi',
            'id'   => 'evalArrayVar',
        ],
        [
            'full' => '~((\$\w+)\s*\.?=\s*"[^"]+";\s*)+eval\((\$\w+\s*\.?\s*)+\)~msi',
            'id'   => 'evalVarConcat',
        ],
        [
            'full' => '~(?:\${"[^"]+"}\["[^"]+"\]="[^"]+";)+(?:\${\${"[^"]+"}\["[^"]+"\]}="[^"]+";)+(eval\(htmlspecialchars_decode\(urldecode\(base64_decode\(\${\${"[^"]+"}\["[^"]+"\]}\)\)\)\);)~msi',
            'id' => 'evalVarSpecific',
        ],
        [
            'full' => '~(?:(?:\$\w+=(?:chr\(\d+\)[;.])+)+\$\w+="[^"]+";(\$\w+)=(?:\$\w+[.;])+\s*)?(\$\w+)=\'([^\']+)\';((?:\s*\2=str_replace\(\'[^\']+\',\s*\'\w\',\s*\2\);\s*)+)(?(1)\s*\1\s*=\s*str_replace\(\'[^+]\',\s*\'[^\']+\',\s*\1\);\s*(\$\w+)\s*=\s*[^;]+;";\s*@?\1\(\s*str_replace\((?:\s*array\(\'[^\']+\',\s*\'[^\']+\'\),){2}\s*\5\)\s*\);|\s*\2=base64_decode\(\2\);\s*eval\(\2\);)~msi',
            'id'   => 'evalVarReplace',
        ],
        [
            'full' => '~((\$[^\s=.;]+)\s*=\s*\(?[\'"]([^\'"]+)[\'"]\)?\s*;?\s*)+\s*.{0,10}?(?:error_reporting\(\d\);|@set_time_limit\(\d\);|@|ini_set\([\'"]\w{1,99}[\'"],\s?\d\);\s?){0,5}(?:eval\s*\(|assert\s*\(|echo)\s*([\'"?>.\s]+)?\(?(base64_decode\s*\(|gzinflate\s*\(|strrev\s*\(|str_rot13\s*\(|gzuncompress\s*\(|urldecode\s*\(|rawurldecode\s*\(|htmlspecialchars_decode\s*\(|convert_uudecode\s*\()+(\({0,1}[\s"\']?(\$[^\s=\'")]+)?(?:str_replace\((?:.+?,){3}\2?)?[\s"\']?\){0,1})(?:[\'"]?\)+;)+~msi',
            'id'   => 'evalVar',
        ],
        [
            'full' => '~((?:(?:\$\w+=[\'"]\\\\[^\'"]+)[\'"];)+)@(eval\((?:"\?>"\.)?(?:\$\w+\()+[\'"]([^\'"]+)[\'"]\)+;)~msi',
            'id'   => 'evalVarSlashed',
        ],
        [
            'full' => '~function\s*(\w{1,40})\((\$\w{1,40})\)\{(\$\w{1,40})=\'base64_decode\';(\$\w{1,40})=\'gzinflate\';return\s*\4\(\3\(\2\)\);\}\$\w{1,40}=\'[^\']*\';\$\w{1,40}=\'[^\']*\';eval\(\1\(\'([^\']*)\'\)\);~msi',
            'id'   => 'evalFunc',
        ],
        [
            'full' => '~function\s*(\w{1,40})\s*\((\$\w{1,40})\)\s*\{\s*(\$\w{1,40})\s*=\s*"\\\\x62\\\\x61\\\\x73\\\\x65\\\\x36\\\\x34\\\\x5f\\\\x64\\\\x65\\\\x63\\\\x6f\\\\x64\\\\x65";\s*(\$\w{1,40})\s*=\s*"\\\\x67\\\\x7a\\\\x69\\\\x6e\\\\x66\\\\x6c\\\\x61\\\\x74\\\\x65";\s*return\s*\4\s*\(\3\s*\(\2\)\);\s*\}\s*\$\w{1,40}\s*=\s*\"[^\"]*\";\s*\$\w{1,40}\s*=\s*\"[^\"]*\";\s*eval\s*\(\1\s*\(\"([^\"]*)\"\)\);~msi',
            'id'   => 'evalFunc',
        ],
        [
            'full' => '~(\$\w+)\s?=\s?[\'"]@?(([\w."]+\()+[\'"]([\w\/+]+)[\'"])\)+;[\'"]\s?;\s?(\$\w+)\s?=\s?([\w@."]+)\s?;\s?@?(\$\w+)\s?=\s\5\([\'"]+,\s?"\1;"\s?\);\7\([\'"]{2}\);~msi',
            'id'   => 'evalConcatFunc',
        ],
        [
            'full' => '~function\sT_\((\$\w+)\)\s{\s(\$\w+)\s=\s256;\s(\$w2)\s=\s8;\s(\$\w+)\s=\sarray\(\);\s(\$\w+)\s=\s0;\s(\$\w+)\s=\s0;\sfor\s\((\$\w+)\s=\s0;\s\7\s<\sstrlen\(\1\);\s\7\+\+\)\s{\s\5\s=\s\(\5\s<<\s8\)\s\+\sord\(\1\[\7\]\);\s\6\s\+=\s8;\sif\s\(\6\s>=\s\3\)\s{\s\6\s-=\s\3;\s(\$\w+)\[\]\s=\s\5\s>>\s\6;\s\5\s&=\s\(1\s<<\s\6\)\s-\s1;\s\2\+\+;\sif\s\(\2\s>>\s\3\)\s{\s\3\+\+;\s}\s}\s}\s(\$\w+)\s=\srange\("\\\\x0",\s"\\\\377"\);\s(\$\w+)\s=\s\'\';\sforeach\s\(\4\sas\s\7\s=>\s(\$\w+)\)\s{\sif\s\(!isset\(\9\[\11\]\)\)\s{\s(\$\w+)\s=\s(\$\w+)\s\.\s\13\[0\];\s}\selse\s{\s\12\s=\s\9\[\11\];\s}\s\10\s\.=\s\12;\sif\s\(\7\)\s{\s\9\[\]\s=\s\13\s\.\s\12\[0\];\s}\s\13\s=\s\12;\s}\sreturn\s\10;\s}\s(\$_\w+)="[\w\\\\]+";eval\(T_\(\14\("(.*)"\)\)\);~mis',
            'fast' => '~function\sT_\((\$\w+)\)\s{\s(\$\w+)\s=\s256;\s(\$w2)\s=\s8;\s(\$\w+)\s=\sarray\(\);\s(\$\w+)\s=\s0;\s(\$\w+)\s=\s0;\sfor\s\((\$\w+)\s=\s0;\s\7\s<\sstrlen\(\1\);\s\7\+\+\)\s{\s\5\s=\s\(\5\s<<\s8\)\s\+\sord\(\1\[\7\]\);\s\6\s\+=\s8;\sif\s\(\6\s>=\s\3\)\s{\s\6\s-=\s\3;\s(\$\w+)\[\]\s=\s\5\s>>\s\6;\s\5\s&=\s\(1\s<<\s\6\)\s-\s1;\s\2\+\+;\sif\s\(\2\s>>\s\3\)\s{\s\3\+\+;\s}\s}\s}\s(\$\w+)\s=\srange\("\\\\x0",\s"\\\\377"\);\s(\$\w+)\s=\s\'\';\sforeach\s\(\4\sas\s\7\s=>\s(\$\w+)\)\s{\sif\s\(!isset\(\9\[\11\]\)\)\s{\s(\$\w+)\s=\s(\$\w+)\s\.\s\13\[0\];\s}\selse\s{\s\12\s=\s\9\[\11\];\s}\s\10\s\.=\s\12;\sif\s\(\7\)\s{\s\9\[\]\s=\s\13\s\.\s\12\[0\];\s}\s\13\s=\s\12;\s}\sreturn\s\10;\s}\s(\$_\w+)="[\w\\\\]+";eval\(T_\(\14\("(.*)"\)\)\);~mis',
            'id'   => 'evalFuncFunc',
        ],
        [
            'full' => '~(\$\w+)\s?=\s?[\'"]([^\'"]+)[\'"];\s?(\$\w+)\s?=\s?[\'"]([^\'"]+)[\'"];\s?(\$\w+)\s?=\s?[\'"]([^\'"]+)[\'"];\s?(\$\w+)\s?=\s?bin2hex\(\5\);\s?(\$\w+)\s?=\s?hex2bin\(\7\);\s*(?:eval\()+[\'"]\?>[\'"]\.\1\(\3\(\8\)+;~msi',
            'id'   => 'evalBinHexVar',
        ],
        [
            'full' => '~((?:(?:\${"(?:\w{0,10}?\\\\x\w{1,10}){1,100}"}\["\w{0,10}?(?:\\\\x\w{1,10}){1,100}"\]|\$\w+)\s*=\s*[\'"][^\'"]+["\'];)+.*?define.*?)(?:\${)?\$\w{1,50}}?\s*=\s*array\(array\(([\'"][^\)]+[\'"])\)\);(.*?create_function\(.*?array_walk\((?:\${\${"(?:\\\\x\w{1,10}){1,10}"}\["(?:\\\\x\w{1,10}){1,10}"\]}|(?:\${)?\$\w+}?),\s*(?:\${\${"\w?(?:\\\\x\w{1,10}){1,10}"}\["(?:\w?\\\\x\w{1,10}){1,20}"\]}|\$\w+)\);)~msi',
            'fast' => '~create_function\([\'"][^"\']+[\'"],\s*(?:[\'"][^"\']+[\'"]\.?)+.*?\);\s*\$[^=]+=\s*array_walk\((?:\${\${"(?:\\\\x\w{1,10}){1,10}"}\["(?:\\\\x\w{1,10}){1,10}"\]}|(?:\${)?\$\w+}?),\s*(?:\${\${"\w?(?:\\\\x\w{1,10}){1,10}"}\["(?:\w?\\\\x\w{1,10}){1,20}"\]}|\$\w+)\);~msi',
            'id' => 'evalArrayWalkFunc'
        ],
        [
            'full' => '~(\$\w+)\s?=\s?[\'"]([^\'"]+)[\'"];\s*eval\([\'"]\?>[\'"]\s?\.\s?base64_decode\(strtr\(substr\(\1\s?,(\d+)\*(\d+)\)\s?,\s?substr\(\1\s?,(\d+)\s?,\s?(\d+)\)\s?,\s*substr\(\s?\1\s?,\s?(\d+)\s?,\s?(\d+)(?:\s?\))+;~msi',
            'id' => 'evalSubstrVal'
        ],
        [
            'full' => '~(\$\w{1,50})=[\'"]([^\'"]+)[\'"];\s?\1\s?=\s?base64_decode\(\1\);\s?eval\(gzinflate\(str_rot13\(\1\)+;~msi',
            'id' => 'evalGzStrRotB64',
        ],
        [
            'full' => '~(preg_replace\(["\'](?:/\.\*?/[^"\']+|[\\\\x0-9a-f]+)["\']\s*,\s*)[^\),]+(?:[\)\\\\0-5]+;[\'"])?(,\s*["\'][^"\']*["\'])\)+;~msi',
            'id'   => 'eval',
        ],
        [
            'full' => '~(\$\w{1,40})\s*=\s*[\'"]([^\'"]*)[\'"]\s*;\s*(\$\w{1,40}\s*=\s*(strtolower|strtoupper)\s*\((\s*\1[\[\{]\s*\d+\s*[\]\}]\s*\.?\s*)+\);\s*)+\s*if\s*\(\s*isset\s*\(\s*\$\{\s*\$\w{1,40}\s*\}\s*\[\s*[\'"][^\'"]*[\'"]\s*\]\s*\)\s*\)\s*\{\s*eval\s*\(\s*\$\w{1,40}\s*\(\s*\$\s*\{\s*\$\w{1,40}\s*\}\s*\[\s*[\'"][^\'"]*[\'"]\s*\]\s*\)\s*\)\s*;\s*\}\s*~msi',
            'id'   => 'evalInject',

        ],
        [
            'full' => '~((\$\w+)\s*=\s*(([base64_decode\'\.\s]+)|([eval\'\.\s]+)|([create_function\'\.\s]+)|([stripslashes\'\.\s]+)|([gzinflate\'\.\s]+)|([strrev\'\.\s]+)|([str_rot13\'\.\s]+)|([gzuncompress\'\.\s]+)|([urldecode\'\.\s]+)([rawurldecode\'\.\s]+));\s*)+\$\w+\s*=\s*\$\w+\(\'\',(\s*\$\w+\s*\(\s*)+\'[^\']+\'\)+;\s*\$\w+\(\);~msi',
            'fast' => '~\$\w+\s*=\s*\$\w+\(\'\',(\s*\$\w+\s*\(\s*)+\'[^\']+\'\)+;\s*\$\w+\(\);~msi',
            'id'   => 'createFuncConcat',

        ],
        [
            'full' => '~(\$\w+)\s*=\s*base64_decode\("([^"]+)"\);(\1\s*=\s*ereg_replace\("([^"]+)","([^"]+)",\1\);)+\1=base64_decode\(\1\);eval\(\1\);~msi',
            'id'   => 'evalEregReplace',

        ],
        [
            'full' => '~((\$\w+)\s*=\s*(([base64_decode"\'\.\s]+)|([eval"\'\.\s]+)|([create_function"\'\.\s]+)|([stripslashes"\'\.\s]+)|([gzinflate"\'\.\s]+)|([strrev"\'\.\s]+)|([str_rot13"\'\.\s]+)|([gzuncompress"\'\.\s]+)|([urldecode"\'\.\s]+)([rawurldecode"\'\.\s]+));\s*)+\s*@?eval\(\$[^)]+\)+;~msi',
            'id'   => 'evalWrapVar',

        ],
        [
            'full' => '~(?:\$\{"[^"]+"\}\["[^"]+"\]="[^"]+";)+(?:\$\{\$\{"[^"]+"\}\["[^"]+"\]\}="[^"]+";)+@?eval\s*\(\s*([\'"?>.]+)?@?\s*(base64_decode\s*\(|gzinflate\s*\(|strrev\s*\(|str_rot13\s*\(|gzuncompress\s*\(|urldecode\s*\(|rawurldecode\s*\(|eval\s*\()+\(?\$\{\$\{"[^\)]+\)+;~msi',
            'id'   => 'escapes',
        ],
        [
            'full' => '~(\$\w+)\s*=(?:\s*(?:(?:["\'][a-z0-9][\'"])|(?:chr\s*\(\d+\))|(?:[\'"]\\\\x[0-9a-f]+[\'"]))\s*?\.?)+;\s*(\$\w+)\s*=(?:\s*(?:(?:["\'][a-z0-9][\'"])|(?:chr\s*\(\d+\))|(?:[\'"]\\\\x[0-9a-f]+[\'"]))\s*?\.?)+;\s*@?\1\s*\(@?\2\s*\([\'"]([^\'"]+)[\'"]\)+;~msi',
            'id'   => 'assert',
        ],
        [
            'full' => '~eval\s*\(str_rot13\s*\([\'"]+\s*(?:.+(?=\\\\\')\\\\\'[^\'"]+)+[\'"]+\)+;~msi',
            'id'   => 'evalCodeFunc',
        ],
        [
            'full' => '~\$\{"GLOBALS"\}\[[\'"](\w+)[\'"]\]=["\'](\w+)[\'"];\$\{"GLOBALS"\}\[[\'"](\w+)[\'"]\]=["\']\2[\'"];\${\$\{"GLOBALS"\}\[[\'"]\3[\'"]\]}=[\'"]([^\'"]+)[\'"];eval.{10,50}?\$\{\$\{"GLOBALS"\}\[[\'"]\1[\'"]\]\}\)+;~msi',
            'id'   => 'evalVarVar',
        ],
        [
            'full' => '~(\$\w+)=[\'"][^"\']+[\'"];(\$\w+)=strrev\(\'edoced_46esab\'\);eval\(\2\([\'"][^\'"]+[\'"]\)+;~msi',
            'id'   => 'edoced_46esab',
        ],
        [
            'full' => '~(\$\w+)=strrev\([\'"](?:|ed|oc|_|4|6|es|ab|(?:"\."))+[\'"]\);\s*(\$\w+)=strrev\([\'"](?:|et|al|fn|iz|g|(?:"\."))+[\'"]\);\s?@?eval\(\2\(\1\([\'"]([\w\/\+=]+)[\'"]\)\)\);~msi',
            'id'   => 'edoced_46esab_etalfnizg',
        ],
        [
            'full' => '~(\$\w+)\s*=\s*"((?:[^"]|(?<=\\\\)")*)";(\$\w+)\s*=\s*(\1\[\d+\]\.?)+;(\$\w+)\s*=\s*[^;]+;(\$\w+)\s*=\s*"[^"]+";\$\w+\s*=\s*\5\."[^"]+"\.\6;\3\((\1\[\d+\]\.?)+,\s*\$\w+\s*,"\d+"\);~smi',
            'fast' => '~(\$\w+)\s*=\s*"((?:[^"]|(?<=\\\\)"){0,1000})";(\$\w+)\s*=\s*(\1\[\d+\]\.?)+;(\$\w+)\s*=\s*[^;]+;(\$\w+)\s*=\s*"[^"]+";\$\w+\s*=\s*\5\."[^"]+"\.\6;\3\((\1\[\d+\]\.?)+,\s*\$\w+\s*,"\d+"\);~smi',
            'id'   => 'eval2',
        ],
        [
            'full' => '~(?:\${"\\\\x[\\\\\w]+"}\["\\\\x[\\\\\w]+"\]\s?=\s?"[\w\\\\]+";){1,10}\${\${"\\\\x[\\\\\w]+"}\["[\\\\\w]+"\]}\s?=\s?"\w{1,100}";\${\${\${"\\\\x[\\\\\w]+"}\["[\\\\\w]+"\]}\s?}="(\\\\x[^"]+)";eval\(((?|str_rot13\(|gzinflate\(|base64_decode\(){1,10})\(\${\${"\\\\x[\\\\\w]+"}\["[\\\\\w]+"\]}\){1,5};~msi',
            'id'   => 'evalEscapedCharsContent',
        ],
        [
            'full' => '~@?(eval|echo|(\$\w+)\s*=\s*create_function)(?:\/\*+\/)?\s*\((\'\',)?\s*([\'"][?>\s]+[\'".\s]+)?\s*\(?\s*@?\s*(?:base64_decode\s*\(|pack\s*\(\'H\*\',|convert_uudecode\s*\(|htmlspecialchars_decode\s*\(|gzdecode\s*\(|stripslashes\s*\(|gzinflate\s*\(|strrev\s*\(|str_rot13\s*\(|gzuncompress\s*\(|urldecode\s*\(|rawurldecode\s*\(|unserialize\s*\(|eval\s*\(|hex2bin\()+.*?[^\'");]+((\s*\.?[\'"]([^\'";]+[\'"]*\s*)+|,\s*true)?\s*[\'"\)]+)+\s*;?(\s*\2\(\);)?~msi',
            'id'   => 'eval',
        ],
        [
            'full' => '~eval\s*/\*[\w\s\.:,]+\*/\s*\([^\)]+\)+;~msi',
            'fast' => '~eval\s*/\*[\w\s\.:,]+\*/\s*\(~msi',
            'id'   => 'eval',
        ],
        [
            'full' => '~((?:\$\w+\s?=\s?(?:base64_decode|str_rot13)\([\'"][^\'"]+[\'"]\);)+)\s?(@?eval\((?:(?:\w+\()*\$\w+\(?)+(?:.*?)?\)+;)~msi',
            'id'   => 'evalFuncVars',
        ],
        [
            'full' => '~eval\("\\\\145\\\\166\\\\141\\\\154\\\\050\\\\142\\\\141\\\\163[^\)]+\)+;~msi',
            'fast' => '~eval\("\\\\145\\\\166\\\\141\\\\154\\\\050\\\\142\\\\141\\\\163~msi',
            'id'   => 'evalHex',
        ],
        [
            'full' => '~eval\s*\("\\\\x?\d+[^\)]+\)+;(?:[\'"]\)+;)?~msi',
            'fast' => '~eval\s*\("\\\\x?\d+~msi',
            'id'   => 'evalHex',
        ],
        [
            'full' => '~(\$\w+)\s=\s(["\']?[\w\/\+]+["\']?);\s(\$\w+)\s=\s((?:str_rot13\(|rawurldecode\(|convert_uudecode\(|gzinflate\(|str_rot13\(|base64_decode\(|rawurldecode\(|)+\1\)\)+);\secho\s(eval\(\3\);)~msi',
            'id'   => 'echoEval',
        ],
        [
            'full' => '~if\(!function_exists\([\'"](\w+)[\'"]\)\){function\s?\1\((\$\w+)\){(\$\w+)=array\((?:\'(\d+)\',)?\'([^\']+)\',\'([^\']+)\',\2\);for\((\$\w+)=0;\7<[34];\7\+\+\){for\((\$\w+)=0;\8<strlen\(\3\[\7\]\);\8\+\+\)\s?\3\[\7\]\[\8\]\s?=\s?chr\(ord\(\3\[\7\]\[\8\]\)-(?:\(\7\?\3\[\8\s?xor\s?\8\]:1\)|1)\);if\(\7==[21]\)\s?\3\[[32]\]=\3\[[01]\]\(\3\[[21]\]\(\3\[[32]\]\)\);}\s?return\s?\3\[[32]\];}(\$\w+)=["\']([\w\+\/=]+)["\'];(\$\w+)=[\'"]\1[\'"];(\$\w+)=\11\([\'"]([^\'"]+)[\'"]\);\$\w+=@?\12\(\'\',\11\(\9\)\);\$\w+\(\);}~msi',
            'id'   => 'evalCreateFunc',
        ],
        [
            'full' => '~(\$\w{1,1000})=[\'"]([\'"\w/\+=]+)[\'"];(\$\w{1,3000}=(?:base64_decode|gzinflate|convert_uudecode|str_rot13)\(\$\w{1,3000}\);){1,100}eval\((\$\w{1,3000})\);~msi',
            'id'   => 'evalAssignedVars',
        ],
        [
            'full' => '~(?:\$_{1,50}\s*=\s*[^;]{2,200}\s*;\s*)+(?:\$_{1,50}\s*=\s*\$_{1,50}\([^\)]+\);\s*|(?:if\(!function_exists\(\'[^\']+\'\)\){function\s\w{1,50}\(\$\w{1,50},\$\w{1,50}\){return\s?eval\("return function\(\$\w{1,50}\){{\$\w{1,50}}};"\);}}\s*)?)+(?:\$_{1,50}\s*=\s*\'[^\']+\';\s*)?(?:\s*(\$_{1,50}\s*=\s*)?\$_+\([^)]*\)+;\s*)+(?:echo\s*\$_{1,50};)?~msi',
            'id'   => 'seolyzer',
        ],
        [
            'full' => '~(\$\w+)="((?:[^"]|(?<=\\\\)")*)";(\s*\$GLOBALS\[\'\w+\'\]\s*=\s*(?:\${)?(\1\[\d+\]}?\.?)+;\s*)+(.{0,400}\s*\1\[\d+\]\.?)+;\s*}~msi',
            'fast' => '~(\$\w+)="((?:[^"]|(?<=\\\\)"){0,1000})";(\s*\$GLOBALS\[\'\w+\'\]\s*=\s*(?:\${)?(\1\[\d+\]}?\.?)+;\s*)+(.{0,400}\s*\1\[\d+\]\.?)+;\s*}~msi',
            'id'   => 'subst2',
        ],
        [
            'full' => '~(\$\w{1,50}\s*=\s*"[^"]{1,1000}";\s*)+(\$\w{1,50}\s*=\s*\$?\w{1,50}\("\w{1,50}"\s*,\s*""\s*,\s*"\w{1,50}"\);\s*)+\$\w{1,50}\s*=\s*\$\w{1,50}\("",\s*\$\w{1,50}\(\$\w{1,50}\("\w{1,50}",\s*"",(\s*\$\w{1,50}\.?)+\)+;\$\w{1,50}\(\);~msi',
            'id'   => 'strreplace',
        ],
        [
            'full' => '~\$\w{1,50}\s?=\s?(?:\'[^\']{1,500}\'|"[^}]{1,500}}");\s?\$\w{1,50}\s?=\s?str_replace\([\'"]\w{1,50}[\'"],\s?[\'"][\'"],\s?["\']\w{1,100}[\'"]\);\s?(?:\$\w{1,50}\s?=\s?(?:\'[^\']{1,500}\'|"[^\s]{1,500}?");\s){1,15}.*?\$\w{1,50}\s?=\s?str_replace\((?:\'[^\']{1,100}\'|"[^"]{1,100}?"),\s?\'\',\s?(?:\$\w{1,50}\s?\.?\s?){1,50}\);\s?\$\w{1,50}\s?=\s?\$\w{1,50}\(\'\',\s?\$\w{1,50}\);\s?\$\w{1,50}\(\);~msi',
            'id'   => 'strreplace',
        ],
        [
            'full' => '~@?echo\s*([\'"?>.\s]+)?@?\s*(base64_decode\s*\(|stripslashes\s*\(|gzinflate\s*\(|strrev\s*\(|str_rot13\s*\(|gzuncompress\s*\(|urldecode\s*\(|rawurldecode\s*\(|eval\s*\()+[\s\/\'"].*?[^\'")]+((\s*\.?[\'"]([^\'";\$]+\s*)+)?\s*[\'"\);]+)+~msi',
            'id'   => 'echo',
        ],
        [
            'full' => '~(\$\w+)="([^"]+)";\s*(\$\w+)=strtoupper\s*\((\1\[\d+\]\s*\.?\s*)+\)\s*;\s*if\(\s*isset\s*\(\${\s*\3\s*}\[\d*\s*\'\w+\'\s*\]\s*\)\s*\)\s*{eval\(\${\3\s*}\[\'\w+\']\s*\)\s*;}~smi',
            'fast' => '~(\$\w+)="([^"]+)";\s*(\$\w+)=strtoupper\s*\((\1\[\d+\]\s*\.?\s*)+\)\s*;\s*if\(\s*isset\s*\(\${\s*\3\s*}\[\d*\s*\'\w+\'\s*\]\s*\)\s*\)\s*{eval\(\${\3\s*}\[\'\w+\']\s*\)\s*;}~smi',
            'id'   => 'strtoupper',
        ],
        [
            'full' => '~(\$\w+)="[^"]+";\s*(\$\w+)=str_ireplace\("[^"]+","",\1\);(\$\w+)\s*=\s*"[^"]+";\s*function\s*(\w+)\((\$\w+,?)+\){\s*(\$\w+)=\s*create_function\(\'\',\$\w+\);\s*array_map\(\6,array\(\'\'\)+;\s*}\s*set_error_handler\(\'\4\'\);(\$\w+)=\2\(\3\);user_error\(\7,E_USER_ERROR\);\s*if\s*.+?}~msi',
            'id'   => 'errorHandler',
        ],
        [
            'full' => '~(\$\w+)=strrev\(str_ireplace\("[^"]+","","[^"]+"\)\);(\$\w+)="([^"]+)";eval\(\1\(\2\)+;}~msi',
            'id'   => 'evalIReplace',
        ],
        [
            'full' => '~error_reporting\((?:0|E_ALL\^E_NOTICE)\);ini_set\("display_errors",\s*[01]\);if\(!defined\(\'(\w+)\'\)\){define\(\'\1\',__FILE__\);if\(!function_exists\("([^"]+)"\)\){function [^(]+\([^\)]+\).+?eval\(""\);.+?;}?eval\(\$[^\)]+\)\);[^\)]+\)+.*?;return\s*\$[^;]+;\s*\?>([^;]+);~msi',
            'id'   => 'PHPJiaMi',
        ],
        [
            'full' => '~\$\w+=0;(\$GLOBALS\[\'\w+\'\])\s*=\s*\'([^\']+)\';\s*(\$\w+)=pack\(\'H\*\',substr\(\1,\s*([-\d]+)\)\);if\s*\(!function_exists\(\'(\w+)\'\)\){function\s*\5\(\$\w+,\s*\$\w+\){\$\w+=\1;\s*\$d=pack\(\'H\*\',substr\(\1,\s*\4\)\);\s*return\s*\$\w+\(substr\(\$\w+,\s*\$\w+,\s*\$\w+\)\);}};eval\(\3\(\'[^\']+\'\)\);~msi',
            'id'   => 'substr',
        ],
        [
            'full' => '~(function\s*(\w+)\((\$\w+)\){\s*return\s*(base64_decode|gzinflate|eval)\(\$\w+(,\d+)?\);}\s*)+(\$\w+)="([^"]+)";(\w+\()+\6\)+~msi',
            'id'   => 'funcs',
        ],
        [
            'full' => '~(?:\$\{\'GLOBALS\'\}\[\'\w+\'\]=\'_F\';)?\$(?:_F|\{\$\{\'GLOBALS\'\}\[\'\w+\'\]\})=_{1,2}(?:FILE|hex)_{1,2};(?:\$\{\'GLOBALS\'\}\[\'\w+\'\]=\'_X\';)?\$(?:_X|\{\$\{\'GLOBALS\'\}\[\'\w+\'\]\})=["\']([^\'"]+)[\'"];\s*(?:\$[_\w]+\.=[\'"][\w\+\/=]+[\'"];){0,30}\$_\w+=base64_decode\(\$_X\);\$_X=strtr\(\$_X,\'([^\']+)\',\'([^\']+)\'\);\$_R=@?(?:(str_replace)|(ereg_replace)|(preg_replace))\(\'\~?__FILE__\~?\',"\'".\$_F."\'",\$_X\);eval\(\$_R\);\$_R=0;\$_X=0;~msi',
            'fast' => '~\$_\w+=base64_decode\(\$_X\);\$_X=strtr\(\$_X,\'([^\']+)\',\'([^\']+)\'\);\$_R=@?(?:(str_replace)|(ereg_replace)|(preg_replace))\(\'\~?__FILE__\~?\',"\'".\$_F."\'",\$_X\);eval\(\$_R\);\$_R=0;\$_X=0;~msi',
            'id'   => 'LockIt2',
        ],
        [
            'full' => '~(?:@error_reporting\(\d+\);\s*@set_time_limit\(\d+\);)?\s*(\$\w+)=([\s\'\w\/+=]+);\s*(\$\w+)=(__FILE__);\s*\1=gzinflate\(str_rot13\(base64_decode\(\$tr\)\)\);\1=strtr\(\1,\'([^\']+)\'\s*,\'([^\']+)\'\);(\$_R)=@?ereg_replace\(\'\~?\4\~?\',"\'".\3."\'",\1\);eval\(\7\);\7=0;\1=0;~msi',
            'fast' => '~(\$\w+)=([\s\'\w\/+=]+);\s*(\$\w+)=(__FILE__);\s*\1=\w+\(\w+\(\w+\(\$tr\)\)\);\1=\w+\(\1,\'([^\']+)\'\s*,\'([^\']+)\'\);(\$_R)=@?\w+\(\'\~?\4\~?\',"\'".\3."\'",\1\);\w+\(\7\);\7=0;\1=0;~msi',
            'id'   => 'anaski',
        ],
        [
            'full' => '~\$\w+="[^"]+";\$l+=0;\$l+=\'base64_decode\';\$l+=0;eval\([^\^]+\^[\dx]+\);}eval\(\$l+\("[^"]+"\)+;eval\(\$l+\);return;~msi',
            'id'   => 'custom1',
        ],
        [
            'full' => '~(\$\w+)\s*=\s*"(\w{32})";\s*(\$\w+)\s*=\s*array\s*\(\);\s*(\3\[\d+\]\s*=\s*"[^"]+";\s*)+\s*(\$\w+)\s*=\s*"base64_decode";\s*\$\w+\s*=\s*(\w+)\s*\(\3,\1\);function\s*\6\(\s*.{200,500}return\s*\$\w+;\s*}\s*eval\s*\(\5\s*\(\$\w+\)\);~msi',
            'id'   => 'custom2',
        ],
        [
            'full' => '~\$\w+=\'=+\s*Obfuscation provided by Unknowndevice64 - Free Online PHP Obfuscator\s*(?:http://www\.ud64\.com/)?\s*=+\';\s*(\$ud64_c[o0]m="[\\\\0-9a-z\."]+;)+\$\w+=(\$ud64_c[o0]m\()+"([^"]+)"\)+;@eval\(\$ud64_c[o0]m\(\'[^\']+\'\)+;~msi',
            'id'   => 'ud64',
        ],
        [
            'full' => '~(\$[\w_]+=("[\\\\\\\\\w]+"\.?)+;)+\$\w+=(?:\$\w+\()+"([\w\/\+=]+)"\)+;@eval\(\$\w+\(\'.*?\'\)+;~msi',
            'id'   => 'ud64',
        ],
        [
            'full' => '~\$\w+=__FILE__;\$\w+=fopen\(\$\w+,\'rb\'\);fread\(\$\w+,(\d+)\);\$\w+=explode\("\\\\t",base64_decode\(fread\(\$\w+,(\d+)\)+;\$\w+=\$\w+\[[\d+]\];[\$l1=\d{}\.;\(\)\[\]]+eval\(\$\w+\(\'[^\']+\'\)+;\s*return\s*;\?>[\w=\+]+~msi',
            'id'   => 'qibosoft',
        ],
        [
            'full' => '~(\$\w+)=base64_decode\("([^"]+)"\);\s*eval\("return\s*eval\(\\\\"\1\\\\"\);"\)~msi',
            'id'   => 'evalReturn',
        ],
        [
            'full' => '~(?:\$[0O]+\[[\'"](\w+)[\'"]\]\.?="[\\\\\w]+";)+(?:\$[0O]+\[[\'"]\w+[\'"]\]\.?=\$[0O]+\[[\'"]\w+[\'"]\]\([\'"][\d\(]+[\'"](,__FILE__)?\);)+@eval\((?:\$[0O]+\[[\'"]\w+[\'"]\]\()+"([^"]+)"\)+;~mis',
            'fast' => '~(?:\$[0O]+\[[\'"](\w+)[\'"]\]\.?="[\\\\\w]+";)+(?:\$[0O]+\[[\'"]\w+[\'"]\]\.?=\$[0O]+\[[\'"]\w+[\'"]\]\([\'"][\d\(]+[\'"](,__FILE__)?\);)+@eval\((?:\$[0O]+\[[\'"]\w+[\'"]\]\()+"([^"]+)"\)+;~mis',
            'id'   => 'evalChars',
        ],
        [
            'full' => '~<\?php\s+((\$GLOBALS\[\s*[\'"]\w+[\'"]\s*\])\s*=\s*base64_decode\("([^"]*)"\);)+\s*\?><\?php\s.+\2.+exit;\s}\sfunction\s\w+\(\)\s{\sreturn\sarray\(\s\'favicon\'\s=>\s\'[^\']+\',\s+\'sprites\'\s=>\s\'[^\']+\',\s\);\s}~msi',
            'id'   => 'globalsBase64',
        ],
        [
            'full' => '~(\$\w+=strrev\("[^"]+"\);)+eval\((\$\w+\()+"[^"]+"\)+;~mis',
            'fast' => '~(\$\w+=strrev\("[^"]+"\);)+eval\((\$\w+\()+"[^"]+"\)+;~mis',
            'id'   => 'strrevVarEval',
        ],
        [
            'full' => '~\$\w+=basename/\*\w+\*/\(/\*\w+\*/trim/\*\w+\*/\(.+?(\$\w+)=.+\1.+?;~msi',
            'id'   => 'comments',
        ],
        [
            'full' => '~(\$\w+)\s*=\s*(base64_decode\s*\(+|gzinflate\s*\(+|strrev\s*\(+|str_rot13\s*\(+|gzuncompress\s*\(+|convert_uudecode\s*\(+|urldecode\s*\(+|rawurldecode\s*\(+|htmlspecialchars_decode\s*\(+)+"([^"]+)"\)+;\s*@?eval\(([\'"?>.\s]+)?\1\);~',
            'fast' => '~(\$\w+)\s*=\s*(base64_decode\s*\(+|gzinflate\s*\(+|strrev\s*\(+|str_rot13\s*\(+|gzuncompress\s*\(+|convert_uudecode\s*\(+|urldecode\s*\(+|rawurldecode\s*\(+|htmlspecialchars_decode\s*\(+)+"([^"]+)"\)+;\s*@?eval\(([\'"?>.\s]+)?\1\);~',
            'id'   => 'varFuncsEval',
        ],
        [
            'full' => '~((\$\w+)="";\$\w+\s*\.=\s*"[^;]+;\s*)+(?:="";)?eval\((\s*\$\w+\s*\.)+\s*"[^"]+(?:"\);)+~msi',
            'id'   => 'evalConcatVars',
        ],
        [
            'full' => '~<\?php\s*defined\(\'[^\']+\'\)\s*\|\|\s*define\(\'[^\']+\',__FILE__\);(global\s*\$[^;]+;)+\s*(if\(!function_exists\(\'([^\']+)\'\)\){\s*function\s*[^\)]+\(\$[^,]+,\$[^=]+=\'\'\){\s*if\(empty\(\$[^\)]+\)\)\s*return\s*\'\';\s*\$[^=]+=base64_decode\(\$[^\)]+\);\s*if\(\$[^=]+==\'\'\)\s*return\s*\~\$[^;]+;\s*if\(\$[^=]+==\'-1\'\)\s*@[^\(]+\(\);\s*\$[^=]+=\$GLOBALS\[\'[^\']+\'\]\[\'[^\']+\'\]\(\$[^\)]+\);\s*\$[^=]+=\$GLOBALS\[\'[^\']+\'\]\[\'[^\']+\'\]\(\$[^,]+,\$[^,]+,\$[^\)]+\);\s*return\s*\$[^^]+\^\$[^;]+;\s*}}\s*)+(\$[^\[]+\["[^"]+"]=[^\(]+\(\'[^\']+\',\'[^\']*\'\);\s*)+(\$[^\[]+\[\'[^\']+\'\]=\$GLOBALS\[\'[^\']+\'\]\[\'[^\']+\'\]\([^\)]*\)+;\s*)+return\(eval\(\$[^\[]+\[\'[^\']+\'\]\)+;\s*\?>\s*#!/usr/bin/php\s*-q\s*(\s*[^\s]+)+~msi',
            'fast' => '~<\?php\s*defined\(\'[^\']{10,30}\'\)\s*\|\|\s*define\(\'[^\']{10,30}\',__FILE__\);(global\s*\$[^;]{10,30};)+\s*if\(!function_exists\(\'([^\']+)\'\)\){\s*function\s*[^\)]+\(\$[^,]{10,30},\$[^=]{10,30}=\'\'\){\s*if\(empty\(\$[^\)]+\)\)\s*return\s*\'\';\s*\$[^=]{10,30}=base64_decode~msi',
            'id'   => 'OELove',
        ],
        [
            'full' => '~(?:\$\w+\s*=(\s*(\d+)\+)*\d+;\s*)?(\$\w+="[^"]+";\s*)+\s*(?:\$\w+\s*=(?:\s*(?:\d+)\+)*\s*\d+;\s*)?(\$\w+)\s*=\s*\w+\(\'[^\']+\',\s*\$\w+,\s*\'[^\']+\'\);.+?\4\("[^"]+"\);\s*\$\w+\s*=\s*\4;\s*(\$\w+="[^"]+";\s*)+.+?\$\w+\(\$\w+,\$\w+\("",\s*\$\w+\(\$\w+\(\$\w+\(\$\w+\(\$\w+,\s*"(\d+)"\)+,\$\w+\);.+function \w+\((\$\w+),\s*\$\w+,\s(\$\w+)\)\s{\8\s=\s\8\s\.\s\8;.+return \7;\s*}~msi',
            'fast' => '~(\$\w+)\s*=\s*\w+\(\'[^\']+\',\s*\$\w+,\s*\'[^\']+\'\);.+?\1\("[^"]+"\);\s*\$\w+\s*=\s*\1;\s*(\$\w+="[^"]+";\s*)+~msi',
            'id'   => 'Obf_20200402_1',
        ],
        [
            'full' => '~(?:\$\w+\s*=\s*"[^"]+";\s*)?(?:((?:\$\w+\s*=\s*\'[^\']+\';\s*)+)(\$\w+=(?:\$\w+\.?)+);)?function\s(\w+)\((\$\w+),\s*(\$\w+),\s*(\$\w+)\)\s*{\s*return\s*([\'\. ]*(\4|\5|\6)[\'\. ]*)+;\s*}\s*(?:\$\w+\s*=\s*"[^"]+";)?(\s*\$\w+\s*=\s*\3\((((\'\')|(\$\w+)|(\$\w+[\[\{]\d+[\]\}](\.\'\')?)|(\$\w+[\[\{]\d+[\]\}]\.\$\w+[\[\{]\d+[\]\}]))\s*,?\s*)+\);\s*)+\s*\$\w+\s*=\s*\3[^"]+[^\']+\'([^\']+)\'"[^/]+\'//\'\)+;~msi',
            'fast' => '~function\s(\w+)\((\$\w+),\s*(\$\w+),\s*(\$\w+)\)\s*{\s*return\s*([\'\. ]*(\2|\3|\4)[\'\. ]*)+;\s*}\s*(?:\$\w+\s*=\s*"[^"]+";)?(\s*\$\w+\s*=\s*\1\((((\'\')|(\$\w+)|(\$\w+[\[\{]\d+[\]\}](\.\'\')?)|(\$\w+[\[\{]\d+[\]\}]\.\$\w+[\[\{]\d+[\]\}]))\s*,?\s*)+\);\s*)+\s*\$\w+\s*=\s*\1[^"]+[^\']+\'([^\']+)\'"[^/]+\'//\'\)+;~msi',
            'id'   => 'Obf_20200402_2',
        ],
        [
            'full' => '~(?:function\s*\w{1,50}\(\$\w{1,50},\s*\$\w{1,50}\)\s*\{(?:\s*\$\w{1,50}\s*=\s*(?:md5\(\$\w{1,50}\)|\d+|base64_decode\(\$\w{1,50}\)|strlen\(\$\w{1,50}\)|\'\');\s*)+\s*for\s*\(\$\w{1,50}\s*=\s\d+;\s*\$\w{1,50}\s*<\s*\$len;\s*\$\w{1,50}\+\+\)\s*\{\s*if\s*\(\$\w{1,50}\s*==\s*\$\w{1,50}\)\s*\{\s*\$\w{1,50}\s*=\s*\d+;\s*}\s*\$\w{1,50}\s*\.=\s*substr\(\$\w{1,50},\s*\$\w{1,50},\s*\d+\);\s*\$\w{1,50}\+\+;\s*\}(?:\s*\$\w{1,50}\s*=\s*\'\';)?\s*for\s*\(\$\w{1,50}\s*=\s*\d+;\s*\$\w{1,50}\s*<\s*\$\w{1,50};\s*\$\w{1,50}\+\+\)\s*{\s*if\s*\(ord\(substr\(\$\w{1,50},\s*\$\w{1,50},\s*\d+\)\)\s*<\s*ord\(substr\(\$\w{1,50},\s*\$\w{1,50},\s*\d+\)\)\)\s*\{\s*\$\w{1,50}\s*\.=\s*chr\(\(ord\(substr\(\$\w{1,50},\s*\$\w{1,50},\s*\d+\)\)\s*\+\s*\d+\)\s*-\s*ord\(substr\(\$\w{1,50},\s*\$\w{1,50},\s*\d+\)\)\);\s*}\s*else\s*{\s*\$\w{1,50}\s*\.=\s*chr\(ord\(substr\(\$\w{1,50},\s*\$\w{1,50},\s*\d+\)\)\s*-\s*ord\(substr\(\$\w{1,50},\s*\$\w{1,50},\s*\d+\)\)\);\s*}\s*}\s*return\s*\$\w{1,50};\s*\}\s*|\$\w{1,50}\s*=\s*"([^"]+)";\s*){2}\s*\$\w{1,50}\s*=\s*"([^"]+)";\s*\$\w{1,50}\s*=\s*\w{1,50}\(\$\w{1,50},\s*\$\w{1,50}\);\s*eval\(\$\w{1,50}\);~msi',
            'id'   => 'Obf_20200414_1',
        ],
        [
            'full' => '~(?:\$\w+\s*=\s*\'\w+\';)?\s*(\$\w+)\s*=\s*urldecode\(\'[%0-9a-f]+\'\);(\s*(\$\w+)\s*=(\s*\1\{\d+\}\.?)+;)+\s*(\$\w+)\s*=\s*"[^"]+"\.\3\("[^"]+"\);\s*eval\(\5\);~msi',
            'fast' => '~(\$\w+)\s*=\s*urldecode\(\'[%0-9a-f]+\'\);(\s*(\$\w+)\s*=(\s*\1\{\d+\}\.?)+;)+\s*(\$\w+)\s*=\s*"[^"]+"\.\3\("[^"]+"\);\s*eval\(\5\);~msi',
            'id'   => 'Obf_20200421_1',
        ],
        [
            'full' => '~(\$\w+)=\'([^\']+)\';(\$\w+)=str_rot13\(gzinflate\(str_rot13\(base64_decode\(\1\)\)\)\);eval\(\3\);~msi',
            'id'   => 'SmartToolsShop',
        ],
        [
            'full' => '~(\$\w+)\s*=\s*\("\?>"\.gzuncompress\(base64_decode\("[^"]+"\)\)\);\s*@?eval\(\1\);~msi',
            'id'   => 'Obf_20200504_1',
        ],
        [
            'full' => '~(\$\w+)=base64_decode\(\'[^\']+\'\);\s*eval\(\1\);~mis',
            'fast' => '~(\$\w+)=base64_decode\(\'[^\']+\'\);\s*eval\(\1\);~mis',
            'id'   => 'Obf_20200507_1',
        ],
        [
            'full' => '~(?:error_reporting\(0\);\s*ini_set\("max_execution_time",0\);\s*(?:/\*.*?\*/)?\s*)?(\$\w+)=\s*\[(("."=>".",?\s*)+)];\s*(\$\w+)=str_split\("([^"]+)"\);\s*(?:\$\w+="";)?\s*foreach\(\4\s*as\s*(\$\w+)\)\s*{\s*foreach\(\s*\1\s*as\s*(\$\w+)=>(\$\w+)\)\s*{\s*if\(\6==\(string\)\8\)\s*\{\s*\$\w+\.=\7;\s*break;\s*}\s*}\s*}~msi',
            'fast' => '~(\$\w+)=\s*\[(("."=>".",?\s*)+)];\s*(\$\w+)=str_split\("([^"]+)"\);\s*(?:\$\w+="";)?\s*foreach\(\4\s*as\s*(\$\w+)\)\s*{\s*foreach\(\s*\1\s*as\s*(\$\w+)=>(\$\w+)\)\s*{\s*if\(\6==\(string\)\8\)\s*\{\s*\$\w+\.=\7;\s*break;\s*}\s*}\s*}~msi',
            'id'   => 'Obf_20200507_4',
        ],
        [
            'full' => '~assert\("[eval"\.]+\([base64_decode\."]+\(\'([^\']+)\'\)\)"\);~msi',
            'id'   => 'Obf_20200507_5',
        ],
        [
            'full' => '~parse_str\s*\(\'([^\']+)\'\s*,\s*(\$\w+)\)\s*;(\2\s*\[\s*\d+\s*\]\s*\(\s*)+\'[^\']+\'\s*\),\s*array\(\s*\),\s*array\s*\(\s*\'[^\']+\'\s*\.(\2\[\s*\d+\s*\]\()+\'([^\']+)\'\s*[\)\s]+\.\'//\'[\s\)]+;~msi',
            'id'   => 'Obf_20200513_1',
        ],
        [
            'full' => '~(\$\w+)=strrev\("[base64_decode"\.]+\);eval\(\1\(\'([^\']+)\'\)\);~msi',
            'id'   => 'Obf_20200526_1',
        ],
        [
            'full' => '~error_reporting\(0\);define\(\'\w+\',\s*__FILE__\);define\(\'\w+\',\s*fopen\(__FILE__,\s*\'r\'\)\);fseek\(\w+,\s*__COMPILER_HALT_OFFSET__\);((\$\w+="\\\\x[0-9a-f]+";)+(\$\w+="[^"]+";)+eval\("\?>"\.(\$\w+\()+"([^"]+)"\)+;)+(?:/\*\w+\*/)?__halt_compiler\(\);[\w#|>^%\[\.\]\\\\/=]+~msi',
            'id'   => 'Obf_20200527_1',
        ],
        [
            'full' => '~(\$\w+)=strrev\("[base64_decode]+"\)\.str_replace\(\'(\w+)\',\'\',\'\w+\'\);\s*eval\(\1\(\$\w+\)\);~msi',
            'id'   => 'Obf_20200602_1',
        ],
        [
            'full' => '~(\$\w+)\s*=\s*"([^"]+)";\s*(\$\w+)\s*=\s*base64_decode\(\1\);\s*eval\(\3\);~msi',
            'id'   => 'Obf_20200720_1',
        ],
        [
            'full' => '~[\'".]+(\$\w+\s*=\s*[\'"]\w+[\'"];)+(\$\w+=\$\w+[\'.]+\$\w+;)+(\$\w+=(str_rot13|base64_decode|gzinflate)\(\$\w+\);)+eval\(\$\w+\);~msi',
            'id'   => 'flamux',
        ],
        [
            'full' => '~function\s*(\w+)\(\)\{\s*return\s*"([^"]+)";\s*\}\s*eval\("([^"]+)"\.\1\(\)\."([^"]+)"\);~msi',
            'id'   => 'bypass',
        ],
        [
            'full' => '~(?:\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]="[\w\\\\\s]+";)+(echo)\s*"(?:[<\w\\\\>\/\s={:}#]+);(?:[\\\\\w\-:]+;)+(?:[\\\\\w}:{\s#]+;)+(?:[\\\\\w}:{#\-\s]+;)+[\\\\\w}<\/]+";\$\w+=["\\\\\w]+;(?:\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]="[\w\\\\\s]+";)+\$\w+=["\\\\\w]+;\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]="[\w\\\\\s]+";error_reporting\(\d\);\$\w+=["\\\\\w]+;\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]="[\w\\\\\s]+";\$\w+=["\\\\\w]+;set_time_limit\(\d\);\$\w+=["\\\\\w]+;(?:\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]="[\w\\\\\s]+";)+(if\(empty\()[\$_\w\["\\\\\]]+\)\){\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]}=[\w()]+;(}else{)\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]}=[\$_\w\["\\\\\]]+;}chdir\(\${\$\w+}\);\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]}=htmlentities\(\$[_\w\["\\\\\].?]+\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]}\);\1[<\\\\\w>\/"]+;\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]="[\w\\\\\s]+";(?:\$\w+=["\w\\\\]+;)+(?:\1["\\\\\w:\s.\$\[\]>()_\'<\/%]+;)+\$\w+=["\w\\\\]+;\1["\\\\\w:\s.\$\[\]>()_\'<\/%]+;\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]="[\w\\\\\s]+";\1["\\\\\w<>=\s\'.]+\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]}[."\\\\\w=\s\/<>]+;(?:\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]="[\w\\\\\s]+";)+\1["<\\\\\w\s\'.\${}>\/]+;\1["<\\\\\w>\s\'.]+\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]}[."&\w\\\\\'<\/]+;\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]="[\w\\\\\s]+";\$\w+=["\\\\\w]+;\1["<\\\\\w>\s=\'.\${}&\/]+;(?:\1["<\\\\\w>\/]+;)+\$\w+=["\\\\\w]+;\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]}=[\$_\w\["\\\\\]]+;\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]="[\w\\\\\s]+";switch\(\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]}\){case"[\w\\\\\s]+":(?:\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]}=[\$_\w\["\\\\\]]+;)+\2\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]}\)\){(?:\$\w+=["\\\\\w]+;)+(?:\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]="[\w\\\\\s]+";)+\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]}=fopen\(\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]},"\w"\);\$\w+=["\\\\\w]+;\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]}=(?:(?|fread|filesize)\(\${\$\w+},?)+\)\);\${\$\w+}=str_replace\("[\w\\\\\s]+",[<\w\\\\>"]+,\${\$\w+}\);\1["\\\\\w<>=\s\'.]+\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]}[."\\\\\w=\s\/<>&\${}\']+;\1["\\\\\w\s.:]+\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]}\."[\w\\\\\s]+";\1["\\\\\w\s\'=]+\.\${\$\w+}\.["<\w\\\\>]+;\1["<\\\\\w>\s=\'\/;]+\3\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]="[\w\\\\\s]+";(?:\$\w+=["\w\\\\]+;)+\${\$\w+}=fopen\(\${\$\w+},"\w"\);if\(fwrite\(\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]},\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]}\)\){\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]="[\w\\\\\s]+";\1\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]}[."\s\\\\\w]+;\3\1["\\\\\w\s.]+\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]}[."<\\\\\w]+;}}fclose\(\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]}\);(break;case")[\w\\\\\s]+":\${\$\w+}=[\$_\w\["\]\\\\]+;if\(unlink\([\${}\w]+\)\){\1\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]}\.["\s\w\\\\.>]+;\3\$\w+=["\w\\\\]+;\1["\\\\\w\s.${}<]+;}\4[\w\\\\\s]+":(?:\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]}=[\$_\w\["\\\\\]]+;)+\2\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]}\)\){\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]="[\w\\\\\s]+";\1["<\w\\\\\s=.]+\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]}.["\\\\\w&.]+\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]}[."\\\\\w\s=]+;(?:\1["\w\\\\:\s\'><=\/]+;)+\3(?:\$\w+=["\w\\\\]+;)+if\(copy\(\${\$\w+},\${\$\w+}\)\){\1"[\w\\\\\s]+";\3\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]="[\w\\\\\s]+";\1"[\w\\\\\s]+"\.\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]}[."<\w>\\\\=&]+;}}\4[\w\\\\\s]+":(?:\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]}=[\$_\w\["\\\\\]]+;)+\2\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]}\)\){\1"[\w\\\\\s]+"\.\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]}[."<\w>\\\\=&]+\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]}[."\'\\\\\w\s=>]+;\1["\\\\\w:\s.\$\[\]>()_\'<\/%]+;\1["\\\\\w\s\'=>\/;]+\3if\(rename\(\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]},\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]}\)\){\1["\\\\\w:\s.\$\[\]>()_\'<\/%]+;\3\$\w+=["\w\\\\]+;\1"[\w\\\\\s]+"\.\${\$\w+}[."\\\\\w>;]+}}\4[\w\\\\\s]+":\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]}=[\$_\w\["\\\\\]]+;\${\$\w+}=[\$_\w\["\]\\\\]+;\2\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]}\)\){\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]="[\w\\\\\s]+";\1["\\\\\w\s\'.]+\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]}\.["\\\\\w=.]+\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]}\.["\\\\\w\s>]+;(?:\1["\\\\\w:\s.\$\[\]>()_\'<\/%]+;)+\1["\\\\\w\s=\'<\/;]+\3if\(rename\(\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]},\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]}\)\){\1["\\\\\w:\s.\$\[\]>()_\'<\/%]+;\3\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]="[\w\\\\\s]+";\1"[\w\\\\\s]+"\.\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]}[."<\w>\\\\=&]+;}}\4[\w\\\\\s]+":\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]}=[\$_\w\["\\\\\]]+;if\(rmdir\(\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]}\)\){\1["\\\\\w:\s.\$\[\]>()_\'<\/%]+;\3\$\w+=["\\\\\w]+;\1"[\w\\\\\s]+"\.\${\$\w+}[."\\\\\w]+;}\4[\w\\\\\s]+":\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]}=[\$_\w\["\\\\\]]+;\2\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]}\)\){(?:\1["\\\\\w\s=.\${}\[\]&\':\/<>]+;)+\3\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]="[\w\\\\\s]+";system\(\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]}\);}\4[\w\\\\\s]+":\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]}=[\$_\w\["\\\\\]]+;\2\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]}\)\){\$\w+=["\w\\\\]+;(?:\1["\\\\\w\s=.\${}\[\]&\':\/<>]+;)+\3\$\w+=["\w\\\\]+;if\(\${\$\w+}=fopen\(\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]},"\w"\)\){\1["\\\\\w\s=.\${}\[\]&\':\/<>]+;\3\$\w+=["\w\\\\]+;\1["\\\\\w\s=.\${}\[\]&\':\/<>]+;}\$\w+=["\w\\\\]+;fclose\(\${\$\w+}\);}\4[\w\\\\\s]+":\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]}=[\$_\w\["\\\\\]]+;\${\$\w+}=basename\([\$_\w\["\\\\\]]+\);\2\${\$\w+}\)\){\1["<\\\\\w\s=\'.]+\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]}\.["&\w\\\\\s=\/\-\'>]+;(?:\1["\\\\\w\s=.\${}\[\]&\':\/<>]+;)+\3\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]="[\w\\\\\s]+";if\(move_uploaded_file\(\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]},\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]}\)\){\1["\\\\\w:\s.\$\[\]>()_\'<\/%]+;unlink\(\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]}\);\3\1"[\w\\\\\s]+"\.\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]}[."<\w>\\\\=&]+;}}\4[\w\\\\\s]+":\${\$\w+}=[\$_\w\["\]\\\\]+;\2\${\$\w+}\)\){(?:\1["\\\\\w\s=.\${}\[\]&\':\/<>]+;)+\1["\\\\\w:\s.\$\[\]>()_\'<\/%]+;\1["\\\\\w\s=.\${}\[\]&\':\/<>]+;\3\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]="[\w\\\\\s]+";\$\w+=["\\\\\w]+;\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]="[\w\\\\\s]+";\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]}=explode\(":",\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]}\);if\(\(!is_numeric\(\${\$\w+}\[\d\]\)\)or\(!is_numeric\(\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]}\[\d\]\)\)\){\1["\\\\\w:\s.\$\[\]>()_\'<\/%]+;\3(?:\$\w+=["\w\\\\]+;)+\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]="[\w\\\\\s]+";\$\w+=["\w\\\\]+;(?:\${\$\w+}=\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]}\[\d\];)+\1["\\\\\w:\s.\$\[\]>()_\'<\/%]+;while\(\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]}<=\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]}\){\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]="[\w\\\\\s]+";\$\w+=["\\\\\w]+;\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]="[\w\\\\\s]+";\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]}=\d;\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]}=fsockopen\(\$\w+,\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]}\)or\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]}=\d;if\(\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]}==\d\){\$\w+=["\\\\\w]+;echo\${\$\w+}\.["\\\\\w>]+;}\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]}\+\+;fclose\(\${\$\w+}\);}}}break;}clearstatcache\(\);(?:\1["\\\\\w:\s.\$\[\]>()_\'<\/%]+;){2}\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]}=scandir\(\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]}\);foreach\(\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]}\s\w+\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]}\){if\(is_file\(\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]}\)\){(?:\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]="[\w\\\\\s]+";)+\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]}=round\(filesize\(\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]}\)\/\d+,\d\);\$\w+=["\w\\\\]+;\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]="[\w\\\\\s]+";\1["<\\\\\w>.\s=]+\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]}[."<\/\w\\\\>;]+\$\w+=["\\\\\w]+;\1["<\\\\\w>.\s=]+\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]}[."\\\\\w\s<\/>]+;\1["<\\\\\w>.\s=]+\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]}[."\\\\\w=&]+\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]}[."\\\\\w\/<>;]+\$\w+=["\\\\\w]+;\1"[\w\\\\\s]+"\.\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]}[."<\w>\\\\=&]+\${\$\w+}[.">\w\\\\\/<]+;(?:\1["\\\\\w\s=.\${}\[\]&\':\/<>]+;)+\3(?:\$\w+=["\\\\\w]+;){2}\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]}=scandir\(\${\$\w+}\);(?:\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]="[\w\\\\\s]+";){2}\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]}=count\(\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]}\)\-\d;\1"[\w\\\\\s]+"\.\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]}[."<\w>\\\\=&]+\/\w+>";\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]="[\w\\\\\s]+";\1["<\\\\\w>.\s=]+\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]}[."\\\\\w\s=<\/]+;(?:\1["\\\\\w\s=.\${}\[\]&\':\/<>]+;){3}}}\1["\\\\\w:\s.\$\[\]>()_\'<\/%]+;~msi',
            'id'   => 'darkShell',
        ],
        [
            'full' => '~(\$\w+)=\'([\w\(;\$\)=\s\[\/\]."*]+)\';(\$\w+)=(?:\1\[[-+\(\d*\/\)]+\]\.?)+;(\$\w+)=(?:\1\[[-+\(\d*\/\)]+\]\.?)+;(\$\w+)=(?:\1\[[-+\(\d*\/\)]+\]\.?)+;(\$\w+)=\s+"([\'\w\/+=]+)";(\$\w+)\.=\4;\8\.=\6;\8\.=\5;@(\$\w+)=\3\(\(\'+\),\s+\(\8\)\);@\9\(\);~msi',
            'id'   => 'wso',
        ],
        [
            'full' => '~(?:(?:@?error_reporting|@?set_time_limit)\(\d+\);\s*){1,2}function\s*class_uc_key\((\$\w{1,50})\){\s*(\$\w{1,50})\s*=\s*strlen\s*\(trim\(\1\)\);\s*(\$\w{1,50})\s*=\s*\'\';\s*for\((\$\w{1,50})\s*=\s*0;\4\s*<\s*\2;\4\+=2\)\s*{\s*\3\s*\.=\s*pack\s*\("C",hexdec\s*\(substr\s\(\1,\4,2\)\)\);\s*}\s*return\s*\3;\s*}\s*header\("\w+-\w+:\s\w+\/\w+;\s*charset=(\w+)"\);\s*(\$\w{1,50})=(?:(?:class_uc_key\("(\w+)"\)|\$\w{1,50})\.?\s*)+\.\'([\w\/\+=\\\\]+\'\)\)\);)\';\s*(\$\w{1,50})=create_function\(\'\',\6\);\9\(\);~msi',
            'id'   => 'anonymousFox',
        ],
        [
            'full' => '~(\$my_sucuri_encoding)\s{0,10}=\s{0,10}[\'"]([^\'"]+)[\'"];\s{0,10}(\$tempb64)\s{0,10}=\s{0,10}base64_decode\(\s{0,10}\1\);\s{0,10}eval\(\s{0,10}\3\s{0,10}\);~msi',
            'id'   => 'wsoEval',
        ],
        [
            'full' => '~(?:(?:(\$\w+)\s*\.?=\s*["\'][assert]+["\'];)+\s*(if\s*\(\!\@\$\w+\)\s*\{\$\w+=1;)?\s*@?\1)(\((?:\w+\()+\'[^;]+;\'\)+;(?(2)}))~msi',
            'id'   => 'assertStr',
        ],
        [
            'full' => '~(function\s\w+\(\$\w+,\$\w+,\$\w+\){return\sstr_replace\(\$\w+,\$\w+,\$\w+\);}\s?){3}(\$\w+)\s=\s\'(\w+)\';\s\2\s=\s(\w+)\(\'(\w+)\',\'\',\2\);\s(\$\w+)\s=\s\'(\w+)\';\s\6\s=\s\4\(\'(\w+)\',\'\',\6\);\s(\$\w+)\s=\s\'(\w+)\';\s\9\s=\s\4\(\'(\w+)\',\'\',\9\);\s(\$\w+)\s=\s\'(\$\w+)\';\s(\$\w+)\s=\s\6\(\12,\9\.\'\(\'\.\2\.\'\(\'\.\12\.\'\)\);\'\);\s\14\(\'(\w+)\'\);~msi',
            'id'   => 'funcVar',
        ],
        [
            'full' => '~(\$\w+)=[\'"]([\w</,\s()\$\+}\\\\\'"?\[\]{;%=^&-]+)[\'"];(\$\w+=(?:\s?\1\[\d+\](?:\s?\.?))+;)+((?:\$\w+\(\d+\);)?(\$\w+=(\$\w+)\(["\']{2},(\$\w+\(\$\w+\(["\'][=\w\+\/]+[\'"]\)\))\);\$\w+\(\);|.*?if\s?\(isset\(\${(?:\$\w+\[\d+\]\.?)+}.*?function\s\w+.*?include\s\${(?:\$\w+\[\d+\]\.?)+}\[(?:\$\w+\[\d+\]\.?)+\];\s?}))~msi',
            'id'   => 'dictionaryVars',
        ],
        [
            'full' => '~(?:(?<concatVar>\$\w+)\s?=\s?""\s?;((?:\s?(?P=concatVar)\s?\.=\s?"[\w]+"\s?;\s?)+))?(\$\w+)\s?=\s?(?:(?P=concatVar)|"(?<strVal>[\w]+)")\s?;\s?if\s?\(\s?!function_exists\s?\(\s?"(\w+)"\)\){\s?function\s\5\(\s?(\$\w+)\){\s?(?:\$\w+\s?=\s?""\s?;)?\s?(\$\w+)\s?=\s?strlen\s?\(\s?\6\s?\)\s?\/\s?2\s?;\s?for\s?\(\s?(\$\w+)\s?=0\s?;\s?\8\s?<\s?\7\s?;\s?\8\+\+\s?\)\s?{\s?\$\w+\s?\.=\s?chr\s?\(\s?base_convert\s?\(\s?substr\s?\(\s?\6\s?,\s?\8\s?\*\s?2\s?,\s?2\s?\)\s?,\s?16\s?,\s?10\s?\)\s?\)\s?;\s?}\s?return\s?\$\w+;\s?}\s?}\s?\$\w+\s?=\s?create_function\s?\(\s?null\s?,\s?\5\(\s?\3\)\)\s?;\s?\3\(\)\s?;~msi',
            'id'   => 'concatVarFunc',
        ],
        [
            'full' => '~function\s?(\w+)\(\){(((\$\w+)\.?="\w+";)+)return\seval\(\4\(\w+\(\)\)\);}function\s(\w+)\((\$\w+)\){((?:(\$\w+)\.?="\w+";)+)return\s\8\(\6\);}function\s?(\w+)\(\){((\$\w+)\.?="([\w\/+=]+)";)return\s(\w+)\(\11\);}function\s\13\((\$\w+)\){(\$\w+)=(\w+)\((\w+)\((\w+)\(\14\)\)\);return\s\15;}function\s\17\(\14\){(((\$\w+)\.?="\w+";)+)return\s\21\(\14\);}\1\(\);function\s\16\(\14\){(((\$\w+)\.?="\w+";)+)return\s\24\(\14\);}~msi',
            'id'   => 'concatVarFuncFunc',
        ],
        [
            'full' => '~(?:(?:\s?\$\w+\s?=\s?strrev\([\'"][^\'"]+[\'"]\);\s?)|(?:\s?\$\w+\s?=\s?strrev\([\'"][^\'"]+[\'"]\);\s?)|(?:\s?eval\((?:\$\w+)?\([\'"][^\'"]+[\'"]\)\);\s?)|(?:\s?eval\(\$\w+\(\$\w+\([\'"][^\'"]+[\'"]\)\)\);\s?)){3,4}~msi',
            'id'   => 'evalVarDoubled',
        ],
        [
            'full' => '~(\$\w+)\s?=\s?(\w+)\("([\w+\/=]+)"\);\s?echo\s?\1;~msi',
            'id'   => 'varFuncsEcho',
        ],
        [
            'full' => '~(\$\w+)="";\s*(?:do\s?{[^}]+}\s?while\s?\(\d+>\d+\);\s*\1=\1\."[^"]+";)?.*?\s?.*?(\$\w+)=(\'[^\']+\'\s?\.\s?(?:\'[^\']+\'\s?\.?\s?)+);\s?.*?(?:\s(\$\w+)=((?:\4\[?{?\d+\]?}?\.?)+);\s?|\$\w{1,50}->\w{1,50}\(\);)?\s*(?:function\s\w+\(\){(?:.*?);\s}\s?\1=\w+\(\1,"\w+"\);\s?|\$\w+=array\((?:\'\w+\',?)+\);\s?|\1=\w+\(\1,\sjoin\(\'\',\s\$\w+\)\s?\);\s?|\s?\$\w+\+=\d+;\s?|\1=\w+\(\1,\w+\(\)\);\s?|function\s\w+\(\){\s?|do{\s?if\s?\(\d+<\d+\)\s?{\s?)*.*?(?:\$\w+\s?=\s?\$\w+\([\'"]{2},\s?\$\w+\(\$\w+(?:\(\1\),\s?(?:\$\w+\[\'\w+\'\]\)\s?)?|\)\s?)\);\s?\$\w+\(\);)(?:\s?function\s\w+\((?:\$\w+,\s?\$\w+)?\)(?:.*?);\s}|\s?class\s\w+\s?{(?:.*?);(?:\s}){1,2})+~msi',
            'fast' => '~function\s+\w+\(\)\{\s*global\s*(\$\w+);\s*return\s*(\1[\[{]\d+[\]}]\.?){15};\s*}~msi',
            'id'   => 'varFuncsMany',
        ],
        [
            'full' => '~((\$(?:GLOBALS|{"[\\\\\w]+"})\[[\'"]\w+["\']\])\s?=\s?[\'"]+([\\\\\w]+)["\'];)\s?(?:(\$GLOBALS\[?(\s?(?:\2|\$GLOBALS\[\'\w+\'\])\[\d+\]\.?)+\])\s?=\s?\g<5>+;\s?)+(?:\g<4>\s?=\s[\$_\w]+;\s)+(?:@\g<4>\(\g<5>+\s?,\s?\w+\s?\);\s?)+@\g<4>\(\d+\);\s{0,50}(?:if\s?\(!\g<4>\s?\(\g<5>+\)\)\s{\s{0,50}\g<4>\(\g<5>+,\s\g<5>*\d*\);\s{0,50}}?\s{0,50})*(?:\$\w+\s?=\s?\w+;\s?)*\g<4>\s?=\s\g<5>+;\s?global\s?\$\w+;\s?function\s\w+\(\$\w+,\s\$\w+\)\s{\s?\$\w+\s?=\s?["\']{2};\s?for\s?\(\$\w+\s?=\d+;\s?\$\w+\s?<\s?\g<4>\(\$\w+\)\s?;\s?\)\s?{\s?for\s?\(\s?\$\w+=\d+;\s?\$\w+\s?<\s?\g<4>\(\$\w+\)\s?&&\s?\$\w+\s?<\g<4>\(\$\w+\);\s?\$\w+\+{2},\s?\$\w+\+{2}\)\s?{\s?\$\w+\s?\.=\s?\g<4>\(\g<4>\(\$\w+\[\$\w+\]\)\s?\^\s?\g<4>\(\$\w+\[\$\w+\]\)\);\s?}\s?}\s?return\s\$\w+;\s?}\s?function\s?\w+\(\$\w+,\s?\$\w+\)\s?{\s?global\s?\$\w+;\s?return\s\g<4>\(\g<4>\(\$\w+,\s?\$\w+\),\s?\$\w+\)\s?;\s?}\s?foreach\s?\(\g<4>\sas\s\$\w+=>\$\w+\)\s?{\s?\$\w+\s?=\s?\$\w+;\s?\$\w+\s?=\s?\$\w+;\s?}\s?if\s?\(!\$\w+\)\s?{\s?foreach\s?\(\g<4>\sas\s\$\w+\s?=>\s?\$\w+\)\s?{\s?\$\w+\s?=\s?\$\w+;\s?\$\w+\s?=\s?\$\w+;\s?}\s?}\s?\$\w+\s?=\s?@\g<4>\(\g<4>\(@?\g<4>\(\$\w+\),\s?\$\w+\)\);\s?if\s?\(isset\(\$\w+\[\g<5>+\]\)\s?&&\s?\$\w+==\$\w+\[\g<5>+\]\)\s?{\s?if\s?\(\$\w+\[\g<5>\]\s?==\s?\g<5>\)\s?{\s?\$\w+\s?=\s?array\(\s?\g<5>+\s?=>\s?@\g<4>\(\),\s?\g<5>+\s?=>\s?\g<5>+,\s?\);\s?echo\s?@\g<4>\(\$\w+\);\s?}\s?elseif\s?\(\$\w+\[\g<5>\]\s?==\s?\g<5>\)\s?{\s?eval\(\$\w+\[\g<5>\]\);\s?}\s?(?:exit\(\);)?\s?}\s?}?~msi',
            'id'   => 'globalArrayEval',
        ],
        [
            'full' => '~<\?php\s{0,30}(\$\w+)\s{0,30}=\s{0,30}"(.+?)";\s{0,30}((?:\$\w+\s{0,30}=\s{0,30}(?:\1\[\'\w\s{0,30}\'\s{0,30}\+\s{0,30}\d+\s{0,30}\+\s{0,30}\'\s{0,30}\w\'\]\s{0,30}\.?\s{0,30})+;\s{0,30})+)(\$\w+)\s{0,30}=\s{0,30}"(\d+)";\s{0,30}(?:\$\w+\s{0,30}=\s{0,30}\$\w+\(\s{0,30}\$\w+\s{0,30},\s{0,30}\$\w+\(\s{0,30}"\s{0,30}"\)\s{0,30},\s{0,30}"[\w\+]+"\)\s{0,30};\s{0,30})+(?:\$\w+\s{0,30}=\s{0,30}\$\w+\(\s{0,30}\$\w+\(\s{0,30}\$\w+\)\s{0,30},\s{0,30}\$\w+\(\s{0,30}?\$\w+\)\s{0,30}\)\s{0,30};\s{0,30})+\$\w+\((?:\s{0,30}\$\w+\(\s{0,30}"\s{0,20}\w\s{0,20}"\)\s{0,30}\.?\s{0,30})+"\(\\\\"\w+\\\\"\s{0,30},\s{0,30}"\s{0,30}\.\s{0,30}\$\w+\(\s{0,30}\$\w+\(\s{0,30}"\d+"\s{0,30},\s{0,30}\$\w+\(\s{0,30}"\s{0,20}"\)\s{0,30},\s{0,30}"[\d\w=]+"\)\s{0,30}\)\s{0,30}\.\s{0,30}"\s{0,30}\)\s{0,30};"\)\s{0,30};\s{0,30}\$\w+\s{0,30}=\s{0,30}\$\w+\(\w+\)\s{0,30};\s{0,30}\$\w+\(\s{0,30}(?:\$\w+\(\s{0,30}"\s{0,30}[?>]\s{0,30}"\)\s{0,30}\.\s{0,30})+(\$\w+)\(\s{0,30}(\$\w+)\(\s{0,30}(\$\w+),\s{0,30}(\$\w+)\(\s{0,30}"\s{0,30}"\)\s{0,30},\s{0,30}(\$\w+)\(\s{0,30}"([()\w@|*#\[\]&\/\+=]+)"\s{0,30},\s{0,30}(\$\w+),\s{0,30}(\$\w+)\)\s{0,30}\)\)\s{0,30}\)\s{0,30};\s{0,30}\$\w+\s?=\s?\d+\s?;\s{0,30}\?>~msi',
            'id'   => 'tinkleShell',
        ],
        [
            'full' => '~(?:\$\w+="\w+";)+(\$\w+)="([\w_)(;\/\.*]+)";\$\w+="\w+";function\s(\w+)\((?:\$\w+,?){3}\){return\s?""(?:\.\$\w+\.""){3};}(?:\$\w+=(?:(?:"\w+")|(?:\3\((?:\1\[\d+\],?\.?)+\))|(?:(?:\3\()+(?:\$\w+\,?(?:\)\,)?)+)(?:(?:(?:\3\()+)*(?:(?:\$\w+,?)+)*(?:\),)*(?:\)*))+);)+\$\w+=\3\((?:\1\[\d+\]\.?)+(?:,"")+\);(?:\$\w+=\3\(\3\(\$\w+,\$\w+,\$\w+\),\3\((?:\$\w+,?)+\),\3\(\$\w+,\3\(\$\w+,\$\w+,""\),\$\w+\)\)\."\'(?<str>[\w\/\+]+)\'")\.\3\((?:\1\[\d+\],?\.?)+\);\$\w+\(\$\w+,array\("","}"\.\$\w+\."\/+"\)\);~msi',
            'id'   => 'wsoFunc',
        ],
        [
            'full' => '~\$\w+\[\'\w+\'\]\s?=\s?"[\w;\/\.*)(]+";\s?\$\w+\[\'\w+\'\]\s?=\s?(?:\$\w+\[\'\w+\'\]\[\d+\]\.?)+;\s?\$\w+\s?=\s?(?:"[\w()]*"\.chr\([\d-]+\)\.?)+"\(";\s?\$\w+\s?=\s?"[)\\\\\w;]+";\s?\$\w+\s?=\s?\$\w+\."\'(?<str>[\w\/\+]+)\'"\.\$\w+;\s?\$\w+\[\'\w+\'\]\((?:\$\w+\[\'\w+\'\]\[\d+\]\.?)+,\s?\$\w+\s?,"\d+"\);~msi',
            'id'   => 'wsoFunc',
        ],
        [
            'full' => '~function\s(\w+)\((\$\w+)\)\s{0,50}{\s{0,50}\2=gzinflate\(base64_decode\(\2\)\);\s{0,50}for\((\$\w+)=\d+;\3<strlen\(\2\);\3\+\+\)\s{0,50}{\s{0,50}\2\[\3\]\s?=\s?chr\(ord\(\2\[\3\]\)-(\d+)\);\s{0,50}}\s{0,50}return\s?\2;\s{0,50}}\s{0,50}eval\(\1\([\'"]([\w\+\/=]+)[\'"]\)\);~msi',
            'id'   => 'evalWanFunc',
        ],
        [
            'full' => '~(?:(?:if\s?\(file_exists\("\w+"\)\)\s?{\s?}\s?else\s?{\s?)?\$\w+\s?=\s?fopen\([\'"][^\'"]+\.php[\'"],\s?[\'"]w[\'"]\);)?\s?(\$\w+)\s?=\s?(?:base64_decode\()?[\'"]([^\'"]+)[\'"]\)?;\s?(?:\$\w{1,50}\s?=\s?fopen\([\'"][^\'"]+[\'"],\s?[\'"]\w[\'"]\);\s?)?(?:echo\s?)?fwrite\(\$\w{1,50}\s?,(?:base64_decode\()?\$\w{1,50}\)?\);\s?fclose\(\$\w{1,50}\);\s?}?~msi',
            'id'   => 'funcFile',
        ],
        [
                'full' => '~(\$(?:GLOBALS\[\')?\w+(?:\'\])?\s{0,100}=\s{0,100}array\(\s{0,100}(?:\s{0,100}\'[^\']+\'\s{0,100}=>\s{0,100}\'?[^\']+\'?,\s{0,100})+\s{0,100}\);\s{0,100}((?:\$\w+=(?:[\'"][^\'"]*[\'"]\.?)+;)+)?(?:if\(!\$?\w+\((?:\'\w*\'\.?|\$\w+)+\)\){function\s{0,100}\w+\(\$\w+\){.*?else{function\s{0,100}\w+\(\$\w+\){.*?return\s{0,100}\$\w+\(\$\w+\);\s?}}){2})\$\w+=(?:\'\w*\'\.?)+;\s?(\$\w+)\s{0,100}=\s{0,100}@?\$\w+\(\'\$\w+\',(?:\$\w+\.\'\(.\.\$\w+\.(?:\'[\w(\$);]*\'\.?)+\)|(?:\'[^\']+\'\.?)+\));.*?\3\([\'"]([^"\']+)[\'"]\);~msi',
            'id'   => 'gulf',
        ],
        [
            'full' => '~(\$\w+)=(\w+);\$\w+="(.+?)";(?:\$\w+=\$\w+;)?(\$\w+)=strlen\(\$\w+\);(\$\w+)=[\'"]{2};for\((\$\w+)=\d+;\6<\4;\6\+\+\)\s?\5\s?\.=\s?chr\(ord\(\$\w+\[\6\]\)\s?\^\s?\1\);eval\("\?>"\.\5\."<\?"\);~msi',
            'id'   => 'evalConcatAsciiChars',
        ],
        [
            'full' => '~(?:\$\w+="[\w=]+";\s?)+(\$\w+)\s?=\s?str_replace\((?:"\w*",?)+\);\s?(\$\w+)\s?=\s?\1\((?:"\w*",?\s?)+\);\s?(\$\w+)\s?=\s?\1\((?:"\w*",?)+\);\s?(\$\w+)\s?=\s?\3\("",\s?(\2\(\2\((\1\("([#;*,\.]+)",\s?"",\s?((?:\$\w+\.?)+)\))\)\))\);\s?\4\(\);~msi',
            'id'   => 'evalPost',
        ],
        [
            'full' => '~\$\w+\s?=\s?"e\/\*\.\/";\spreg_replace\(strrev\(\$\w+\),"([\\\\\w]+)\'([\w\/\+=]+)\'([\\\\\w]+)","\."\);~msi',
            'id'   => 'evalPregStr',
        ],
        [
            'full' => '~\$GLOBALS\[\'\w+\'\]=array\(\'preg_re\'\s?\.\'place\'\);\s?function\s\w+\(\$\w+\)\s?{\$\w+=array\("\/\.\*\/e","([\\\\\w]+)\'([\w\/\+]+)\'([\\\\\w]+)","{2}\);\s?return\s\$\w+\[\$\w+\];}\s?\$GLOBALS\[\'\w+\'\]\[\d+\]\(\w+\(\d+\),\w+\(\d+\),\w+\(\d+\)\);~msi',
            'id'   => 'evalPregStr',
        ],
        [
            'full' => '~class\s?\w+{\s?function\s?__destruct\(\){\s?\$this->\w+\(\'([\w&]+)\'\^"([\\\\\w]+)",array\(\(\'([#\w]+)\'\^"([\\\\\w]+)"\)\."\(base64_decode\(\'([\w\+\/=]+)\'\)\);"\)\);\s?}\s?function\s?\w+\(\$\w+,\$\w+\){\s?@array_map\(\$\w+,\$\w+\);\s?}\s?}\s?\$\w+\s?=\s?new\s?\w+\(\);~msi',
            'id'   => 'classDestructFunc',
        ],
        [
            'full' => '~\$\w+="([\\\\\w]+)";\s?\$\w+=\$\w+\(\'([\w\+\/=]+)\'\);\s?\$\w+\s?=\s?"([\\\\\w]+)";\s?\$\w+\s?=\s?\$\w+\([\'"]{2}.\s?eval\(\$\w+\)\);\s?\$\w+\([\'"]{2}\);~msi',
            'id'   => 'createFuncEval',
        ],
        [
            'full' => '~((\$\w+)="([\w-]+)";\s*(?:\$\w+=\'\d+\';\s*)*\s*((?:\$\w+=(?:\2{\d+}\.?)+;)+)+)(?:header[^\)]+\);)?(?:\$\w+=)?(\$\{"[GLOBALSx0-9a-f\\\\]+"})(.+?((.+?\5).+?)+)"[^"]+"\]\(\);~msi',
            'id'   => 'dictionaryCreateFuncs',
        ],
        [
            'full' => '~(\$\w+)\s?=\s?"([\w\s=]+)";\s?(\$\w+)\s?=\s?array\(((?:\d+,?\s?)+)\);\s?(\$\w+)\s?=\s?array\(((?:"[\w\d\s\/\.]+",?\s?)+)\);\s?(\$\w+)\s?=\s?\'\';\s?(?:\$\w+\s=(?:\s?\5\[\d+\]\s?\.?)+;\s?)+(\$\w+)\s?=\s?\$\w+\("\\\\r\\\\n",\s?\1\);\s?for\((\$\w+)=0;\9\s?<\s?sizeof\(\8\);\9\+\+\){\s?\7\s\.=\s?\$\w+\(\8\[\9\]\);\s?}\s?\1\s?=\s?\7;\s?(\$\w+)\s?=\s?\3;\s?(\$\w+)\s?=\s?"";\s?for\((\$\w+)=0;\s?\12<sizeof\(\10\);\s?\12\+=2\){\s?if\(\12\s?%\s?4\){\s?\11\.=\s?substr\(\1,\10\[\12\],\10\[\12\+1\]\);\s?}else{\s?\11\.=strrev\(substr\(\1,\10\[\12\],\10\[\12\+1\]\)\);\s?}\s?};\s?\1\s?=\s?\$\w+\(\11\);\s(\$\w+)\s?=\s?array\(\);\s?(\$\w+)\s?=\s?(?:\5\[\d+\]\s?\.?\s?;?)+;\s?(\$\w+)\s?=\s?(?:\5\[\d+\]\s?\.?\s?)+;\s?(\$\w+)\s?=\s?\'\';\s?for\((\$\w+)=0;\s?\17<strlen\(\1\);\s?\17\+=32\){\s?\13\[\]\s?=\s?substr\(\1,\s?\17,\s?32\);\s?}\s?(?:\$\w+\s?=\s?(?:\5\[\d+\]\s?\.?\s?)+;\s)+\$\w+\s?=\s?\'\';\s?\$\w+\s?=\s?\(\$\w+\(\$\w+\(\$\w+\)\)\)\s?%\s?sizeof\(\$\w+\);\s?\$\w+\s?=\s?\$\w+\[\$\w+\];\s?(\$\w+)\s?=\s?(?:\5\[\d+\]\s?\.?\s?)+;(\s?\18\s?=\s?\$_POST\[\18\];\s?(\14\s?=\s?\15\(\$_COOKIE\[\14\]\);)\s?\$\w+\s?=\s?\5\[\d+\]\s?\.\s?\5\[\d+\];\s?(eval\(\$\w+\(\18\)\);)\s?if\(!\16\){\s?((?:\$\w+\s?=\s?(?:\5\[\d+\]\s?\.?\s?)+;\s)+)(\$\w+\(\$\w+\);\s?echo\(\$\w+\);)\s?})~msi',
            'fast' => '~(\s?(\$\w+)\s?=\s?\$_POST\[\2\];\s?((\$\w+)\s?=\s?\$\w+\(\$_COOKIE\[\4\]\);)\s?(\$\w+)\s?=\s?(\$\w+)\[\d+\]\s?\.\s?\6\[\d+\];\s?(eval\(\$\w+\(\2\)\);)\s?if\(!\5\){\s?((?:\$\w+\s?=\s?(?:\6\[\d+\]\s?\.?\s?)+;\s)+)(\$\w+\(\$\w+\);\s?echo\(\$\w+\);)\s?})~msi',
            'id'   => 'evalPostDictionary',
        ],
        [
            'full' => '~(\$\w)\s?=\s?str_rot13\("([^"]+)"\);preg_replace\("//e","\1",""\);~msi',
            'id'   => 'strrotPregReplaceEval',
        ],
        [
            'full' => '~(\$\w+)\s*=\s*[^\']+\'([^\']+)\';\s*(\$\w+)\s*=\s*\'([^\']+)\';\s*if\(!file_exists\(\$file\)+\{\s*@file_put_contents\(\1,base64_decode\(base64_decode\(\3\)+;\s*\}\s*\@include\s*\$file;~msi',
            'id'   => 'dropInclude',
        ],
        [
            'full' => '~(?(DEFINE)(?\'c\'(?:/\*[^/]*/?\*/)*))(?&c)@?(eval|echo|(\$\w+)\s*=\s*create_function)(?:\/\*+\/)?\s*(?&c)\((?&c)(\'\',)?\s*([\'"?>.\s]+)?\s*\(?\s*@?\s*((?&c)base64_decode(?&c)\s*\((?&c)|(?&c)pack(?&c)\s*\(\'H\*\',|(?&c)convert_uudecode(?&c)\s*\(|(?&c)htmlspecialchars_decode(?&c)\s*\(|(?&c)stripslashes(?&c)\s*\(|(?&c)gzinflate(?&c)\s*\(|(?&c)strrev(?&c)\s*\(|(?&c)str_rot13(?&c)\s*\(|(?&c)gzuncompress(?&c)\s*\(|(?&c)urldecode(?&c)\s*\(|(?&c)rawurldecode(?&c)\s*\(|(?&c)eval(?&c)\s*\()+.*?[^\'")]+(?&c)(((?&c)\s*(?&c)\.?(?&c)[\'"]((?&c)[^\'";]+(?&c)[\'"](?&c)*\s*)+(?&c))?(?&c)\s*[\'"\);]+(?&c))+(?&c)(\s*\2\(\);(?&c))?~msi',
            'id'   => 'evalComments',
        ],
        [
            'full' => '~\@?error_reporting\(0\);\@?set_time_limit\(0\);(?:\s*rename\([^;]+;)?\s*(\$\w+)="([^"]+)";\s*\1=\@?urldecode\(\1\);\1=\@?strrev\(\1\);\@?eval\(\1\);~msi',
            'id'   => 'strrevUrldecodeEval',
        ],
        [
            'full' => '~(\$\w+\s*=\s*"\w+";\s*\@?error_reporting\(E_ERROR\);\s*\@?ini_set\(\'display_errors\',\'Off\'\);\s*\@?ini_set\(\'max_execution_time\',\d+\);\s*header\("[^"]+"\);\s*)?(\$\w+)\s*=\s*"([^"]+)";\s*(\$\w+)\s*=\s*pack\("H\*",str_rot13\(\2\)+;\s*(?:eval\(\4\);|(\$\w+)=\$\w+\(\'\',\4\);\s*\5\(\);)~msi',
            'id'   => 'evalPackStrrot',
        ],
        [
            'full' => '~\$\w+\s*=\s*\d+;\s*function\s*(\w+)\(\$\w+,\s*\$\w+\)\{\$\w+\s*=\s*\'\';\s*for[^{]+\{([^}]+\}){2}\s*\$\w{1,40}\s*=\s*((\'[^\']+\'\s*\.?\s*)+);\s*\$\w+\s*=\s*Array\(((\'\w\'=>\'\w\',?\s*)+)\);\s*eval(?:/\*[^/]\*/)*\(\1\(\$\w+,\s*\$\w+\)+;~msi',
            'id'   => 'urlDecodeTable',
        ],
        [
            'full' => '~((?:\$\w+=\'\w\';)+)((?:\$\w+=(\$\w+\.?)+;)+)eval\((\$\w+\()+\'([^\']+)\'\)+;~msi',
            'id'   => 'evalVarChar',
        ],
        [
            'full' => '~(\$\w+\s*=\s*(base64_decode\s*\(|gzinflate\s*\(|strrev\s*\(|str_rot13\s*\(|gzuncompress\s*\(|urldecode\s*\(|rawurldecode\s*\(|htmlspecialchars_decode\s*\()+"([^"]+)"\);)\s*eval\("?(\$\w+)"?\);~msi',
            'id'   => 'evalVarFunc',
        ],
        [
            'full' => '~((?:\$\w+\s*=\s*("[\w=+/\\\\]+");\s*)+)(eval\((\$\w+\(+)+(\$\w+)\)+);~msi',
            'id'   => 'evalVarsFuncs',
        ],
        [
            'full' => '~<\?php\s*(?:/\*[^=\$\{\}/]{99,499}\bencipher\s*can\s*be\s*obtained\s*from:\s*https?://docs\.google\.com/[^\*\$\(;\}\{=]{1,99}\*/\s*)?(\$[^\w=(,${)}]{0,50})=\'(\w{0,50})\';((?:\$[^\w=(,${)}]{0,50}=(?:\1{\d+}\.?){0,50};){1,20})(\$[^=]{0,50}=\$[^\w=(,${)}]{1,50}\(\$[^\w=(,${)}]{1,50}\(\'\\\\{2}\',\'/\',__FILE__\)\);(?:\$[^\w=(,${)}]{0,50}=\$[^\w=(,${)}]{0,50}\(\$[^\w=(,${)}]{0,50}\);){2}\$[^\w=(,${)}]{0,50}=\$[^\w=(,${)}]{0,50}\(\'\',\$[^\w=(,${)}]{0,50}\)\.\$[^\(]{0,50}\(\$[^\w=(,${)}]{0,50},\d+,\$[^\w=(,${)}]{0,50}\(\$[^\w=(,${)}]{0,50},\'@ev\'\)\);\$[^\w=(,${)}]{0,50}=\$[^\(]{0,50}\(\$[^\w=(,${)}]{0,50}\);\$[^\w=(,${)}]{0,50}=\$[^\w=(,${)}=]{0,50}=\$[^\w=(,${)}]{0,50}=NULL;@eval\(\$[^\w=(,${)}]{0,50}\(\$[^\w=(,${)}(]{0,50}\(\$[^\w=(,${)}]{0,50},\'\',\$[^\w=(,${)}]{0,50}\(\'([^\']{0,500})\',\'([^\']{0,500})\',\'([^\']{0,500})\'\){4};)unset\((?:\$[^,]{0,50},?){0,20};return;\?>.+~msi',
            'id'   => 'evalFileContent',
        ],
        [
            'full' => '~echo\s{0,50}"(\\\\\${\\\\x\d{2}(?:[^"]+(?:\\\\")*)*[^"]+)";~msi',
            'id'   => 'echoEscapedStr',
        ],
        [
            'full' => '~file_put_contents\(\$\w+\[[\'"]\w+[\'"]\]\.[\'"][/\w]+\.php[\'"],(base64_decode\([\'"]([\w=]+)[\'"]\))\)~msi',
            'id'   => 'filePutDecodedContents',
        ],
        [
            'full' => '~eval\(implode\(array_map\([\'"](\w+)[\'"],str_split\([\'"]([^\'"]+)[\'"]\)\)\)\);~msi',
            'id'   => 'evalImplodedArrStr',
        ],
        [
            'full' => '~(\$\w+)\s?=\s?\'(.*?NULL\);)\';\s*(\$\w+)\s?=\s?[\'"]([\w\\\\]+)[\'"];\s?\3\([\'"]/\(\.\*\)/e[\'"],\s?[\'"]([\w\\\\]+)[\'"],\s?NULL\);~msi',
            'id'   => 'pregReplaceCodeContent',
        ],
        [
            'full' => '~(\$\w+)\s*=\s*"([^"]+)";(?:\$\w+)\s*=\s*base64_decode\("[^"]+"\);(\$\w+)\s*=\s*gzinflate\(base64_decode\(\1\)\);((\s*\$\w+\s*=\s*\[(\'[^\']+\',?)+\];)+)\s*\3\s*=\s*str_replace\(\$\w+,\$\w+,\3\);\s*eval\(\3\);\$\w+="[^"]+";~msi',
            'id'   => 'sistemitComEnc',
        ],
        [
            'full' => '~((?:\$\w+\s*\.?=\s*"[^"]*";\s*)+)(\$\w+)\s*=\s*str_replace\(\s*"([^"]+)",\s*"",\s*\$\w+\s*\);\s*(\$\w+)\s*=\s*str_replace\(\s*"([^"]+)",\s*"",\s*"([^"]+)"\s*\);\s*(\$\w+)\s*=\s*\4\(\s*\2\s*\);\s*\7\s*=\s*"[^"]+\7";\s*eval\(\s*\7\s*\);~msi',
            'id'   => 'concatVarsReplaceEval',
        ],
        [
            'full' => '~(\$\w{1,50})\s?=\s?file_get_contents\(__FILE__\);\s?\1\s?=\s?base64_decode\(substr\(\1,\s?([+-]\d+)\)\);\s*\1\s?=\s?gzuncompress\(\1\);\s*eval\(\1\);\s*die\(\);\?>\s*([^"\']+)~msi',
            'fast' => '~\$\w{1,50}\s?=\s?file_get_contents\(__FILE__\);\s?\$\w{1,50}\s?=\s?base64_decode\(substr\(\$\w{1,50},\s?([+-]\d+)\)\);\s*\$\w{1,50}\s?=\s?gzuncompress\(\$\w{1,50}\);\s*eval\(\$\w{1,50}\);\s*die\(\);\?>\s*([^"\']+)~msi',
            'id' => 'decodeFileContent',
        ],
        [
            'full' => '~((\$\w+\s*=\s*\(?(base64_decode\s*\(|gzinflate\s*\(|strrev\s*\(|str_rot13\s*\(|gzuncompress\s*\(|urldecode\s*\(|rawurldecode\s*\(|htmlspecialchars_decode\s*\()*((?:"([^"]+)";\s*)|(?:\$\w+)\)*;\s*))+)(eval\("?(\$\w+)"?\);)~msi',
            'id'   => 'evalVarFunc2',
        ],
        [
            'full' => '~((\$\w+)\s*=\s*"([^"]+)";)\s*((\$\w+)\s*=\s*array\(((\s*\d+,?)+)\);)\s*((\$\w+)\s*=\s*array\(((\s*"[^"]+",?)+)\);)\s*(\$\w+)\s*=\s*\'\';(\s*\$\w+\s*=\s*(?:\9\[\d+\]\s*\.?\s*)+;)+(.+?(\s*\$\w+\s*=\s*\w+\((?:\9\[\d+\]\s*\.?\s*)+)\);\s*eval\(\$\w+\);\s*\})~msi',
            'fast' => '~((\s*(\$\w+)\s*=\s*\w+\((\$\w+)\[\d+\]\s*\.\s*(?:\4\[\d+\]\s*\.?\s*)+)\);\s*eval\(\3\);\s*\})~msi',
            'id'   => 'evalArrays',
        ],
        [
            'full' => '~\$\w+\s?=\s?preg_replace\([\'"]/([^\'"/]+)/\w{0,2}[\'"],[\'"]([^\'"]+)[\'"],[\'"]{2}\);~msi',
            'id'   => 'pregReplaceVar',
        ],
        [
            'full' => '~function\s(\w+)\((\$\w+),\s?(\$\w+)\){\s?(\$\w+)=[\'"]{2};\s?for\(\$\w+=0;\$\w+<strlen\(\2\);\)\s?for\(\$\w+=0;\$\w+<strlen\(\3\);\$\w+\+\+,\s?\$\w+\+\+\)\s?\4\s?\.=\s?\2{\$\w+}\s?\^\s?\3{\$\w+};\s?return\s?\4;\s?};eval\(\1\(base64_decode\([\'"]([^\'"]+)[\'"]\),[\'"]([^\'"]+)[\'"]\)\);~msi',
            'id'   => 'evalFuncTwoArgs',
        ],
        [
            'full' => '~function\s(\w+)\(\$\w+\)\s?{\s?\$\w+\s?=\s?[\'"]{2};\s?unset\(\$\w+\);\s?\$\w+\s?=\s?[\'"]([^\'"]+)[\'"];\s?\$\w+\s?=\s?preg_replace\("/([^"]+)/",\s?[\'"]{2},\s?\$\w+\);\s?\$\w+\s?=\s?(?:(?:[\'"]\w+[\'"]|\$\w+)\.?)+;\s?\$\w+\s?=\s?\$\w+\([\'"]\$\w+[\'"],\s?\$\w+\);\s?@?\$\w+\(\$\w+\);\s?}\s?function\s?(\w+)\(\$\w+\)\s?{\s?\$\w+\s?=\s?[\'"](.*?)[\'"];\s?\$\w+\s?=\s?preg_replace\("/([^\'"]+)/",\s?[\'"]{2},\s?\$\w+\);\s?return\s?\$\w+\(\$\w+\);\s?}\s?\1\(\4\(\s?join\([\'"]([^\'"]+)[\'"],\s?array\(((?:[\'"][^\'"]+[\'"][,\s]*)+)\)+;~msi',
            'id'   => 'evalPregReplaceFuncs',
        ],
        [
            'full' => '~error_reporting\(0\);((?:\$\w+=\'[^;]+;)+)error_reporting\(0\);((?:\$\w+=\$\w+\(\$\w+\(\'([^\']+)\'\)\);)+\$\w+=(?:\$\w+\()+\'([^\']+)\'\)+\.(?:\$\w+\()+\'([^\']+)\'\)+;\$\w+=(?:\$\w+\()+\'([^\']+)\'\)+;\$\w+=(?:\$\w+\()+"\\\\n",\s*\'\',\s*\'([^\']+)\'\)+;(?:[^}]+\})+}\s*echo\s*(?:\$\w+\()+\'([^\']+)\'\)+);exit;~msi',
            'id'   => 'urlMd5Passwd',
        ],
        [
            'full' => '~((?:\$\w+\s?=\s?\'(?:[^\']+)\';\s?)+)((?:\$\w+\s?=\s?(?:\$\w+(?:\[[\'"]?\d+[\'"]?\])?\s?\.?\s?)+;)+\$\w+\s?=\s?\$\w+\s?\(\$\w+,(?:\$\w+(?:\[[\'"]?\d+[\'"]?\])?\s?\.?\s?)+\);\s*\$\w+\(\$\w+,(?:\$\w+(?:\[[\'"]?\d+[\'"]?\])?\s?[.,]?\s?)+\);)~msi',
            'fast' => '~((?:\$\w+\s?=\s?(?:\$\w+(?:\[[\'"]?\d+[\'"]?\])?\s?\.?\s?)+;)+\$\w+\s?=\s?\$\w+\s?\(\$\w+,(?:\$\w+(?:\[[\'"]?\d+[\'"]?\])?\s?\.?\s?)+\);\s*\$\w+\(\$\w+,(?:\$\w+(?:\[[\'"]?\d+[\'"]?\])?\s?[.,]?\s?)+\);)~msi',
            'id'   => 'ManyDictionaryVars',
        ],
        [
            'full' => '~function\s(\w+)\(\$\w+\)\s?{\s?\$\w+\s?=\s?(?:[\'"][\\\\\w]+[\'"]\(\d+\s?[-+]\s?\d+\)\s?\.?\s?)+;\s?(?:\$\w+\s?=\s?\$\w+\([\'"](?:edoced_46esab|etalfnizg|ecalper_rts)[\'"]\);\s?)+\$\w+\s?=\s?\$\w+\(array\(((?:\s?"[^"]+",?)+)\),\s?[\'"]{2},\s?\$\w+\);\s?return\s?(?:\$\w+\(){2}\$\w+\)\);\s?}\s?(\$\w+\s?=\s?[\'"]\w+[\'"];)?\s?ob_start\(\);\s?\?>(.*?)<\?php\s?\$\w+\s?=\s?ob_get_clean\(\);\s?eval\(\1\(\$\w+\)\);\s?\?>~msi',
            'id'   => 'evalBuffer',
        ],
        [
            'full' => '~((?:\$\w+\s?=\s?[\'"]\w*[\'"];\s?){0,50}(\$\w+)\s?=\s?[\'"]([^\'"]+)[\'"];(?:\$\w+\s?\.?=\s?(?:\$\w+{\d+}\.?)+;)+)\s?(eval\((\$\w+)\([\'"]([^\'"]+)[\'"]\)\);)~msi',
            'id' => 'evalDictionaryVars',
        ],
        [
            'full' => '~\$\w+\s?=\s?[\'"]([^\'"]+)[\'"];(?:\$\w+\s?=\s?base64_decode\([\'"][^\'"]+[\'"]\);)+\$\w+\s?=\s?\$\w+\(\$\w+\(\$\w+\)\);\$\w+\s?=\s?\$\w+\(\$\w+\);(\$\w+)\s?=\s?[\'"]{2};for\(\$\w+\s?=\s?0\s?;\s?\$\w+\s?<\s?\$\w+\s?;\s?\$\w+\+\+\){\2\s?\.=\s?\$\w+\(\(\$\w+\(\$\w+\[\$\w+\]\)\^(\d+)\)\);}eval\(\2\);return;~msi',
            'id' => 'evalFuncXored',
        ],
        [
            'full' => '~[\'"]-;-[\'"];(.*?\(\'\\\\\\\\\',\'/\',__FILE__\)\);.*?,[\'"];[\'"]\),[\'"]"[\'"]\);.*?)[\'"]-;-[\'"];((\$\w+)=[\'"]([^\'"]+)[\'"];.*?\$\w+\s?\.\s?\3,\s?[\'"]([^\'"]+)[\'"],\s?[\'"]([^\'"]+)[\'"]\)\)\).*?)[\'"]-;-[\'"];(.*?)[\'"]-;-[\'"];~msi',
            'id' => 'evalFuncExplodedContent',
        ],
        [
            'full' => '~(\$\w{0,100}\s?=\s?(?:chr\(\w{1,10}\)\s?\.?\s?){1,100};\s?(?:\$\w{0,100}\s?=\s?(?:\s?(?:[\'"][\\\\\w]{1,10}[\'"]|[\d\.]{1,5}\s[*\+\-\.]\s\d{1,5})\s?\.?)+?;\s?){1,10}(?:\$\w{0,100}\s?=\s?(?:chr\(\w{1,10}\)\s?\.?){1,100};)?\s?\$\w{1,50}\s?=\s?\$\w{1,50}\(\$\w{1,50}\((?:[\'"][^\'"]{1,500}[\'"]\s?\.?\s?)+\),\s?(?:[\'"][^\'"]{1,500}[\'"]\s?\.?\s?)+,\s?substr\(hash\([\'"]SHA256[\'"],(?:\s?[\'"]\d{1,15}[\'"]\s?\.?){2},\s?true\),\s?(\d{1,10}),\s?(\d{1,10})\),\s?OPENSSL_RAW_DATA,\s?\$\w{1,50}\);.*?)(\$\w{1,50})\s?=\s?\$\w{1,50}\([\'"]([^\'"]+)[\'"],\s*[\'"]{2},\s*[\'"]([^\'"]+)[\'"]\);\s?return\s?@eval\(((?:\$\w{1,50}\s?\()+\$\w{1,50}(?:\)\s?)+);\s?exit;~msi',
            'id' => 'evalEncryptedVars',
        ],
        [
            'full' => '~function\s(\w+)\((\$\w+),\s*(\$\w+)[^)]+\)\s*\{\s*\$\w+\s*=\s*\2;\s*\$\w+\s*=\s*\'\';\s*for\s*\(\$\w+\s*=\s*0;\s*\$\w+\s*<\s*strlen\(\$\w+\);\)\s*{\s*for\s*\(\$\w+\s*=\s*0;\s*\$\w+\s*<\s*strlen\(\3\)\s*&&\s*\$\w+\s*<\s*strlen\(\$\w+\);\s*\$\w+\+\+,\s*\$\w+\+\+\)\s*{\s*\$\w+\s*\.=\s*\$\w+\[\$\w+\]\s*\^\s*\3\[\$\w+\];\s*}\s*}\s*return \$\w+;\s*}\s*\$\w+\s*=\s*["\'][^"\']+[\'"];\s*\$\w+\s*=\s*[\'"]([^\'"]+)["\'];\s*(?:\$\w+\s*=\s*["\']+;\s*)+(?:foreach[^{]+{[^}]+}\s*)+(\$\w+)\s*=\s*\$\w+\([create_funion\'. "]+\);\s*(\$\w+)\s*=\s*\5\(["\'][^"\']*[\'"],\s*\$\w+\(\1\(\$\w+\(\$\w+\),\s*["\']([^\'"]+)["\']\)+;\s*\6\(\);~msi',
            'id' => 'xoredKey',
        ],
        [
            'full' => '~(\$\w+)=str_rot13\(\'[^\']+\'\);(\$\w+)=str_rot13\(strrev\(\'[^\']+\'\)\);(\s*eval\(\1\(\2\(\'([^\']+)\'\)+;)+~msi',
            'id' => 'evalGzB64',
        ],
        [
            'full' => '~(function\s*(_\d+)\((\$\w+)\)\s*{(\$\w+)=Array\(\'[^)]+\'\);return\s*base64_decode\(\4\[\3\]\);\})(.+?\2\(\d+\))+[^;]+;exit;~msi',
            'id' => 'evalArrayB64',
        ],
        [
            'full' => '~http_response_code\(\d{1,3}\);function\s?(\w{1,100})\(\$\w{1,50}\){if\s?\(empty\(\$\w{1,50}\)\)\s?return;\$\w{1,50}\s?=\s?"[^"]{1,500}";(?:(?:\$\w{1,50}\s?=\s?[\'"]{0,2}){1,4};){1,2}\$\w{1,50}\s?=\s?0;\$\w{1,50}\s?=\s?"";\$\w{1,50}\s?=\s?preg_replace\("[^"]{1,50}",\s?"",\s?\$\w{1,50}\);do{.*?while\s?\(\$\w{1,50}\s?<\s?strlen\(\$\w{1,50}\)\);return\s?\$\w{1,50};}eval\(\1\(hex2bin\("(\w{1,30000})"\)\)\);~msi',
            'id' => 'evalFuncBinary',
        ],
        [
            'full' => '~(\$\w{1,50}\s?=\s?\'\w{1,500}\';){1,5}\$\w{1,50}\s?=\s?(?:\$\w{1,50}\.?){1,10};\$\w{1,50}=\$\w{1,50}\([\'"]H\*[\'"],[\'"](\w{1,200})[\'"]\);\s?\$\w{1,50}\("[^"]{1,100}","(\\\\x[^\']{1,500})(\'[^\']{1,50000}\')\\\\x[^"]{1,50}",[\'"]{2}\);~msi',
            'id' => 'evalPackFuncs',
        ],
        [
            'full' => '~parse_str\s*\(((?:\s?\'[^\']+\'\s?\.?\s?){1,500}),\s?(\$\w{1,50})\s?\)\s?;@?\s?\2\s?\[\s?\d{1,5}\s?\]\(\s?\2\s?\[\d{1,5}\]\s?,\s?array\s?\(\s?\)\s?,\s?array\s?\(\s?\'([^\']{1,10})\'\s?\.(\$\w{1,50}\s?\[\s?\d\s?\]\s?\(\s?\$\w{1,50}\s?\[\s?\d\s?\]\s?\(\s?\$\w{1,50}\s?\[\s?\d{1,2}\s?\]\s?\(\s?)(\'[^\']{1,50000}\'\s?)\)\)\)\.\s?\'([^\']{1,10})\'\s?\)\s?\)\s?;~msi',
            'id' => 'parseStrFunc',
        ],
        [
            'full' => '~eval\("\\\\(\$\w+)=(gz[^\)]+\)\);)"\);eval\("\?>"\.\1\);~msi',
            'id' => 'evalGzinflate',
        ],
        [
            'full' => '~function\s?(\w{1,50})\(\$\w{1,50}\)\s?{\s?(\$\w{1,50})\s?=\s?\("([^"]{1,500})"\);\s?(?:\$\w{1,50}\s?=\s?(?:"[^"]+"|\$\w{1,50}|[\'"]{2});\s?)+for\(\$\w{1,50}\s?=\s?0;\s?\$\w{1,50}<strlen\(\$\w{1,50}\);\s?\)\s?{\s?for\(\$\w{1,50}\s?=\s?0;\s?\(\$\w{1,50}<strlen\(\2\)\s?&&\s?\$\w{1,50}<strlen\(\$\w{1,50}\)\);\s?\$\w{1,50}\+\+,\$\w{1,50}\+\+\){\s?(?:\$\w{1,50}\s?=\s?"[^"]+";\s?){1,2}\$\w{1,50}\s?\.=\s?\$\w{1,50}{\$\w{1,50}}\s?\^\s?\$\w{1,50}{\$\w{1,50}};\s?\$\w{1,50}\s?=\s?"[^"]+";\s?}\s?}\s?return\s?\$\w{1,50};\s?}\s?(\$\w{1,50})\s?=\s?preg_replace\("([^"]+)",\s?"",\s?"([^"]+)"\);\s?(?:\s?\$\w{1,50}\s?=\s?(?:"[^"]+"|\w{1,50}\(\$\w{1,50}\("[^"]+"\)\)|\$\w{1,50}\(\)\.\s?\w{1,50}\(\$\w{1,50}\("[^"]+"\)\)|"[^"]+"\s*\.\s*\w+\(\$\w+\("[^"]+"\)\));\s?){1,50}(\$\w{1,50}\(\$\w{1,50},(?:\$\w{1,50}\.?)+\);)\s?(?:\$\w{1,50}\s?=\s?"[^"]+";\s?|include\s?\$\w{1,50};\s){1,50}~msi',
            'id' => 'funcVars',
        ],
        [
            'full' => '~(\$\w+)\s*=\s*"([^"]+)";(?:\$\w+\s*=\s*(?:\1\[\d+\][\.;])+)+@?(?:\$\w+[\(,])+((?:\1\[\d+\][\.;\)])+)\)\),\$\w+\[\d+\],\$\w+\[\d+\]\);~msi',
            'id' => 'dictVars',
        ],
        [
            'full' => '~\$\w{1,50}\s?=\s?(?:\'\'|\.|chr\(\d+\)|\'\w+\')+\s?;\$\w{1,50}\s?=\s?\$\w{1,50}\(\'\',array\(((?:"[^"]+",?)+)\)\);(?:\$\w{1,50}\s?=\s?(?:\'\'|\.|chr\(\d+\)|\'\w+\')+\s?;)+\$\w{1,50}\s?=\s?\$\w{1,50}\(\'\',\$\w{1,50}\(((?:\'[^\']+\'\s?\.?)+)\)\);\$\w{1,50}\(\);\$\w{1,50}\(\$\w{1,50}\(\$\w{1,50}\)\);~msi',
            'id' => 'decodedDoubleStrSet',
        ],
        [
            'full' => '~(\$\w{1,100})=[\'"]([^"\']+)[\'"];(\$\w{1,100}=(?:(?:strrev\("[^"]+"\)|"[^"]+")\.?)+;(\$\w{1,100})\s?=\s?\$\w{1,100}\([\'"]([^"\']+)[\'"]\);\$\w{1,100}=(?:(?:strrev\("[^"]+"\)|"[^"]+")\.?)+;(\$\w{1,100})\s?=\s?\$\w{1,100}\(\'\1\',\$\w{1,100}\);\$\w{1,100}\(\1\);)~msi',
            'fast' => '~(\$\w{1,100})=[\'"]([^"\']+)[\'"];(\$\w{1,100}=(?:(?:strrev\("[^"]+"\)|"[^"]+")\.?)+;(\$\w{1,100})\s?=\s?\$\w{1,100}\([\'"]([^"\']+)[\'"]\);\$\w{1,100}=(?:(?:strrev\("[^"]+"\)|"[^"]+")\.?)+;(\$\w{1,100})\s?=\s?\$\w{1,100}\(\'\$\w{1,100}\',\$\w{1,100}\);\$\w{1,100}\(\$\w{1,100}\);)~msi',
            'id' => 'createFuncStrrev',
        ],
        [
            'full' => '~(\$\w+)\s*=\s*create_function\(\'\$\w+\',strrev\(\'[^\']+\'\)\);\s*\1\(strrev\(\'([^\']+)\'\)\);~msi',
            'id' => 'strrevBase64',
        ],
        [
            'full' => '~(\$\w+)\s*=\s*"([^"]+)";if\(!function_exists\("([^"]+)"\)\){function\s*\3\(\$\w+\)\{\$\w+=(\d+);foreach\(array\(((?:"[0-9a-f]+",?)+)\)as\$\w+=>\$\w+\)[^}]+\}\}\3\(\1\."([^"]+)"\);~msi',
            'id' => 'customDecode',
        ],
        [
            'full' => '~((?:\$\w+\s*=\s*[abcdehnoprstux\._64\'"]+;\s*)+)(\$\w+="?\w+["\(\)]*;\s*)+\$\w+="[^"]+";\s*\$\w+=(\$\w+\("([^"]+)"\);)[^/]+/pre>\';~msi',
            'id' => 'expDoorCode',
        ],
        [
            'full' => '~include\((base64_decode\(\'([^\']+)\'\))\);~msi',
            'id' => 'includeB64',
        ],
        [
            'full' => '~(\$\w+)=strrev\(\'nib2xeh\'\);(\$\w+)=array\(((?:\'[^\']+\',?)+)\);(\$\w+)\s*=\s*\'\';for\s*\(\$\w+\s*=\s*0;\s*\$\w+\s*<\s*\d+;\s*\$\w+\+\+\)\s*\{\4\s*\.=\s*str_replace\(array\(((?:\'([^\']*)\',?)+)\),\s*array\(((?:\'[^\']*\',?)+)\),\s*\2\[\$\w+\]\);\}eval\(\1\(\4\)\);~msi',
            'id' => 'nib2xeh',
        ],
        [
            'full' => '~error_reporting\(0\);\s*\$\w+\s*=\s*"[0-9a-f]{32}";\s*((\$\w+)\s*=\s*((?:\w+\()+)\'([^\']+)\'\)+;\$\w+\s*=\s*"";for\s*\(\$\w+\s*=\s*0;\s*\$\w+\s*<\s*120;\s*\$\w+\+\+\)[^}]+}\$\w+\s*=\s*strlen\(\2\);\$\w+\s*=\s*strlen\(sha1\(hash\(str_rot13\("fun256"\),\s*md5\(\$\w+\)+;for[^}]+}[^}]+}eval\(\$\w+\);)~msi',
            'id' => 'fun256',
        ],
        [
            'full' => '~(\$\w+)\s*=\s*((?:\w+\()+)\'([^\']+)\'\)+;\s*if\s*\(\s*\'\w{40,40}\'\s*==\s*sha1\(\s*\1\s*\)\s*\)\s*{\s*\1\s*=\s*gzinflate\s*\(\s*gzinflate\s*\(\s*base64_decode\(\s*\1\s*\)\s*\)\s*\)\s*;\s*\$\w{1,10}\s*=\s*""\s*;for\s*\([^)]+\)\s*{[^}]+}\s*(?:\s*\$[^;]+;\s*)+for\s*\([^)]+\)\s*{\s*\$[^;]+;\s*if\s*\([^)]+\)\s*{[^}]+}(?:\s*\$[^;]+;\s*)+}\s*eval\s*\(\s*\$\w+\s*\)\s*;\s*}\s*else\s*{[^}]+}~msi',
            'id' => 'fun256',
        ],
        [
            'full' => '~(\$\w+)\s?=\s?\'([^\']+)\';\s?(\$\w+\s?=\s?(?:\1\[\d+\]\.?)+;\s?(?:(?:\$\w+\s?=\s?(?:\$\w+\()+(?:(?:\1\[\d+\])\.?|"[^"]+"\.?)+)\)+;\s?)+)(\$\w+\s?=\s?\$\w+\(\'H\*\',\s?\$\w+\(\'/\[([^]]+)\]\+/\w\',\'\',\s?(\$\w+)\(\1\)\)\);\s?eval\(\$\w+\);)~msi',
            'id' => 'evalPackPreg',
        ],
        [
            'full' => '~((?:\$_\w{1,50}\s?=\s?"[^"]{1,100}";)+)@eval\("\?>"\.(\$_\w{1,50}\((/\*.*?\*\/)\$\w{1,50}\("[^"]+"\)\))\);~msi',
            'id' => 'evalVarWithComment',
        ],
        [
            'full' => '~(?(DEFINE)(?\'s\'((?:chr\([0-9a-fx]+([/\-+\*][0-9a-fx]+)?\)|str_rot13\(\'[^\']+\'\)|base64_decode\(\'[^\']+\'\)|\'[^\']*\')[\.]?)+))(\$\w+)=create_function\(((?P>s)),((?P>s))\);\4\(base64_decode\(((?P>s))\)\);~msi',
            'id' => 'createFuncObf',
        ],
        [
            'full' => '~(\$[\w_]{1,50})\s*=\s*\[\s*base64_decode\s*\(\s*[\'"]([\w=]+)[\'"]\s*\)\s*,\s*([^;]{2,200})\]\s*;\s*(if\s*[^}]+}\s*else\s*{[^}]+}\s*function\s\w+[^}]+})~mis',
            'fast' => '~(\$[\w_]{1,50})\s*=\s*\[\s*base64_decode\s*\(\s*[\'"]([\w=]+)[\'"]\s*\)\s*,\s*([^;]{2,200})\]\s*;\s*(if\s*[^}]+}\s*else\s*{[^}]+}\s*function\s\w+[^}]+})~mis',
            'id' => 'base64Array',
        ],
        [
            'full' => '~(\$[\w]{1,34}\s*=\s*[\'"](?:[\\\\\w]{1,32}\\\[\\\\\w]{1,32})[\'"]\s*;\s*(?:\$[\w]{1,34}\s*=\s*[\'"][^\'"]+[\'"];){1,3})\s*@?eval\s*\(\s*([^;]{0,100})\);~mis',
            'id' => 'simpleVarsAndEval',
        ],
        [
            'full' => '~(if\(defined\(\'PHP_MAJOR_VERSION\'\)[^{]{1,30}{\s*if[^}]+}\s*}\s*.*?if\s*\(\s*!\s*function_exists\s*\(\s*\'nel\'\s*\)\s*\)\s*{\s*)(function\s*nel\s*\(\s*\$i\s*\)\s*{\s*\$[\w]+\s*=\s*array\(([^)]+)\);[^}]+})(.*}\s*exit\s*;\s*}\s*})~mis',
            'id' => 'replaceFuncWithBase64DecodeArray',
        ],
        [
            'full' => '~\$\w{1,50}\s?=\s?(?:\'[^\']+\'\.?)+;\$\w{1,50}\s?=\s?create_function\(\'\$\w{1,50}\',\$\w{1,50}\);((?:\$\w{1,50}\s?=\s?(?:\'[^\']+\'\.?)+;)+)\$\w{1,50}\(((?:\$\w{1,50}\()+"[^"]+"\)+;)~msi',
            'id' => 'createFuncVars',
        ],
        [
            'full' => '~\$\w{1,50}\s?=\s?json_decode\((base64_decode\([\'"][^\'"]+[\'"]\))\);~msi',
            'id' => 'jsonDecodedVar',
        ],
        [
            'full' => '~if\s?\(file_put_contents\(\$\w{1,50}\.[\'"][^\'"]+[\'"],(base64_Decode\([\'"][^\'"]+[\'"]\))\)\)echo\s?[\'"][^\'"]+[\'"];~msi',
            'id' => 'filePutPureEncodedContents',
        ],
        [
            'full' => '~function\s?(\w{1,50})\((\$\w{1,50})\){for\s?\((\$\w{1,50})\s?=\s?0;\s?\3\s?<=\s?strlen\(\2\)-1;\s?\3\+\+\s?\){(\$\w{1,50})\s?\.=\s?\2{strlen\(\2\)-\3-1};}return\(\4\);}((?:eval\(\1\(\'[^\']+\'\)\);)+)~msi',
            'id' => 'evalFuncReverse',
        ],
        [
            'full' => '~function\s?(\w{1,50})\(\$\w{1,50}\)\s?{return\s?base64_decode\(\$\w{1,50}\);}(?:.*?\1\("[^"]+"\))+~msi',
            'fast' => '~function\s?\w{1,50}\(\$\w{1,50}\)\s?{return\s?base64_decode\(\$\w{1,50}\);}(?:.*?\w{1,50}\("[^"]+"\))+~msi',
            'id' => 'base64decodeFuncs',
        ],
        [
            'full' => '~error_reporting\(\s?0\s?\);\s?(\$\w{1,50})\s?=\s?[\'"]([^\'"]+)[\'"];\s?(\$\w{1,50})\s?=\s?(?:\1\[\d+\]\.?)+;\s?(\$\w{1,50})\s?=\s?eval\s?\(\3\s?\("((?:\\\\x\w{1,50})+)"\s?\([\'"]{1,2}([^"\']+)[\'"]{1,2}\)\)\);\s?create_function\(\'\',\s?\'}\'\.\4\.\'//\'\);~msi',
            'fast' => '~error_reporting\(\s?0\s?\);\s?(\$\w{1,50})\s?=\s?[\'"]([^\'"]+)[\'"];\s?\$\w{1,50}\s?=\s?(?:\$\w{1,50}\[\d+\]\.?)+;\s?(\$\w{1,50})\s?=\s?eval\s?\(\$\w{1,50}\s?\("((?:\\\\x\w{1,5})+)"\s?\([\'"]{1,2}([^"\']+)[\'"]{1,2}\)\)\);\s?create_function\(\'\',\s?\'}\'\.\$\w{1,50}\.\'//\'\);~msi',
            'id' => 'evalCreateFuncWithDictionaryVar',
        ],
        [
            'full' => '~error_reporting\(\s?0\s?\);\s?(\$\w+)\s?=\s?"([^"]+)";(?:\$\w+\s?=\s?(?:\$\w+\[\d+\]\.?)+;)+function\s\w+\((?:\$\w+,?){5}\){\s*return\s?(?:\$\w+\.?){5};}(?:\$\w+\s?=\s?(?:[\'"][^\'"]*[\'"]\.?)+;)+\$\w+\s?=\s?\w+\((?:\$\w+,?){5}\);(?:\$\w+\s?=\s?(?:[\'"][^\'"]*[\'"]\.?)+;)+function\s(\w+)\((?:\$\w+,?){3}\){\s*return\s?(?:\$\w+\.?){3};}\$\w+\s?=\s?((?:\3\((?:(?:\$\w+|\.?[\'"][^"\']*[\'"]\.?)+,?){3}\)\.)+["\']{1,2}([^"\']+)[\'"]{1,2}\.\$\w+);\$\w+\(\'\',\s?\'}\'\.\$\w+\.\'//\'\);~msi',
            'id' => 'evalCreateFuncWithVars',
        ],
        [
            'full' => '~(error_reporting\([^)]+\);define\(\'([^\']+)\',\s*\'[^\']+\'\);\$(?:_GET|GLOBALS)\[\2\]\s*=\s*explode\(\'([^\']+)\',\s*gzinflate\(substr\(\'(.*)\',([0-9a-fx]+),\s*([0-9\-]+)\)\)\);\s*)(.+?)((\$(?:_GET|GLOBALS)\{\2\}\{[a-fx\d]+\})(.+?\2)+.+)}(?:,!\d+\);|\)\);(\$\w+\((?:\$\w+\.?)+\);))~msi',
            'id' => 'explodeSubstrGzinflate',
        ],
        [
            'full' => '~error_reporting\([^)]+\);header\([^)]+\);ini_set\([^)]+\);ini_set\([^)]+\);define\(\'PASSWD\',\'[^)]+\);define\(\'VERSION\',\'Bypass[^)]+\);define\(\'THISFILE\'[^;]+;define\(\'THISDIR\',[^;]+;define\(\'ROOTDIR\',[^;]+;(((?:\$\w+=\'[^\']+\';)+)((?:\$\w+=str_replace\(\'[^\']+\',\'\',\'[^\']+\'\);)+)(\$\w+)=\$\w+\(\$\w+\(\'[^\']+\'\),\$\w+\(\'[^\']+\'\)\);\4\(((?:\$\w+\.?)+)\);)~msi',
            'id' => 'base64Vars',
        ],
        [
            'full' => '~function\s*(\w+)\(\$\w+,\$\w+\)\s*\{\$\w+=array\(\);for\(\$\w+=0;\$\w+<256;\$\w+\+\+\)(?:[^}]+}){2}return\s*\$res;\s*}\s*function\s*(\w+)\(\)\s*{(?:[^}]+}){12}(?:\$\w+=(?:chr\([0-9b]+\)\.?)+;)+\2\(\);@?eval\(\$\w+\(\1\(\$\{\'[^\']+\'\.(?:\(\'.\'\^\'.\'\)\.?)+}\[\(\'.\'\^\'.\'\)\.\(\'.\'\^\'.\'\)\],\$\w+\("([^"]+)"\)\)\)\);exit;~msi',
            'id' => 'chr0b',
        ],
        [
            'full' => '~@?error_reporting\(0\);\s*@?ini_set\(\'error_log\',NULL\);\s*@?ini_set\(\'log_errors\',0\);\s*(\$\w+)=strrev\([base64_decode\'\.]+\);(\$\w+)=gzinflate\(\1\(\'([^\']+)\'\)\);\s*create_function\("","}\2//"\);~msi',
            'id' => 'createFuncPlugin',
        ],
        [
            'full' => '~((?:\$\w+\s*=\s*str_replace\("[^"]+",\s*"",\s*"[^"]+"\);\s*)+)\s*(eval\((?:\$\w+\()+\'([^\']+)\'\)+;)~msi',
            'id' => 'strreplaceEval',
        ],
        [
            'full' => '~(\$\w+)\s*\s*=\s*"[a-f0-9]{32,40}";\s*(\$\w+)\s*=\s*"[create_fution".]+;\s*(\$\w+)=@?\2\(\'(\$\w+),(\$\w+)\',\'[eval\'\.]+\("\\\\\1=\\\\"\5\\\\";\?>"[gzinflate\.\']+\(\s*[base64_decode\'\.]+\(\4\)+;\'\);\s*@?\$\w+\("([^"]+)",\1\);~msi',
            'id' => 'hackM19',
        ],
        [
            'full' => '~(\$\w+)\s*=\s*strrev\("[create_funtio"\.\s]+\);\s*(\$\w+)\s*=\s*\1\(\'(\$\w+)\',\s*strrev\(\';\)+\w+\$\([bas64_dcode\'\.\s]+\([bzdecompres\'\.\s]+">\?"\([eval\.\'\s]+\)\);\s*\2\("([^"]+)"\);~msi',
            'id' => 'ev404',
        ],
        [
            'full' => '~class\s+(_\w+)\s*{\s*private\s+static\s*\$\w{1,5}\s*;\s*public\s*static\s*function\s*(\w+)[^}]{1,1000}\s*}\s*private\s*static\s*function\s*\w{1,10}\s*\(\s*\)\s*{self::\$\w{1,5}\s*=\s*array\s*\(\s*([^)]+)\s*\);\s*}\s*}\s*class\s+(_\w+)\s*{\s*private\s+static\s*\$\w{1,5}\s*;\s*public\s*static\s*function\s*(\w+)[^}]{1,1000}\s*}\s*private\s*static\s*function\s*\w{1,10}\s*\(\s*\)\s*{self::\$\w{1,5}\s*=\s*array\s*\(\s*([^)]+)\s*\);\s*}\s*}\s*(.{1,5000}exit\s*;\s*})~mis',
            'id' => 'twoHashFunc',
        ],
        [
            'full' => '~(\s*function\s*(\w+)\((\$\w+)\)\s*\{\s*(?:\$\w+\s*=\s*[gzinflatebs64_dco\'\.]+;\s*)+\3\s*=\s*(?:\$\w+\()+\3\)+;\s*return\s*\3;}(\$\w+)\s*=\s*\'([^\']+)\';\s*(\$\w+)\s*=\s*\'\2\';\s*\3\s*=\s*\6\(\'[^)]+\);\s*(\$\w+)\s*=\s*\3\(\'\',\6\(\4\)+;\7\(\);)\s*\w+\(\d+(,\'[^\']+\',\'[^\']+\')?\);~msi',
            'id' => 'setVars',
        ],
        [
            'full' => '~(?:\$\w+=\'[gzuncompresbae64_dtfi\.\']+;\s*)+\$\w+=\$\w+\(\'(\$\w+)\',\'[eval\'\.]+\(\1\);\'\);\s*(\$\w+)=\'([^\']+)\';\s*\$\w+\("\?>"\.(\$\w+\()+\2\)+;~msi',
            'id' => 'createFuncGzB64',
        ],
        [
            'full' => '~(\$\w{1,50})=(?:[\'"][create_funcion]+[\'"]\.?)+;\$\w{1,50}=\1\([\'"](\$\w{1,50})[\'"],(?:[\'"][eval(gzuncomprsb64_d]+[\'"]\.?)+[\'"][decode(]+\2\)+;[\'"]\);\$\w{1,50}\([\'"]([^\'"]+)[\'"]\);~msi',
            'id' => 'createFuncGzB64',
        ],
        [
            'full' => '~(\$\w+)=strrev\(\'[base64_dco]+\'\);\s?(\$\w+)=gzinflate\(\1\(\'([^\']+)\'\)\);\s?create_function\("","}\2//"\);~msi',
            'id' => 'createFuncGzInflateB64',
        ],
        [
            'full' => '~(\$\w+)\s*=\s*(\(?\s*gzinflate\s*\(\s*base64_decode\s*)\(\s*\'([^\']+)\'\s*\)\s*\)\s*\)?\s*;\s*\$\w+\s*=\s*@?create_function\(\'([^\']*)\',\s*(?:\1|\'@?eval\(\4\)[^\']+\')\)\s*;\s*@?\$\w+(?:\(\)|\(\1\));~msi',
            'id' => 'createFuncGzInflateB64',
        ],
        [
            'full' => '~(\$\w+)="((?:\\\\\w+)+)";((\$\w+)=\1\("[^"]+"\);)@(eval\(\1\("[^"]+"\)\);)(\$\w+=(?:\$\w+\[\d+\]\.?)+;)((\$\w+)=(\$\w+)\(\1\("([^"]+)"\),-1\);)((?:\$\w+=(?:\$\w+\[\d+\]\.?)+;)+)@(eval\(\$\w+\(\1\("[^"]+"\)\)\));~msi',
            'id' => 'wsoShellDictVars',
        ],
        [
            'full' => '~error_reporting\(\d+\);(\$\w+)="([^"]+)";(\$\w+)=explode\("([^"]+)","([^"]+)"\);foreach\(\3\sas\s\$\w+=>\$\w+\){\$\w+=preg_split\("//",\$\w+,-1,[^)]+\);\3\[\$\w+\]=implode\("",array_reverse\(\$\w+\)\);}(\$\w+)=explode\("([^"]+)","([^"]+)"\);foreach\(\6\sas\s\$\w+=>\$\w+\){\${\$\w+}=\3\[\$\w+\];}function\s(\w+)\(\$\w+,\$\w+\){\$\w+=\${"[^"]+"}\["([^"]+)"\]\("//",\$\w+,-1,[^)]+\);foreach\(\$\w+\sas\s\$\w+=>\$\w+\){\$\w+\[\$\w+\]=\${"[^"]+"}\["([^"]+)"\]\(\${"[^"]+"}\["([^"]+)"\]\(\$\w+\)\+\$\w+\);}\$\w=\${"[^"]+"}\["([^"]+)"\]\("",\$\w+\);return\s\$\w+;}(\$\w+)=\9\(\14,-2\);@ini_set\(\'[^\']+\',\'[^\']+\'\);((?:\$\w+=(?:\$\w+\[\d+\]\.?)+;)(\$\w+)=(?:\$\w+\[\d+\]\.?)+;)function\s(\w+)\(\$\w+\){\$\w+=\9\(\$\w+,1\);\$\w+=strtr\(\$\w+,"([^"]+)","([^"]+)"\);return\s\$\w+;}((?:\$\w+\.?=(?:\$\w+\[\d+\]\.?)+;)+)(\$\w+)=\${"[^"]+"}\["[^"]+"\]\(\'(?:\$\w+,?)+\',(\$\w+)\(\17\("([^"]+)"\)\)\);@\${"[^"]+"}\["[^"]+"\]\((?:@\$\w+,?)+\);~msi',
            'id' => 'funcDictVars',
        ],
        [
            'full' => '~((\$\w{1,10})\s*=\s*\(\s*[\'"]([^\'"]{40,50000})[\'"]\s*\)\s*;\s*(\$\w{1,10})\s*=\s*base64_decode\s*\(\s*\2\s*\)\s*;)\s*(\$\w{1,10}\s*=\s*fopen\s*[^;]+;\s*echo\s*fwrite[^;]+;\s*fclose[^;]+;)~mis',
            'id' => 'funcFile2',
        ],
        [
            'full' => '~function\s*(\w+)\((\$\w+)\)\s*\{\s*\2=((?:\w+\()+)\2(\)+);\s*for\(\$\w=0;\$\w+<strlen\(\2\);\$\w+\+\+\)\s*\{\s*\2\[\$\w+\]\s*=\s*chr\(ord\(\2\[\$\w+\]\)-(\d+)\);\s*\}\s*return\s*\2;\s*\}eval\(\1\(("[^"]+")\)\);~mis',
            'id' => 'sec7or',
        ],
        [
            'full' => '~error_reporting\(0\);\s*class\s*(\w+)\{\s*private\s*\$\w+=\s*array\(\s*((?:"[^"]+"=>"[^"]+",?\s*)+)\)\s*;\s*public\s*function\s*(\w+)\s*\(\s*\$\w+,\s*\$\w+\s*\)\s*{[^}]+}\s*public\s*function\s*(\w+)\s*\(\$\w+,\$\w+\)\s*{[^}]+}\s*private\s*function\s*\w+\((?:\$\w+,?){7}\)\s*{[^}]+}return\s*array\((?:\$\w+,?){3}\);}}\s*(\$\w+)=new\s*\1;\s*(\$\w+)=\5->\3\(\'tmhapbzcerff\',array\(\'onfr\',\'_qrpbqr\',\'fgeeri\'\)\);\5->\4\(\6,\'\'\);\s*die\(\);~msi',
            'id' => 'classWithArrays',
        ],
        [
            'full' => '~error_reporting\(0\);(\s*(\$\w+)="[asert\."]+;\s*\$(\w+)=\2\(strrev\("([^"]+)"\)\);\s*\$\{\'\3\'\};)~msi',
            'id' => 'assertStrrev',
        ],
        [
            'full' => '~error_reporting\(0\);\$\w+\="[^"]+";\$\w+\=explode\("[^"]+","[^"]+"\);foreach\(\$\w+ as \$\w+\=\>\$\w+\)\{\$\w+\=preg_split\("//",\$\w+,\-1,PREG_SPLIT_NO_EMPTY\);\$\w+\[\$\w+\]\=implode\("",array_reverse\(\$\w+\)\);\}\$\w+\=explode\("[^"]+","[^"]+"\);foreach\(\$\w+ as \$\w+\=\>\$\w+\)\{\$\{\$\w+\}\=\$\w+\[\$\w+\];\}function \w+\(\$\w+,\$\w+\)\{\$\w+\=\$\{"[^"]+"\}\["\w+"\]\("//",\$\w+,\-1,PREG_SPLIT_NO_EMPTY\);foreach\(\$\w+ as \$\w+\=\>\$\w+\)\{\$\w+\[\$\w+\]\=\$\{"[^"]+"\}\["[^"]+"\]\(\$\{"[^"]+"\}\["\w+"\]\(\$\w+\)\+\$\w+\);\}\$\w+\=\$\{"[^"]+"\}\["\w+"\]\("",\$\w+\);return \$\w+;\}\$\w+\=\w+\(\$\w+,\-2\);@ini_set\(\'memory_limit\',\'1024M\'\);(?:\$\w+\=(?:\$\w+\{\d+\}\.?)+;)+function \w+\(\$\w+\)\{\$\w+\=\w+\(\$\w+,(\d+)\);\$\w+\=strtr\(\$\w+,"([^"]+)","([^"]+)"\);return \$\w+;\}(?:\$\w+\.?=(?:\$\w+\{\d+\}\.?)+;)+\$\w+\=\$\{"[^"]+"\}\["\w+"\]\(\'\$\w+,\$\w+,\$\w+,\$\w+\',\$\w+\(\w+\("([^"]+)"\)\)\);@\$\{"[^"]+"\}\["\w+"\]\(@\$\w+,@\$\w+,@\$\w+,@\$\w+,@\$\w+,@\$\w+\);~msi',
            'id' => 'b64strtr',
        ],
        [
            'full' => '~error_reporting\(\d\);function\s(\w{1,50})\(\$\w{1,50},\$\w{1,50}\){if\(file_exists\("[^"]+"\)\){touch\(__FILE__,filemtime\("[^"]+"\)\);}\$\w{1,50}=str_replace\(array\(\'([^\']+)\',\'([^\']+)\'\),array\(\'([^\']+)\',\'([^\']+)\'\),\$\w{1,50}\);\$\w{1,50}=strrev\(\'[base64]+\'\)\."_"\.strrev\(\'[decode]+\'\);\$\w{1,50}=\$\w{1,50}\(\$\w{1,50}\);\$\w{1,50}=strrev\(\'[gzinflate]+\'\);return@\$\w{1,50}\(\$\w{1,50}\);}\s?\$\w{1,50}=\'([^;]+;)([^\']+)">\';preg_match\(\'#\6\(\.\*\)">#\',\$\w{1,50},\$\w{1,50}\);\$\w{1,50}=\$\w{1,50}\[1\];\$\w{1,50}=\1\(\$\w{1,50},\$\w{1,50}\);if\(isset\(\$\w{1,50}\)\){eval\(\$\w{1,50}\);}~msi',
            'id' => 'gzB64strReplaceDataImage',
        ],
        [
            'full' => '~(\$\w{1,50})=array\((?:base64_decode\([\'"][^\'"]+[\'"]\),?){2}base64_Decode\(strrev\(str_rot13\(explode\(base64_decode\([\'"][^\'"]+[\'"]\),file_get_contents\(__FILE__\)\)\[1\]\){4};preg_replace\(\1\[0\],serialize\(eval\(\1\[2\]\)\),\1\[1\]\);exit\(\);\s?\?>\s*([^\s]{1,5000})~msi',
            'id' => 'serializeFileContent',
        ],
        [
            'full' => '~(function\s\w{1,50}\(\$\w{1,50}\)\s?{\s?global\s(?:\$\w{1,50},?\s*)+;\s*\$\w{1,50}\(\$\w{1,50},\s?\$\w{1,50},\s?\$\w{1,50}\(\)\s?\+\s?\w{1,50}\(\$\w{1,50}\),\s?(?:\$\w{1,50}\s?,?\.?\s*)+\);\s*}\s*global\s?(?:\$\w{1,50},?\s*)+;\s*(?:\$\w{1,50}\s?=\s?\'[^\']+\';\s*)+function\s?\w{1,50}\(\$\w{1,50}\)\s{\s*global\s?(?:\$\w{1,50},?\s*)+;.*?return\s\$\w{1,50}\(\$\w{1,50}\);\s}\s*(?:\$\w{1,50}\s?=\s?\'[^\']*\';\s*)+(?:function\s\w{1,50}\(.*?(?:\$\w{1,50}\s?=\s?\'[^\']*\';\s*)+)+(?:\$\w{1,50}\s\.?=\s\$\w{1,50};\s*)+.*?extract\(\w{1,50}\(get_defined_vars\(\)\)\);)\s*(\$\w{1,50}\(\d\);\s*\$\w{1,50}\(\$\w{1,50},\s?0\);\s*\$\w{1,50}\s=\s\$\w{1,50}\(\$_REQUEST,\s?\$_COOKIE,\s?\$_SERVER\);.*?\$\w{1,50}\(\$\w{1,50}\);\s*echo\s?\$\w{1,50};)~msi',
            'id' => 'globalVarsManyReplace',
        ],
        [
            'full' => '~\$\w{1,50}\s{0,100}=\s{0,100}"([^"]{1,50000})";\s?(\$\w{1,50}\s?=\s?(?:["][^"]{1,5}["]\.?)+;\s?\s?(?:\s?\$\w{1,50}\s?\.?=(?:\s?(?:\s?"[^"]+"|\$\w{1,50})\s?\.?)+;\s?)+)\$\w{1,50}\s?\(\s?\$\w{1,50},((?:\$\w{1,50}\()+\$\w{1,50}\)+),"[^"]{1,100}"\);~msi',
            'id' => 'concatVarsPregReplace',
        ],
        [
            'full' => '~(?:\$\w{1,50}\s?=\s?(?:"[^"]+"\.?)+;)+\s?echo\sjson_encode\(array\([\'"][^"\']+[\'"]=>@\$\w{1,50}\(__FILE__,(\$\w{1,50}\([\'"][^"\']+[\'"]\)\))>0,[\'"][^"\']+[\'"]=>__FILE__\)\);exit;~msi',
            'id' => 'filePutContentsB64Decoded',
        ],
        [
            'full' => '~(\$\w{1,50})\s?=\s?base64_decode\([\'"][^\'"]+[\'"]\);\s?\$\w{1,50}\s?=\s?\$_POST\[[\'"][^\'"]+[\'"]\]\.[\'"][^\'"]+[\'"];\s?\$\w{1,50}\s?=\s?fopen\([\'"][^\'"]+[\'"]\.\$\w{1,50},\s?[\'"]w[\'"]\);\s?fwrite\(\$\w{1,50},\1\);~msi',
            'id' => 'fwriteB64DecodedStr',
        ],
        [
            'full' => '~file_put_contents\(\$_SERVER\[\'[^\']+\'\]\.\'[^\']+\',base64_decode\(\'[^\']+\'\)\);~msi',
            'id' => 'filePutContentsB64Content',
        ],
        [
            'full' => '~((\$\w{1,50})\s?=\s?((?:chr\(\d{1,5}\)\.?)+);)(\$\w{1,50})\s?=\s?(?:\2\[\d{1,5}\]\.?)+;(\$\w{1,50})\s?=\s?(?:\2\[\d{1,5}\]\.?)+;\4\(\5\(null,\s?((?:\2\[\d{1,5}\]\.?)+)\)\);~msi',
            'id' => 'chrDictCreateFunc',
        ],
        [
            'full' => '~(?:function\s\w{1,50}\((?:\$\w{1,50}\,?)+\){return\sstr_replace\((?:\$\w{1,50}\,?)+\);}\s?){3}(\$\w{1,50})\s?=\s?[\'"]([^\'"]+)[\'"];\s?\$\w{1,50}\s?=\s?\w{1,50}\([\'"]([^\'"]+)[\'"],\'\',\1\);\s?(?:\$\w{1,50}\s?=\s?[\'"][^\'"]+[\'"];\s?\$\w{1,50}\s?=\s?\w{1,50}\([\'"][^\'"]+[\'"],\'\',\$\w{1,50}\);\s?){2}\$\w{1,50}\s?=\s?[\'"][^\'"]+[\'"];\s?\$\w{1,50}\s?=\s?\$\w{1,50}\(\$\w{1,50},\$\w{1,50}\.\'\(\'\.\1\.\'\(\'\.\$\w{1,50}\.\'\)\);\'\);\s?\$\w{1,50}\([\'"]([^\'"]+)[\'"]\);~msi',
            'id' => 'strReplaceFuncsEvalVar',
        ],
        [
            'full' => '~\$\w{1,50}\s?=\s?"\\\\x[^"]+";\${\$\w{1,50}}\s?=\s?base64_decode\("(.*?\\\\x[^"]+")\);\s?eval\(".*?\\\\x[^\$]+\$\w{1,50}\\\\"\);"\);~msi',
            'id' => 'B64SlashedStr',
        ],
        [
            'full' => '~(\$\w{1,50})\s?=\s?array\((?:[\'"][base64_dco]+[\'"],?\s?)+\);\s?array_splice\(\1,\s?4,\s?0,\s?8\*8\);\s?(\$\w{1,50})\s?=\s?implode\(\'\',\s?array_reverse\(\1\)\);\s?(\$\w{1,50})\s?=\s?\2\([\'"]([^\'"]+)[\'"]\);\s?eval\(\3\);~msi',
            'id' => 'B64ArrayStrEval',
        ],
        [
            'full' => '~(\$\w{1,50})\s?=\s?[\'"]([^\'"]+)[\'"];\s?\$\w{1,50}\s?=\s?(?:\1\[\d+\]\.?)+;\s?@\$\w{1,50}\((?:\1\[\d+\]\.?)+,(?:\1\[\d+\]\.?)+"\("\.(?:\1\[\d+\]\.?)+\'\([\'"]([^\'"]+)[\'"]\)\);\',"\."\);~msi',
            'id' => 'DictVarsPregReplaceB64',
        ],
        [
            'full' => '~(\$\w+\s*=\s*\'[bs64_dcogzinflate\.\'\s]+;\s*)+(\$\w+)\s*=\s*\'([^\']+)\';\s*eval\((?:\$\w+\()+\2\)+;~msi',
            'id' => 'evalVarB64',
        ],
        [
            'full' => '~(if\s*\(\!function_exists\s*\("([^"]+)"\)\)\s*\{\s*function\s*\2\s*\((\$\w+)\)\s*\{\s*(\$\w+)\s*=\s*"";\s*(\$\w+)\s*=\s*0;\s*\$\w+\s*=\s*strlen\s*\(\3\);\s*while\s*\(\$\w+\s*<\s*\$\w+\)\s*\{\s*if\s*\(\3\[\5\]\s*==\s*\'\s\'\)\s*\{\s*\4\s*\.=\s*"\s";\s*\}\s*else\sif\s*\(\3\[\5\]\s*==\s*\'!\'\)\s*\{\s*\4\s*\.=\s*chr\s*\(\s*\(ord\s*\(\3\[\5\+\d\]\)-ord\s*\(\'A\'\)\)\*16\+\s*\(ord\s*\(\3\[\5\+\d\]\)-ord\s*\(\'a\'\)\)\);\s*\5\s*\+=\s*2;\s*\}\s*else\s*\{\s*\4\s*\.=\s*chr\s*\(ord\s*\(\3\[\5\]\)\+1\);\s*\}\s*\5\+\+;\s*\}\s*return\s*\4;\s*\}\s*\}\s*)eval\s*\(\2\s*\(\'([^\']+)\'\)\);~msi',
            'id' => 'decodeAChar',
        ],
        [
            'full' => '~(\$\w+)="([^"]+)";(\$\w+)="[str_eplac"\.]+";((?:\$\w+\s*=\s*\3\("([^"]+)","","[^"]+"\);)+)(\$\w+)\s*=\s*\$\w+\(\'\',\s*((?:\$\w+\()+\1\)\))\);\6\(\);~msi',
            'id' => 'strReplaceCreateFunc',
        ],
        [
            'full' => '~function\s*(\w+)\((\$\w+)\)\s*\{\s*\$\w+\s*=\s*strlen\(trim\(\2\)+;\s*\$\w+\s*=\s*\'\';\s*(\$\w+)\s*=\s*0;\s*while\s*\(\(\(\$\w+\s*<\s*\$\w+\)+\s*\{\s*(\$\w+)\s*\.=\s*pack\([\'"]C[\'"],\s*hexdec\(substr\(\2,\s*\3,\s*2\)\)\);\s*\3\s*\+=\s*2;\s*\}\s*return\s*\4;\s*\}\s*eval\(\1\([\'"]([0-9a-f]+)[\'"]\)\s*\.\s*\'([^\']+\'\)+;)\s*\'\);~msi',
            'id' => 'evalbin2hex',
        ],
        [
            'full' => '~function\s\w{1,50}\(\$\w{1,50},\s?\$\w{1,50}\)\s?{\s?return;\s?}\s?function\s\w{1,50}\((?:\$\w{1,50}\s?=\s?"",?\s?){2}\)\s?{.*?(?:function\s\w{1,50}\((?:\$\w{1,50},?\s?)+\)\s?{\s?return\s\$\w{1,50};\s?}\s?)+function\s\w{1,50}\(\).*?(?:function\s\w{1,50}\((?:\$\w{1,50},?\s?)+\)\s?{\s?return\s\$\w{1,50};\s?}\s?)+function\s\w{1,50}\(\).*?(?:function\s\w{1,50}\((?:\$\w{1,50},?\s?)+\)\s?{\s?return\s\$\w{1,50};\s?}\s?)+(?:header\(\w{1,50}\([\'"][^\'"]+[\'"]\)\);\s?)+define.*?PDO\(.*?\$\w{1,50}\s?=\s?0;\s?function\s?\w{1,50}\(\$\w{1,50}\)\s?{\s?global.*?function\s(\w{1,50})\(\$\w{1,50}\)\s?{\s?\$\w{1,50}\s?=\s?"";\s?for\s?\(\$\w{1,50}\s?=\s?0;\s?\$\w{1,50}\s?<\s?strlen\(\$\w{1,50}\)\s?-\s?1;\s?\$\w{1,50}\s?\+=2\)\s?{\s?\$\w{1,50}\s?\.=\s?chr\(hexdec\(\$\w{1,50}\[\$\w{1,50}\]\s?\.\s?\$\w{1,50}\[\$\w{1,50}\s?\+\s?1\]\)\s?\^0x66\);\s?}\s?return\s\$\w{1,50};\}(?:.*?(?:function\s\w{1,50}\((?:\$\w{1,50},?\s?)+\)\s?{\s?return\s\$\w{1,50};\s?}\s?)+)+~msi',
            'id' => 'manyFuncsWithCode',
        ],
        [
            'full' => '~((?:\$GLOBALS\["[^"]+"\]=base64_decode\("[^"]*"\);)+).{0,10}((?:\$GLOBALS\[\$GLOBALS\["[^"]+"\]\]=base64_decode\(\$GLOBALS\["[^"]+"\]\);)+).{0,10}((?:\$GLOBALS\[\$GLOBALS\[\$GLOBALS\["[^"]+"\]\]\]=base64_decode\(\$GLOBALS\[\$GLOBALS\["[^"]+"\]\]\);)+).{0,10}(\$\w+)=\$_POST\[\$GLOBALS\[\$GLOBALS\[\$GLOBALS\["[^"]+"\]\]\]\];if\(\4\!=\$GLOBALS\[\$GLOBALS\[\$GLOBALS\["[^"]+"\]\]\]\)\s*\{(\$\w+)=base64_decode\(\$_POST\[\$GLOBALS\[\$GLOBALS\[\$GLOBALS\["[^"]+"\]\]\]\]\);@?eval\("\\\\\$\w+=\5;"\);\}~msi',
            'id' => 'manyGlobals',
        ],
        [
            'full' => '~(\$[0o]+)="([\\\\x0-9a-f]+)";(\$[0o]+)=@?\1\(\'([^\']+)\',"([\\\\x0-9a-f]+)"\);@?\3\("([^"]+)"\);~msi',
            'id' => 'gzB64Func',
        ],
        [
            'full' => '~(?:(?:session_start|error_reporting|set_time_limit)\(\d*\);\s?)+(?:@?ini_set\([\'"][^\'"]+[\'"],[\'"][^\'"]+[\'"]\);\s?)+((\$\w{1,50})\s?=\s?(?:[\'"][base64_dco]+[\'"]\.?)+;\s(\$\w{1,50})\s?=\s?\2\(((?:[\'"][^\'"]+[\'"]\.?)+)\);)\s?(\$\w{1,50})\s?=\s?array\(((?:(?:\s?\3\((?:[\'"][^\'"]+[\'"]\.?)+\)(?:\.?)?|\3|\2|(?:chr\(\d+\)\.?))+,\s?)+\${(?:chr\(\d+\)\.?)+}\[(?:chr\(\d+\)\.?)+\])\);\s?(?:.*?\5\[\d+\])+~msi',
            'id' => 'dictArrayFuncVars',
        ],
        [
            'full' => '~function\s(\w{1,50})\(\){\$\w{1,50}\s?=\s?[\'"]([^\'"]+)[\'"];\$\w{1,50}\s?=\s?str_rot13\(\$\w{1,50}\);\$\w{1,50}\s?=\s?base64_decode\([\'"]([^\'"]+)[\'"]\);(\$\w{1,50})\s?=\s?@\$\w{1,50}\(\'\',\s?pack\(\'H\*\',\s?\$\w{1,50}\)\);\s?\4\(\);\s?}\1\(\);~msi',
            'id' => 'createFuncPackStrRot13',
        ],
        [
            'full' => '~error_reporting\(0\);\s?(?:\s?function\s(\w{1,50})\((?:\$\w{1,50}\,?\s?){3}\)\s?{\s?return\s?[\'"]{2}\s?\.\s?(?:\$\w{1,50}\s?\.\s?[\'"]{2}\s?\.?\s?)+;\s*}|\s?(?:\w{1,50}:)?(\$\w{1,50})\s?=\s?"([^"]+)";){2}\s?(?:\s?(?:\w{1,50}:)?\$\w{1,50}\s?=\s?\1\((?:\2\[0\d{1,5}\][,.\s\'"]*)+\);\s?)+\s?print_r\(\2\[0\d{1,5}\]\);\s?echo\s?"[^"]+";\s*(\$\w{1,50})=\1\((?:\1\((?:(?:\$\w{1,50}|""),?)+\),?\.?)+\)\."\'([^\'"]+)\'"\.\1\((?:\2\[0\d{1,5}\],?)+\."",\2\[0\d{1,5}\]\);\s?print_r\(\$\w{1,50}\);\s?(?:\$\w{1,50}=\1\((?:\2\[0\d{1,5}\][.,]?)+\);\s?)+\$\w{1,50}=\1\(\1\((?:\$\w{1,50},?)+\),\$\w{1,50},\1\((?:\$\w{1,50},?)+\)\);\s?\$\w{1,50}\(create_function,array\("","}"\.\4\."//"\)\);~msi',
            'id' => 'dictVarsCreateFunc',
        ],
        [
            'full' => '~(?:function\s(\w{1,50})\((?:\$\w{1,50}\,?\s?){3}\)\s?{\s?return\s?[\'"]{2}\s?\.\s?(?:\$\w{1,50}\s?\.\s?[\'"]{2}\s?\.?\s?)+;\s*}\s?|(?:\w{1,50}:)?(\$\w{1,50})\s?=\s?"([^"]+)";\s?){2}(?:\s?\$\w{1,50}\s?=\s?\1\((?:(?:(?:\2\[\d+\])?[,.\s\'"]*)+|(?:\s?\1\((?:\$\w{1,50}[,.\s\'"]*)+\),?)+)\);)+\s?(\$\w{1,50})\s?=\s?\1\((?:\s?\1\((?:\$\w{1,50}[,.\s\'"]*)+\),?)+\)\s?\.\s?"\'([^"]+)\'"\s?\.\s?\1\((?:(?:\2\[\d+\])?[,.\s\'"]*)+\);\s?\$\w{1,50}\(\$\w{1,50},\s?array\(\'\',\s?"}"\s?\.\s?\4\s?\.\s?"//"\)\);~msi',
            'id' => 'dictVarsCreateFunc',
        ],
        [
            'full' => '~function\s(\w{1,50})\((\$\w{1,50})\)\s?{.*?\$\w+\s?=\s?"[^"]+";\$\w{1,50}\s?=\s?str_split\(\$\w{1,50}\);\$\w{1,50}\s?=\s?array_flip\(\$\w{1,50}\);\$\w{1,50}\s?=\s?0;\$\w{1,50}\s?=\s?"";\$\w{1,50}\s?=\s?preg_replace\("[^"]+",\s?"",\s?\$\w{1,50}\);do\s?{(?:\$\w{1,50}\s?=\s?\$\w{1,50}\[\$\w{1,50}\[\$\w{1,50}\+\+\]\];){4}\$\w{1,50}\s?=\s?\(\$\w{1,50}\s?<<\s?2\)\s?\|\s?\(\$\w{1,50}\s?>>\s?4\);\$\w{1,50}\s?=\s?\(\(\$\w{1,50}\s?&\s?15\)\s?<<\s?4\)\s?\|\s?\(\$\w{1,50}\s?>>\s?2\);\$\w{1,50}\s?=\s?\(\(\$\w{1,50}\s?&\s?3\)\s?<<\s?6\)\s?\|\s?\$\w{1,50};\$\w{1,50}\s?=\s?\$\w{1,50}\s?\.\s?chr\(\$\w{1,50}\);if\s?\(\$\w{1,50}\s?!=\s?64\)\s?{\$\w{1,50}\s?=\s?\$\w{1,50}\s?\.\s?chr\(\$\w{1,50}\);}if\s?\(\$\w{1,50}\s?!=\s?64\)\s?{\$\w{1,50}\s?=\s?\$\w{1,50}\s?\.\s?chr\(\$\w{1,50}\);}}\s?while\s?\(\$\w{1,50}\s?<\s?strlen\(\$\w{1,50}\)\);return\s?\$\w{1,50};}\s?.*?function\s(\w{1,50})\(\){\$\w{1,50}\s?=\s?@file_get_contents\(\w{1,50}\(\)\);.*?(\$\w{1,50})\s?=\s?"([^"]{1,20000})";.*?\4\s?=\s?@unserialize\(\1\(\4\)\);.*?(function\s(\w{1,50})\(\$\w{1,50}=NULL\){foreach\s?\(\3\(\)\s?as.*?eval\(\$\w{1,50}\);}}}).*?(\7\(\);)~msi',
            'id' => 'decodedFileGetContentsWithFunc',
        ],
        [
            'full' => '~((?:\$\w{1,50}\s?\.?=\s?"\\\\[^"]+";)+)((?:\$\w{1,50}=\$\w{1,50}\(\$\w{1,50}\);){3})(\$\w{1,50})=[\'"]([^\'"]+)[\'"];(\$\w{1,50})=[\'"]([^\'"]+)[\'"];if\(function_exists\(\$\w{1,50}\)\){\$\w{1,50}=@\$\w{1,50}\(\'\3,\$\w{1,50}\',(\$\w{1,50}\(\$\w{1,50}\()\5\)\)\);if\(\$\w{1,50}\)\3=@\$\w{1,50}\(\3,\$\w{1,50}\);\s?}else{.*?};if\(function_exists\(\$\w{1,50}\)\)\s?{\$\w{1,50}=@\$\w{1,50}\("",\7\3\)\)\);if\(\$\w{1,50}\)@\$\w{1,50}\(\);}else{.*?};~msi',
            'id' => 'createFuncVarsCode',
        ],
        [
            'full' => '~(\$\w+)=\'[preg_lac.\']+\';\1\(\'[#\~\\\\1\'.e]+\',\'([^,]+)\',\'1\'\);~msi',
            'id' => 'pregConcat',
        ],
        [
            'full' => '~(?:\$\{"[^"]+"\^"[^"]+"\}\s*=\s*"[^"]+"\s*\^\s*"[^"]+";\s*)+\$\{"[^"]+"\^"[^"]+"\}\s*=\s*\(\s*\$\{"[^"]+"\^"[^"]+"\}\(\s*\$\{"[^"]+"\^"[^"]+"\}\s*\(\s*\'([^\']+)\'\)\s*\)\s*\)\s*;\s*\$\{"[^"]+"\^"[^"]+"\}="[^"]+"\s*\^\s*"[^"]+";\s*\$\{"[^"]+"\^"[^"]+"\}\s*=\s*@?\$\{"[^"]+"\^"[^"]+"\}\(\'[^\']+\',\s*"[^"]+"\s*\^\s*"[^"]+"\)\s*;@?\${"[^"]+"\^"[^"]+"\}\(\$\{"[^"]+"\^"[^"]+"\}\);~msi',
            'id' => 'xoredStrings',
        ],
        [
            'full' => '~\$\w+\s*=\s*\'([^\']+)\';\s*//base64 - gzinflate - str_rot13 - convert_uu - gzinflate - base64~msi',
            'id' => 'commentWithAlgo',
        ],
        [
            'full' => '~error_reporting\(0\);\s*set_time_limit\(0\);\s*ini_set\(\'memory_limit\',\s*\'-1\'\);\s*if\(isset\(\$_POST\[\'pass\']\)\)\s*{\s*function\s*[^}]+}\s*file_put_contents\((\$\w+)\."[^"]+",\s*gzdeflate\(file_get_contents\(\1\),\s*\d\)\);\s*unlink\(\1\);\s*copy\(\'\.htaccess\',\'[^\']+\'\);\s*(\$\w+)\s*=\s*base64_decode\("[^"]+"\);\s*(?:\$\w+\s*=\s*str_replace\(\'[^\']+\',\s*[^;]+;\s*)+\$\w+\s*=\s*\$\w+;\s*(\$\w+)\s*=\s*"<\?php[^;]+;\s*\?>";\s*(\$\w+)\s*=\s*fopen\(\'[^\']+\',\'w\'\);\s*fwrite\(\4,\s*\3\);\s*fclose\(\4\);\s*(\$\w+)\s*=\s*base64_decode\("[^"]+"\);\s*(\$\w+)\s*=\s*fopen\(\'[^\']+\',\s*\'w\'\);\s*fwrite\(\6,\s*\5\);\s*fclose\(\6\);\s*echo\s*"[^"]+";\s*}\s*function\s*(\w+)[^}]+}[^}]+[\s}]+[^!]+!+\';[^!]+!+\';\s*}\s*exit\(\);\s*}\s*function\s*\w+\(\){~msi',
            'id' => 'fileEncryptor',
        ],
        [
            'full' => '~function\s?\w{1,50}\(\$\w{1,50}\)\s*{(\$\w{1,50}=true;)?((?:\$\w{1,50}\s?=\s?[\'"](?:base64_(?:de|en)code|[\\\\xa-f0-9]+)[\'"];)+).*?exit;}}\w{1,50}\([\'"][^\'"]+[\'"]\);~msi',
            'id' => 'base64decodedFuncContents',
        ],
        [
            'full' => '~((?:if\(!function_exists\(base64_[end]+code\)\)\{function\s*(\w+)[^{]+({([^{}]*+(?:(?3)[^{}]*)*+)})\}\s*else\s*\{function\s*\2\((\$\w+)\)\s*\{\s*global\s*base64_[end]+code;return\s*base64_[end]+code\(\5\);\}\})+).*?((?:function\s*(\w+)\(\$\w+\)\{return\s*\w+\(\$\w+\);\s*\}\s*)+).*?(eval\(gzinflate\(\7\(\'([^\']+)\'\)\)\);)~msi',
            'id' => 'definedB64',
        ],
        [
            'full' => '~(?(DEFINE)(?\'v\'(?:(?:\$\{)*"GLOBALS"\}\["\w+"\]\}?|\$\w+|"\w+")))(?:(?&v)\s*=\s*"\w+";\s*)+(?:if\s*\(isset\(\$_GET\["[^"]+"\]\)\)\s*\{\s*echo\s*(?:"[^"]+"|\$_GET\["[^"]+"\]);\s*die;\s*\}\s*)*(?:(?&v)\s*=\s*"\w+";\s*)*function\s*(\w+)\(\$\w+,\s*\$\w+\s*=\s*\'\'\)\s*\{\s*(?:(?&v)\s*=\s*(?&v);\s*)+[^\^]+\^\s*(?&v)\[(?&v)\];\s*\}\s*\}\s*return\s*(?&v);\s*\}\s*(?:\$\w+\s*=\s*"[^"]+";)?\s*(?&v)\s*=\s*"[^"]+";\s*(?:(?&v)\s*=\s*"[^"]+";)?\s*(?:\$\w+ = "D";)?\s*((?&v))\s*=\s*"([^"]+)";(?:\s*(?&v)\s*=\s*[\'"][^\'"]*[\'"];\s*)+(?:foreach\s*\(array\(([\d\s,]+)\)\s*as\s*(?&v)\)\s*\{\s*(?:(?&v)\s*=\s*"\w+";\s*)*\s*(?&v)\s*\.=\s*(?&v)\[(?&v)\];\s*\}\s*(?:\s*(?&v)\s*=\s*[\'"][^\'"]*[\'"];\s*)?)+\s*(?&v)\s*=\s*(?&v)\([creat_fuion"\'\s\.]+\);\s*(?&v)\s*=\s*(?&v)\("[^"]*",\s*(?&v)\s*\(\2\((?&v)\((?&v)\),\s*"([^"]+)"\)\)\);\s*(?&v)\(\);~msi',
            'id' => 'B64Xored',
        ],
        [
            'full' => '~(\$\w{1,50})\s?=\s?<<<FILE\s*([\w\s+/=]+)FILE;\s*(\$\w{1,50}\s?=\s?(base64_decode\(\1\));)~msi',
            'id' => 'B64AssignedVarContent',
        ],
        [
            'full' => '~(\$\w{1,50})\s?=\s?\'([^\']+)\';((?:\$\w{1,50}\s?=\s?(?:\1\[[()\d/+*-]+\]\.?)+;)+)\$\w{1,50}\s?=\s?"[^"]+";(?:\$\w{1,50}\s?\.?=\s?\$\w{1,50};)+@?\$\w{1,50}\s?=\s?\$\w{1,50}\(\(\'\'\),\s?\((\$\w{1,50})\)\);@?\$\w{1,50}\(\);~msi',
            'id' => 'dictVarsWithMath',
        ],
        [
            'full' => '~(\$\w{1,50})\s?=\s?"([^"]+)";\s*class\s?(\w+){\s*var\s?\$\w{1,50};\s*function\s__construct\(\)\s?{\s?\$this->\w{1,50}\(\d+\);\s*}\s*function\s?(\w{1,50})\(\$\w{1,50}\)\s?{\s?\$\w{1,50}\s?=\s?\$_SERVER\[\'HTTP_USER_AGENT\'\];\s?if\s?\(\s?preg_match\(\'/\s?Apple\(\.\*\)\s?\\\\\(/is\',.*?str_replace.*?explode.*?\'0+\';(?:.*?function\s\w{1,50}\([^)]+\){.*?(?:unpack|pack|\$this->|fmod|chr))+.*?return\s\$\w{1,50};[\s}]+(\$\w{1,50})\s?=\s?hex2bin\(\1\);\s?\$\w{1,50}\s?=\s?new\s?\3\(\d+\);\s?(\$\w{1,50})\s?=\s?\$\w{1,50}->\4\(\5\);\s?eval\(\6\);~msi',
            'id' => 'classDecryptedWithKey',
        ],
        [
            'full' => '~((\$\w+)\s*=\s*str_rot13\(base64_decode\(\'([^\']+)\'\)\);\s*(\$\w+)\s*=\s*str_rot13\(base64_decode\(\'([^\']+)\'\)\);\s*\$\w+\s*=\s*\'[^\']+\';)\s*preg_match\(\$\w+\(\$\w+\(\'[^\']+\'\)\),\s*file_get_contents\(__FILE__\),\s*\$\w+\);\s*(eval\(\$\w+\(\$\w+\(\'([^\']+)\'\)\)\);)\s*eval\(\$\w+\(\$\w+\(\'[^\']+\'\)\)\);\s*unset\(\$\w+,\s*\$\w+\);\s*__halt_compiler\(\);\s*\?>\s*\[PHPkoru_Info\]\s*[^\]]+\]\s*\[PHPkoru_Code\]\s*([^\[]+)\[/PHPkoru_Code\]~msi',
            'id' => 'PHPkoru',
        ],
        [
            'full' => '~(\$\w+)\s*=\s*"([^"]+)";\s*(\$\w+)\s*=\s*\$this->(\w+)\("([^"]+)"\);\s*(\$\w+)\s*=\s*\3\(\'\',\s*\$this->\4\(\1\)\);\s*\6\(\);~msi',
            'id' => 'JoomlaInject',
        ],
        [
            'full' => '~((\$\w{1,50})\s*=\s*[\'"]([^"\']+)[\'"];\s*)\$\w{1,50}\s*=\s*fopen\([^)]+\);\s*\$\w{1,50}\s*=\s*fwrite\s?\(\$\w{1,50}\s*,\s*(base64_decode\(\2\))\);~msi',
            'id' => 'fwriteB64Content',
        ],
        [
            'full' => '~(\$\w{1,50})\s*=\s*"([^"]+)";\s*(\$\w{1,50})\s*=\s*base64_decode\(\1\);\s*(\$\w{1,50})\s*=\s*base64_decode\("([^"]+)"\);\s*(\$\w{1,50}\s*=(\s*\3\s*\.\s*\4);)~msi',
            'id' => 'B64concatedVars',
        ],
        [
            'full' => '~(\$\w{1,50})\s*=\s*"(\\\\[\w\\\\]+)";\s*(\$\w{1,50})\s*=\s*@\1\([\'"](\$\w{1,50})[\'"]\s*,\s*"(\\\\[\w\\\\]+)"\);\s*@\3\(([\'"][^\'"]+[\'"])\);~msi',
            'id' => 'slashedCreateFunc',
        ],
        [
            'full' => '~(\$\w{1,50})\s*=\s*"([^"]+)";((?:\$\w{1,50}\s*=\s*(?:\$\w{1,50}\[\d+\]\.?)+;)+@?(?:\$\w{1,50}(?:\[\d+\]\.?)?[,()]*)+;)~msi',
            'id' => 'varDictCreateFunc',
        ],
        [
            'full' => '~@call_user_func\(create_function\([\'"]\s*[\'"],gzinflate\(base64_decode\([\'"\\\\]{1,3}([^\'"\\\\]+)[\'"\\\\]{1,3}\)\)\),[^)]+\);~msi',
            'id' => 'callFuncGzB64',
        ],
        [
            'full' => '~@?(\$\w{1,50})\s*=\s*"([^"]+)";@?(\$\w{1,50})\s*=\s*array\((\d+),(\d+),(\d+),(\d+),(\d+),(\d+)\);@?(\$\w{1,50})\s*=\s*"([^"]+)";@?(\$\w{1,50})\s*=\s*[\'"]{2};for\s*\(\$\w{1,50}\s?=\s?0;\s?\$\w{1,50}\s?<\s?6;\s?\$\w{1,50}\+\+\)\s*{@?\$\w{1,50}\s?=\s?@?\3\[@?\$\w{1,50}\]\s*;@?\12\.=\s?@?\1\[@?\$\w{1,50}\]\s?;\s*}@?\12\(((?:"\\\\x[^"]+"\.?)+)\);~msi',
            'id' => 'assertDictVarEval',
        ],
        [
            'full' => '~function\s+(\w{1,50})\((\$\w{1,50})\)\s*{\s*\$\w{1,50}\s?=\s?"[^"]+";\s?(?:(?:\$\w{1,50}\s?=\s?)+"";)+.*?<<\s?2.*?<<\s?6.*?!=\s?64.*return\s?\$\w{1,50};}\s?function\s+(\w{1,50})\(\$\w{1,50}\){\s*return\s\1\(\$\w{1,50}\);}\s*eval\(\3\(gzinflate\(\3\("([^"]+)"\),0\)+~msi',
            'id' => 'B64FuncEvalGz',
        ],
        [
            'full' => '~(\$\w{1,50})\s*=\s*"([^"]+)";\s*(\$\w{1,50})\s?=\s?(?:[\d\-+*])+;\s*\$\w{1,50}\s?=\s?[\'"]base[\'"]\s?\.\s?\3\.\s?[\'"]_decode[\'"];\s*\$\w{1,50}\s?=\s?\$\w{1,50}\(\$\w{1,50}\);(\$\w{1,50})\s?=\s?@?gzinflate\(\$\w{1,50}\);@?eval\(("\?>"\.?)?\4\);~msi',
            'id' => 'B64Gz',
        ],
        [
            'full' => '~\$\w+\s*=\s*"\w{32}";\s*function\s*(\w+)\((\$\w+)\)\{\s*\2=gzinflate\(base64_decode\(\2\)\);\s*for\(\$\w+=0;\$\w+<strlen\s*\(\2\);\$\w+\+\+\)\s*\{\2\[\$\w+\]\s*=\s*chr\(ord\(\2\[\$\w+\]\)(-?\d+)\);\s*\}\s*return\s*\2;\s*\}eval\(\1\s*\("([^"]+)"\)\);~msi',
            'id' => 'deltaOrd',
        ],
        [
            'fast' => '~<\?php\s(?:eval\(")?ob_start\(\);(?:"\))?\s\?>(.*?)<\?php\s(eval\(")?if\(!function_exists\("([^"]+)"\)\)\{function\s\3\(\)\{(\$[^=]+)=str_replace\(array\(([^)]+)\),array\(([^)]+)\),ob_get_clean\(\)\);for\((\$[^=]+)=1,(\$[^=]+)=ord\(\4\[0\]\);\7<strlen\(\4\);\7\+\+\)\4\[\7\]=chr\(ord\(\4\[\7\]\)-\8-\7\);\4\[0\]=\'\s\';return\s\4;\}\}(?:"\))?\s\?>(.*?)<\?php\s(\$[^=]+)=\3\(\);\s*eval\(\10\s*\)\s*(\?>\s*)+~msi',
            'full' => '~(?:<\?php\s*\$\w+\s*=\s*"[^"]+";\s*\?>\s*)?<\?php\s(?:eval\(")?ob_start\(\);(?:"\))?\s\?>(.*?)<\?php\s(eval\(")?if\(!function_exists\("([^"]+)"\)\)\{function\s\3\(\)\{(\$[^=]+)=str_replace\(array\(([^)]+)\),array\(([^)]+)\),ob_get_clean\(\)\);for\((\$[^=]+)=1,(\$[^=]+)=ord\(\4\[0\]\);\7<strlen\(\4\);\7\+\+\)\4\[\7\]=chr\(ord\(\4\[\7\]\)-\8-\7\);\4\[0\]=\'\s\';return\s\4;\}\}(?:"\))?\s\?>(.*?)<\?php\s(\$[^=]+)=\3\(\);\s*eval\(\10\s*\)\s*(\?>\s*)+~msi',
            'id' => 'outputBuffer',
        ],
        [
            'fast' => '~\s*(\$\w+)\s*=\s*[base64_decode"\.]+;.*?\1(?:.{0,300}?\1\((?:\$\w+|"[^"]+")\))+[^\}]+\}~msi',
            'full' => '~(?:\$\w+\s*=\s*\$_SERVER\["DOCUMENT_ROOT"\]\."/";)?\$\w+\s*=\s*"[^"]+";(?:\$\w+\s*=\s*\$_SERVER\["DOCUMENT_ROOT"\]\."/";)?\s*(\$\w+)\s*=\s*[base64_decode"\.]+;.*?\1(?:.{0,300}?\1\((?:\$\w+|"[^"]+")\))+[^\}]+\}~msi',
            'id' => 'doorwayInstaller',
        ],
        [
            'full' => '~(\$\w+)\s*=\s*"([^"]+)";\s*(\$\w+)\s*=\s*str_replace\((\w),"","[^"]+"\);\s*\3\(\'[eval\'.]+\(\'[base64_dcod\'.]+\(\'[gzinflate.\']+\(\'[base64_dcod\'.]+\(\'[^\)]+\)[^;]+;~msi',
            'id' => 'strReplaceAssert',
        ],
        [
            'full' => '~(?:(\$\{\'GLOBALS\'\}\[\'[^\']+\'\])=\'\w+\';\s*)+.*\1\};\}~msi',
            'id' => 'anaLTEAMShell',
        ],
        [
            'full' => '~(\$\w+)=\'[function_exis\'\.]+;\$\w+=\'[charodet\'\.]+;(\$\w+)=\'[eval\'\.]+;(\$\w+)=\'[gzinflate\'\.]+;(if\(!\1\(\'[base64_dcon\'\.]+\)\)({([^{}]*+(?:(?5)[^{}]*)*+)})else{function\s*[^}]+\}\})+(\$\w+)=\'[create_funion\'\.]+;(\$\w+)\s*=\s*\7\(\'([^\']+)\',\2\.\'\(\'\.\3\.\'\(\'\.\'[^(]+\(\9\)\'\.\'\)\'\.\'\)\'\.\';\'\);\8\("([^"]+)"\);~msi',
            'id' => 'zeuraB64Gzinflate',
        ],
        [
            'full' => '~function\s*(\w+)\((\$\w+)\)\{((?:(\$\w+)\s*=\s*str_replace\(\'[^\']+\',\'[^\']+\',\'[^\']+\'\);\s*)+)return\s*(\$\w+\(\'\',\$\w+\(\2\)\);)\}(\$\w+)\s*=\'([^\']+)\';(\$\w+)=\1\(\6\);\8\(\);~msi',
            'id' => 'strReplaceFunc',
        ],
        [
            'full' => '~(\$\w+)=array\(array\(((?:\'[^\']+\',?)+)\)\);\s*(?:/\*[^\*]+\*/)?(\$\w+)(?:/\*[^\*]+\*/)?[^\?]+\?>\s*\.\s*base64_decode\s*\(\s*str_rot13\s*\(\s*join\s*\(\s*\'\'\s*,\s*\3\s*\)\s*\)\s*\)\s*\.\s*\'[^\']+\'\s*\);(?:/\*[^\*]+\*/)?\s*(\$\w+)=array_walk\s*\(\1,\$\w+\);~msi',
            'id' => 'arrayMapB64',
        ],
        [
            'full' => '~preg_replace\(\'/\.\+\/e\',str_replace\("([^"]+)","([^"])*","([^"]+)"\),\'\.\'\);~msi',
            'id' => 'pregReplaceStrReplace',
        ],
        [
            'full' => '~(\$\w+)\s*=\s*(base64_decode\("([^"]+)"\));\s*(\$\w+)\s*=\s*(base64_decode\("([^"]+)"\));\s*echo\s*"[^"]+";\s*if\s*\(\$\w+\s*==\s*"[^"]+"\)\s*\$\w+\s*=\s*"[^"]+"\.\4\."[^"]+"\.\1;~msi',
            'id' => 'echoB64',
        ],
        [
            'full' => '~(\$\w+\s*=\s*"[^"]+"\^"[^"]+";)+\$\w+\s*=\s*\(?(?:@?\$\w+\()+\'([^\']+)\'\)+;(\$\w+\s*=\s*"[^"]+"\^"[^"]+";)+(\$\w+)\s*=\s*\(?(?:@?\$\w+\()+\'\$\w+\',"[^"]+"\^"[^"]+"\);@?\4\(\$\w+\);~msi',
            'id' => 'createFuncXored',
        ],
        [
            'full' => '~(\$\w{1,50})\s?=\s?array\(((?:\'[^\']\',?)+)\);\s?(?:\$\w{1,50}\s?=\s?(?:\1\[\d+\]\.?)+;\s?)+(\$\w{1,50})\s?=\s?((?:\$\w{1,50}\.?)+)\'(\$\w{1,50})\'\.(?:\1\[\d+\]\.?)+;\5\s?=\s?"([^"]+)";\s?@?eval\(\3\);~msi',
            'id' => 'evalDictArrayConcat',
        ],
        [
            'full' => '~(?:(?:\$\w+="[^"]+"|\$\w+="[a-f0-9\\\\x]+"\^"[a-f0-9\\\\x]+");)+\$\w+=(?:\$\w+\.?)+;\s*(\$\w+)\("/(\w+)/e",(\$\w+),"\2"\);\s*\1\("/\2/e",(\$\w+),"\2"\);~msi',
            'id' => 'pregReplaceXored',
        ],
        [
            'full' => '~\$\w{1,5}=\'([a-z0-9+/=]{1,100}\s[a-z0-9+/=\s]+)\';(\$\w)=["\']_COOK[\\\\x0-9]{1,10}";\s*if\(!empty\(\${\2}\[["\']key["\']\]\)\){(?:\$\w=[^;]{1,30};\s*){1,5}for\([^)]{1,40}\)(?:\$\w\[?\]?=[^;]{1,30};\s*){1,5}for\([^)]{1,40}\){[^}]{1,150}}if[^;]{1,50};\s*if\(\(\$\w=@?gzinflate\(\$\w\)\)&&\(md5\(substr\(\$\w,\d,\$\w\)\)===\'([a-f0-9]{32})\'\)\){\$\w{1,5}=[^;]{1,100};if\(PHP_VERSION<\'5\'\){[^}]{1,1000}}@create_function\(\'\',"[^"]{1,100}"\.\$\w{1,5}\.\'{\'\);}}\s*DIE\(.{1,500}>"\);~mis',
            'id' => 'base64EncryptedGz',
        ],
        
        /*[
            'full' => '~class\s*(\w+)\s*{\s*function\s*__construct\(\)\s*\{\s*(\$\w+)\s*=\s*\$this->(\w+)\(\$this->\w+\);\s*\2\s*=\s*\$this->(\w+)\(\$this->(\w+)\(\2\)\);\s*\2\s*=\s*\$this->(\w+)\(\2\);\s*if\(\2\)\s*\{\s*\$this->(\w+)\s*=\s*\2\[\d\];\s*\$this->(\w+)\s*=\s*\2\[\d\];\s*\$this->\w+\s*=\s*\2\[\d\];\s*\$this->(\w+)\(\2\[\d\],\s*\2\[\d\]\);\s*\}\s*\}\s(?:function\s*\w+\((?:(?:\$\w+),?\s?){0,3}\)\s*\{\s*(?:\$this->\w+\s*=\s*\$\w+;\s*\$this->\w+\s*=\s*\$\w+;\s*\$this->\w+\s*=\s*\$this->\3\(\$this->\w+\);\s*\$this->\w+\s*=\s*\$this->\5\(\$this->\w+\);\s*\$this->\w+\s*=\s*\$this->\w+\(\);\s*if\(strpos[^{]+{[^}]+}\s*\}\s*|\$\w+\s*=\s*(?:\$this->\w+\[\d\]\.?)+;\s*(?:\$\w+\s*=\s*@?\$\w+\((?:\'\',\s*)?(?:(?:\$\w+),?\s?){0,3}\);)?\s*(?:return\s*\$\w+(?:\((?:"[^"]+",\s*"",\s*\$\w+)?\))?;)?\s*\}\s*|\$\w+\s*=\s*strlen\(\$\w+\)\s*\+\s*strlen\(\$\w+\);\s*while\(strlen\(\$\w+\)\s*<\s*\$\w+\)\s*\{\s*\$\w+\s*=\s*ord\(\$\w+\[\$this->\w+\]\)\s*-\s*ord\(\$\w+\[\$this->\w+\]\);\s*\$\w+\[\$this->\w+\]\s*=\s*chr\(\$\w+\s*%\s*\(2048/8\)\);\s*\$\w+\s*\.=\s*\$\w+\[\$this->\w+\];\s*\$this->\w+\+\+;\s*\}\s*return\s*\$\w+;\s*\}\s*|\$this->\w+\s*=\s*\$this->\w+\(\$this->\w+,\s*\$this->\w+,\s*\$this->\w+\);\s*\$this->\w+\s*=\s*\$this->\w+\(\$this->\w+\);\s*return\s*\$this->\w+;\s*\}\s*))+var\s*\$\w+;\s*var\s*\$\w+\s*=\s*0;\s*(?:var\s*\$\w+\s*=\s*array\([\'gzinflatecr_utobs64dtkp, ]+\);\s*)+var\s*\$\w+\s*=\s*\'([^\']+)\';\s*var\s*\$\w+\s*=\s*\'([^\']+)\';\s*\}\s*new\s*\1\(\);~msi',
            'id' => 'classDecoder',
        ],
        [
            'full' => '~if\(isset\(\$_POST\[\'\w+\'\]\)\){echo[\s\'\w]+;\s*exit\(\);}\s*if\(isset\(\$_COOKIE\)\){(\$\w+)=\$_COOKIE;\(count\(\1\)==\d+&&in_array\(gettype\(\1\)\.count\(\1\),\1\)\)\?\(\(\1\[\d+\]=\1\[\d+\]\.\1\[\d+\]\)&&\(\1\[\d+\]=\1\[\d+\]\(\1\[\d+\]\)\)&&\(\1=\1\[\d+\]\(\1\[\d+\],\1\[\d+\]\(\1\[\d+\]\)\)\)&&\1\(\)\):\1;}\s*if\(!isset\(\$_POST\[\'\w+\'\]\)&&!isset\(\$_GET\[\'\w+\'\]\)\){exit\(\);}\s*(?:(\$\w+)\[\d+\]=\'\w+\';)+\s*if\(isset\(\$_POST\[\'\w+\'\]\)\){\$\w+=\$_POST\[\'\w+\'\];}else{\$\w+=\$_GET\[\'\w+\'\];}\s*\$\w+\s*=\s*array_flip\(str_split\(\'(\w+)\'\)\);\$\w+\s*=\s*str_split\(md5\(\$\w+\)\.md5\(\$\w+\)\);\$\w+\s*=\s*array\(\);\$\w+\s*=\s*\'\';\s*foreach\s*\(\$\w+\s*as\s*\$\w+\s*=>\s*\$\w+\)\s*{while\s*\(1\)\s*{if\(isset\(\$\w+\[\$\w+\[\$\w+\]\]\)\){\$\w+\[\$\w+\]\+\+;}else\{\$\w+\[\$\w+\[\$\w+\]\]=\'\';break;}}}\s*foreach\s*\(\$\w+\s*as\s*\$\w+\s*=>\s*\$\w+\)\s*{\$\w+\s*\.=\s*\$\w+\[\$\w+\];}\s*eval\(trim\(base64_decode\(base64_decode\(\$\w+\)\)\)\);~mis',
            'fast' => '~if\(isset\(\$_POST\[\'\w+\'\]\)\){echo[\s\'\w]+;\s*exit\(\);}\s*if\(isset\(\$_COOKIE\)\){(\$\w+)=\$_COOKIE;\(count\(\1\)==\d+&&in_array\(gettype\(\1\)\.count\(\1\),\1\)\)\?\(\(\1\[\d+\]=\1\[\d+\]\.\1\[\d+\]\)&&\(\1\[\d+\]=\1\[\d+\]\(\1\[\d+\]\)\)&&\(\1=\1\[\d+\]\(\1\[\d+\],\1\[\d+\]\(\1\[\d+\]\)\)\)&&\1\(\)\):\1;}\s*if\(!isset\(\$_POST\[\'\w+\'\]\)&&!isset\(\$_GET\[\'\w+\'\]\)\){exit\(\);}\s*(?:(\$\w+)\[\d+\]=\'\w+\';)+\s*if\(isset\(\$_POST\[\'\w+\'\]\)\){\$\w+=\$_POST\[\'\w+\'\];}else{\$\w+=\$_GET\[\'\w+\'\];}\s*\$\w+\s*=\s*array_flip\(str_split\(\'(\w+)\'\)\);\$\w+\s*=\s*str_split\(md5\(\$\w+\)\.md5\(\$\w+\)\);\$\w+\s*=\s*array\(\);\$\w+\s*=\s*\'\';\s*foreach\s*\(\$\w+\s*as\s*\$\w+\s*=>\s*\$\w+\)\s*{while\s*\(1\)\s*{if\(isset\(\$\w+\[\$\w+\[\$\w+\]\]\)\){\$\w+\[\$\w+\]\+\+;}else\{\$\w+\[\$\w+\[\$\w+\]\]=\'\';break;}}}\s*foreach\s*\(\$\w+\s*as\s*\$\w+\s*=>\s*\$\w+\)\s*{\$\w+\s*\.=\s*\$\w+\[\$\w+\];}\s*eval\(trim\(base64_decode\(base64_decode\(\$\w+\)\)\)\);~mis',
            'id' => 'scriptWithPass',
        ],*/

        /*************************************************************************************************************/
        /*                                          JS patterns                                                      */
        /*************************************************************************************************************/

        [
            'full' => '~(eval\()?String\.fromCharCode\(([\d,\s]+)\)+;~msi',
            'fast' => '~String\.fromCharCode\([\d,\s]+\)+;~msi',
            'id'   => 'JS_fromCharCode',
        ],
        [
            'full' => '~(?:eval\()?unescape\(\'([^\']+)\'\)\);\s{0,50}eval\(unescape\(\'([^\']+)\'\)\s{0,50}\+\s{0,50}\'([^\']+)\'\s{0,50}\+\s{0,50}unescape\(\'[^\']+\'\)\);~msi',
            'fast' => '~unescape\(\'([^\']+)\'\)\);\s{0,50}eval\(unescape\(\'([^\']+)\'\)\s{0,50}\+\s{0,50}\'([^\']+)\'\s{0,50}\+\s{0,50}unescape\(\'[^\']+\'\)\);~msi',
            'id'   => 'JS_unescapeContentFuncWrapped',
        ],
        [
            'full' => '~var\s*(\w+)=\s*\[((?:\'[^\']+\',?)+)\];\(function\(\w+,\w+\)\{var\s*\w+=function\(\w+\)\{while\(--\w+\)\{\w+\[\'push\'\]\(\w+\[\'shift\'\]\(\)\);\}\};.*?\(\1,(0x\w+)\)\);var\s*(\w+)=function\s*\((\w+),(\w+)\)\s*\{\5=\5-0x\d+;var\s*\w+=\w+\[\5\];if\(\4\[\'\w+\']===undefined\)\{\(function\(\)\{var\s*(\w+);try\{var\s*(\w+)=Function\(\'[^;]++;\'\);\7=\8\(\);\}catch\(\w+\)\{\7=window;\}var\s*\w+=\'[^\']+\';\7\[\'atob\'\]\|\|\(\7\[\'atob\'\]=function\(\w+\)\{[^}]+\}return\s*\w+;\}\);\}\(\)\);var\s*\w+=function\(\w+,\w+\)\{var\s*\w+=.+?String\[\'fromCharCode\'\].+?return\s*\w+;\};\4\[\'\w+\'\]=\w+;\4\[\'\w+\'\]=\{\};\4\[\'\w+\'\]=!!\[\];\}var\s*\w+=\4\[\'\w+\'\]\[\w+\];.+?((.+?\4\(\'0x\d+\',\'[^\']+\'\)).+?)+[^\s]+~msi',
            'fast' => '~var\s*(\w+)=\s*\[((?:\'[^\']+\',?)+)\];\(function\(\w+,\w+\)\{var\s*\w+=function\(\w+\)\{while\(--\w+\)\{\w+\[\'push\'\]\(\w+\[\'shift\'\]\(\)\);\}\};.*?var\s*(\w+)=function\s*\((\w+),(\w+)\)\s*\{\4=\4-0x\d+;var\s*\w+=\w+\[\4\];if\(\3\[\'\w+\']===undefined\)\{\(function\(\)\{var\s*(\w+);try\{var\s*(\w+)=Function\(\'[^;]++;\'\);\6=\7\(\);\}catch\(\w+\)\{\6=window;\}var\s*\w+=\'[^\']+\';\6\[\'atob\'\]\|\|\(\6\[\'atob\'\]=function\(\w+\)\{[^}]+\}return\s*\w+;\}\);\}\(\)\);var\s*\w+=function\(\w+,\w+\)\{var\s*\w+=.+?String\[\'fromCharCode\'\].+?return\s*\w+;\};\3\[\'\w+\'\]=\w+;\3\[\'\w+\'\]=\{\};\3\[\'\w+\'\]=!!\[\];\}var\s*\w+=\3\[\'\w+\'\]\[\w+\];.+?((.+?\3\(\'0x\d+\',\'[^\']+\'\)).+?)+[^\s]+~msi',
            'id'   => 'JS_ObfuscatorIO',
        ],
        [
            'full' => '~<script\s(?:language|type)=[\'"](?:text/)?javascript[\'"]>\s*(?:(?:<!--.*?-->)?\s?<!--\s*)?document\.write\((?:unescape\()?[\'"]([^\'"]+)[\'"]\)\)?;(?:\s?//-->)?\s*</script>~msi',
            'id'   => 'JS_documentWriteUnescapedStr',
        ],
        [
            'full' => '~eval\(function\(p,a,c,k,e,(?:d|r)\)\{.*?}\(\'(.*)\', *(\d+), *(\d+), *\'(.*?)\'\.split\(\'\|\'\),\d,\{\}\)\);~msi',
            'id'   => 'JS_deanPacker',
        ],
        [
            'full' => '~\(function\s*\(\$,\s*document\)\s*({([^{}]*+(?:(?1)[^{}]*)*+)})\)\(\(function\s*\((\w),\s*(\w)\)\s*\{\s*function\s*(\w)\((\w+)\)\s*\{\s*return\s*Number\(\6\)\.toString\(36\)\.replace\(/\[0\-9\]/g,\s*function\s*\((\w)\)\s*\{\s*return\s*String\.fromCharCode\(parseInt\(\7,\s*10\)\s*\+\s*65\);\s*\}\s*\);\s*\}\s*var\s*\w+\s*=\s*\{\s*\$:\s*function\s*\(\)\s*\{\s*var\s*\w+\s*=\s*\{\};\s*[^}]+\}\s*return\s*\w;\s*\}\s*\};\s*\3\s*=\s*\3\.split\(\'\+\'\);\s*for\s*\(var\s*\w\s*=\s*0;\s*\w\s*<\s*(\d+);\s*\w\+\+\)\s*\{\s*\(function\s*\(\w\)\s*\{\s*Object\.defineProperty\(\w,\s*\5\(\w\),\s*\{\s*get:\s*function\s*\(\)\s*\{\s*return\s*\w\[\w\]\[0\]\s*\!==\s*\';\'\s*\?\s*\4\(\w\[\w\]\)\s*:\s*parseFloat\(\w\[\w\]\.slice\(1\),\s*10\);\s*\}\s*\}\);\s*\}\(\w\)\);\s*\}\s*return\s*\w;\s*\}\(\'([^\']+)\',\s*function\s*\(\w\)\s*\{\s*for\s*\(var\s*(\w)\s*=\s*\'([^\']+)\',\s*(\w)\s*=\s*\[([^\]]+)\],\s*\w\s*=\s*\'\'[^{]+\{\s*var\s*(\w)\s*=\s*\10\.indexOf\(\w\[\w\]\);\s*\12\.indexOf\(\w\[\w\]\)\s*>\s*\-1\s*&&\s*0\s*===\s*\12\.indexOf\(\w\[\w\]\)\s*&&\s*\(\w\s*=\s*0\),\s*\14\s*>\s*-1\s*&&\s*\(\w\s*\+=\s*String\.fromCharCode\(\w\s*\*\s*\10\.length\s*\+\s*\14\),\s*\w\s*=\s*1\);\s*\}\s*return\s*\w;\s*\}\)\),\s*\(function\s*\(\w\)\s*\{\s*var\s*_\s*=\s*{};\s*for\s*\(\w\s*in\s*\w\)\s*\{\s*try\s*\{\s*_\[\w\]\s*=\s*\w\[\w\]\.bind\(\w\);\s*\}\s*catch\s*\(\w\)\s*\{\s*_\[\w\]\s*=\s*\w\[\w\];\s*\}\s*\}\s*return\s*_;\s*\}\)\(document\)\)~msi',
            'id'   => 'JS_objectDecode',
        ],
        /*************************************************************************************************************/
        /*                                          PYTHON patterns                                                 */
        /*************************************************************************************************************/

        [
            'full' => '~eval\(compile\(zlib\.decompress\(base64\.b64decode\([\'"]([^\'"]+)[\'"]\)\),[\'"]<string>[\'"],[\'"]exec[\'"]\)\)~msi',
            'id'   => 'PY_evalCompileStr',
        ],
    ];

    private $full_source;
    private $prev_step;
    private $cur;
    private $obfuscated;
    private $max_level;
    private $max_time;
    private $run_time;
    private $fragments;
    private $grabed_signature_ids;
    private $active_fragment;
    private $excludes;

    public function __construct($text, $origin_text = '', $max_level = 30, $max_time = 5)
    {
        $this->text         = $text;
        $this->full_source  = $text;

        if ($this->defineSpecificObfuscator($text, $origin_text)) {
            $this->text         = $origin_text;
            $this->full_source  = $origin_text;
        }

        $this->max_level            = $max_level;
        $this->max_time             = $max_time;
        $this->fragments            = [];
        $this->grabed_signature_ids = [];
        $this->excludes             = [];
    }

    private function getPreviouslyDeclaredVars($string)
    {
        $foundVar = false;
        foreach ($this->fragments as $frag => $fragment) {
            if ($foundVar || strpos($frag, '$codelock_lock') !== false) {
                break;
            }

            $subject = '';
            $pos     = strpos($fragment, $string . '=') ?: strpos($fragment, $string . ' ');
            if ($pos !== false && strpos(substr($fragment, $pos + strlen($string)), '$') !== 1) {
                $subject = substr($fragment, $pos);
            } else {
                $pos = strpos($frag, $string . '=') ?: strpos($frag, $string . ' ');
                if ($pos !== false) {
                    $subject = substr($frag, $pos);
                } else {
                    $pos = strpos($this->full_source, $string . '=') ?: strpos($this->full_source, $string . ' ');
                    if ($pos !== false) {
                        $subject = substr($this->full_source, $pos);
                    } else {
                        continue;
                    }
                }
            }

            if (@preg_match_all('~(\$\w{1,40})\s*=\s*((\(*(base64_decode\s*\(|pack\s*\(\'H\*\',|convert_uudecode\s*\(|htmlspecialchars_decode\s*\(|stripslashes\s*\(|gzinflate\s*\(|strrev\s*\(|str_rot13\s*\(|gzuncompress\s*\(|urldecode\s*\(|rawurldecode\s*\(|eval\s*\()+((?:(["\'])((.*?[^\\\\])??((\\\\\\\\)+)?+)\6[^;]+)|(?:\$\w+)\)*;*))|((["\'])((.*?[^\\\\])??((\\\\\\\\)+)?+)\12));~msi', $subject, $matches, PREG_SET_ORDER) > 0) {
                foreach ($matches as $m) {
                    if ($m[1] !== $string) {
                        continue;
                    }
                    if (isset($m[12]) && $m[12] !== '') {
                        $str = substr(@$m[2], 1, -1);
                        $foundVar = true;
                    }
                    if (isset($m[5]) && $m[5] !== '') {
                        $str = $this->unwrapFuncs($m[2]);
                        $foundVar = true;
                    }

                    $this->fragments[$this->active_fragment] = str_replace($m[0], '', $this->fragments[$this->active_fragment]);
                    break;
                }
            }
        }
        return $str;
    }

    private function defineSpecificObfuscator($text, $origin_text)
    {
        if (strpos($origin_text, '#!/') === 0                                                                                                       //not a php file
            || strpos($origin_text, '0=__FILE__;')                                             &&
                (strpos($origin_text, ';return;?>') || strpos($origin_text, 'This file is protected by copyright law and provided under'))  //lockit1 || evalFileContentBySize
            || strpos($origin_text, 'The latest version of Encipher can be obtained from')  && strpos($origin_text, '\'@ev\'));')           //EvalFileContent
            || strpos($origin_text, 'substr(file_get_contents(__FILE__),')                  && strpos($origin_text, '__halt_compiler();')   //EvalFileContentOffset
            || strpos($text, 'create_function(\'\', base64_decode(@stream_get_contents(')   && strpos($text, '@fopen(__FILE__,')            //wpKey (eval)
            || strpos($origin_text, '//base64 - gzinflate - str_rot13 - convert_uu - gzinflate - base64')                                          //
        ) {
            return true;
        }

        $text_wo_ws = str_replace(' ', '', $text);
        if (strpos($text_wo_ws, '=file(__FILE__);eval(base64_decode(')      && strpos($text_wo_ws, '));__halt_compiler();') //zeura hack
            || strpos($text_wo_ws, 'define(\'__LOCALFILE__\',__FILE__);')   && strpos($text_wo_ws, '__halt_compiler();')    //obf_20200527_1
            || strpos($text_wo_ws, '");$cvsu=$gg') || strpos($text_wo_ws, '$cyk=$cyd[')                                     //TinkleShell
        ) {
            return true;
        }

        return false;
    }

    private function checkObfuscatorExcludes($str, $type = false, $matches = [])
    {
        switch ($type) {
            case '':
                if(strpos($str, '# Malware list detected by AI-Bolit (http') !== false) {
                    return '';
                }
                if(strpos($str, '#Malware list detected by AI-Bolit(http') !== false) {
                    return '';
                }
                if(strpos($str, '<div class="header">Отчет сканера ') !== false) {
                    return '';
                }
                if (strpos($str, '$default_action="FilesMan"') !== false) {
                    return '';
                }
                break;
            case 'echo':
                if (preg_match('~\$_[GPRC](?:OST|ET|EQUEST|OOKIE)~ms', $matches[0])) {
                    return '';
                }
                if (!isset($matches[5]) || $matches[5] === '') {
                    return '';
                }
                break;
            case 'eval':
                if (strpos($matches[0], 'file_get_contents') !== false) {
                    return '';
                }
                if (preg_match('~\$_[GPRC](?:OST|ET|EQUEST|OOKIE)~ms', $matches[0])) {
                    return '';
                }
                if (strpos($matches[0], '=> array(\'eval(base64_decode(\')') !== false) {
                    return '';
                }
                if (@$matches[6] === '\'";') {
                    return '';
                }
                break;
        }
        return $type;
    }

    public function getObfuscateType($str)
    {
        $str = preg_replace('~\s+~', ' ', $str);
        $l_UnicodeContent = Helpers::detect_utf_encoding($str);
        if ($l_UnicodeContent !== false) {
            if (function_exists('iconv')) {
                $str = iconv($l_UnicodeContent, "CP1251//IGNORE", $str);
            }
        }
        if ($this->checkObfuscatorExcludes($str) === '') {
            return '';
        }
        foreach (self::$signatures as $signature) {
            $fast_regexp = isset($signature['fast']) ? $signature['fast'] : $signature['full'];
            if (isset($this->excludes[$str]) && in_array($signature['id'], $this->excludes[$str])) {
                continue;
            }
            if (preg_match($fast_regexp, $str, $matches)) {
                return $this->checkObfuscatorExcludes($str, $signature['id'], $matches);
            }
        }
        return '';
    }

    private function getObfuscateFragment($str, $type)
    {
        foreach (self::$signatures as $signature) {
            if ($signature['id'] == $type && preg_match($signature['full'], $str, $matches)) {
                return $matches;
            }
        }
        return '';
    }

    public function getFragments()
    {
        if (count($this->fragments) > 0) {
            return $this->fragments;
        }
        return false;
    }

    public function getGrabedSignatureIDs()
    {
        return array_keys($this->grabed_signature_ids);
    }

    private function grabFragments()
    {
        if ($this->cur === null) {
            $this->cur = $this->text;
        }
        $str = $this->cur;
        reset(self::$signatures);
        while ($sign = current(self::$signatures)) {
            $regex = $sign['full'];
            if (preg_match($regex, $str, $matches)) {
                $this->grabed_signature_ids[$sign['id']] = 1;
                $this->fragments[$matches[0]] = $matches[0];
                $str = str_replace($matches[0], '', $str);
            } else {
                next(self::$signatures);
            }
        }
    }

    private function deobfuscateFragments()
    {
        $prev_step = '';
        if (!count($this->fragments)) {
            return;
        }
        $i = 0;
        foreach ($this->fragments as $frag => $value) {
            if ($frag !== $value) {
                continue;
            }
            $this->active_fragment = $frag;
            $type = $this->getObfuscateType($value);

            while ($type !== '' && $i < 50) {
                $match  = $this->getObfuscateFragment($value, $type);
                if (!is_array($match)) {
                    break;
                }
                $find   = $match[0] ?? '';
                $func   = 'deobfuscate' . ucfirst($type);

                try {
                    $temp = @$this->$func($find, $match);
                } catch (Exception $e) {
                    $temp = '';
                }
                if ($temp !== '' && $temp !== $find) {
                    $value = str_replace($find, $temp, $value);
                } else {
                    $this->excludes[preg_replace('~\s+~', ' ', $value)][] = $type;
                    $this->fragments[$frag] = $value;
                    $type = $this->getObfuscateType($value);
                    continue;
                }

                $this->fragments[$frag] = $value;
                $type = $this->getObfuscateType($value);
                $value_hash = hash('sha256', $value);
                if ($prev_step === $value_hash) {
                    break;
                }
                $prev_step = $value_hash;
                $i++;
            }
            $this->fragments[$frag] = Helpers::postProcess($this->fragments[$frag]);
        }
    }

    public function deobfuscate($hangs = 0, $prev_step = '')
    {
        $deobfuscated   = '';
        $this->run_time = microtime(true);
        $this->cur      = $this->text;

        $this->grabFragments();
        $this->deobfuscateFragments();

        $deobfuscated = $this->cur;

        if (count($this->fragments) > 0 ) {
            foreach ($this->fragments as $fragment => $text) {
                $deobfuscated = str_replace($fragment, $text, $deobfuscated);
            }
        }

        $deobfuscated = Helpers::postProcess($deobfuscated);

        if (substr_count(substr($deobfuscated, 0, 400), 'base64_decode(\'') > 3) {
            $deobfuscated = preg_replace_callback('~base64_decode\(\'([^\']+)\'\)~msi', static function ($matches) {
                return "'" . base64_decode($matches[1]) . "'";
            }, $deobfuscated);
        }

        if ($this->getObfuscateType($deobfuscated) !== '' && $hangs < 6) {
            $this->text = $deobfuscated;
            if ($prev_step === hash('sha256', $deobfuscated)) {
                return $deobfuscated;
            }
            $deobfuscated = $this->deobfuscate(++$hangs, hash('sha256', $deobfuscated));
        }
        return $deobfuscated;
    }

    public static function getSignatures()
    {
        return self::$signatures;
    }

    private function deobfuscateStrrotPregReplaceEval($str, $matches)
    {
        $find = $matches[0];
        $res = str_rot13($matches[2]);
        $res = str_replace($find, $res, $str);
        return $res;
    }

    private function deobfuscateObf_20200618_1($str)
    {
        preg_match('~(\$\{"[\\\\x47c2153fGLOBALS]+"\}\["[\w\\\\]+"\]="[\w\\\\]+";(\$\w+="\w+";)?)+.+\$\{"[\\\\x47c2153fGLOBALS]+"\}\["[\w\\\\]+"\].+}+~msi', $str, $matches);
        $find = $matches[0];
        $res = stripcslashes($str);
        $res = str_replace($find, $res, $str);
        return $res;
    }

    private function deobfuscateBypass($str, $matches)
    {
        $find = $matches[0];
        $bypass = stripcslashes($matches[2]);
        $eval = $matches[3] . $bypass . $matches[4];
        $res = str_replace($find, $eval, $str);
        return $res;
    }

    private function deobfuscateObf_20200720_1($str, $matches)
    {
        $find = $matches[0];
        $res = base64_decode($matches[2]);
        $res = str_replace($find, $res, $str);
        return $res;
    }

    private function deobfuscateGoto($str)
    {
        return Helpers::unwrapGoto($str);
    }

    private function deobfuscateObf_20200527_1($str)
    {
        preg_match('~error_reporting\(0\);define\(\'\w+\',\s*__FILE__\);define\(\'\w+\',\s*fopen\(__FILE__,\s*\'r\'\)\);fseek\(\w+,\s*__COMPILER_HALT_OFFSET__\);((\$\w+="\\\\x[0-9a-f]+";)+(\$\w+="[^"]+";)+eval\("\?>"\.(\$\w+\()+"([^"]+)"\)+;)+(?:/\*\w+\*/)?__halt_compiler\(\);([\w#|>^%\[\.\]\\\\/=]+)~msi', $str, $matches);
        $find = $matches[0];
        $res = $str;
        $encoded = $matches[6];
        $res = preg_replace_callback('~(\$\w+="\\\\x[0-9a-f]+";)+(\$\w+="[^"]+";)+eval\("\?>"\.(\$\w+\()+"([^"]+)"\)+;~msi', static function ($m) use ($str) {
            $layer1 = hex2bin(str_rot13(gzinflate(str_rot13(base64_decode($m[4])))));
            if (preg_match('~(\$\w+="[^"]+";)+eval\(\$\w\.(\$\w+\()+"([^"]+)"\)+;~msi', $layer1, $matches)) {
                $temp = "?>" . hex2bin(str_rot13(gzinflate(str_rot13(base64_decode($matches[3])))));
                while (preg_match('~(\$\w+)=strrev\(\1\);(\1=\s*str_replace\([\'"]([^"\']+)[\'"],"[^"]+",\1\);)+@?eval\("\?\>"\.\$\w+\(\1\)+;~msi', $temp, $matches)) {
                    if (preg_match_all('~(\$\w+)="([^"]+)";~msi', $layer1, $matches1)) {
                        foreach($matches1[1] as $k => $v) {
                            if ($v !== $matches[1]) {
                                continue;
                            }
                            $code = $matches1[2][$k];
                            $code = strrev($code);
                            if (preg_match_all('~str_replace\([\'"]([^"\']+)[\'"],"([^"]+)"~msi', $temp, $m, PREG_SET_ORDER)) {
                                foreach($m as $item) {
                                    $code = str_replace($item[1], $item[2], $code);
                                }
                                $temp = base64_decode($code);
                            }
                            break;
                        }
                    }
                }
                return $temp;
            }
        }, $res);
        if (preg_match_all('~str_replace\([\'"]([^"\']+)[\'"],[\'"]([^"\']+)[\'"]~msi', $res, $m, PREG_SET_ORDER)) {
            foreach($m as $item) {
                $encoded = str_replace($item[1], $item[2], $encoded);
            }
            $res = base64_decode($encoded);
        }

        $res = str_replace($find, $res, $str);
        return $res;
    }

    private function deobfuscateObf_20200602_1($str)
    {
        preg_match('~(\$\w+)=strrev\("[base64_decode]+"\)\.str_replace\(\'(\w+)\',\'\',\'\w+\'\);\s*eval\(\1\((\$\w+)\)\);~msi', $str, $matches);
        $find = $matches[0];
        $res = 'eval(base64_decode(' . $matches[3] . '));';
        $res = str_replace($find, $res, $str);
        return $res;
    }

    private function deobfuscateObf_20200526_1($str, $matches)
    {
        $find = $matches[0];
        $res = base64_decode($matches[2]);
        $res = str_replace($find, $res, $str);
        return $res;
    }

    private function deobfuscateObf_20200522_1($str, $matches)
    {
        $find = $matches[0];
        $res = strrev(gzinflate(base64_decode(substr($matches[14], (int)hex2bin($matches[4]) + (int)hex2bin($matches[6]), (int)hex2bin($matches[8])))));
        $res = str_replace($find, $res, $str);
        return $res;
    }

    private function deobfuscateObf_20200507_5($str, $matches)
    {
        $find = $matches[0];
        $res = base64_decode($matches[1]);
        $res = str_replace($find, $res, $str);
        return $res;
    }

    private function deobfuscateObf_20200507_4($str, $matches)
    {
        $find = $matches[0];
        $ar = $matches[2];
        $ar = explode(",\n", $ar);
        $array = [];
        foreach ($ar as $v) {
            $array[substr(trim($v),1,1)] = substr(trim($v), -2, 1);
        }
        unset($ar);
        $res = '';
        $split = str_split($matches[5]);
        foreach ($split as $x) {
            foreach ($array as $main => $val) {
                if ($x == (string)$val) {
                    $res .= $main;
                    break;
                }
            }
        }
        $res = gzinflate(base64_decode($res));
        $res = str_replace($find, $res, $str);
        return $res;
    }

    private function deobfuscateObf_20200513_1($str, $matches)
    {
        $find = $matches[0];
        $res = gzuncompress(base64_decode(strrev($matches[5])));
        $res = str_replace($find, $res, $str);
        return $res;
    }

    private function deobfuscateObf_20200507_2($str, $matches)
    {
        $find = $matches[0];
        $res = base64_decode($matches[4]);
        $res = str_replace($find, $res, $str);
        return $res;
    }

    private function deobfuscateObf_20200507_1($str)
    {
        preg_match('~(\$\w+)=base64_decode\(\'([^\']+)\'\);\s*eval\(\1\);~mis', $str, $matches);
        $find = $matches[0];
        $res = base64_decode($matches[2]);
        $res = str_replace($find, $res, $str);
        return $res;
    }

    private function deobfuscateObf_20200504_1($str)
    {
        preg_match('~(\$\w+)\s*=\s*\("\?>"\.gzuncompress\(base64_decode\("([^"]+)"\)\)\);\s*@?eval\(\1\);~msi', $str, $matches);
        $find = $matches[0];
        $res = ' ?>' . gzuncompress(base64_decode($matches[2]));
        $res = str_replace($find, $res, $str);
        return $res;
    }

    private function deobfuscateSmartToolsShop($str, $matches)
    {
        $find = $matches[0];
        $res = str_rot13(gzinflate(str_rot13(base64_decode($matches[2]))));
        $res = str_replace($find, $res, $str);
        return $res;
    }

    private function deobfuscateObf_20200421_1($str)
    {
        preg_match('~(?:\$\w+\s*=\s*\'\w+\';)?\s*(\$\w+)\s*=\s*urldecode\(\'[%0-9a-f]+\'\);(\s*(\$\w+)\s*=(\s*\1\{\d+\}\.?)+;)+\s*(\$\w+)\s*=\s*"[^"]+"\.\3\("([^"]+)"\);\s*eval\(\5\);~msi', $str, $matches);
        $find = $matches[0];
        $res = ' ?>' . base64_decode($matches[6]);
        $res = str_replace($find, $res, $str);
        return $res;
    }

    private function deobfuscateObf_20200414_1($str, $matches)
    {
        $data = $matches[1];
        $key = $matches[2];
        $res = Helpers::obf20200414_1_decrypt($data, $key);
        return $res;
    }

    private function deobfuscateObf_20200402_2($str, $matches)
    {
        $find = $matches[0];
        $code = $matches[17];
        if (isset($matches[1]) && !empty($matches[1])) {
            $vars = Helpers::collectVars($matches[1], '\'');
            $code = Helpers::replaceVarsFromArray($vars, $matches[2], false, true);
            $code = Helpers::collectStr($code, '\'');
            $code = substr($code, strpos($code,'\'') + 1);
        }
        $code = preg_replace_callback('~\s*"\s*\.((?:min|max|round)?\(\s*\d+[\.\,\|\s\|+\|\-\|\*\|\/]([\d\s\.\,\+\-\*\/]+)?\))\s*\.\s*"~msi', static function($m) {
            return substr(Helpers::calc($m[1]), 1, -1);
        }, $code);
        $res = gzinflate(base64_decode($code)) ?:base64_decode($code);
        $res = str_replace($find, $res, $str);
        return $res;
    }

    private function deobfuscateTwoHashFunc($str, $matches)
    {
        $funcs = [
            $matches[1].'::'.$matches[2] => [
                'data' => Helpers::prepareArray($matches[3]),
                'func' => null,
            ],
            $matches[4].'::'.$matches[5] => [
                'data' => Helpers::prepareArray($matches[6]),
                'func' => null,
            ],
        ];
        
        $code = Helpers::normalize($matches[7]);
        
        foreach ($funcs as $name => &$params){
            $data = $params['data'];
            if (isset($data[0]) && intval($data[0])) {
                $params['func'] = function ($n, $k) use ($data) {
                    if (!isset($data[$n])) {
                        return false;
                    }
                    return $data[$n];
                };
            }
            else {
                $params['func'] = function ($n, $k) use ($data){
                    $l = strlen($k);
                    if (!isset($data[$n])) {
                        return false;
                    }
                    $r = base64_decode($data[$n]);
                    for ($i = 0, $c = strlen($r); $i !== $c;  ++$i) {
                        $r[$i] = chr(ord($r[$i]) ^ ord($k[$i % $l]));
                    }
                    return '\'' . $r . '\'';
                };
            }
        }
        unset($params);
        
        $new_code = preg_replace_callback('~(_\w{1,5})::(\w{1,5})\s*\(([^)]+)\)~mis', function ($m) use ($funcs) {
            $original       = $m[0];
            $class_name     = $m[1];
            $method_name    = $m[2];
            $vars           = str_replace(['"', "'"], '', $m[3]);
            
            list($var1, $var2) = explode(',', $vars);
            $func_name = $class_name . '::' . $method_name;
            if (!isset($funcs[$func_name]['func'])) {
                return $original;
            }
            return $funcs[$func_name]['func']($var1, $var2);
        }, $code);
        return MathCalc::calcRawString($new_code);        
    }    
    
    private function deobfuscateObf_20200402_1($str, $matches)
    {
        $find = $matches[0];
        $res = gzinflate(hex2bin(pack('H*',$matches[6])));
        $res = preg_replace('~//.+$~m', '', $res);
        preg_match('~\$\w+\(\$\w+,\$\w+\("",\s*\$\w+\(\$\w+\(\$\w+\(\$\w+\(\$\w+,\s*"(\d+)"\)+,\$\w+\);.+function \w+\((\$\w+),\s*\$\w+,\s(\$\w+)\)\s{\3\s=\s\3\s\.\s\3;.+return \2;}~msi', $res, $matches);
        $res = gzinflate(hex2bin(pack('H*',$matches[1])));
        $res = str_replace($find, $res, $str);
        return $res;
    }

    private function deobfuscateOELove($str)
    {
        preg_match('~<\?php\s*defined\(\'[^\']+\'\)\s*\|\|\s*define\(\'[^\']+\',__FILE__\);(global\s*\$[^;]+;)+\s*(if\(!function_exists\(\'([^\']+)\'\)\){\s*function\s*[^\)]+\(\$[^,]+,\$[^=]+=\'\'\){\s*if\(empty\(\$[^\)]+\)\)\s*return\s*\'\';\s*\$[^=]+=base64_decode\(\$[^\)]+\);\s*if\(\$[^=]+==\'\'\)\s*return\s*\~\$[^;]+;\s*if\(\$[^=]+==\'-1\'\)\s*@[^\(]+\(\);\s*\$[^=]+=\$GLOBALS\[\'[^\']+\'\]\[\'[^\']+\'\]\(\$[^\)]+\);\s*\$[^=]+=\$GLOBALS\[\'[^\']+\'\]\[\'[^\']+\'\]\(\$[^,]+,\$[^,]+,\$[^\)]+\);\s*return\s*\$[^^]+\^\$[^;]+;\s*}}\s*)+(\$[^\[]+\["[^"]+"]=[^\(]+\(\'[^\']+\',\'[^\']*\'\);\s*)+(\$[^\[]+\[\'[^\']+\'\]=\$GLOBALS\[\'[^\']+\'\]\[\'[^\']+\'\]\([^\)]*\)+;\s*)+return\(eval\(\$[^\[]+\[\'[^\']+\'\]\)+;\s*\?>\s*#!/usr/bin/php\s*-q\s*((\s*[^\s]+)+)~msi', $str, $matches);
        $find = $matches[0];
        $res = $str;
        $code = $matches[6];
        $res = iconv('UTF-8', 'ASCII//IGNORE', $res);

        preg_match('~\$GLOBALS\[\'[^\']+\'\]\[\'[^\']+\'\]\(\'([\da-f]{32})\'\);~msi', $res, $hash);
        $hash = strrev($hash[1]);
        preg_match_all('~\$GLOBALS\[\'[^\']+\'\]\[\'[^\']+\'\]\(\'([\d]{10})\'\)~msi', $res, $substr_offsets);
        $substr_offsets = $substr_offsets[1];
        $substr_offsets = array_map('strrev', $substr_offsets);
        $substr_offsets = array_map('intval', $substr_offsets);

        preg_match_all('~if\s*\(\!function_exists\(\'([^\']+)\'\)~msi', $res, $decoders);
        $decoders = $decoders[1];
        $var_array = [];
        preg_match_all('~\$([^\[]{3,20})\["([^"]+)"\]=(\w+)\(\'([^\']*)\',\'([^\']*)\'\);~msi', $res, $vars, PREG_SET_ORDER);
        $var_name = $vars[0][1];
        foreach ($vars as $var) {
            if ($var[3] === $decoders[0] || $var[3] === $decoders[1]) {
                $var_array[$var[2]] = Helpers::OELoveDecoder($var[4], $var[5]);
                $res = str_replace($var[0], '', $res);
            }
        }
        $layer1 = substr($code, 0, $substr_offsets[3] + 96);
        $layer1_dec = iconv('UTF-8', 'ASCII//IGNORE', gzuncompress(base64_decode($layer1)));
        $code = str_replace($layer1, $layer1_dec, $code);
        preg_match_all('~\$([^\[]{3,20})\["([^"]+)"\]=(\w+)\(\'([^\']*)\',\'([^\']*)\'\);~msi', $code, $vars, PREG_SET_ORDER);
        foreach ($vars as $var) {
            if ($var[3] === $decoders[0] || $var[3] === $decoders[1]) {
                $var_array[$var[2]] = Helpers::OELoveDecoder($var[4], $var[5]);
                $code = str_replace($var[0], '', $code);
            }
        }
        $layer2_start = strpos($code, '?>') + 2;
        $layer2 = substr($code, $layer2_start + $substr_offsets[2]);
        $layer2_dec = iconv('UTF-8', 'ASCII//IGNORE', gzuncompress(base64_decode(str_rot13($layer2))));
        $res = $layer2_dec;
        foreach($var_array as $k => $v) {
            $res = str_replace('$GLOBALS[\'' . $var_name . '\'][\'' . $k . '\'](', $v . '(', $res);
            $res = str_replace('$GLOBALS[\'' . $var_name . '\'][\'' . $k . '\']', '\'' . $v . '\'', $res);
        }

        $res = preg_replace_callback('~(\w+)\(\'([^\']*)\',\'([^\']*)\'\)~msi', static function ($m) use ($decoders) {
            if ($m[1] !== $decoders[0] && $m[1] !== $decoders[1]) {
                return $m[0];
            }
            return '\'' . Helpers::OELoveDecoder($m[2], $m[3]) . '\'';
        }, $res);

        $res = str_replace($find, $res, $str);
        return $res;
    }

    private function deobfuscateEvalConcatVars($str)
    {
        preg_match('~((\$\w+="";\$\w+\s*\.=\s*"[^;]+;\s*)+)(?:="";)?(eval\((\s*(\$\w+)\s*\.)+\s*"([^"]+)(?:"\);)+)~msi', $str, $matches);
        $find = $matches[0];
        $res = $str;
        $parts = [];
        preg_match_all('~(\$\w+)="";\1\s*\.=\s*"([^"]+)"~msi', $matches[1], $matches1, PREG_SET_ORDER);
        foreach($matches1 as $match) {
            $parts[$match[1]] = stripcslashes(stripcslashes($match[2]));
        }
        $res = stripcslashes(stripcslashes($matches[3]));
        foreach($parts as $k => $v) {
            $res = str_replace($k, "'" . $v . "'", $res);
        }
        $res = preg_replace_callback('/[\'"]\s*?\.+\s*?[\'"]/smi', static function($m) {
            return '';
        }, $res);

        $res = str_replace($find, $res, $str);
        return $res;
    }

    private function deobfuscateEvalAssignedVars($str, $matches)
    {
        $res = $str;

        $vars = [$matches[1] => $matches[2]];

        $res = preg_replace_callback('~(\$\w{1,3000})=(base64_decode|gzinflate|convert_uudecode|str_rot13)\((\$\w{1,3000})\);~msi',
            function ($match) use (&$vars) {
                $func = $match[2];
                if (Helpers::isSafeFunc($func) && isset($vars[$match[3]])) {
                    $vars[$match[1]] = @$func($vars[$match[3]]);
                    return '';
                }
                return $match[1] . '=' . $match[2] . '(\'' . $match[3] . '\';';
            }, $res);

        $res = $vars[$matches[4]] ?? Helpers::replaceVarsFromArray($vars, $res);

        return $res;
    }

    private function deobfuscateVarFuncsEval($str)
    {
        preg_match('~((\$\w+)\s*=\s*)(base64_decode\s*\(+|gzinflate\s*\(+|strrev\s*\(+|str_rot13\s*\(+|gzuncompress\s*\(+|convert_uudecode\s*\(+|urldecode\s*\(+|rawurldecode\s*\(+|htmlspecialchars_decode\s*\(+)+"([^"]+)"\)+(;\s*@?eval\(([\'"?>.\s]+)?\2\);)~', $str, $matches);
        $find = $matches[0];
        $res = $str;
        $res = str_replace([$matches[5], $matches[1]], [');', 'eval('], $res);
        $res = str_replace($find, $res, $str);
        return $res;
    }

    private function deobfuscateComments($str, $matches)
    {
        $find = $matches[0];
        $res = preg_replace('~/\*\w+\*/~msi', '', $str);
        $res = str_replace($find, $res, $str);
        return $res;
    }

    private function deobfuscateStrrevVarEval($str)
    {
        preg_match('~(\$\w+=strrev\("[^"]+"\);)+eval\((\$\w+\()+"([^"]+)"\)+;~mis', $str, $matches);
        $find = $matches[0];
        $res = gzinflate(base64_decode($matches[3]));
        $res = str_replace($find, $res, $str);
        return $res;
    }

    private function deobfuscateAanKFM($str, $matches)
    {
        $find = $matches[0];
        $res = $str;
        $key = Helpers::aanKFMDigitsDecode($matches[3]);
        $res = Helpers::Xtea_decrypt($matches[4], $key);
        $res = str_replace($find, $res, $str);
        return $res;
    }

    private function deobfuscateEvalChars($str, $matches)
    {
        $find = $matches[0];
        $res = $str;
        while(preg_match_all('~(?:@eval((?:\(\$[0O]+\[[\'"]\w+[\'"]\])+)\("([^"]+)"\)+;)|("\)\?\$[O0]+)~msi', $res, $matches, PREG_SET_ORDER)) {
            $match = $matches[0];
            if (isset($matches[1])) $match = $matches[1];
            $count = ($match[1] !== '') ? substr_count($match[1], '(') : 0;
            if ($count == 2) {
                $res = gzinflate(base64_decode($match[2]));
            } else if ($count == 3) {
                $res = gzinflate(base64_decode(str_rot13($match[2])));
            }
            if (isset($match[3]) && ($match[3] !== '')) {
                $res = preg_replace_callback('~(\$[0O]+\["\w+"\]\()+"([^"]+)"\)+;?~msi', static function($m) {
                    return gzinflate(base64_decode(str_rot13($m[2])));
                }, $res);
            }
        }
        $res = str_replace($find, $res, $str);
        return $res;
    }

    private function deobfuscateGlobalsBase64($str)
    {
        preg_match('~<\?php\s+((\$GLOBALS\[\s*[\'"]\w+[\'"]\s*\])\s*=\s*base64_decode\("([^"]*)"\);)+\s*\?>(<\?php\s.+\2.+exit;\s}\sfunction\s\w+\(\)\s{\sreturn\sarray\(\s\'favicon\'\s=>\s\'[^\']+\',\s+\'sprites\'\s=>\s\'[^\']+\',\s\);\s})~msi', $str, $matches);
        $find = $matches[0];
        $vars = [];
        preg_match_all('~(\$GLOBALS\[\s*[\'"]\w+[\'"]\s*\])\s*=\s*base64_decode\("([^"]*)"\);~msi', $matches[0], $matches1, PREG_SET_ORDER);
        foreach($matches1 as $match) {
            $vars[$match[1]] = base64_decode($match[2]);
        }
        $code = $matches[4];
        foreach ($vars as $var => $value) {
            $code = str_replace($var . '(', $value . '(', $code);
            $code = str_replace($var, "'" . $value . "'", $code);
        }
        $res = $code;
        $res = str_replace($find, $res, $str);
        return $res;
    }

    private function deobfuscateEvalReturn($str, $matches)
    {
        $find = $matches[0];
        $res = stripcslashes(base64_decode($matches[2]));
        $res = str_replace($find, $res, $str);
        return $res;
    }

    private function deobfuscateQibosoft($str)
    {
        preg_match('~\$\w+=__FILE__;\$\w+=fopen\(\$\w+,\'rb\'\);fread\(\$\w+,(\d+)\);\$\w+=explode\("\\\\t",base64_decode\(fread\(\$\w+,(\d+)\)+;\$\w+=\$\w+\[[\d+]\];[\$l1=\d{}\.;\(\)\[\]]+eval\(\$\w+\(\'([^\']+)\'\)+;\s*return\s*;\?>[\w=\+]+~msi', $str, $matches);
        $find = $matches[0];
        $res = $str;
        $hangs = 15;
        $obfPHP = explode('?>', $str);
        $obfPHP = $obfPHP[1];
        preg_match('~eval\(\$\w+\(\'([^\']+)\'\)+;~msi', $res, $temp);
        $res = str_replace($temp[0], base64_decode($temp[1]), $res);
        $offset = $matches[2];
        while (preg_match('~\$\w+\(\$\w+,(\d+)\);\s*eval\(\$\w+\(\$\w+\(\$\w+,(\d+)\)+;~msi', $res, $temp2) && $hangs--) {
            $offset += $temp2[1];
            $decode_loop = base64_decode(substr($obfPHP, $offset, $temp2[2]));
            $offset += $temp2[2];
            if (preg_match('~eval\(\$\w+\(\'([^\']+)\'\)+;~msi', $decode_loop, $temp)) {
                $res = str_replace($temp2[0], base64_decode($temp[1]), $res);
            } else {
                $res = $decode_loop;
            }

        }
        $res = str_replace($find, $res, $str);
        return $res;
    }

    private function deobfuscateUd64($str)
    {
        preg_match('~(\$ud64_c[o0]m="[\\\\0-9a-z\."]+;)+\$\w+=(\$ud64_c[o0]m\()+"([^"]+)"\)+;@eval\(\$ud64_c[o0]m\(\'[^\']+\'\)+;~msi', $str, $matches);
        $find = $matches[0];
        $res = gzinflate(convert_uudecode(base64_decode(gzinflate(base64_decode(str_rot13($matches[3]))))));
        $res = str_replace($find, $res, $str);
        return $res;
    }

    private function deobfuscateCustom1($str)
    {
        preg_match('~\$\w+="([^"]+)";\$l+=0;\$l+=\'base64_decode\';\$l+=0;eval\(.+?;eval\(\$l+\);return;~msi', $str, $matches);
        return Helpers::someDecoder3($matches[1]);
    }

    private function deobfuscateCustom2($str, $matches)
    {
        $find = $matches[0];
        $key = $matches[2];
        $var = $matches[3];
        preg_match_all('~(\$\w+)\[\d+\]\s*=\s*"([^"]+)";~msi', $str, $matches);
        foreach ($matches[1] as $k => &$m) {
            if ($m !== $var) {
                unset($matches[2][$k]);
            }
        }
        $res = base64_decode(Helpers::someDecoder4($matches[2], $key));
        $res = str_replace($find, $res, $str);
        return $res;
    }

    private function deobfuscateLockIt2($str, $matches)
    {
        $find = $matches[0];
        $res = $matches[1];

        if(strpos($str, '$_X="') !== false && strpos($res, '\\x') !== false) {
            $res = stripcslashes($res);
        }
        if (preg_match_all('~\$[_\w]+\.=[\'"]([\w\+\/=]+)[\'"];~', $matches[0], $concatVars)) {
            foreach ($concatVars[1] as $concatVar) {
                $res .= $concatVar;
            }
        }
        $res = base64_decode($res);
        $res = strtr($res, $matches[2], $matches[3]);
        $res = str_replace($find, $res, $str);
        return $res;
    }

    private function deobfuscateAnaski($str, $matches)
    {
        $find = $matches[0];

        $res = gzinflate(str_rot13(base64_decode($matches[2])));
        $res = strtr($res, $matches[5], $matches[6]);

        return $res;
    }

    private function deobfuscateFuncs($str, $matches)
    {
        $find = $matches[0];
        $funcs = [];
        $payload = $matches[7];
        $var = $matches[6];
        $res = $str;
        $res = preg_replace_callback('~function\s*(\w+)\((\$\w+)\){\s*return\s*(\w+)\(\2(,\d+)?\);}\s*~msi', static function($matches2) use (&$funcs){
            $funcs[$matches2[1]] = $matches2[3];
            return '';
        }, $res);
        foreach ($funcs as $k => $v) {
            $res = str_replace($k . '(', $v . '(', $res);
        }
        $res = str_replace([$var . '="' . $payload . '";', $var], ['', '"' . $payload . '"'], $res);
        $res = str_replace($find, $res, $str);
        return $res;
    }

    private function deobfuscateSubstr($str)
    {
        preg_match('~\$\w+=0;(\$GLOBALS\[\'\w+\'\])\s*=\s*\'([^\']+)\';\s*(\$\w+)=pack\(\'H\*\',substr\(\1,\s*([-\d]+)\)\);if\s*\(!function_exists\(\'(\w+)\'\)\){function\s*\5\(\$\w+,\s*\$\w+\){\$\w+=\1;\s*\$d=pack\(\'H\*\',substr\(\1,\s*\4\)\);\s*return\s*\$\w+\(substr\(\$\w+,\s*\$\w+,\s*\$\w+\)\);}};eval\(\3\(\'([^\']+)\'\)\);~msi', $str, $matches);
        $find = $matches[0];
        $substr_array = $matches[2];
        $offset = intval($matches[4]);
        $func = $matches[5];
        $eval = pack('H*',substr($substr_array, $offset));
        $res = Helpers::isSafeFunc($eval) ? @$eval($matches[6]) : $matches[6];
        $res = preg_replace_callback('~(\w+)\(([-\d]+),\s*([-\d]+)\)~mis', static function ($matches) use ($eval, $substr_array, $func) {
            if ($matches[1] !== $func) {
                return $matches[0];
            }
            $res = Helpers::isSafeFunc($eval) ? @$eval(substr($substr_array, $matches[2], $matches[3])) : $matches[0];
            return '\'' . $res . '\'';
        }, $res);
        $res = str_replace($find, $res, $str);
        return $res;
    }

    private function deobfuscatePHPJiaMi($str, $matches)
    {
        $find = $matches[0];
        $bin = bin2hex($str);
        preg_match('~6257513127293b24[a-z0-9]{2,30}3d24[a-z0-9]{2,30}2827([a-z0-9]{2,30})27293b~', $bin, $hash);
        preg_match('~2827([a-z0-9]{2})27293a24~', $bin, $rand);
        $hash = hex2bin($hash[1]);
        $rand = hex2bin($rand[1]);
        $res = Helpers::PHPJiaMi_decoder(substr($matches[3], 0, -45), $hash, $rand);
        $res = str_rot13(@gzuncompress($res) ?: $res);

        if (preg_match('~global\s*(\$[^,;]+);((?:\1\[\'[^\']+\'\]=[^(]+\(\'[^\']+\'\);)+)~msi', $str, $tmp))
        {
            $tmp = explode(';', $tmp[2]);
            foreach ($tmp as $entry) {
                if ($entry === '') {
                    continue;
                }
                preg_match('~\$([^\[]+)(\[\'[^\']+\'\])=([^\(]+)\(\'([^\']+)\'\)~', $entry, $parts);
                $res = str_replace('$GLOBALS[\'' . $parts[1] . '\']' . $parts[2], Helpers::PHPJiaMi_decoder($parts[4], $hash, $rand), $res);
            }
            $func_decrypt = $parts[3];
            $hangs = 20;
            while (($start = strpos($res, $func_decrypt . '(\'')) && $start !== false && $hangs--) {
                $end = strpos($res,'\'', $start + strlen($func_decrypt) + 2) + 1;
                $data = substr($res, $start + strlen($func_decrypt) + 2, $end - ($start + strlen($func_decrypt) + 2 + 1));
                $res = substr_replace($res, '\'' . Helpers::PHPJiaMi_decoder($data, $hash, $rand) . '\'', $start, ($end - $start) + 1);
            }
        }
        $res = str_replace($find, $res, $str);
        return $res;
    }

    private function deobfuscateEvalIReplace($str, $matches)
    {
        $find = $matches[0];
        $res = base64_decode($matches[3]);
        $res = str_replace($find, $res, $str);
        return $res;
    }

    private function deobfuscateErrorHandler($str)
    {
        preg_match('~(\$\w+)="[^"]+";\s*(\$\w+)=str_ireplace\("[^"]+","",\1\);(\$\w+)\s*=\s*"([^"]+)";\s*function\s*(\w+)\((\$\w+,?)+\){\s*(\$\w+)=\s*create_function\(\'\',\$\w+\);\s*array_map\(\7,array\(\'\'\)+;\s*}\s*set_error_handler\(\'\5\'\);(\$\w+)=\2\(\3\);user_error\(\8,E_USER_ERROR\);\s*if\s*.+?}~msi', $str, $matches);
        $find = $matches[0];
        $res = base64_decode($matches[4]);
        $res = str_replace($find, $res, $str);
        return $res;
    }

    private function deobfuscateStrtoupper($str, $matches)
    {
        $find = $matches[0];
        $res = $str;
        $alph = $matches[2];
        $var = $matches[1];
        $res = str_replace("{$var}=\"{$alph}\";", '', $res);
        for ($i = 0, $iMax = strlen($alph); $i < $iMax; $i++) {
            $res = str_replace($var . '[' . $i . '].', "'" . $alph[$i] . "'", $res);
            $res = str_replace($var . '[' . $i . ']', "'" . $alph[$i] . "'", $res);
        }
        $res = str_replace("''", '', $res);
        $res = str_replace("' . '", '', $res);
        $res = str_replace("' '", '', $res);
        preg_match('~(\$\w+)\s*=\s*strtoupper\s*\(\s*\'(\w+)\'\s*\)\s*;~msi', $res, $matches);
        $matches[2] = strtoupper($matches[2]);
        $res = str_replace($matches[0], '', $res);
        $res = preg_replace_callback('~\${\s*(\$\w+)\s*}~msi', static function ($m) use ($matches) {
            if ($m[1] !== $matches[1]) {
                return $m[0];
            }
            return '$' . $matches[2];
        }, $res);
        $res = str_replace($find, $res, $str);
        return $res;
    }

    private function deobfuscateEval2($str)
    {
        preg_match('~(\$\w+)\s*=\s*"((?:[^"]|(?<=\\\\)")*)";(\$\w+)\s*=\s*(\1\[\d+\]\.?)+;(\$\w+)\s*=\s*[^;]+;(\$\w+)\s*=\s*"[^"]+";\$\w+\s*=\s*\5\."([^"]+)"\.\6;\3\((\1\[\d+\]\.?)+,\s*\$\w+\s*,"\d+"\);~smi', $str, $matches);
        $res = $str;
        list($find, $var, $alph) = $matches;
        for ($i = 0, $iMax = strlen($alph); $i < $iMax; $i++) {
            $res = str_replace($var . '[' . $i . '].', "'" . $alph[$i] . "'", $res);
            $res = str_replace($var . '[' . $i . ']', "'" . $alph[$i] . "'", $res);
        }
        $res = gzinflate(base64_decode(substr($matches[7], 1, -1)));
        $res = str_replace($find, $res, $str);
        return $res;
    }

    private function deobfuscateEvalEregReplace($str, $matches)
    {
        $find = $matches[0];
        $res = base64_decode($matches[2]);
        preg_match_all('~(\$\w+)\s*=\s*ereg_replace\("([^"]+)","([^"]+)",\1\);~smi', $str, $matches);
        foreach ($matches[2] as &$pat) {
            if ($pat[0] === '[') {
                $pat = substr($pat, 1, -1);
            }
        }
        unset($pat);
        $res = str_replace($matches[2], $matches[3], $res);
        $res = base64_decode($res);
        $res = str_replace($find, $res, $str);
        return $res;
    }

    private function deobfuscateStrreplace($str, $matches)
    {
        $find = $matches[0];
        $res = $str;

        $str_replace = '';
        $base64_decode = '';
        $layer = '';

        if (!preg_match_all('~(?:(\$\w{1,50})\s?=\s?((?:\'[^\']{1,500}\'|"[^\n]{1,500}?"));[\n\s])~msi', $str, $matches, PREG_SET_ORDER)) {
            preg_match_all('~(\$\w+)\s*=\s*([\'"](?|[^\']+\'|[^"]+"));~msi', $str, $matches, PREG_SET_ORDER);
        }
        foreach ($matches as $i => $match) {
            $vars[$match[1]] = substr($match[2], 1, -1);
        }

        $res = preg_replace_callback('~(\$\w+)\s*=\s*str_replace\([\'"](\w+)[\'"],\s*[\'"]{2},\s*[\'"](\w+)[\'"]\)~msi',
            static function ($matches) use (&$vars, &$str_replace) {
                $vars[$matches[1]] = str_replace($matches[2], "", $matches[3]);
                if ($vars[$matches[1]] === 'str_replace') {
                    $str_replace = $matches[1];
                }
                return $matches[1] . ' = "' . $vars[$matches[1]] . '"';
            }, $res);

        if ($str_replace !== '') {
            $res = preg_replace_callback('~(\$\w+)\s*=\s*(\$\w+)\("(\w+)",\s*"",\s*"(\w+)"\)~msi',
                static function ($matches) use (&$vars, &$base64_decode, $str_replace) {
                    if ($matches[2] !== $str_replace) {
                        return $matches[0];
                    }
                    $vars[$matches[1]] = str_replace($matches[3], "", $matches[4]);
                    if ($vars[$matches[1]] === 'base64_decode') {
                        $base64_decode = $matches[1];
                    }
                    return $matches[1] . ' = "' . $vars[$matches[1]] . '"';
                }, $res);

            $res = preg_replace_callback('~(\$\w+)\((\$\w+)\("(\w+)",\s*"",\s*([\$\w\.]+)\)~msi',
                static function ($matches) use (&$vars, &$layer, $base64_decode, $str_replace) {
                    if ($matches[1] !== $base64_decode && $matches[2] !== $str_replace) {
                        return $matches[0];
                    }
                    $tmp = explode('.', $matches[4]);
                    foreach ($tmp as &$item) {
                        $item = $vars[$item];
                    }
                    unset($item);
                    $tmp = implode('', $tmp);
                    $layer = base64_decode(str_replace($matches[1], "", $tmp));

                    return $matches[0];
                }, $res);
        }

        if ($base64_decode !== '') {
            $regex = '~(\$\w+)\((\$\w+)\("(\w+)",\s*"",\s*([\$\w\.]+)\)~msi';
        } else {
            $regex = '~(str_replace)\(([\'"])([^\'"]+)[\'"],\s*[\'"]{2},\s*([\$\w\. ]+)\);\s?(\$\w+)\s*=\s*\$\w+\([\'"]{2},\s*\$\w+\);\s*\5\(\);~msi';
        }
        preg_replace_callback($regex,
            static function ($matches) use (&$vars, &$layer, $base64_decode, $str_replace) {
                if ($base64_decode !== '' && $matches[1] !== $base64_decode && $matches[2] !== $str_replace) {
                    return $matches[0];
                }
                $tmp = preg_split('~\s*\.\s*~msi', $matches[4]);

                foreach ($tmp as &$item) {
                    $item = $vars[$item];
                }
                unset($item);
                $tmp = implode('', $tmp);
                $layer = str_replace($matches[3], "", $tmp);
                if ($base64_decode !== '') {
                    $layer = base64_decode($layer);
                }
                return $matches[0];
            }, $res);
        $res = str_replace($find, $layer, $str);
        return $res;
    }

    private function deobfuscateSeolyzer($str, $matches)
    {
        $find           = $matches[0];
        $res            = $str;
        $vars           = [];
        $base64_decode  = '';
        $layer          = '';
        $gzuncompress   = '';

        preg_match_all('~(\$\w+)\s*=\s*([^$][^;]+)\s*;~msi', $str, $matches, PREG_SET_ORDER);
        foreach ($matches as $i => $match) {
            $var_name   = $match[1];
            $var_val    = trim($match[2]);
            if (preg_match('~"[^"]{0,20}"\s*\.chr\s*\(~i', $var_val)) {
                $var_val = Helpers::normalize($var_val);
            }
            $var_val = preg_replace('~^["\'](.*)["\']$~i', '\1', $var_val);
            $vars[$var_name] = trim($var_val);
            if ($var_val === 'base64_decode') {
                $base64_decode = $var_name;
            }
        }

        $res = preg_replace_callback('~\s*=\s*(\$\w+)\((\$\w+)\)~msi', static function ($matches) use (&$vars, &$gzuncompress, &$layer, $base64_decode) {
            if ($matches[1] !== $base64_decode) {
                return $matches[0];
            }
            if (!isset($vars[$matches[2]])) {
                return $matches[2];
            }
            $tmp = base64_decode($vars[$matches[2]]);
            if ($tmp === 'gzuncompress') {
                $gzuncompress = $matches[2];
            }
            $vars[$matches[2]] = $tmp;
            return " = '{$tmp}'";
        }, $res);

        if ($gzuncompress !== '') {
            $res = preg_replace_callback('~(\$\w+)\(\s*(\$\w+)\((\$\w+)\)~msi',
                function ($matches) use (&$vars, $gzuncompress, &$layer, $base64_decode) {
                    if ($matches[1] !== $gzuncompress && $matches[2] !== $base64_decode) {
                        return $matches[0];
                    }
                    if (!isset($vars[$matches[3]])) {
                        return $matches[3];
                    }
                    $tmp = gzuncompress(base64_decode($vars[$matches[3]]));
                    $layer = $matches[3];
                    $vars[$matches[3]] = $tmp;
                    return "'{$tmp}'";
                }, $res);
            $res = $vars[$layer];
        } else if (preg_match('~\$\w+\(\s*(\$\w+)\((\$\w+)\)~msi', $res)) {
            $res = preg_replace_callback('~\$\w+\(\s*(\$\w+)\((\$\w+)\)~msi',
                function ($matches) use (&$vars, &$layer, $base64_decode) {
                    if ($matches[1] !== $base64_decode) {
                        return $matches[0];
                    }
                    if (!isset($vars[$matches[2]])) {
                        return $matches[2];
                    }
                    $tmp = base64_decode($vars[$matches[2]]);
                    $layer = $matches[2];
                    $vars[$matches[2]] = $tmp;
                    return "'{$tmp}'";
                }, $res);
            $res = $vars[$layer];
        }
        return str_replace($find, $res, $str);
    }

    private function deobfuscateCreateFunc($str, $matches)
    {
        $result = $str;
        $funcs = str_replace($matches[4], '', $matches[3]);

        if (Helpers::concatStr($matches[1]) === 'create_function'
            && Helpers::concatStr($matches[2]) === 'eval') {
            $funcs = explode('(', $funcs);
            $iMax = count($funcs) - 2;
            $final_code = $matches[5];

            for ($i = $iMax; $i >= 0; $i--) {
                if ($funcs[$i][0] !== '\'' && $funcs[$i][0] !== '"') {
                    $funcs[$i] = '\'' . $funcs[$i];
                }
                $func = Helpers::concatStr($funcs[$i] . '"');
                if (Helpers::isSafeFunc($func)) {
                    $final_code = @$func($final_code);
                }
            }
            $result = $final_code;
        }
        $result = ' ?>' . $result;

        return $result;
    }

    private function deobfuscateGotoShell($str, $matches)
    {
        $str = Helpers::normalize($str);

        $str = preg_replace('~\${\'GLOBALS\'}\[\'(\w+)\'\]~msi', '$\1', $str);

        $vars = Helpers::collectVars($str, '\'');
        $need_remove_vars = [];
        foreach ($vars as $name => $value) {
            $last_str = $str;
            $str = str_replace('${' . $name . '}', '$' . $value, $str);
            if ($last_str != $str) {
                $need_remove_vars[$name] = $value;
            }
        }

        foreach ($need_remove_vars as $name => $value) {
            if (substr_count($str, $name) != 1) {
                continue;
            }
            $str = str_replace($name.'=\'' . $value . '\';', '', $str);
        }
        return $str;
    }

    private function deobfuscateCreateFuncConcat($str, $matches)
    {
        $find = $matches[0];
        $res = $str;
        $vars = [];
        $res = preg_replace_callback('~(?|(\$\w+)\s*=\s*(([base64_decode\'\.\s]+)|([eval\'\.\s]+)|([create_function\'\.\s]+)|([stripslashes\'\.\s]+)|([gzinflate\'\.\s]+)|([strrev\'\.\s]+)|([str_rot13\'\.\s]+)|([gzuncompress\'\.\s]+)|([urldecode\'\.\s]+)([rawurldecode\'\.\s]+));)~', static function($matches) use (&$vars) {
            $tmp = str_replace("' . '", '', $matches[0]);
            $tmp = str_replace("'.'", '', $tmp);
            $value = str_replace("' . '", '', $matches[2]);
            $value = str_replace("'.'", '', $value);
            $vars[$matches[1]] = substr($value, 1, -1);
            return $tmp;
        }, $res);
        foreach($vars as $key => $var) {
            $res = str_replace($key, $var, $res);
            $res = str_replace($var . " = '" . $var . "';", '', $res);
            $res = str_replace($var . ' = "";', '', $res);
        }
        $res = str_replace($find, $res, $str);
        return $res;
    }

    private function deobfuscateEvalWrapVar($str, $matches)
    {
        $find = $matches[0];
        $res = $str;
        $vars = [];
        $res = preg_replace_callback('~(?|(\$\w+)\s*=\s*(([base64_decode"\'\.\s]+)|([eval"\'\.\s]+)|([create_function"\'\.\s]+)|([stripslashes"\'\.\s]+)|([gzinflate"\'\.\s]+)|([strrev"\'\.\s]+)|([str_rot13"\'\.\s]+)|([gzuncompress"\'\.\s]+)|([urldecode"\'\.\s]+)([rawurldecode"\'\.\s]+));)~msi', static function($matches) use (&$vars) {
            $tmp = str_replace(["' . '", "\" . \""], '', $matches[0]);
            $tmp = str_replace(["'.'", "\".\""], '', $tmp);
            $value = str_replace(["' . '", "\" . \""], '', $matches[2]);
            $value = str_replace(["'.'", "\".\""], '', $value);
            $vars[$matches[1]] = substr($value, 1, -1);
            return $tmp;
        }, $res);
        $temp = substr($res, strpos($res, '@eval'));
        $temp1 = $temp;
        foreach($vars as $key => $var) {
            $temp = str_replace($key, $var, $temp);
        }
        $res = str_replace($temp1, $temp, $res);
        $res = str_replace($find, $res, $str);
        return $res;
    }

    private function deobfuscateForEach($str, $matches)
    {
        $find = $matches[0];
        $alph = $matches[3];
        $vars = [];
        $res = $str;

        preg_replace('~\s*/\*\w+\*/\s*~msi', '', $res);

        $res = preg_replace_callback('~foreach\(\[([\d,]+)\]\s*as\s*\$\w+\)\s*\{\s*(\$\w+)\s*\.=\s*\$\w+\[\$\w+\];\s*\}~mis', static function($matches) use ($alph, &$vars) {
            $chars = explode(',', $matches[1]);
            $value = '';
            foreach ($chars as $char) {
                $value .= $alph[$char];
            }
            $vars[$matches[2]] = $value;
            return "{$matches[2]} = '{$value}';";
        }, $res);

        foreach($vars as $key => $var) {
            $res = str_replace($key, $var, $res);
            $res = str_replace($var . " = '" . $var . "';", '', $res);
            $res = str_replace($var . ' = "";', '', $res);
        }

        preg_match('~(\$\w+)\s*=\s*strrev\([create_function\.\']+\);~ms', $res, $matches);
        $res = str_replace($matches[0], '', $res);
        $res = str_replace($matches[1], 'create_function', $res);
        $res = str_replace($find, $res, $str);
        return $res;
    }

    private function deobfuscateSubst2($str)
    {
        preg_match('~(\$\w+)="([^"])+(.{0,70}\1.{0,400})+;\s*}~msi', $str, $matches);
        $find = $matches[0];
        $res = $str;
        preg_match('~(\$\w+)="(.+?)";~msi', $str, $matches);
        $alph = stripcslashes($matches[2]);
        $var = $matches[1];
        for ($i = 0, $iMax = strlen($alph); $i < $iMax; $i++) {
            $res = str_replace($var . '[' . $i . '].', "'" . $alph[$i] . "'", $res);
            $res = str_replace($var . '[' . $i . ']', "'" . $alph[$i] . "'", $res);
        }
        $res = str_replace("''", '', $res);
        preg_match_all('~(\$GLOBALS\[\'\w{1,40}\'\])\s*=\s*\'(([^\'\\\\]++|\\\\.)*)\';~msi', $res, $matches, PREG_SET_ORDER);

        foreach ($matches as $index => $var) {
            $res = str_replace($var[1], $var[2], $res);
            $res = str_replace($var[2] . " = '" . $var[2] . "';", '', $res);
        }

        $res = str_replace($find, $res, $str);
        return $res;
    }

    private function deobfuscateAssert($str, $matches)
    {
        $find = $matches[0];
        $res = base64_decode($matches[3]);
        $res = str_replace($find, $res, $str);
        return $res;
    }

    private function deobfuscateUrlDecode2($str, $matches)
    {
        $find = $matches[0];
        $res = $str;
        if (isset($matches[10])) {
            $res = base64_decode($matches[10]);
        }
        if (preg_match('~\$\w+=["\']([^\'"]+)[\'"];\s*eval\(\'\?>\'\.[\$\w\(\)\*,\s]+;~msi', $res, $match)) {
            $res = base64_decode(strtr(substr($match[1], 52*2), substr($match[1], 52, 52), substr($match[1], 0, 52)));
        }

        if (preg_match('~function\s*(\w+)\(\$\w+\)[\w{\$=\s*();<+\[\]\-]+\}\s+return[\$\s\w;]+}eval\(\1\("([\w\/+=]+)?"\)\);~', $res, $matchEval)) {
            $res = gzinflate(base64_decode($matchEval[2]));
            for ($i=0, $iMax = strlen($res); $i < $iMax; $i++) {
                $res[$i] = chr(ord($res[$i])-1);
            }
            $res = str_replace($find, $res, $str);
            return $res;
        }

        if (preg_match('~header\(\'[^\']+\'\);(?:\$\w+=\${[^}]+}\[[^\]]+\]\(\'.*?\'?;}?\'\);)+\${[^}]+}\[[^\]]+\]\(\);~msi',
            $matches[6], $match)) {
            $res = stripcslashes($match[0]);
            $dictionaryValue = urldecode($matches[3]);
            $vars = Helpers::getVarsFromDictionary($dictionaryValue, $str);
            $res = Helpers::replaceVarsFromArray($vars, $res);
            $res = Helpers::replaceCreateFunction($res);

            preg_match('~\$([0_O]+)\s*=\s*function\s*\((\$\w+)\)\s*\{\s*\$[O_0]+\s*=\s*substr\s*\(\2,(\d+),(\d+)\);\s*\$[O_0]+\s*=\s*substr\s*\(\2,([\d-]+)\);\s*\$[O_0]+\s*=\s*substr\s*\(\2,(\d+),strlen\s*\(\2\)-(\d+)\);\s*return\s*gzinflate\s*\(base64_decode\s*\(\$[O_0]+\s*\.\s*\$[O_0]+\s*\.\s*\$[O_0]+\)+;~msi', $res, $m);
            $res = preg_replace_callback('~\$\{"GLOBALS"}\["([0_O]+)"\]\s*\(\'([^\']+)\'\)~msi', static function ($calls) use ($m) {
                if ($calls[1] !== $m[1]) {
                    return $calls[0];
                }
                $temp1 = substr($calls[2], $m[3], $m[4]);
                $temp2 = substr($calls[2], $m[5]);
                $temp3 = substr($calls[2], $m[6],strlen($calls[2]) - $m[7]);
                return "'" . gzinflate(base64_decode($temp1 . $temp3 . $temp2)) . "'";
            }, $res);
            return $res;
        }


        $res = str_replace($find, ' ?>' . $res, $str);
        return $res;
    }

    private function deobfuscatePHPMyLicense($str)
    {
        preg_match('~\$\w+\s*=\s*base64_decode\s*\([\'"][^\'"]+[\'"]\);\s*if\s*\(!function_exists\s*\("rotencode"\)\).{0,1000}eval\s*\(\$\w+\s*\(base64_decode\s*\([\'"]([^"\']+)[\'"]\)+;~msi', $str, $matches);
        $find = $matches[0];
        $res = $str;
        $hang = 10;
        while(preg_match('~eval\s*\(\$\w+\s*\(base64_decode\s*\([\'"]([^"\']+)[\'"]\)+;~msi', $res, $matches) && $hang--) {
            $res = gzinflate(base64_decode($matches[1]));
        }
        $res = str_replace($find, $res, $str);
        return $res;
    }

    private function deobfuscateEdoced_46esab($str)
    {
        preg_match('~(\$\w+)=[\'"]([^"\']+)[\'"];(\$\w+)=strrev\(\'edoced_46esab\'\);eval\(\3\([\'"]([^\'"]+)[\'"]\)+;~msi', $str, $matches);
        $find = $matches[0];
        $res = '';
        $decoder = base64_decode($matches[4]);
        preg_match('~(\$\w+)=base64_decode\(\$\w+\);\1=strtr\(\1,[\'"]([^\'"]+)[\'"],[\'"]([^\'"]+)[\'"]\);~msi', $decoder, $matches2);
        $res = base64_decode($matches[2]);
        $res = strtr($res, $matches2[2], $matches2[3]);
        $res = str_replace($find, $res, $str);
        return $res;
    }

    private function deobfuscateEdoced_46esab_etalfnizg($str, $matches)
    {
        return gzinflate(base64_decode($matches[3]));
    }

    private function deobfuscateEvalVarVar($str)
    {
        preg_match('~\$\{"GLOBALS"\}\[[\'"](\w+)[\'"]\]=["\'](\w+)[\'"];\$\{"GLOBALS"\}\[[\'"](\w+)[\'"]\]=["\']\2[\'"];(\${\$\{"GLOBALS"\}\[[\'"]\3[\'"]\]})=[\'"]([^\'"]+)[\'"];eval.{10,50}?(\$\{\$\{"GLOBALS"\}\[[\'"]\1[\'"]\]\})\)+;~msi', $str, $matches);
        $find = $matches[0];
        $res = str_replace($matches[4], '$' . $matches[2], $str);
        $res = str_replace($matches[6], '$' . $matches[2], $res);
        $res = str_replace($find, $res, $str);
        return $res;
    }

    private function deobfuscateEscapes($str, $matches)
    {
        $find = $matches[0];
        $res = stripcslashes($str);
        $res = str_replace($find, $res, $str);
        preg_match_all('~(\$\{"GLOBALS"\}\[[\'"](\w+)[\'"]\])=["\'](\w+)[\'"];~msi', $res, $matches, PREG_SET_ORDER);
        foreach ($matches as $match) {
            $res = str_replace([$match[0], '${' . $match[1] . '}'], ['', '$' . $match[3]], $res);
        }

        return $res;
    }

    private function deobfuscateparenthesesString($str)
    {
        $hangs = 5;
        $res = $str;
        $find = '';
        while (preg_match('~for\((\$\w+)=\d+,(\$\w+)=\'([^\$]+)\',(\$\w+)=\'\';@?ord\(\2\[\1\]\);\1\+\+\)\{if\(\1<\d+\)\{(\$\w+)\[\2\[\1\]\]=\1;\}else\{\$\w+\.\=@?chr\(\(\5\[\2\[\1\]\]<<\d+\)\+\(\5\[\2\[\+\+\1\]\]\)\);\}\}\s*.{0,500}eval\(\4\);(if\(isset\(\$_(GET|REQUEST|POST|COOKIE)\[[\'"][^\'"]+[\'"]\]\)\)\{[^}]+;\})?~msi', $res, $matches) && $hangs--) {
            if($hangs == 4) {
                $find = $matches[0];
            }
            $res = '';
            $temp = [];
            $matches[3] = stripcslashes($matches[3]);
            for($i=0, $iMax = strlen($matches[3]); $i < $iMax; $i++)
            {
                if($i < 16) $temp[$matches[3][$i]] = $i;
                else $res .= @chr(($temp[$matches[3][$i]]<<4) + ($temp[$matches[3][++$i]]));
            }
        }
        if(!isset($matches[6])) {
            //$xor_key = 'SjJVkE6rkRYj';
            $xor_key = $res^"\n//adjust sy"; //\n//adjust system variables";
            $res = $res ^ substr(str_repeat($xor_key, (strlen($res) / strlen($xor_key)) + 1), 0, strlen($res));
        }
        if(substr($res,0,12)=="\n//adjust sy") {
            $res = str_replace($find, $res, $str);
            return $res;
        } else return $str;
    }

    private function deobfuscateEvalInject($str, $matches)
    {
        $res = $str;
        $find = $matches[0];
        $alph = $matches[2];

        for ($i = 0, $iMax = strlen($alph); $i < $iMax; $i++) {
            $res = str_replace($matches[1] . '[' . $i . '].', "'" . $alph[$i] . "'", $res);
            $res = str_replace($matches[1] . '[' . $i . ']', "'" . $alph[$i] . "'", $res);
        }

        $res = str_replace("''", '', $res);
        $res = str_replace("' '", '', $res);

        $res = str_replace($find, $res, $str);
        return $res;
    }

    private function deobfuscateWebshellObf($str)
    {
        $res = $str;
        preg_match('~function\s*(\w{1,40})\s*\(\s*(\$\w{1,40})\s*,\s*(\$\w{1,40})\s*\)\s*\{\s*(\$\w{1,40})\s*=\s*str_rot13\s*\(\s*gzinflate\s*\(\s*str_rot13\s*\(\s*base64_decode\s*\(\s*[\'"]([^\'"]*)[\'"]\s*\)\s*\)\s*\)\s*\)\s*;\s*(if\s*\(\s*\$\w+\s*==[\'"][^\'"]*[\'"]\s*\)\s*\{\s*(\$\w{1,40})\s*=(\$\w+[\{\[]\d+[\}\]]\.?)+;return\s*(\$\w+)\(\3\);\s*\}\s*else\s*)+\s*if\s*\(\s*\$\w+\s*==[\'"][^\'"]*[\'"]\s*\)\s*\{\s*return\s*eval\(\3\);\s*\}\s*\};\s*(\$\w{1,40})\s*=\s*[\'"][^\'"]*[\'"];(\s*\10\([\'"][^\'"]*[\'"],)+\s*[\'"]([^\'"]*)[\'"]\s*\)+;~msi',$str, $matches);
        $find = $matches[0];

        $alph = str_rot13(gzinflate(str_rot13(base64_decode($matches[5]))));

        for ($i = 0, $iMax = strlen($alph); $i < $iMax; $i++) {
            $res = str_replace($matches[4] . '{' . $i . '}.', "'" . $alph[$i] . "'", $res);
            $res = str_replace($matches[4] . '{' . $i . '}', "'" . $alph[$i] . "'", $res);
        }
        $res = base64_decode(gzinflate(str_rot13(convert_uudecode(gzinflate(base64_decode(strrev($matches[12])))))));
        $res = str_replace($find, $res, $str);
        return $res;
    }

    private function deobfuscateXorFName($str, $matches, $xor_key = null)
    {
        if (!isset($matches)) {
            preg_match('~(?(DEFINE)(?\'c\'(?:/\*\w+\*/)*))(\$\w+)\s*=\s*basename(?&c)\((?&c)trim(?&c)\((?&c)preg_replace(?&c)\((?&c)rawurldecode(?&c)\((?&c)"[%0-9A-F\.]+"(?&c)\)(?&c),\s*\'\',\s*__FILE__(?&c)\)(?&c)\)(?&c)\)(?&c);(\$\w+)\s*=\s*"([%\w\.\-\~]+)";(?:(\$\w+)=[^;]+;\5(?&c)\((?&c)\'\',\s*\'};\'\s*\.\s*(?&c)\()?(?:eval(?&c)\()?(?&c)rawurldecode(?&c)\((?&c)\3(?&c)\)(?&c)\s*\^\s*substr(?&c)\((?&c)str_repeat(?&c)\((?&c)\2,\s*(?&c)\((?&c)strlen(?&c)\((?&c)\3(?&c)\)(?&c)/strlen(?&c)\((?&c)\2(?&c)\)(?&c)\)(?&c)\s*\+\s*1(?&c)\)(?&c),\s*0,(?&c)\s*strlen(?&c)\((?&c)\3(?&c)\)(?&c)\)(?&c)\)(?:(?&c)\s*\.\s*\'{\'(?&c)\))?(?&c);~msi', $str, $matches);
        }
        $encrypted = rawurldecode($matches[4]);
        if (!isset($xor_key)) {
            $plain_text = '@ini_set(\'error_log\', NULL);';
            $plain_text2 = 'if (!defined(';
            $xor_key = substr($encrypted, 0, strlen($plain_text)) ^ $plain_text;
            if (preg_match('~\.?[a-z0-9-_]{8,}\.\w{3}~', $xor_key, $m)) {
                $xor_key = $m[0];
            } else {
                $xor_key = substr($encrypted, 0, strlen($plain_text2)) ^ $plain_text2;
                if (preg_match('~\.?[a-z0-9-_]{8,}\.\w{3}~', $xor_key, $m)) {
                    $xor_key = $m[0];
                }
            }
        }
        $result = $encrypted ^ substr(str_repeat($xor_key, (strlen($encrypted) / strlen($xor_key)) + 1), 0, strlen($encrypted));
        return $result;
    }

    private function deobfuscateSubstCreateFunc($str)
    {
        preg_match('~(\$\w{1,40})=\'(([^\'\\\\]|\\\\.)*)\';\s*((\$\w{1,40})=(\1\[\d+].?)+;\s*)+(\$\w{1,40})=\'\';\s*(\$\w{1,40})\(\7,\$\w{1,40}\.\"([^\"]+)\"\.\$\w{1,40}\.\5\);~msi', $str, $matches);
        $find = $matches[0];
        $php = base64_decode($matches[9]);
        preg_match('~(\$\w{1,40})=(\$\w{1,40})\("([^\']+)"\)~msi', $php, $matches);
        $matches[3] = base64_decode($matches[3]);
        $php = '';
        for ($i = 1, $iMax = strlen($matches[3]); $i < $iMax; $i++) {
            if ($i % 2) {
                $php .= substr($matches[3], $i, 1);
            }
        }
        $php = str_replace($find, $php, $str);
        return $php;
    }

    private function deobfuscateZeura($str, $matches)
    {
        $offset = (int)$matches[8] + (int)$matches[9];
        $obfPHP = explode('__halt_compiler();', $str);
        $obfPHP = end($obfPHP);
        $php = gzinflate(base64_decode(substr(trim($obfPHP), $offset)));
        $php = stripcslashes($php);
        $php = str_replace($matches[0], $php, $str);
        return $php;
    }

    private function deobfuscateZeuraFourArgs($str, $matches)
    {
        $offset = $matches[6] * -1;
        $res    = gzinflate(base64_decode(substr(trim($str), $offset)));

        return $res;
    }

    private function deobfuscateSourceCop($str, $matches)
    {
        $key = $matches[2];
        $obfPHP = $matches[1];
        $res = '';
        $index = 0;
        $len = strlen($key);
        $temp = hexdec('&H' . substr($obfPHP, 0, 2));
        for ($i = 2, $iMax = strlen($obfPHP); $i < $iMax; $i += 2) {
            $bytes = hexdec(trim(substr($obfPHP, $i, 2)));
            $index = (($index < $len) ? $index + 1 : 1);
            $decoded = $bytes ^ ord(substr($key, $index - 1, 1));
            if ($decoded <= $temp) {
                $decoded = 255 + $decoded - $temp;
            } else {
                $decoded -= $temp;
            }
            $res .= chr($decoded);
            $temp = $bytes;
        }
        $res = str_replace($matches[0], $res, $str);
        return $res;
    }

    private function deobfuscateGlobalsArray($str, $matches)
    {
        $res = $str;
        $alph = stripcslashes($matches[3]);
        $res = preg_replace('~\${"[\\\\x0-9a-f]+"}\[\'\w+\'\]\s*=\s*"[\\\\x0-9a-f]+";~msi', '', $res);

        for ($i = 0, $iMax = strlen($alph); $i < $iMax; $i++) {
            $res = str_replace([
                $matches[1] . '[' . $matches[2] . ']' . '[' . $i . '].',
                $matches[1] . '[' . $matches[2] . ']' . '[' . $i . ']'
            ], array("'" . $alph[$i] . "'", "'" . $alph[$i] . "'"), $res);
        }
        $res = str_replace("''", '', $res);

        preg_match_all('~(\$\w+)\[(\'\w+\')]\s*=\s*\'(\w+)\';~msi', $res, $funcs);
        foreach ($funcs[1] as $k => $var) {
            if ($var !== $matches[1]) {
                continue;
            }
            $vars[] = $funcs[2][$k];
            $func[] = $funcs[3][$k];
        }

        foreach ($vars as $index => $var) {
            $res = str_replace($matches[1] . '[' . $var . ']', $func[$index], $res);
        }

        foreach ($func as $remove) {
            $res = str_replace($remove . " = '" . $remove . "';", '', $res);
            $res = str_replace($remove . "='" . $remove . "';", '', $res);
        }
        $res = str_replace($matches[0], $res, $str);
        return $res;
    }

    private function deobfuscateXbrangwolf($str, $match)
    {
        return $match[0];
    }

    private function deobfuscateObfB64($str, $matches)
    {
        $res = base64_decode($matches[3]);
        $res = str_replace($matches[0], $res, $str);
        return $res;
    }

    private function deobfuscateArrayOffsets($str)
    {
        $vars = [];
        preg_match('~(\$\w{1,40})\s*=\s*\'([^\']*)\';\s*(\$\w{1,40})\s*=\s*explode\s*\((chr\s*\(\s*\(\d+\-\d+\)\)),substr\s*\(\1,\s*\((\d+\-\d+)\),\s*\(\s*(\d+\-\d+)\)\)\);.+\1\s*=\s*\$\w+[+\-\*]\d+;~msi', $str, $matches);

        $find = $matches[0];
        $obfPHP = $matches[2];
        $matches[4] = Helpers::calc($matches[4]);
        $matches[5] = (int)Helpers::calc($matches[5]);
        $matches[6] = (int)Helpers::calc($matches[6]);

        $func = explode($matches[4], strtolower(substr($obfPHP, $matches[5], $matches[6])));
        $func[1] = strrev($func[1]);
        $func[2] = strrev($func[2]);

        preg_match('~\$\w{1,40}\s=\sexplode\((chr\(\(\d+\-\d+\)\)),\'([^\']+)\'\);~msi', $str, $matches);
        $matches[1] = Helpers::calc($matches[1]);
        $offsets = explode($matches[1], $matches[2]);

        $res = '';
        for ($i = 0; $i < (sizeof($offsets) / 2); $i++) {
            $res .= substr($obfPHP, $offsets[$i * 2], $offsets[($i * 2) + 1]);
        }

        preg_match('~return\s*\$\w{1,40}\((chr\(\(\d+\-\d+\)\)),(chr\(\(\d+\-\d+\)\)),\$\w{1,40}\);~msi', $str, $matches);
        $matches[1] = Helpers::calc($matches[1]);
        $matches[2] = Helpers::calc($matches[2]);

        $res = Helpers::stripsquoteslashes(str_replace($matches[1], $matches[2], $res));
        $res = "<?php\n" . $res . "?>";

        preg_match('~(\$\w{1,40})\s=\simplode\(array_map\(\"[^\"]+\",str_split\(\"(([^\"\\\\]++|\\\\.)*)\"\)\)\);(\$\w{1,40})\s=\s\$\w{1,40}\(\"\",\s\1\);\s\4\(\);~msi', $res, $matches);

        $matches[2] = stripcslashes($matches[2]);
        for ($i=0, $iMax = strlen($matches[2]); $i < $iMax; $i++) {
            $matches[2][$i] = chr(ord($matches[2][$i])-1);
        }

        $res = str_replace($matches[0], $matches[2], $res);

        preg_match_all('~(\$\w{1,40})\s*=\s*\"(([^\"\\\\]++|\\\\.)*)\";~msi', $res, $matches, PREG_SET_ORDER);
        foreach ($matches as $match) {
            $vars[$match[1]] = stripcslashes($match[2]);
        }

        preg_match_all('~(\$\w{1,40})\s*=\s*\'(([^\'\\\\]++|\\\\.)*)\';~msi', $res, $matches, PREG_SET_ORDER);
        foreach ($matches as $match) {
            $vars[$match[1]] = Helpers::stripsquoteslashes($match[2]);
        }

        preg_match('~(\$\w{1,40})\s*=\s*\"\\\\x73\\\\164\\\\x72\\\\137\\\\x72\\\\145\\\\x70\\\\154\\\\x61\\\\143\\\\x65";\s(\$\w{1,40})\s=\s\'(([^\'\\\\]++|\\\\.)*)\';\seval\(\1\(\"(([^\"\\\\]++|\\\\.)*)\",\s\"(([^\"\\\\]++|\\\\.)*)\",\s\2\)\);~msi', $res, $matches);

        $matches[7] = stripcslashes($matches[7]);
        $matches[3] = Helpers::stripsquoteslashes(str_replace($matches[5], $matches[7], $matches[3]));


        $res = str_replace($matches[0], $matches[3], $res);

        preg_match_all('~(\$\w{1,40})\s*=\s*\"(([^\"\\\\]++|\\\\.)*)\";~msi', $res, $matches, PREG_SET_ORDER);
        foreach ($matches as $match) {
            $vars[$match[1]] = stripcslashes($match[2]);
        }

        preg_match_all('~(\$\w{1,40})\s*=\s*\'(([^\'\\\\]++|\\\\.)*)\';~msi', $res, $matches, PREG_SET_ORDER);
        foreach ($matches as $match) {
            $vars[$match[1]] = Helpers::stripsquoteslashes($match[2]);
        }

        preg_match('~\$\w{1,40}\s=\sarray\(((\'(([^\'\\\\]++|\\\\.)*)\',?(\.(\$\w{1,40})\.)?)+)\);~msi', $res, $matches);

        foreach ($vars as $var => $value) {
            $matches[1] = str_replace("'." . $var . ".'", $value, $matches[1]);
        }

        $array2 = explode("','", substr($matches[1], 1, -1));
        preg_match('~eval\(\$\w{1,40}\(array\((((\"[^\"]\"+),?+)+)\),\s(\$\w{1,40}),\s(\$\w{1,40})\)\);~msi', $res, $matches);

        $array1 = explode('","', substr($matches[1], 1, -1));

        $temp = array_keys($vars);
        $temp = $temp[9];

        $arr = explode('|', $vars[$temp]);
        $off=0;
        $funcs=[];

        for ($i = 0, $iMax = count($arr); $i < $iMax; $i++) {
            if ($i === 0) {
                $off = 0;
            } else {
                $off = $arr[$i - 1] + $off;
            }
            $len = $arr[$i];
            $temp = array_keys($vars);
            $temp = $temp[7];

            $funcs[] = substr($vars[$temp], $off, $len);
        }

        for ($i = 0; $i < 5; $i++) {
            if ($i % 2 === 0) {
                $funcs[$i] = strrev($funcs[$i]);
                $g = substr($funcs[$i], strpos($funcs[$i], "9") + 1);
                $g = stripcslashes($g);
                $v = explode(":", substr($funcs[$i], 0, strpos($funcs[$i], "9")));
                for ($j = 0, $jMax = count($v); $j < $jMax; $j++) {
                    $q = explode("|", $v[$j]);
                    $g = str_replace($q[0], $q[1], $g);
                }
                $funcs[$i] = $g;
            } else {
                $h = explode("|", strrev($funcs[$i]));
                $d = explode("*", $h[0]);
                $b = $h[1];
                for ($j = 0, $jMax = count($d); $j < $jMax; $j++) {
                    $b = str_replace($j, $d[$j], $b);
                }
                $funcs[$i] = $b;
            }
        }
        $temp = array_keys($vars);
        $temp = $temp[8];
        $funcs[] = str_replace('9', ' ', strrev($vars[$temp]));
        $funcs = implode("\n", $funcs);
        preg_match('~\$\w{1,40}\s=\s\'.+?eval\([^;]+;~msi', $res, $matches);
        $res = str_replace($matches[0], $funcs, $res);
        $res = stripcslashes($res);
        $res = str_replace('}//}}', '}}', $res);
        $res = str_replace($find, $res, $str);
        return $res;
    }

    private function deobfuscateArrayOffsetsEval($str, $matches)
    {
        $arg1 = explode(chr(Helpers::calculateMathStr($matches[4])), $matches[5]);
        $arg2 = $matches[2];
        $code = null;

        for ($enqvlelpmr = 0; $enqvlelpmr < (sizeof($arg1) / 2); $enqvlelpmr++) {
            $code .= substr($arg2, $arg1[($enqvlelpmr * 2)], $arg1[($enqvlelpmr * 2) + 1]);
        }

        $res = str_replace(
            chr(Helpers::calculateMathStr($matches[20])),
            chr(Helpers::calculateMathStr($matches[21])),
            $code
        );

        $arg1 = substr(
            $matches[2],
            Helpers::calculateMathStr($matches[7]),
            Helpers::calculateMathStr($matches[8])
        );

        $func = substr(
            $matches[2],
            Helpers::calculateMathStr($matches[23]),
            Helpers::calculateMathStr($matches[24])
        );

        return $res;
    }

    private function deobfuscateXoredVar($str, $matches)
    {
        $res = $str;
        $find = $matches[0];
        $str = str_replace('\\\'', '@@quote@@', $str);
        preg_match_all('~(\$\w{1,40})\s*=\s*\'([^\']*)\'\s*(?:\^\s*\'([^\']*)\')?;~msi', $str, $matches, PREG_SET_ORDER);
        $vars = [];
        foreach ($matches as $match) {
            $vars[$match[1]] = str_replace('@@quote@@', '\\\'', $match[2]);
            if (isset($match[3])) {
                $vars[$match[1]] ^= str_replace('@@quote@@', '\\\'', $match[3]);
            }
            $res = str_replace($match[0], $match[1] . "='" . $vars[$match[1]] . "';", $res);
        }

        preg_match_all('~(\$\w{1,40})\s*=\s*(\w+);~msi', $str, $matches, PREG_SET_ORDER);
        foreach ($matches as $match) {
            $vars[$match[1]] = $match[2];
        }

        preg_match_all('~(\$\w{1,40})\s*=\s*\'([^\']*)\'\^(\$\w+);~msi', $str, $matches, PREG_SET_ORDER);
        foreach ($matches as $match) {
            if (isset($vars[$match[3]])) {
                $vars[$match[1]] = str_replace('@@quote@@', '\\\'', $match[2]) ^ $vars[$match[3]];
                $res = str_replace($match[0], $match[1] . "='" . $vars[$match[1]] . "';", $res);
            }
        }

        preg_match_all('~(\$\w{1,40})\s*=\s*(\$\w+)\^\'([^\']*)\';~msi', $res, $matches, PREG_SET_ORDER);
        foreach ($matches as $match) {
            if (isset($vars[$match[2]])) {
                $vars[$match[1]] = str_replace('@@quote@@', '\\\'', $match[3]) ^ $vars[$match[2]];
                $res = str_replace($match[0], $match[1] . "='" . $vars[$match[1]] . "';", $res);
            }
        }
        preg_match_all('~(?<!\.)\'([^\']*)\'\^(\$\w+)~msi', $res, $matches, PREG_SET_ORDER);
        foreach ($matches as $match) {
            if (isset($vars[$match[2]])) {
                $res = str_replace($match[0], "'" . addcslashes(str_replace('@@quote@@', '\\\'', $match[1]) ^ $vars[$match[2]], '\\\'') . "'", $res);
            }
        }
        preg_match_all('~(\$\w+)\^\'([^\']*)\'~msi', $res, $matches, PREG_SET_ORDER);
        foreach ($matches as $match) {
            if (isset($vars[$match[1]])) {
                $res = str_replace($match[0], "'" . addcslashes($vars[$match[1]] ^ str_replace('@@quote@@', '\\\'', $match[2]), '\\\'') . "'", $res);
            }
        }

        preg_match_all('~(\$\w+)(\.)?=(\$\w+)?(?:\'([^\']*)\')?\.?(\$\w+)?(?:\'([^\']*)\')?(?:\^(\$\w+))?(?:\.\'([^\']*)\')?;~msi', $res, $matches, PREG_SET_ORDER);
        foreach ($matches as $match) {
            $val = '';

            //var
            if (isset($match[2]) && $match[2] !== '') {
                if (isset($vars[$match[1]])) {
                    $val .= $vars[$match[1]];
                } else {
                    continue;
                }
            }

            //var
            if (isset($match[3]) && $match[3] !== '') {
                if (isset($vars[$match[3]])) {
                    $val .= $vars[$match[3]];
                } else {
                    continue;
                }
            }

            //str
            if (isset($match[4]) && $match[4] !== '') {
                $val .= $match[4];
            }

            //var
            if (isset($match[5]) && $match[5] !== '') {
                if (isset($vars[$match[5]])) {
                    $val .= $vars[$match[5]];
                } else {
                    continue;
                }
            }

            //str
            if (isset($match[6]) && $match[6] !== '') {
                $val .= $match[6];
            }

            //var and str
            if (isset($match[7]) && $match[7] !== '') {
                if (isset($vars[$match[7]])) {
                    $additionalStr = '';
                    if (isset($match[8]) && $match[8] !== '') {
                        $additionalStr = $match[8];
                    }
                    $val ^= $vars[$match[7]] . $additionalStr;
                } else {
                    continue;
                }
            } else {
                if (isset($match[8]) && $match[8] !== '') {
                    $val .= $match[8];
                }
            }

            $vars[$match[1]] = $val;
            $res = str_replace($match[0], '', $res);
        }

        $res = preg_replace_callback('~(\$\w+)([()]|==)~msi', static function ($match) use ($vars) {
            $res = $vars[$match[1]] ?? $match[1];
            if (isset($vars[$match[1]]) && ($match[2] === ')' || $match[2] === '==')) {
                $res = "'$res'";
            }

            return $res . $match[2];
        }, $res);

        foreach ($vars as $var => $value) {
            $res = str_replace($var, $value, $res);
            $res = str_replace($value . "='" . $value . "';", '', $res);
        }
        $res = str_replace($find, $res, $str);

        if (preg_match('~((\$\w+)=\${\'(\w+)\'};)(?:.*?)((\$\w+)=\2(\[\'[^\']+\'\]);)~msi', $res, $matches)) {
            $res = str_replace($matches[1], '', $res);
            $res = str_replace($matches[4], '', $res);
            $cookieVar = sprintf('$%s%s', $matches[3], $matches[6]);
            $res = str_replace($matches[5], $cookieVar, $res);
        }

        return $res;
    }

    private function deobfuscatePhpMess($str, $matches)
    {
        $res = base64_decode(gzuncompress(base64_decode(base64_decode($matches[4]))));
        $res = str_replace($matches[0], $res, $str);
        return $res;
    }

    private function deobfuscatePregReplaceSample05($str)
    {
        $res = '';
        preg_match('~(\$\w{1,40})\s*=\s*\"([^\"]+)\";\s*\$\w+\s*=\s*\$\w+\(\1,\"([^\"]+)\",\"([^\"]+)\"\);\s*\$\w+\(\"[^\"]+\",\"[^\"]+\",\"\.\"\);~msi', $str, $matches);
        $res = strtr($matches[2], $matches[3], $matches[4]);
        $res = base64_decode($res);
        $res = str_replace($matches[0], $res, $str);
        return $res;
    }

    private function deobfuscatePregReplaceB64($str, $matches)
    {
        $find = $matches[0];
        $res = str_replace($find, base64_decode($matches[4]), $str);
        $res = stripcslashes($res);
        preg_match('~eval\(\${\$\{"GLOBALS"\}\[\"\w+\"\]}\(\${\$\{"GLOBALS"\}\[\"\w+\"]}\(\"([^\"]+)\"\)\)\);~msi', $res, $matches);
        $res = gzuncompress(base64_decode($matches[1]));
        preg_match('~eval\(\$\w+\(\$\w+\("([^"]+)"\)\)\);~msi', $res, $matches);
        $res = gzuncompress(base64_decode($matches[1]));
        preg_match('~eval\(\$\w+\(\$\w+\("([^"]+)"\)\)\);~msi', $res, $matches);
        $res = gzuncompress(base64_decode($matches[1]));
        preg_match_all('~\$(\w+)\s*(\.)?=\s*("[^"]*"|\$\w+);~msi', $res, $matches, PREG_SET_ORDER);
        $var = $matches[0][1];
        $vars = [];
        foreach ($matches as $match) {
            if($match[2]!=='.') {
                $vars[$match[1]] = substr($match[3], 1, -1);
            }
            else {
                $vars[$match[1]] .= $vars[substr($match[3], 1)];
            }
        }
        $res = str_replace("srrKePJUwrMZ", "=", $vars[$var]);
        $res = gzuncompress(base64_decode($res));
        preg_match_all('~function\s*(\w+)\(\$\w+,\$\w+\)\{.+?}\s*};\s*eval\(((\1\(\'(\w+)\',)+)\s*"([\w/\+]+)"\)\)\)\)\)\)\)\);~msi', $res, $matches);
        $decode = array_reverse(explode("',", str_replace($matches[1][0] . "('", '', $matches[2][0])));
        array_shift($decode);
        $arg = $matches[5][0];
        foreach ($decode as $val) {
            $arg = Helpers::someDecoder2($val, $arg);
        }
        $res = $arg;
        $res = str_replace($find, $res, $str);
        return $res;
    }

    private function deobfuscateDecoder($str, $matches)
    {
        $res = Helpers::someDecoder($matches[2]);
        $res = str_replace($matches[0], $res, $str);
        return $res;
    }

    private function deobfuscateGBE($str)
    {
        preg_match('~(\$\w{1,40})=\'([^\']+)\';\1=gzinflate\(base64_decode\(\1\)\);\1=str_replace\(\"__FILE__\",\"\'\$\w+\'\",\1\);eval\(\1\);~msi', $str, $matches);
        $res = str_replace($matches[0], gzinflate(base64_decode($matches[2])), $str);
        return $res;
    }

    private function deobfuscateGBZ($str, $matches)
    {
        $res = str_replace($matches[0], base64_decode(str_rot13($matches[4])), $str);
        return $res;
    }

    private function deobfuscateBitrix($str, $matches)
    {
        $find       = $matches[0];
        $res        = $str;
        $funclist   = [];
        $strlist    = [];
        
        $res = preg_replace("|[\"']\s*\.\s*['\"]|smi", '', $res);
        $res = Helpers::replaceMinMaxRound($res, 111);
        $res = Helpers::replaceBase64Decode($res, '"');
        $replace_from = [];
        $replace_to   = [];
        if (preg_match_all('|\$GLOBALS\[[\'"](.+?)[\'"]\]\s*=\s*Array\((.+?)\);|smi', $res, $founds, PREG_SET_ORDER)) {
            foreach ($founds as $found) {
                $varname = $found[1];
                $funclist[$varname] = explode(',', $found[2]);
                $funclist[$varname] = array_map(function ($value) {
                    return trim($value, "'\"");
                }, $funclist[$varname]);

                foreach ($funclist as $var => $funcs) {
                    foreach($funcs as $k => $func) {
                        $replace_from[] = '$GLOBALS["' . $var . '"][' . $k . ']';
                        $replace_from[] = '$GLOBALS[\'' . $var . '\'][' . $k . ']';
                        $replace_to[] = $func;
                        $replace_to[] = $func;
                    }
                }
                $replace_from[] = $found[0];
                $replace_to[] = '';
                $res = str_replace($replace_from, $replace_to, $res);
            }
        }

        $array_temp = [];
        while (preg_match('~function\s*(\w{1,60})\(\$\w+\){\$\w{1,60}\s*=\s*Array\((.{1,30000}?)\);\s*return\s*base64_decode[^}]+}~msi', $res, $found)) {
            $strlist = explode(',', $found[2]);
            $array_temp[$found[1]] = array_map('base64_decode', $strlist);
            $replace_from = [];
            $replace_to = [];
            foreach($array_temp[$found[1]] as $k => $v) {
                $replace_from[] = $found[1] . '(' . $k . ')';
                $replace_to[] = '\'' . $v . '\'';
            }
            $replace_from[] = $found[0];
            $replace_to[] = '';
            $res = str_replace($replace_from, $replace_to, $res);
        }

        $res = preg_replace('~\'\s*\.\s*\'~', '', $res);
        if (preg_match_all('~\s*function\s*(_+(.{1,60}?))\(\$[_0-9]+\)\s*\{\s*static\s*\$([_0-9]+)\s*=\s*(true|false);.{1,30000}?\$\3\s*=\s*array\((.*?)\);\s*return\s*base64_decode\(\$\3~smi', $res, $founds, PREG_SET_ORDER)) {
            foreach ($founds as $found) {
                $strlist = explode('",', $found[5]);
                $strlist = implode("',", $strlist);
                $strlist = explode("',", $strlist);
                $array_temp[$found[1]] = array_map('base64_decode', $strlist);
                $replace_from = [];
                $replace_to = [];
                foreach($array_temp[$found[1]] as $k => $v) {
                    $replace_from[] = $found[1] . '(' . $k . ')';
                    $replace_to[] = '\'' . $v . '\'';
                }
                $res = str_replace($replace_from, $replace_to, $res);
            }
        }
        $res = str_replace($find, $res, $str);
        return $res;
    }

    private function deobfuscateLockIt($str, $matches)
    {
        $phpcode = base64_decode(Helpers::getTextInsideQuotes(Helpers::getEvalCode($str)));
        $result = $str;
        $offset = 0;
        $dictName = $matches[1];
        $dictVal = urldecode($matches[2]);
        $vars = [$dictName => $dictVal];

        $vars = Helpers::getVarsFromDictionaryDynamically($vars, $str);

        if (preg_match('~eval\(~msi', $matches[15])) {
            $phpcode = base64_decode(Helpers::getTextInsideQuotes(Helpers::getEvalCode($matches[15])));
        }

        if ($matches[7] !== '' && preg_match('~eval\(~msi', $matches[7])) {
            $phpcode2 = base64_decode(Helpers::getTextInsideQuotes(Helpers::getEvalCode($matches[7])));
            $vars = Helpers::collectVars($phpcode2, "'", $vars);
        }

        if (preg_match('~\$_F=__FILE__;\$_X=\'([^\']+)\';\s*eval\s*\(\s*\$?\w{1,60}\s*\(\s*[\'"][^\'"]+[\'"]\s*\)\s*\)\s*;~msi', $str, $matches)) {
            $needles = Helpers::getNeedles($phpcode);
            $needle        = $needles[0];
            $before_needle = $needles[1];
            $strToDecode = base64_decode($matches[1]);
            return '<?php ' . strtr($strToDecode, $needle, $before_needle);
        }

        $count = 0;
        preg_match_all('~,(\d+|0x\w+)\)~msi', $phpcode, $offsetMatches, PREG_SET_ORDER);
        if (count($offsetMatches) === 2) {
            foreach ($offsetMatches as $offsetMatch) {
                if (strpos($offsetMatch[1], '0x') !== false && isset($str[$offset + hexdec($offsetMatch[1])])) {
                    $count++;
                    $offset += hexdec($offsetMatch[1]);
                } else if (isset($str[$offset + (int)$offsetMatch[1]])) {
                    $count++;
                    $offset += (int)$offsetMatch[1];
                }
            }
        }

        $finalOffset = 0;
        if (preg_match('~(\$[O0]*)=(\d+|0x\w+);~msi', $str, $match) && $count === 2) {
            if (strpos($match[2], '0x') !== false) {
                $finalOffset = hexdec($match[2]);
            } else {
                $finalOffset = (int)$match[2];
            }
        }

        $result = substr($str, $offset);
        if ($finalOffset > 0) {
            $result = substr($result, 0, $finalOffset);
        }

        if (preg_match('~[\'"]([^\'"]+)[\'"],[\'"]([^\'"]+)[\'"]~msi', $phpcode, $needleMatches)) {
            $result = strtr($result, $needleMatches[1], $needleMatches[2]);
        }

        $result = base64_decode($result);

        $result = Helpers::replaceVarsFromArray($vars, $result, true);

        for ($i = 0; $i < 2; $i++) {
            $result = preg_replace_callback('~eval\s?\(((?:(?:gzinflate|str_rot13|base64_decode)\()+\'[^\']+\'\)+);~msi',
                function ($match) {
                    return $this->unwrapFuncs($match[1]);
                }, $result);

            $result = preg_replace_callback('~eval\s?\((?:str_rot13\()+\'((?|\\\\\'|[^\'])+\')\)\);~msi',
                function ($match) {
                    return str_rot13($match[1]);
                }, $result);
        }

        $result = preg_replace_callback(
            '~(echo\s*)?base64_decode\(\'([\w=\+\/]+)\'\)~',
            function ($match) {
                if ($match[1] != "") {
                    return 'echo \'' . base64_decode($match[2]) . '\'';
                }
                return '\'' . str_replace('\'', '\\\'', base64_decode($match[2])) . '\'';
            },
            $result
        );

        $result = Helpers::replaceVarsFromArray($vars, $result, true);

        return '<?php ' . $result;
    }

    private function deobfuscateB64inHTML($str, $matches)
    {
        $obfPHP        = $str;
        $phpcode       = base64_decode(Helpers::getTextInsideQuotes(Helpers::getEvalCode($obfPHP)));
        $needles       = Helpers::getNeedles($phpcode);
        $needle        = $needles[count($needles) - 2];
        $before_needle = end($needles);
        $pointer1 = $matches[2];
        $temp = strtr($obfPHP, $needle, $before_needle);
        $end = 8;
        for ($i = strlen($temp) - 1; $i > strlen($temp) - 15; $i--) {
            if ($temp[$i] === '=') {
                $end = strlen($temp) - 1 - $i;
            }
        }

        $phpcode = base64_decode(substr($temp, strlen($temp) - $pointer1 - ($end-1), $pointer1));
        $phpcode = str_replace($matches[0], $phpcode, $str);
        return $phpcode;
    }

    private function deobfuscateStrtrFread($str, $layer2)
    {
        $str = explode('?>', $str);
        $str = end($str);
        $res = substr($str, $layer2[1], strlen($str));
        $res = base64_decode(strtr($res, $layer2[2], $layer2[3]));
        $res = str_replace($layer2[0], $res, $str);
        return $res;
    }

    private function deobfuscateStrtrBase64($str, $matches)
    {
        $str = strtr($matches[2], $matches[3], $matches[4]);
        $res = base64_decode($str);
        $res = str_replace($matches[0], $res, $str);
        return $res;
    }

    private function deobfuscateByteRun($str)
    {
        preg_match('~\$_F=__FILE__;\$_X=\'([^\']+)\';\s*eval\s*\(\s*\$?\w{1,60}\s*\(\s*[\'"][^\'"]+[\'"]\s*\)\s*\)\s*;~msi', $str, $matches);
        $res = base64_decode($matches[1]);
        $res = strtr($res, '123456aouie', 'aouie123456');
        $res = str_replace($matches[0], $res, $str);
        return $res;
    }

    private function deobfuscateExplodeSubst($str, $matches)
    {
        $find = $matches[0];
        $res = $str;
        preg_match('~(\$_\w+\[\w+\])\s*=\s*explode\(\'([^\']+)\',\s*\'([^\']+)\'\);.+?(\1\[[a-fx\d]+\])\(\);~msi', $res, $matches);
        $subst_array = explode($matches[2], $matches[3]);
        $res = preg_replace_callback('~((\$_GET\[[O0]+\])|(\$[O0]+))\[([a-fx\d]+)\](\()?~msi', static function ($matches) use ($subst_array) {
            if (isset($matches[5])) {
                return $subst_array[hexdec($matches[4])] . '(';
            }
            return "'" . $subst_array[hexdec($matches[4])] . "'";
        }, $res);
        $res = str_replace($find, $res, $str);

        return $res;
    }

    private function deobfuscateSubst($str, $matches)
    {
        $find = $matches[0];
        $res = $str;
        $alph = stripcslashes($matches[2]);

        for ($i = 0, $iMax = strlen($alph); $i < $iMax; $i++) {
            $res = str_replace(
                [$matches[1] . '[' . $i . '].', $matches[1] . '[' . $i . ']'],
                ["'" . $alph[$i] . "'", "'" . $alph[$i] . "'"],
                $res
            );
        }
        $res = str_replace("''", '', $res);
        $var = $matches[3];


        preg_match_all('~(\$\w+)\[\]\s*=\s*\'([\w\*\-\#]+)\'~msi', $res, $matches);

        for ($i = 0, $iMax = count($matches[2]); $i <= $iMax; $i++) {
            if ($matches[1][$i] !== $var) {
                continue;
            }
            if (@function_exists($matches[2][$i])) {
                $res = str_replace($var . '[' . $i . ']', $matches[2][$i], $res);
            } else {
                $res = @str_replace($var . '[' . $i . ']', "'" . $matches[2][$i] . "'", $res);
            }
        }
        $res = str_replace($find, $res, $str);
        return $res;
    }

    private function deobfuscateUrldecode($str)
    {
        preg_match('~(\$\w+=\'[^\']+\';\s*)+(\$[\w{1,40}]+)=(urldecode|base64_decode)?\(?[\'"]([\w+%=-]+)[\'"]\)?;(\$[\w+]+=(\$(\w+\[\')?[O_0]*(\'\])?([\{\[]\d+[\}\]])?\.?)+;)+[^\?]+(\?\>[\w\~\=\/\+]+|.+\\\\x[^;]+;)~msi', $str, $matches);
        $find = $matches[0];
        $res = $str;
        $res = stripcslashes($res);
        if ($matches[3] === "urldecode") {
            $alph = urldecode($matches[4]);
            $res = str_replace('urldecode(\'' . $matches[4] . '\')', "'" . $alph . "'", $res);
        } elseif ($matches[3] === 'base64_decode') {
            $alph = base64_decode($matches[4]);
            $res = str_replace('base64_decode(\'' . $matches[4] . '\')', "'" . $alph . "'", $res);
        } else {
            $alph = $matches[4];
        }

        for ($i = 0, $iMax = strlen($alph); $i < $iMax; $i++) {
            $res = str_replace([
                    $matches[2] . '[' . $i . '].',
                    $matches[2] . '[' . $i . ']',
                    $matches[2] . '{' . $i . '}.',
                    $matches[2] . '{' . $i . '}'
                ], [
                    "'" . $alph[$i] . "'",
                    "'" . $alph[$i] . "'",
                    "'" . $alph[$i] . "'",
                    "'" . $alph[$i] . "'"],
                $res
            );
        }
        $res = str_replace("''", '', $res);

        preg_match_all('~\$(\w+)\s*=\s*\'([\w\*\-\#]+)\'~msi', $res, $matches, PREG_SET_ORDER);
        for ($i = 0, $iMax = count($matches); $i < $iMax; $i++) {
            $res = str_replace(['$' . $matches[$i][1] . '(' , '${"GLOBALS"}["' . $matches[$i][1] . '"]' . '('],
                $matches[$i][2] . '(', $res, $c);
            $res = str_replace(['$' . $matches[$i][1], '${"GLOBALS"}["' . $matches[$i][1] . '"]'],
                    "'" . $matches[$i][2] . "'", $res, $cc);

            if ($c > 0 || $cc > 0) {
                $res = str_replace([
                    "'" . $matches[$i][2] . "'='" . $matches[$i][2] . "';",
                    $matches[$i][2] . "='" . $matches[$i][2] . "';",
                    $matches[$i][2] . "=" . $matches[$i][2] . ';',
                    $matches[$i][0] . ';'
                ], '', $res);
            }
        }

        $res = Helpers::replaceCreateFunction($res);

        preg_match('~\$([0_O]+)\s*=\s*function\s*\((\$\w+)\)\s*\{\s*\$[O_0]+\s*=\s*substr\s*\(\2,(\d+),(\d+)\);\s*\$[O_0]+\s*=\s*substr\s*\(\2,([\d-]+)\);\s*\$[O_0]+\s*=\s*substr\s*\(\2,(\d+),strlen\s*\(\2\)-(\d+)\);\s*return\s*gzinflate\s*\(base64_decode\s*\(\$[O_0]+\s*\.\s*\$[O_0]+\s*\.\s*\$[O_0]+\)+;~msi', $res, $matches);
        $res = preg_replace_callback('~\$\{"GLOBALS"}\["([0_O]+)"\]\s*\(\'([^\']+)\'\)~msi', static function ($calls) use ($matches) {
            if ($calls[1] !== $matches[1]) {
                return $calls[0];
            }
            $temp1 = substr($calls[2], $matches[3], $matches[4]);
            $temp2 = substr($calls[2], $matches[5]);
            $temp3 = substr($calls[2], $matches[6],strlen($calls[2]) - $matches[7]);
            return "'" . gzinflate(base64_decode($temp1 . $temp3 . $temp2)) . "'";
        }, $res);

        $res = str_replace($find, $res, $str);
        return $res;
    }

    private function deobfuscateUrlDecode3($str, $matches)
    {
        $dictionaryKey = $matches[4];
        $dictionaryVal = urldecode($matches[3]);

        $result = Helpers::replaceVarsFromDictionary($dictionaryKey, $dictionaryVal, $str);

        return $result;
    }

    public function unwrapFuncs($string, $level = 0)
    {
        $close_tag = false;
        $res = '';

        if (trim($string) == '') {
            return '';
        }
        if ($level > 100) {
            return '';
        }
        if ((($string[0] === '\'') || ($string[0] === '"')) && (substr($string, 1, 2) !== '?>')) {
            if($string[0] === '"' && preg_match('~\\\\x\d+~', $string)) {
                return stripcslashes($string);
            }
            $end = -2;
            if ($string[-3] === '\'') {
                $end = -3;
            }
            return substr($string, 1, $end);
        }

        if ($string[0] === '$') {
            preg_match('~\$\w{1,40}~', $string, $string);
            $string  = $string[0];
            $str = $this->getPreviouslyDeclaredVars($string);
            return $str;
        }

        $pos      = strpos($string, '(');
        $function = substr($string, 0, $pos);
        $arg      = $this->unwrapFuncs(substr($string, $pos + 1), $level + 1);

        if (strpos($function, '?>') !== false || strpos($function, "'.") !== false) {
            $function = str_replace(["'?>'.", '"?>".', "'?>' .", '"?>" .', "'."], '', $function);
            $close_tag = true;
        }
        $function = str_replace(['@', ' '], '', $function);
        $safe = Helpers::isSafeFunc($function);

        if ($safe) {
            if ($function === 'pack') {
                $args = explode(',', $arg);
                $args[0] = substr(trim($args[0]), 0, -1);
                $args[1] = substr(trim($args[1]), 1);
                $res = @$function($args[0], $args[1]);
            } elseif ($function === 'unserialize') {
                $res = Helpers::unserialize($arg);
            } elseif ($function === 'str_replace') {
                $args = explode(',', $arg);
                $args[0] = substr(trim($args[0]), 0, -1 );
                $args[1] = substr(trim($args[1]), 0);
                if (trim($args[1]) === 'null') {
                    $args[1] = null;
                }
                $args[2] = $this->unwrapFuncs(trim($args[2]), $level + 1) ?? $args[2];
                $res = @$function($args[0], $args[1], $args[2]);
            } else if ($function === 'chr') {
                $res = @$function((int)$arg);
            } else {
                $res = @$function($arg);
            }
        } else {
            $res = $arg;
        }
        if ($close_tag) {
            $res = "?> " . $res;
            $close_tag = false;
        }
        return $res;
    }

    private function deobfuscateEvalFunc($str)
    {
        $res = $str;
        $res = stripcslashes($res);
        preg_match('~function\s*(\w{1,40})\((\$\w{1,40})\)\s*\{\s*(\$\w{1,40})\s*=\s*\"base64_decode\";\s*(\$\w{1,40})\s*=\s*\"gzinflate\";\s*return\s*\4\(\3\(\2\)\);\s*\}\s*\$\w{1,40}\s*=\s*\"[^\"]*\";\s*\$\w{1,40}\s*=\s*\"[^\"]*\";\s*eval\(\1\(\"([^\"]*)\"\)\);~msi', $res, $matches);
        $res = gzinflate(base64_decode($matches[5]));
        $res = str_replace($str, $res, $str);
        return $res;
    }

    private function deobfuscateEvalConcatFunc($str, $matches)
    {
        $res = $matches[2];

        if (str_replace('"."', '', $matches[6]) === '"create_function"') {
            $brackets = '';
            $res = preg_replace_callback('~[\w."]+\(~', static function ($match) use (&$brackets) {
                $replace = strtolower(str_replace('"."', '', $match[0]));
                if (strpos($replace, 'eval') === false) {
                    $brackets .= ')';
                    return $replace;
                }
                return "";
            }, $res);

            $res .= "'$matches[4]'" . $brackets . ';';
            $res = $this->unwrapFuncs($res);
        }

        return $res;
    }

    private function deobfuscateEvalHex($str)
    {
        preg_match('~eval\s*\("(\\\\x?\d+[^"]+)"\);~msi', $str, $matches);
        $res = stripcslashes($matches[1]);
        $res = str_replace($matches[1], $res, $res);
        $res = str_replace($matches[0], $res, $str);
        return $res;
    }

    private function deobfuscateEvalVarConcat($str, $matches)
    {
        $find = $matches[0];
        $res = $str;
        preg_match_all('~(\$\w+)\s*\.?=\s*"([^"]+)";~msi', $str, $matches, PREG_SET_ORDER);
        $vars = [];
        foreach ($matches as $match) {
            $res = str_replace($match[0], '', $res);
            $res = str_replace($match[1], '"' . $match[2] . '"', $res);
        }
        $res = preg_replace('/[\'"]\s*?\.+\s*?[\'"]/smi', '', $res);
        $res = str_replace($find, $res, $str);
        return $res;
    }

    public function deobfuscateEvalVarSpecific($str, $matches)
    {
        $res = $str;

        if (preg_match('~\${"[^"]+"}\["[^"]+"\]|\${\${"[^"]+"}\["[^"]+"\]}~msi', $str)) {
            $res = stripcslashes($res);

            preg_match_all('~(\${"[^"]+"}\["[^"]+"\])="([^"]+)";~msi',$res, $match, PREG_SET_ORDER);
            foreach ($match as $m) {
                $res = str_replace('${' . $m[1] . '}', '$' . $m[2], $res);
            }
        }

        $vars = Helpers::collectVars($res);

        if (preg_match('~eval\(htmlspecialchars_decode\(urldecode\(base64_decode\((\$\w+)\)\)\)\);~msi', $res, $m) && isset($vars[$m[1]])) {
            $res = htmlspecialchars_decode(urldecode(base64_decode($vars[$m[1]])));
        }

        $res = Helpers::replaceVarsFromArray($vars, $res, false, true);

        return $res;
    }

    private function deobfuscateEvalVar($str, $matches)
    {
        $find = $matches[0];
        $evalVar = $matches[7];
        if (!$evalVar) {
            $evalVar = $matches[6];
            $pregVal = '\$\w+';
            $pregStr = '[\'"]?([\/\w\+=]+)[\'"]?';
            $pregFunc = '(?:base64_decode\s*\(|gzinflate\s*\(|strrev\s*\(|str_rot13\s*\(|gzuncompress\s*\(|urldecode\s*\(|rawurldecode\s*\(|htmlspecialchars_decode\s*\()+(?:["\']([\/\w\+=]+)["\'])';
            while (preg_match('~str_replace\(["\']([\/\w]+)["\'],\s?["\']([\/\w\+=]+)["\'],\s?(?|(' . $pregVal . ')|(?:' . $pregStr . ')|(' . $pregFunc . '))\)~msi', $evalVar, $match)) {
                $result = $match[0];
                if (preg_match('~' . $pregVal . '~', $match[3], $arg)) {
                    $result = str_replace($match[1], $match[2], $matches[3]);
                } elseif (preg_match('~' . $pregFunc . '~', $match[3], $arg)) {
                    $unwrappedVar = $this->unwrapFuncs($arg[0]);
                    $result = str_replace($match[1], $match[2], $unwrappedVar);
                } elseif (preg_match('~' . $pregStr . '~', $match[3], $arg)) {
                    $result = str_replace($match[1], $match[2], $match[3]);
                }

                $evalVar = str_replace($match[0], "\"$result\"" . ')', $evalVar);
            }
            return $this->unwrapFuncs($matches[5] . $evalVar);
        }

        $str = str_replace(['\\\'', '\\"'], ['@@slaquote@@', '@@sladquote@@'], $str);
        $val = '';
        $index = 0;
        if (@preg_match_all('~(\$[^\s=\'"\)]+)\s*=\s*\(?(?|("[^"]+")|(\'[^\']+\'))\)?\s*;?~msi', $str, $matches)) {
            $matches[1] = array_reverse($matches[1], true);
            $index = array_search($evalVar, $matches[1], true);
            if ($index !== false) {
                $val = @$matches[2][$index];
            }
        }

        $string = $str;
        if ($val !== '') {
            $string = str_replace($matches[0][$index], '', $string);
            $val = substr($val, 1, -1);
            $var_index = substr_count($string, $evalVar . ' = ');
            $text = "'" . addcslashes(stripcslashes($val), "\\'") . "'";
            preg_match_all('~(\$[^\s=\'"\)]+)(?=[^a-zA-Z0-9])~ms', $string, $matches, PREG_OFFSET_CAPTURE);
            $matches = array_reverse($matches[1]);
            foreach($matches as $match) {
                if ($match[0] === $evalVar) {
                    $string = substr_replace($string, $text, $match[1], strlen($match[0]));
                    break;
                }
            }

            $string = preg_replace_callback('~\(\s*(\$[^\s=\'"\)]+)~msi', static function($m) use ($evalVar, $text) {
                if ($m[1] !== $evalVar) {
                    return $m[0];
                }
                return '(' . $text;
            }, $string);
        }

        $string = str_replace('assert(', 'eval(', $string);
        $string = str_replace('@@slaquote@@', '\\\'', $string);
        $string = str_replace('@@sladquote@@', '\\"', $string);
        $string = str_replace("eval(''.", 'eval(', $string);
        $res = str_replace($find, $string, $str);
        if (strpos($string, 'gzinflate(\'') !== false) {
            $res = $this->deobfuscateEval(stripcslashes($res), []);
        }
        return $res;
    }

    private function deobfuscateEval($str, $matches)
    {
        if (preg_match('~\)+\..{0,30}base64_decode~msi', $str)) {
            $res = explode(').', $str);
            $res = implode(')); eval(', $res);
            return $res;
        }

        if (preg_match('~@?stream_get_contents\(\$\w+\),\s*true~msi', $str, $matches)) {
            if (preg_match('~(\$\w+)\s*=\s*@?fopen\(__FILE__,\s*\'\w+\'\);\s*@?fseek\(\1,\s*([0-9a-fx]+)~msi', $this->full_source, $m)) {
                $offset = hexdec($m[2]);
                $end = substr($this->full_source, $offset);
                $res = str_replace($matches[0], '\'' . $end . '\'', $str);
                return $res;
            }
        }

        $res = $str;
        $group = '';
        if (preg_match('~(preg_replace\(["\'](?:/\.\*?/[^"\']+|[\\\\x0-9a-f]+)["\']\s*,\s*)[^\),]+(?:[\)\\\\0-5]+;[\'"])?(,\s*["\'][^"\']*["\'])\)+;~msi', $res, $matches)) {
            if (strpos(stripcslashes($matches[1]), '(.*)') !== false || strpos(stripcslashes($matches[1]), '(.+)') !== false) {
                $group = substr(stripcslashes($matches[2]), 2, -1);
            }
            $res = str_replace([$matches[1], $matches[2]], ['eval(', ''], $res);
            if ($group !== '' && strpos(stripcslashes($res), '\1') !== false) {
                $res = stripcslashes($res);
                $res = str_replace('\1', $group, $res);
            }
            return $res;
        }

        if (strpos($res, 'e\x76al') !== false
            || strpos($res, '\x29') !== false
            || strpos($res, 'base64_decode("\\x') !== false
        ) {
            $res = stripcslashes($res);
        }
        if (strpos($res, '"."') !== false) {
            $res = str_replace('"."', '', $res);
        }

        if (preg_match('~((\$\w+)\s*=\s*create_function\(\'\',\s*)[^\)]+\)+;\s*(\2\(\);)~msi', $res, $matches)) {
            $res = str_replace($matches[1], 'eval(', $res);
            $res = str_replace($matches[3], '', $res);
            return $res;
        }

        if (preg_match('~eval\s*/\*[\w\s\.:,]+\*/\s*\(~msi', $res, $matches)) {
            $res = str_replace($matches[0], 'eval(', $res);
            return $res;
        }
        if (preg_match('~\$_(POST|GET|REQUEST|COOKIE)~ms', $res)) {
            return $res;
        }

        $res = preg_replace('~"\s+\?>\s*"\s*\.~m', '"?>".', $res, 3);

        $string = substr($res, 5, -2);
        $res = $this->unwrapFuncs($string);

        if (preg_match('~\?>\s*([\w/+]+==)~msi', $res, $match)) {
            $code = base64_decode($match[1]);
            if (strpos($code, 'error_reporting(') !== false) {
                $res = '?> ' . $code;
            }
        }

        if (preg_match('~chr\(\d+\^\d+\)~msi', $res)) {
            $res = Helpers::normalize($res);
        }
        $res = str_replace($str, $res, $str);
        return $res;
    }

    private function deobfuscateEvalCodeFunc($str, $matches)
    {
        $res = substr($str, 5, -2);
        $res = $this->unwrapFuncs($res);
        $res = stripcslashes($res);
        $res = str_replace($str, $res, $str);
        return $res;
    }

    private function deobfuscateEcho($str, $matches)
    {
        $res = $str;
        $string = $matches[0];
        if (preg_match('~\$_(POST|GET|REQUEST|COOKIE)~ms', $res)) {
            return $res;
        }
        $string = substr($string, 5);
        $res = $this->unwrapFuncs($string);
        $res = str_replace($string, '\'' . addcslashes($res, '\'') . '\';', $str);
        return $res;
    }

    private function deobfuscateFOPO($str, $matches)
    {
        $phpcode = Helpers::formatPHP($str);
        $phpcode = base64_decode(Helpers::getTextInsideQuotes(Helpers::getEvalCode($phpcode)));


        if (preg_match('~eval\s*\(\s*\$[\w|]+\s*\(\s*\$[\w|]+\s*\(~msi', $phpcode)) {
            preg_match_all('~\$\w+\(\$\w+\(\$\w+\("[^"]+"\)+~msi', $phpcode, $matches2);
            $array = end($matches2);
            @$phpcode = gzinflate(base64_decode(str_rot13(Helpers::getTextInsideQuotes(end($array)))));
            $old = '';
            $hangs = 0;
            while (($old != $phpcode) && (strpos($phpcode, 'eval($') !== false)
                   && (strpos($phpcode, '__FILE__') === false) && $hangs < 30) {
                $old = $phpcode;
                $funcs = explode(';', $phpcode);
                if (count($funcs) === 5) {
                    $phpcode = gzinflate(base64_decode(str_rot13(Helpers::getTextInsideQuotes(Helpers::getEvalCode($phpcode)))));
                } elseif (count($funcs) === 4) {
                    $phpcode = gzinflate(base64_decode(Helpers::getTextInsideQuotes(Helpers::getEvalCode($phpcode))));
                }
                $hangs++;
            }
            $res = str_replace($matches[0], substr($phpcode, 2), $str);
        } else {
            $res = str_replace($matches[0], $phpcode, $str);
        }

        return $res;
    }

    private function deobfuscateFakeIonCube($str, $matches)
    {
        $subst_value = 0;
        $matches[1] = Helpers::calc($matches[1]);
        $subst_value = (int)$matches[1] - 21;
        $code = @pack("H*", preg_replace("/[A-Z,\r,\n]/", "", substr($str, $subst_value)));
        $res = str_replace($matches[0], $code, $str);
        return $res;
    }

    private function deobfuscateCobra($str, $matches)
    {
        $find = $matches[0];
        $res = $str;
        $res = preg_replace_callback(
            '~eval\(\"return strrev\(base64_decode\(\'([^\']+)\'\)\);\"\)~msi',
            static function ($matches) {
                return strrev(base64_decode($matches[1]));
            },
            $res
        );

        $res = preg_replace_callback(
            '~eval\(gzinflate\(base64_decode\(\.\"\'([^\']+)\'\)\)\)\;~msi',
            static function ($matches) {
                return gzinflate(base64_decode($matches[1]));
            },
            $res
        );

        preg_match('~(\$\w{1,40})\s*=\s*\"([^\"]+)\"\;\s*\1\s*=\s*explode\(\"([^\"]+)\",\s*\s*\1\);~msi', $res, $matches);
        $var = $matches[1];
        $decrypt = base64_decode(current(explode($matches[3], $matches[2])));
        $decrypt = preg_replace_callback(
            '~eval\(\"return strrev\(base64_decode\(\'([^\']+)\'\)\);\"\)~msi',
            static function ($matches) {
                return strrev(base64_decode($matches[1]));
            },
            $decrypt
        );

        $decrypt = preg_replace_callback(
            '~eval\(gzinflate\(base64_decode\(\.\"\'([^\']+)\'\)\)\)\;~msi',
            static function ($matches) {
                return gzinflate(base64_decode($matches[1]));
            },
            $decrypt
        );

        preg_match('~if\(\!function_exists\(\"(\w+)\"\)\)\s*\{\s*function\s*\1\(\$string\)\s*\{\s*\$string\s*=\s*base64_decode\(\$string\)\;\s*\$key\s*=\s*\"(\w+)\"\;~msi', $decrypt, $matches);

        $decrypt_func = $matches[1];
        $xor_key = $matches[2];

        $res = preg_replace_callback(
            '~\\' . $var . '\s*=\s*.*?eval\(' . $decrypt_func . '\(\"([^\"]+)\"\)\)\;\"\)\;~msi',
            static function ($matches) use ($xor_key) {
                $string = base64_decode($matches[1]);
                $key = $xor_key;
                $xor = "";
                for ($i = 0, $iMax = strlen($string); $i < $iMax;) {
                    for ($j = 0, $jMax = strlen($key); $j < $jMax; $j++,$i++) {
                        if (isset($string[$i])) {
                            $xor .= $string[$i] ^ $key[$j];
                        }
                    }
                }
                return $xor;
            },
            $res
        );
        $res = str_replace($find, $res, $str);
        return $res;
    }

    private function deobfuscateFlamux($str, $matches)
    {
        $str = $matches[0];

        $vars = [];
        preg_match_all('~(\$\w+=[\'"]\w+[\'"];)~', $str, $match);
        foreach ($match[0] as $var) {
            $split = explode('=', str_replace(';', '', $var));
            $vars[$split[0]] = $split[1];
        }

        $res = '';
        preg_match_all('~(\$\w+=\$\w+[\'.]+\$\w+;)~', $str, $match);
        for ($i = 0, $iMax = count($match[0]); $i < $iMax; $i++) {

            $split = explode('=', str_replace(';', '', $match[0][$i]));
            $concats = explode('.', $split[1]);
            $str_to_concat = '';
            foreach ($concats as $concat) {
                $str_to_concat .= $vars[$concat] ?? '';
            }

            $vars[$split[0]] = $str_to_concat;

            if ($i === ($iMax - 1)) {
                $res = gzinflate(base64_decode(base64_decode(str_rot13($str_to_concat))));
            }
        }

        return $res;
    }

    private function deobfuscateDarkShell($str, $matches)
    {
        return stripcslashes($matches[0]);
    }

    private function deobfuscateWso($str, $matches)
    {
        $result = $matches[0];
        $contentVar = $matches[8];

        preg_match_all('~(\[([-+\(\d*\/\)]+)\])+~', $result, $mathMatches);
        foreach ($mathMatches[0] as $index => $match) {
            $search = $mathMatches[2][$index];
            $mathResult = Helpers::calculateMathStr($search);

            $result = str_replace("[$search]", "[$mathResult]", $result);
        }

        $dictionary = $matches[2];

        $variables = Helpers::getVarsFromDictionary($dictionary, $result);
        $variables[$matches[6]] = $matches[7];

        preg_match_all('~(\$\w+)\.=(\$\w+)~', $result, $matches);
        foreach ($matches as $index => $match) {
            $var = $matches[1][$index];
            $value = $matches[2][$index];
            if (!isset($variables[$var])) {
                $variables[$var] = (string)$variables[$value] ?? '';
            } else {
                $variables[$var] .= (string)$variables[$value] ?? '';
            }
        }

        if (isset($variables[$contentVar])) {
            $result = $variables[$contentVar];
        }

        if (preg_match('~(\$\w+)\s+=\s+(["\'\w\/+]+);(\$\w+)=base64_decode\(\1\);(\$\w+)=gzinflate\(\3\);eval\(\4\);~msi', $result, $match)) {
            $result = gzinflate(base64_decode($match[2]));
        }

        $result = str_replace('<?php', '', $result);

        return $result;
    }

    private function deobfuscateAnonymousFox($str, $matches)
    {
        $string = $matches[7];
        $array = strlen(trim($string));
        $debuger = '';
        for ($one = 0; $one < $array; $one += 2) {
            $debuger .= pack("C", hexdec(substr($string, $one, 2)));
        }
        $string = $debuger;

        $result = $string . $matches[8] . "';";

        return $result;
    }

    private function deobfuscateWsoEval($str, $matches)
    {
        $result = base64_decode($matches[2]);

        preg_match('~data:image/png;(.*)">~im', $result, $match);
        $result = str_replace( array ('%', '#'), array ('/', '+'), $match[1]);
        $result = gzinflate(base64_decode($result));

        return $result;
    }

    private function deobfuscateAssertStr($str, $matches)
    {
        return 'eval' . $matches[3];
    }

    private function deobfuscateEvalFuncFunc($str, $matches)
    {
        return Helpers::decrypt_T_func(base64_decode($matches[15]));
    }

    private function deobfuscateFuncVar($str, $matches)
    {
        $arg1 = str_replace($matches[5], '', $matches[3]);
        $funcName = str_replace($matches[8], '', $matches[7]);
        $insidefuncName = str_replace($matches[11], '', $matches[10]);

        if ($funcName === 'create_function') {
            $result = sprintf('%s(%s(\'%s\');', $insidefuncName, $arg1, $matches[15]);
        } else {
            $result = sprintf(
                '%s = %s(\'%s\',\'%s(%s(%s));\');%s(\'%s\');',
                $matches[14],
                $funcName,
                $matches[13],
                $insidefuncName,
                $arg1,
                $matches[13],
                $matches[14],
                $matches[15]
            );
        }

        return $result;
    }

    private function deobfuscateEchoEval($str, $matches)
    {
        $content = $matches[4];
        $content = str_replace($matches[1], $matches[2], $content);
        $result = str_replace($matches[3], $content, $matches[5]);

        return $result;
    }

    private function deobfuscateDictionaryVars($str, $matches)
    {
        $dictionary = $matches[2];
        $dictionary = str_replace("\'", "'", $dictionary);
        $dictionary = str_replace('\"', '"', $dictionary);
        $content = $matches[4];
        $vars = Helpers::getVarsFromDictionary($dictionary, $matches[0]);

        if (isset($vars[$matches[6]]) && $vars[$matches[6]] === 'create_function') {
            $content = str_replace($matches[5], 'eval(' . $matches[7] . ');', $content);
        }

        $content = Helpers::replaceVarsFromDictionary($matches[1], $dictionary, $content);

        foreach ($vars as $key => $value) {
            $content = str_replace($key, $value, $content);
        }

        $content = preg_replace_callback('~\${[\'"](\w+)[\'"]}~msi', static function ($m) {
            return '$' . $m[1];
        }, $content);

        $content = str_replace("''}", "\''}", $content);

        return $content;
    }

    private function deobfuscateConcatVarFunc($str, $matches)
    {
        $strVar = "";
        if ($matches['concatVar'] !== "") {
            $strVar = Helpers::concatVariableValues($matches[2], false);
        } else {
            if ($matches['strVal'] !== "") {
                $strVar = $matches['strVal'];
            }
        }

        $result = "";
        $iMax = strlen($strVar) / 2;
        for ($i = 0; $i < $iMax; $i++) {
            $result .= chr(base_convert(substr($strVar, $i * 2, 2), 16, 10));
        }
        return $result;
    }

    private function deobfuscateConcatVarFuncFunc($str, $matches)
    {
        $result = $matches[12];

        $func1 = Helpers::concatVariableValues($matches[2]);
        $func2 = Helpers::concatVariableValues($matches[22]);
        $func3 = Helpers::concatVariableValues($matches[19]);
        $func4 = Helpers::concatVariableValues($matches[7]);

        $result = sprintf('eval(%s(%s(%s(%s("%s")))));', $func1, $func2, $func3, $func4, $result);

        return $result;
    }

    private function deobfuscateEvalVarDoubled($str)
    {
        $result = $str;

        preg_match_all('~(\$\w+)\s?=\s?(\w+)\([\'"]([^\'"]+)[\'"]\);~', $str, $varMatches);

        foreach ($varMatches[0] as $index => $varMatch) {
            $var_name = $varMatches[1][$index];
            $func_name = $varMatches[2][$index];
            $str = $varMatches[3][$index];

            if (Helpers::isSafeFunc($func_name)) {
                $str = @$func_name($str);
            }
            $result = str_replace($varMatch, '', $result);
            $result = str_replace($var_name, $str, $result);
        }

        return $result;
    }

    private function deobfuscateVarFuncsEcho($str, $matches)
    {
        $result = $str;
        $func = $matches[2];

        if (Helpers::isSafeFunc($matches[2])) {
            $result = @$func($matches[3]);
            $result = str_replace('<?php', '', $result);
        }

        return $result;
    }

    private function deobfuscateVarFuncsMany($str, $matches)
    {
        $result          = $matches[0];
        $strName         = $matches[1];
        $dictionaryName  = $matches[2];
        $dictionaryValue = Helpers::collectStr("$matches[3]", "'");

        $funcs = [];
        $vars  = [];

        $result = preg_replace_callback('~(\$\w+)=((?:(\$\w{1,50})\[?{?\d+\]?}?\.?)+);~msi',
            function ($m) use (&$vars, $dictionaryValue) {
                $vars = array_merge($vars, Helpers::getVarsFromDictionary($dictionaryValue, $m[0]));
                return '';
            }, $result);

        $result = preg_replace_callback(
            '~(\$\w+)\s?=\s?array\([\'"]([\w+\/]+)[\'"]\s?,\s?[\'"]([\w+\/]+)[\'"](?:\s?,[\'"]([\w+\/]+)[\'"]\s?)?\);\s?((?:(?:\$\w+=\s?\w+\(\$\w+,\s?)|(?:return\s?))(join\([\'"]{2},\s?\1\))\s?\)?\s?;)~msi',
            function ($match) {
                $joinedVars = implode("", [$match[2], $match[3], $match[4]]);
                $replace    = str_replace($match[6], "'$joinedVars'", $match[5]);

                return $replace;
            },
            $result
        );

        $result = preg_replace_callback(
            '~global\s(\$\w+);\s?((\$\w+)\s?=\s?[\'"]([\w\/+]+)[\'"];\s?(\$\w+)\s?=\s?[\'"]([\w\/+]+)[\'"];\s?(\$\w+)\s?=\s?[\'"]([\w\/+]+)[\'"];\s?\1\s?\.=\s?"({\3}{\5}{\7})");~',
            function ($match) {
                $concatedVars = $match[4] . $match[6] . $match[8];
                $replace      = str_replace($match[2], sprintf('%s.="%s"', $match[1], $concatedVars), $match[0]);

                return $replace;
            },
            $result
        );

        $result = preg_replace_callback(
            '~((\$\w+)\s?=\s?[\'"]([\w\/+=]+)[\'"];\s?(\$\w+)\s?=\s?[\'"]([\w\/+=]+)[\'"];\s?return\s?"({\2}{\4})");~msi',
            function ($match) {
                $concatedVars = $match[3] . $match[5];
                $replace      = str_replace($match[1], sprintf('return "%s"', $concatedVars), $match[0]);

                return $replace;
            },
            $result
        );

        $result = preg_replace_callback(
            '~(?:class\s(?<className>\w+)\s?{\s?)?(?:public\s)?function\s(?<methodName>\w+\(\)){\s?(?<codeBlock>.*?;)\s}\s?(?:}\s?)?~msi',
            function ($match) use (&$funcs, $strName, $dictionaryName, $dictionaryValue) {
                $str      = "";
                $isConcat = false;

                if (preg_match(
                    '~return\s[\'"]([\w+\/+=]+)[\'"];~msi',
                    $match[0],
                    $returnCode
                )) {
                    $str = $returnCode[1];
                } else {
                    if (preg_match(
                        '~global\s(\$\w+);\s?\1\s?\.=\s?["\']([\w+\/+]+)["\'];?~msi',
                        $match[0],
                        $concatCode
                    )) {
                        $str      = $concatCode[2];
                        $isConcat = true;
                    } else {
                        if (preg_match(
                            '~global\s(\$' . substr(
                                $dictionaryName,
                                1
                            ) . ');\s*return\s*((?:\s?\1\[?{?\d+\]?}?\s?\.?\s?)+);?~msi',
                            $match[0],
                            $returnCode
                        )) {
                            $str      = Helpers::getVarsFromDictionary(
                                $dictionaryValue,
                                sprintf('%s=%s', $dictionaryName, $returnCode[2])
                            );
                            $str      = $str[$dictionaryName];
                            $isConcat = false;
                        }
                    }
                }
                $funcs[$match['methodName']]['str']    = $str;
                $funcs[$match['methodName']]['concat'] = $isConcat;

                return "";
            },
            $result
        );

        $result = preg_replace_callback(
            '~(\$[^' . substr($strName, 1) . ']\w+)\s?=\s?(\w+\(\));~ms',
            function ($match) use ($funcs, &$vars) {
                if (isset($funcs[$match[2]]) && !$funcs[$match[2]]['concat']) {
                    $vars[$match[1]] = $funcs[$match[2]]['str'];
                }
                return "";
            },
            $result
        );

        foreach ($vars as $name => $var) {
            $result = str_replace($name, $var, $result);
        }

        $result = preg_replace_callback(
            '~([\w_]+)\s?\(\s?([\w_]+)\s?\(\s?((?:\$' . substr($dictionaryName,
                1) . '[{\[]\d+[\]}]\s?\.?)+)\s?,\s?(\d+)\s?\),\s?((?:\d+,?)+)\);~msi',
            function ($match) use ($dictionaryValue, $dictionaryName) {
                $str = Helpers::getVarsFromDictionary(
                    $dictionaryValue,
                    sprintf('%s=%s', $dictionaryName, $match[3])
                );
                $res = "";
                if (Helpers::isSafeFunc($match[2])) {
                    $res = @$match[2]($str[$dictionaryName], $match[4]);
                }

                if (Helpers::isSafeFunc($match[1])) {
                    $args   = [$res];
                    $digits = explode(',', $match[5]);
                    foreach ($digits as $digit) {
                        $args[] = (int)$digit;
                    }
                    $reflectionMethod = new ReflectionFunction($match[1]);
                    $res              = $reflectionMethod->invokeArgs($args);
                }
                return "\"$res\";";
            },
            $result
        );

        $strToDecode = "";

        $regexFinal = str_replace('mainVar', $strName,
            '~(?:\mainVar\s?=\s?\w+\(\s?\mainVar\s*,\s?["\'](?<concat>[\w+\/]+)[\'"]\s?\)\s?;)|(?:\mainVar\s?=\s?\w+\(\s?\mainVar\s?,\s?(?<concatFunc>\w+\(\))\)\s?;)|(?:\mainVar\s?\.?=\s?(?:\mainVar\.)?\s?["\'](?<concatStr>[\w+\/=]+)[\'"]\s?;)|(?:\mainVar\s?\.?=\s?(?<concatFuncSingle>\w+\(\))\s?;)|(\$\w+\s?=\s?new\s\w+\(\)\s?;\s?\mainVar\s?\.?=\s?\mainVar\s?\.\s?\$\w+->(?<concatFuncClass>\w+\(\)\s?))|(?:(?<func>[^,\s]\w+\(\)))~msi');

        $result = preg_replace_callback(
            $regexFinal,
            function ($match) use (&$strToDecode, $funcs) {
                if (isset($match['concat']) && $match['concat'] !== "") {
                    $strToDecode .= $match['concat'];
                    return;
                }
                if (isset($match['concatStr']) && $match['concatStr'] !== "") {
                    $strToDecode .= $match['concatStr'];
                    return;
                }
                if (isset($match['concatFunc']) && $match['concatFunc'] !== "") {
                    $strToDecode .= $funcs[$match['concatFunc']]['str'];
                    return;
                }
                if (isset($match['concatFuncSingle']) && $match['concatFuncSingle'] !== "") {
                    $strToDecode .= $funcs[$match['concatFuncSingle']]['str'];
                    return;
                }
                if (isset($match['concatFuncClass']) && $match['concatFuncClass'] !== "") {
                    $strToDecode .= $funcs[$match['concatFuncClass']]['str'];
                    return;
                }
                if (isset($match['func']) && $match['func'] !== "") {
                    $strToDecode .= $funcs[$match['func']]['str'];
                    return;
                }
            },
            $result
        );

        $code   = $result;
        $result = base64_decode($strToDecode);

        if (preg_match('~((\$\w+)="";).*?((\$\w+)=create_function\(\'(\$\w+,\$\w+)\',\s?(base64_decode\(((?:"[\w+=]+"\.?)+)\))\);).*?(\$\w+\s?=\s?create_function\("",\s?\4\(base64_decode\(\2\),\s?(\$_COOKIE\[\'\w+\'\])\)\s?\);)~msi',
            $code, $codeMatch)) {
            $initialCode = base64_decode(Helpers::collectStr($codeMatch[7]));

            $result = sprintf("function %s(%s){%s}%s='%s';%s(%s,%s);",
                substr($codeMatch[4], 1), $codeMatch[5], $initialCode, $codeMatch[2], $result,
                substr($codeMatch[4], 1), $codeMatch[2], $codeMatch[9]);
        }

        return $result;
    }

    private function deobfuscateGlobalArrayEval($str, $matches)
    {
        $result = str_replace($matches[1], "", $str);

        $dictionary = stripcslashes($matches[3]);
        $dictionaryVar = stripcslashes($matches[2]);
        $dictionaryVar = str_replace('{"GLOBALS"}', 'GLOBALS', $dictionaryVar);

        $result = Helpers::replaceVarsFromDictionary($dictionaryVar, $dictionary, $result);

        preg_match_all('~(\$GLOBALS\[[\'\w]+\])\s?=\s?[\'"]?([\w\-\_\$]+)["\']?;\s?~msi', $result, $varMatch);

        foreach ($varMatch[1] as $index => $var) {
            $result = str_replace([$varMatch[0][$index], $varMatch[1][$index]], ["", $varMatch[2][$index]],
                $result);
        }

        return $result;
    }

    private function deobfuscateTinkleShell($str, $matches)
    {
        $result = $str;
        $dictionaryStr = $matches[2];
        $decodeKey = Helpers::getDecryptKeyForTinkleShell(strlen($str));
        $vars = [
            $matches[4] => $matches[5],
        ];

        $result = str_replace(' ', '', $result);
        $matches[3] = str_replace(' ', '', $matches[3]);

        preg_match_all('~(\$\w+)=(?:\$\w+\[\'\w\'\+\d+\+\'\w\'\]\.?)+;~msi', $matches[3], $matchVars);
        foreach ($matchVars[0] as $index => $match) {
            preg_match_all('~\$\w+\[\'\w\'\+(\d+)\+\'\w\'\]\.?~msi', $match, $values);
            foreach ($values[1] as $value) {
                if (!isset($vars[$matchVars[1][$index]])) {
                    $vars[$matchVars[1][$index]] = $dictionaryStr[$value] ?? $value;
                } else {
                    $vars[$matchVars[1][$index]] .= $dictionaryStr[$value] ?? $value;
                }
            }
        }

        $result = str_replace($matches[3], "", $result);

        preg_match_all('~(\$\w+)=(\$\w+)\((\$\w+),(\$\w+)\(""\),"([\w\+]+)"\);~msi', $result, $matchVars);
        foreach ($matchVars[1] as $index => $varName) {
            $func = $vars[$matchVars[2][$index]] ?? $matchVars[2][$index];
            $arg1 = $vars[$matchVars[3][$index]] ?? $matchVars[3][$index];
            $arg2 = $vars[$matchVars[4][$index]] ?? $matchVars[4][$index];
            $argStr = $matchVars[5][$index];

            if (Helpers::isSafeFunc($func)) {
                $value = @$func($arg1, $arg2 === 'trim' ? "" : $arg2, $argStr);

                $vars[$varName] = $value;
            }
            $result = str_replace($matchVars[0][$index], '', $result);
        }

        $func = $vars[$matches[10]] ?? '';
        if (Helpers::isSafeFunc($func)) {
            $result = @$func($matches[11], $vars[$matches[12]] ?? "", $decodeKey);
        }
        $func = $vars[$matches[7]] ?? '';
        if (Helpers::isSafeFunc($func)) {
            $result = @$func($vars[$matches[8]] ?? '', "", $result);
        }
        $func = $vars[$matches[6]] ?? '';
        if (Helpers::isSafeFunc($func)) {
            $result = @$func($result);
        }

        return $result;
    }

    private function deobfuscateWsoFunc($str, $matches)
    {
        if (isset($matches['str'])) {
            return gzinflate(base64_decode($matches['str']));
        }

        return $matches[0];
    }

    private function deobfuscateEvalWanFunc($str, $matches)
    {
        $result = gzinflate(base64_decode($matches[5]));

        for ($i = 0, $iMax = strlen($result); $i < $iMax; $i++) {
            $result[$i] = chr(ord($result[$i]) - (int)$matches[4]);
        }

        return $result;
    }

    private function deobfuscateFuncFile($str, $matches)
    {
        return base64_decode($matches[2]);
    }
    
    private function deobfuscateFuncFile2($str, $matches)
    {
        $var_fragment   = $matches[1];
        $decoded_code   = base64_decode($matches[3]);
        $var_name       = $matches[4];
        $new_fragment   = "$var_name = '$decoded_code';";
        return str_replace($var_fragment, $new_fragment, $str);
    }

    private function deobfuscateGulf($str, $matches)
    {
        $result = str_replace("'.'", '', str_replace($matches[2], '', $matches[1]));

        $vars = Helpers::collectVars($matches[2], "'");
        $result = Helpers::replaceVarsFromArray($vars, $result);

        $tempCode = gzinflate(base64_decode($matches[4]));

        $result .= PHP_EOL . $tempCode;

        return $result;
    }

    private function deobfuscateEvalConcatAsciiChars($str, $matches)
    {
        $result = '';

        $num = (int)$matches[2];
        $str = (string)$matches[3];
        $len = strlen($str);

        for ($i = 0; $i < $len; $i++) {
            $result .= chr(ord($str[$i]) ^ $num);
        }

        $result = str_replace(['<?php', '?>', '', ''], '', $result);

        return $result;
    }

    private function deobfuscateEvalPost($str, $matches)
    {
        $vars = Helpers::collectVars($str);

        $result = str_replace('.', "", $matches[8]);
        $result = str_replace($matches[7], "", Helpers::replaceVarsFromArray($vars, $result));
        $result = base64_decode(base64_decode($result));

        return $result;
    }

    private function deobfuscateEvalPregStr($str, $matches)
    {
        $result = sprintf("%s'%s'%s", stripcslashes($matches[1]), $matches[2], stripcslashes($matches[3]));

        $result = $this->unwrapFuncs($result);

        return $result;
    }

    private function deobfuscateClassDestructFunc($str, $matches)
    {
        $result = $str;

        $arg1 = $matches[1] ^ stripcslashes($matches[2]);
        $arg2 = $matches[3] ^ stripcslashes($matches[4]);

        if ($arg1 === 'assert' && $arg2 === 'eval') {
            $result = base64_decode($matches[5]);
        }

        return $result;
    }

    private function deobfuscateCreateFuncEval($str, $matches)
    {
        $result = $str;

        $func = stripcslashes($matches[1]);

        if (Helpers::isSafeFunc($func)) {
            $result = @$func($matches[2]);
        }

        return $result;
    }

    private function deobfuscateEvalCreateFunc($str, $matches)
    {
        $result = $str;

        if (!(isset($matches[4]) && $matches[4] !== ''))
        {
            $arr = [
                0 => $matches[5],
                1 => $matches[6],
                2 => $matches[13],
            ];

            $func_1 = Helpers::decodeEvalCreateFunc_2($arr);
            if (strtoupper($func_1) === 'CREATE_FUNCTION') {
                $arr[2] = $matches[10];
                $result = Helpers::decodeEvalCreateFunc_2($arr);
                return $result;
            }
        }

        $arr = [
            0 => $matches[4],
            1 => $matches[5],
            2 => $matches[6],
            3 => $matches[13],
        ];

        $func_1 = Helpers::decodeEvalCreateFunc_1($arr);
        if (strtoupper($func_1) === 'CREATE_FUNCTION') {
            $arr[3] = $matches[10];

            $result = Helpers::decodeEvalCreateFunc_1($arr);
            
            $result = preg_replace_callback(Helpers::REGEXP_BASE64_DECODE, function ($match) {
                $extraCode = $this->unwrapFuncs($match[0]);

                if (preg_match('~if\(!function_exists\([\'"](\w+)[\'"]\)\){function\s?\1\((\$\w+)\){(\$\w+)=array\(\'([{\w\]]+)\',\'([\w`]+)\',\2\);for\((\$\w+)=0;\6<3;\6\+\+\){for\((\$\w+)=0;\7<strlen\(\3\[\6\]\);\7\+\+\)\s?\3\[\6\]\[\7\]\s?=\s?chr\(ord\(\3\[\6\]\[\7\]\)-1\);if\(\6==1\)\s?\3\[2\]=\3\[0\]\(\3\[1\]\(\3\[2\]\)\);}\s?return\s?\3\[2\];}(\$\w+)=["\']([\w\+\/=]+)["\'];(\$\w+)=[\'"]\1[\'"];(\$\w+)=\10\([\'"]([\w=]+)[\'"]\);\$\w+=\11\(\'\',\10\(\8\)\);\$\w+\(\);}~msi', $extraCode, $matchCode)) {
                    $arr = [
                        0 => $matchCode[4],
                        1 => $matchCode[5],
                        2 => $matchCode[12],
                    ];

                    $func_1 = Helpers::decodeEvalCreateFunc_2($arr);
                    if (strtoupper($func_1) === 'CREATE_FUNCTION') {
                        $arr[2] = $matchCode[9];

                        $extraCode = str_replace($matchCode[0], Helpers::decodeEvalCreateFunc_2($arr), $extraCode);
                    }
                }
                return $extraCode;
            }, $result);
        }

        return $result;
    }

    private function deobfuscateEvalFuncVars($str, $matches)
    {
        $result = $str;
        $vars = Helpers::collectFuncVars($matches[1]);

        $result = Helpers::replaceVarsFromArray($vars, $matches[2]);


        if (strpos($result, 'eval') !== false) {
            $result = $this->unwrapFuncs($result);
        }
        return $result;
    }

    private function deobfuscateDictionaryCreateFuncs($str, $matches)
    {
        $vars = Helpers::getVarsFromDictionary($matches[3], $matches[4]);
        $result = str_replace($matches[4], '', $str);

        $result = preg_replace_callback('~\${"[\\\\\w]+"}\["[\\\\\w]+"\]~msi', static function ($match) {
            return stripcslashes($match[0]);
        }, $result);

        $result = preg_replace_callback('~\${"GLOBALS"}\["(\w+)"\]~msi', static function ($match) use ($vars) {
            $varName = '$' . $match[1];

            return $vars[$varName] ?? $varName;
        }, $result);

        preg_match('~(\$\w+)=create_function\(\'(\$\w+)\',\'\$\w+=substr\(\2,0,5\);\$\w+=substr\(\2,-5\);\$\w+=substr\(\2,7,strlen\(\2\)-14\);return\s*gzinflate\(base64_decode\(\$\w+\.\$\w+\.\$\w+\)\);\'\);~msi', $result, $decoderFunc);
        $result = str_replace($decoderFunc[0], '', $result);
        $decoderFunc = $decoderFunc[1];
        $result = Helpers::replaceCreateFunction($result);
        $result = preg_replace_callback('~(\$\w+)\s*\(\'([^\']+)\'\)~msi', function($m) use ($decoderFunc) {
            if ($m[1] !== $decoderFunc) {
                return $m[0];
            }
            return '\'' . Helpers::dictionarySampleDecode($m[2]) .'\'';
        }, $result);

        $result = Helpers::normalize($result);

        return $result;
    }

    private function deobfuscateEvalPostDictionary($str, $matches)
    {
        $finalCode = $matches[19];
        $result = str_replace($finalCode, '', $str);
        $arrayNum = [];
        $arrayStr = [];

        $regex = '~"?([\w\.\/\s]+)"?,?\s?~msi';
        preg_match_all($regex, $matches[6], $arrayStrMatches);
        foreach ($arrayStrMatches[1] as $arrayStrMatch) {
            $arrayStr[] = $arrayStrMatch;
        }

        $result = Helpers::replaceVarsFromDictionary($matches[5], $arrayStr, $result);
        $vars = Helpers::collectVars($result, "'");

        $regexSpecialVars = '~(\$\w+)([()\]])~msi';
        $code1 = preg_replace_callback($regexSpecialVars, static function ($match) use ($vars) {
            $res = $vars[$match[1]] ?? $match[1];
            if ($match[2] === ']' || $match[2] === ')') {
                $res = "'$res'";
            }
            return $res . $match[2];
        }, $matches[20]);

        $code2 = str_replace($matches[18], '$_POST[\'' . ($vars[$matches[18]] ?? $matches[18]) . '\']', $matches[21]);
        $code2 = Helpers::replaceVarsFromArray($vars, $code2);

        $tempStr = Helpers::replaceVarsFromDictionary($matches[5], $arrayStr, $matches[22]);
        $vars = Helpers::collectVars($tempStr, "'");

        $code3 = preg_replace_callback($regexSpecialVars, static function ($match) use ($vars) {
            $res = $vars[$match[1]] ?? $match[1];
            if ($match[2] === ']' || $match[2] === ')') {
                $res = "'$res'";
            }
            return $res . $match[2];
        }, $matches[23]);

        $result = $code1 . $code2 . $code3;

        return $result;
    }

    private function deobfuscateDropInclude($str, $matches)
    {
        $key = basename($matches[2]);
        $encrypted = base64_decode(base64_decode($matches[4]));
        return $this->deobfuscateXorFName($encrypted, null, $key);
    }

    private function deobfuscateEvalComments($str, $matches)
    {
        return preg_replace('~/\*[^/]*/?\*/~msi', '', $str);
    }

    private function deobfuscateStrrevUrldecodeEval($str, $matches)
    {
        return strrev(urldecode($matches[2]));
    }

    private function deobfuscateEvalPackStrrot($str, $matches)
    {
        return pack("H*", str_rot13($matches[3]));
    }

    private function deobfuscateUrlDecodeTable($str, $matches)
    {
        $matches[3] = str_replace([" ", "\r", "\n", "\t", "'.'"], '', $matches[3]);
        $matches[5] = str_replace([" ", "'", ">"], '', $matches[5]);
        $temp = explode(',', $matches[5]);
        $array = [];
        foreach ($temp as $value) {
            $temp = explode("=", $value);
            $array[$temp[0]] = $temp[1];
        }
        $res = '';
        for ($i=0, $iMax = strlen($matches[3]); $i < $iMax; $i++) {
            $res .= isset($array[$matches[3][$i]]) ? $array[$matches[3][$i]] : $matches[3][$i];
        }
        $res = substr(rawurldecode($res), 1, -2);
        return $res;
    }

    private function deobfuscateEvalVarChar($str, $matches)
    {
        $chars = Helpers::collectVarsChars($matches[1]);
        $vars = Helpers::assembleStrings($chars, $matches[2]);
        $str = str_replace($matches[1], '', $str);
        $str = str_replace($matches[2], '', $str);
        foreach ($vars as $var => $func) {
            $str = str_replace($var, $func, $str);
        }
        return $str;
    }

    private function deobfuscateEvalVarFunc($str, $matches)
    {
        $var = Helpers::collectFuncVars($matches[1]);
        return $var[$matches[4]];
    }

    private function deobfuscateEvalVarsFuncs($str, $matches)
    {
        $vars = Helpers::collectVars($matches[1]);
        $vars[$matches[5]] = $matches[2];
        $res = Helpers::replaceVarsFromArray($vars, $matches[3]);
        return $res;
    }

    private function deobfuscateEvalFileContent($str, $matches)
    {
        $res = $matches[4];
        $vars = Helpers::getVarsFromDictionary($matches[2], $matches[3]);
        $vars[$matches[1]] = $matches[2];
        $res = Helpers::replaceVarsFromArray($vars, $res);
        if (preg_match('~\$[^=]{0,50}=file\(str_replace\(\'\\\\{2}\',\'/\',__FILE__\)\);(\$[^=]{0,50})=array_pop\(\$[^)]{0,50}\);(\$[^=]{0,50})=array_pop\(\$[^)]{0,50}\);\$[^=]{0,50}=implode\(\'\',\$[^)]{0,50}\)\.substr\(\$[^,]{0,50},0,strrpos\(\$[^,]{0,50},\'@ev\'\)\);\$[^=]{0,50}=md5\(\$[^)]{0,50}\);(?:\$[^=]{0,50}=){0,3}NULL;@eval\(base64_decode\(str_replace\(\$[^,]{0,50},\'\',strtr\(\'~msi',
            $res, $match)) {
            $arr = explode(PHP_EOL, $str);
            foreach ($arr as $index => $val) {
                if ($index !== count($arr) - 1) {
                    $arr[$index] .= PHP_EOL;
                }
            }

            $arr1 = array_pop($arr);
            $arr2 = array_pop($arr);

            $vars[$match[1]] = $arr1;
            $vars[$match[2]] = $arr2;

            $res = implode('', $arr) . substr($arr2, 0, strrpos($arr2, '@ev'));
            $md5 = md5($res);
            $res = base64_decode(str_replace($md5, '', strtr($matches[5], $matches[6], $matches[7])));


            if (preg_match('~eval\((?:\$[^(]{0,50}\(){2}\$[^,]{0,50},\s{0,10}\'([^\']{1,500})\',\s{0,10}\'([^\']{1,500})\'\){3};~msi',
                $res, $match)) {
                $res = Helpers::replaceVarsFromArray($vars, $res);
                if (preg_match('~eval\(base64_decode\(strtr\(~msi', $res)) {
                    $res = base64_decode(strtr($arr1, $match[1], $match[2]));
                    $res = '<?php ' . PHP_EOL . $res;
                }
            }
        }

        return $res;
    }

    private function deobfuscateEvalArrayVar($str, $matches)
    {
        $result = $str;

        $array1 = str_split($matches[2]);
        $array2 = [];
        $arrayStr = base64_decode($matches[1]);

        if (preg_match('~(\$\w+)=\[(["\'][\w\[\];\'"|,.{}+=/&][\'"]=>["\'][\w\[\];\'"|,.{}+=/&][\'"],?\s{0,50})+\];~msi',
            $arrayStr, $match)) {
            preg_match_all('~["\']([\w\[\];\'"|,.{}+=/&])[\'"]=>["\']([\w\[\];\'"|,.{}+=/&])[\'"]~msi', $match[0],
                $arrayMatches);

            foreach ($arrayMatches[1] as $index => $arrayMatch) {
                $array2[$arrayMatches[1][$index]] = $arrayMatches[2][$index];
            }

            $newStr = "";
            foreach ($array1 as $xx) {
                foreach ($array2 as $main => $val) {
                    if ($xx == (string)$val) {
                        $newStr .= $main;
                        break;
                    }
                }
            }

            $result = gzinflate(base64_decode($newStr));
        }

        return $result;
    }

    private function deobfuscateEvalConcatedVars($str, $matches)
    {
        $iter = [2 => $matches[2], 4 => $matches[4], 6 => $matches[6], 12 => $matches[12]];
        foreach ($iter as $index => $item) {
            $matches[$index] = preg_replace_callback('~chr\((\d+)\)~msi', static function ($match) use (&$matches) {
                return '\'' . chr($match[1]) . '\'';
            }, $matches[$index]);

            $matches[$index] = Helpers::concatStr($matches[$index]);
            $matches[$index] = base64_decode($matches[$index]);
        }

        $result = str_replace([$matches[1], $matches[8], $matches[10]], [$matches[2], 0, 0], $matches[7]);

        if (Helpers::isSafeFunc($matches[4])) {
            $code = @$matches[4]($matches[6]);
            $code = gzinflate(str_rot13($code));
        } else {
            $code = 'gzinflate(str_rot13(\'' . $matches[4] . '\')));';
        }

        $result .= $matches[12] . $code;

        return $result;
    }

    private function deobfuscateEchoEscapedStr($str, $matches)
    {
        $i = 1;
        $result = $matches[1];
        $result = str_replace('\\\\\\', '\\\\', $result);

        while ($i < 3) {
            if (!preg_match('~(\\\\x[0-9a-f]{2,3})~msi', $result)) {
                break;
            }

            $result = preg_replace_callback('~(\\\\x[0-9a-f]{2,3})~msi', static function ($m) {
                return stripcslashes($m[1]);
            }, $result);

            $i++;
        }

        $result = stripslashes($result);
        $vars = Helpers::collectVars($result);

        $result = preg_replace_callback('~(?<!{)\${[\'"]GLOBALS[\'"]}\[[\'"](\w+)[\'"]\]=[\'"](\w+)[\'"];~msi',
            function ($m) use (&$vars) {
                $vars['$' . $m[1]] = $m[2];

                return '';
            }, $result);

        $result = Helpers::replaceVarsFromArray($vars, $result);

        foreach ($vars as $name => $val) {
            $result = str_replace("$val=\"$val\";", '', $result);
        }

        return $result;
    }

    public function deobfuscateFilePutDecodedContents($str, $matches)
    {
        $res = $str;
        $content = base64_decode($matches[2]);
        $res = str_replace($matches[1], $content, $res);

        $res = preg_replace_callback('~chr\((\d+)\)~msi', static function ($match) use (&$matches) {
            return '\'' . chr($match[1]) . '\'';
        }, $res);

        $res    = Helpers::concatStringsInContent($res);
        $res    = Helpers::replaceBase64Decode($res, '\'');
        $vars   = Helpers::collectVars($res);
        $res    = Helpers::replaceVarsFromArray($vars, $res);
        $res    = Helpers::removeDuplicatedStrVars($res);
        
        return $res;
    }

    public function deobfuscatePregReplaceStr($str, $matches)
    {
        return stripcslashes($matches[1]);
    }

    public function deobfuscateEvalImplodedArrStr($str, $matches)
    {
        $split = str_split(stripcslashes($matches[2]));
        $map = array_map(static function($str) {
            return chr(ord($str) - 1);
        }, $split);
        return implode($map);
    }

    public function deobfuscatePregReplaceCodeContent($str, $matches)
    {
        $func = stripcslashes($matches[5]);

        $res = $matches[2];

        if (preg_match('~eval\(preg_replace\([\'"]/([^/])/[\'"],\s?[\'"](.*?)[\'"],\s?(\$\w+)\)\);~msi', $func,
            $match)) {
            if ($match[3] === $matches[1]) {
                $res = str_replace($match[1], stripcslashes($match[2]), $res);
            }
        }

        $vars = [];

        $res = preg_replace_callback('~(\$\w+)\s?=\s?([\'"])(.*?)\2;~msi', static function ($m) use (&$vars) {
            $value = $m[3];
            if ($m[2] === '"') {
                $value = stripcslashes($value);
            }

            $vars[$m[1]] = $value;

            return sprintf('%s=\'%s\';', $m[1], $value);
        }, $res);

        $arrayVar = [];
        $arrayVarName = '';

        if (preg_match('~(\$\w+)\s?=\s?array\((?:\'[^\']+\',?)+\);~msi', $res, $m)) {
            $arrayVarName = $m[1];

            preg_match_all('~\'([^\']+)\',?~msi', $m[0], $arrMatch, PREG_PATTERN_ORDER);
            if (isset($arrMatch[1])) {
                foreach ($arrMatch[1] as $arr) {
                    $arrayVar[] = $arr;
                }
            }
        }

        if (preg_match('~(\$\w+)\((\$\w+),\s?(\$\w+)\s?\.\s?\'\(((?:["\']\w+[\'"],?)+)\)[\'"]\s?\.\s?(\$\w+),\s?null\);~msi',
            $res, $match)) {
            $arrayVar2 = [];
            preg_match_all('~[\'"](\w+)[\'"],?~msi', $match[4], $arrMatch2, PREG_PATTERN_ORDER);
            if (isset($arrMatch2[1])) {
                foreach ($arrMatch2[1] as $arr) {
                    $arrayVar2[] = $arr;
                }
            }

            if (isset($vars[$match[5]])
                && (preg_match('~,\s?(\$\w+),\s?(\$\w+)\)\);~msi', $vars[$match[5]], $m)
                    && $m[1] === $arrayVarName
                    && isset($vars[$m[2]])
                )) {
                $res = str_replace($arrayVar2, $arrayVar, $vars[$m[2]]);
            }
        }

        return $res;
    }

    public function deobfuscateSistemitComEnc($str, $matches)
    {
        $res = gzinflate(base64_decode($matches[2]));
        preg_match_all('~\$\w+\s*=\s*\[((\'[^\']+\',?)+)~msi', $matches[4], $replace, PREG_SET_ORDER);
        $find = explode("','", substr($replace[0][1], 1, -1));
        $replace = explode("','", substr($replace[1][1], 1, -1));
        $res = str_replace($find, $replace, $res);
        return $res;
    }

    public function deobfuscateConcatVarsReplaceEval($str, $matches)
    {
        $res = Helpers::concatVariableValues($matches[1]);
        $res = str_replace($matches[5], '', $res);
        $res = base64_decode($res);
        return $res;
    }

    public function deobfuscateEvalVarFunc2($str, $matches)
    {
        return $this->unwrapFuncs($matches[6]);
    }

    public function deobfuscateEvalArrays($str, $matches)
    {
        $res = str_replace('\'\'', '@@empty@@', $str);
        $vars = explode('", "', substr($matches[10], 1, -1));

        $res = preg_replace_callback('~(\$\w+)\[(\d+)\]\s*\.?\s*~msi', static function($m) use ($vars, $matches) {
            if ($m[1] !== $matches[9]) {
                return $m[0];
            }
            return "'" . $vars[(int)$m[2]] . "'";
        }, $res);
        $res = str_replace(['\'\'', '@@empty@@', $matches[8]], ['', '\'\'', ''], $res);
        preg_match_all('~(\$\w+)\s*=\s*\'([^\']+)\';~msi', $res, $m, PREG_SET_ORDER);
        $vars = [];
        foreach ($m as $var) {
            $vars[$var[1]] = '\'' . $var[2] . '\'';
            $res = str_replace($var[0], '', $res);
        }
        $res = Helpers::replaceVarsFromArray($vars, $res);
        return $res;
    }

    public function deobfuscatePregReplaceVar($str, $matches)
    {
        $result = stripcslashes($matches[2]);

        $regex = stripcslashes($matches[1]);
        if ($regex === '.*') {
            return $result;
        }

        $result = preg_replace_callback($regex, static function ($m) {
            return '';
        }, $result);

        return $result;
    }

    public function deobfuscateEvalBinHexVar($str, $matches)
    {
        $func1 = stripcslashes($matches[2]);
        $func2 = stripcslashes($matches[4]);
        $result = '';

        if (Helpers::isSafeFunc($func2) && Helpers::isSafeFunc($func1)) {
            $result = '?>' . @$func1(@$func2($matches[6]));
        } else {
            $result = sprintf("'?>'.%s(%s('%s');", $func1, $func2, $matches[6]);
        }

        return $result;
    }

    public function deobfuscateEvalFuncTwoArgs($str, $matches)
    {
        $arg1 = base64_decode($matches[5]);
        $arg2 = $matches[6];

        $result = "";
        for ($o = 0, $oMax = strlen($arg1); $o < $oMax;) {
            for ($u = 0, $uMax = strlen($arg2); $u < $uMax; $u++, $o++) {
                $result .= $arg1[$o] ^ $arg2[$u];
            }
        }

        return $result;
    }

    public function deobfuscateEvalVarReplace($str, $matches)
    {
        $res = $matches[3];
        $replaces = explode(';', $matches[4]);
        foreach ($replaces as $replace) {
            if (preg_match('~(\$\w+)=str_replace\(\'([^\']+)\',\s*\'(\w)\',\s*\1\);~msi', $replace, $m)) {
                $res = str_replace($m[2], $m[3], $res);
            }
        }
        $res = base64_decode($res);
        return $res;
    }

    public function deobfuscateEvalPregReplaceFuncs($str, $matches)
    {
        $func1Str = preg_replace('/' . $matches[3] . '/', "", $matches[2]);
        $func2Str = preg_replace('/' . $matches[6] . '/', "", $matches[5]);

        $strToDecode = '';
        preg_match_all('~[\'"]([^\'"]+)[\'"],?~msi', $matches[8], $strMatches, PREG_SET_ORDER);
        foreach ($strMatches as $index => $strMatch) {
            if ($index > 0) {
                $strToDecode .= PHP_EOL;
            }
            $strToDecode .= $strMatch[1];
        }

        $result = @$func2Str($strToDecode);

        if (preg_match('~eval\(\$\w+\);~msi', $func1Str) && Helpers::isSafeFunc($func2Str)) {
            $result = @$func2Str($strToDecode);
            $result = stripcslashes($result);
            $vars = Helpers::collectVars($result);
            if (preg_match('~\$\w+=\$\w+\([\'"]\([\'"],__FILE.*?(?:\$\w+\(){3}[\'"][^\'"]+[\'"]\)\)\)\);~msi', $result,
                $m)) {
                $result = $m[0];
            }
            $result = Helpers::replaceVarsFromArray($vars, $result);
            $result = preg_replace_callback('~gzinflate\(base64_decode\(str_rot13\(["\']([^\'"]+)[\'"]\)\)\)~msi',
                function ($m) {
                    return gzinflate(base64_decode(str_rot13($m[1])));
                }, $result);
        }

        return $result;
    }

    public function deobfuscateEvalVarSlashed($str, $matches)
    {
        $vars = Helpers::collectVars($matches[1]);
        $result = Helpers::replaceVarsFromArray($vars, $matches[2]);
        $result = $this->unwrapFuncs($result);

        return $result;
    }

    public function deobfuscateUrlMd5Passwd($str, $matches)
    {
        while(preg_match('~((?:(\$\w+)=\'[^;]+\';)+)~mis', $str, $matches2)) {
            $vars = Helpers::collectVars($matches2[1], "'");
            $str = Helpers::replaceVarsFromArray($vars, $str, true);
            $str = preg_replace_callback('~str_rot13\(urldecode\(\'([%\da-f]+)\'\)\)~mis', static function($m) {
                return "'" . str_rot13(urldecode($m[1])) . "'";
            }, $str);
            $str = str_replace($matches2[0], '', $str);
        }
        return $str;
    }

    public function deobfuscateBlackScorpShell($str, $matches)
    {
        $vars = Helpers::collectVars($matches[2], "'");
        $vars2 = Helpers::collectVars($matches[3], "'");
        array_walk($vars2, static function(&$var) {
            $var = "'$var'";
        });
        $str = gzinflate(base64_decode($vars2[$matches[5]]));
        $str = Helpers::replaceVarsFromArray($vars, $str, true);
        $str = Helpers::replaceVarsFromArray($vars2, $str);
        $str = str_ireplace('assert', 'eval', $str);
        return $str;
    }

    public function deobfuscateManyDictionaryVars($str, $matches)
    {
        $vars = Helpers::collectVars($matches[1], "'");
        $result = $matches[2];

        foreach ($vars as $dictName => $dictVal) {
            $result = preg_replace_callback(
                '~(\$\w+)[\[{][\'"]?(\d+)[\'"]?[\]}]~msi',
                static function ($m) use ($dictVal, $dictName) {
                    if ($m[1] !== $dictName) {
                        return $m[0];
                    }
                    return "'" . $dictVal[(int)$m[2]] . "'";
                },
                $result
            );
        }
        $result = Helpers::replaceVarsFromArray($vars, $result, true, true);
        $result = preg_replace_callback('~(\.?)\s?[\'"]([\w=\+/()\$,;:"\s?\[\]]+)[\'"]\s?~msi', static function ($m) {
            return $m[2];
        }, $result);

        return $result;
    }

    public function deobfuscateEvalBuffer($str, $matches)
    {
        $result = $matches[4];

        preg_match_all('~"([^"]+)"~msi', $matches[2], $arrMatches, PREG_SET_ORDER);

        $array = [];
        foreach ($arrMatches as $arrMatch) {
            $array[] = stripcslashes($arrMatch[1]);
        }

        $result = str_replace($array, '', $result);

        $result = gzinflate(base64_decode($result));

        return $result;
    }

    public function deobfuscateEvalArrayWalkFunc($str, $matches)
    {
        $result = stripcslashes($matches[1]) . '?>' . PHP_EOL;
        $encodedStr = '';

        preg_match_all('~(?:[\'"]([^\'"]{1,500})[\'"])~msi', $matches[2], $arrayMatches, PREG_SET_ORDER);

        foreach ($arrayMatches as $arrayMatch) {
            $encodedStr .= stripcslashes($arrayMatch[1]);
        }

        $result .= base64_decode(str_rot13($encodedStr));

        return $result;
    }

    public function deobfuscateEvalDictionaryVars($str, $matches)
    {
        $result = $str;
        $vars = Helpers::collectVars($matches[1]);
        $vars[$matches[2]] = $matches[3];

        $vars = Helpers::getVarsFromDictionaryDynamically($vars, $matches[1]);

        $func = $vars[$matches[5]] ?? null;
        if ($func && Helpers::isSafeFunc($func)) {
            $result = @$func($matches[6]);
        }

        $result = Helpers::replaceVarsFromArray($vars, $result);

        return $result;
    }

    public function deobfuscateEvalSubstrVal($str, $matches)
    {
        $result = strtr(
            substr($matches[2], (int)$matches[3] * (int)$matches[4]),
            substr($matches[2], (int)$matches[5], (int)$matches[6]),
            substr($matches[2], (int)$matches[7], (int)$matches[8])
        );

        return '?> ' . base64_decode($result);
    }

    public function deobfuscateEvalFuncXored($str, $matches)
    {
        $vars = Helpers::collectFuncVars($str);
        $result = Helpers::replaceVarsFromArray($vars, $str);

        if (preg_match('~\$\w+\s?=\s?gzinflate\(base64_decode\(.*?strlen.*?chr\(\(ord.*?\^~msi', $result)) {
            $encodedStr = gzinflate(base64_decode($matches[1]));
            $len = strlen($encodedStr);
            $result = '';
            for ($i = 0; $i < $len; $i++) {
                $result .= chr((ord($encodedStr[$i]) ^ (int)$matches[3]));
            }
        }

        return $result;
    }

    public function deobfuscateEvalFileContentOffset($str, $matches)
    {
        $result = $matches[1];

        $encodedStr = substr($str, (int)$matches[3]);
        $result = str_replace($matches[2], "'$encodedStr'", $result);

        return '<?php ' . $this->unwrapFuncs($result);
    }

    public function deobfuscateEvalFuncExplodedContent($str, $matches)
    {
        $decodedStr = trim(trim($matches[7], ";"), '"');
        $strMD5 = md5($matches[1]);

        $result = base64_decode(
            str_replace($strMD5, '', strtr($decodedStr . $matches[4], $matches[5], $matches[6]))
        );

        return $result;
    }

    public function deobfuscateEvalEncryptedVars($str, $matches)
    {

        $vars_str = preg_replace_callback('~(\d{1,10}\.\d{1,10})\s?\*\s?(\d{1,10})~msi', static function ($m) {
            $res = (double)($m[1]) * (int)$m[2];

            return "'$res'";
        }, $matches[1]);

        $vars_str = str_replace('"', "'", Helpers::normalize($vars_str));

        $vars = Helpers::collectVars($vars_str, "'");
        $vars_str = Helpers::replaceVarsFromArray($vars, $vars_str);
        $vars = Helpers::collectFuncVars($vars_str, $vars);
        $vars_str = Helpers::removeDuplicatedStrVars($vars_str);

        if ($a = preg_match('~(\$\w{1,50})=openssl_decrypt\(base64_decode\([\'"]([^\'"]+)[\'"]\),\'AES-256-CBC\',substr\(hash\(\'SHA256\',[\'"]([^\'"]+)[\'"],true\),0,32\),OPENSSL_RAW_DATA,([^\)]{0,50})\);~msi',
            $vars_str, $varMatch)) {
            $vars[$varMatch[1]] = openssl_decrypt(base64_decode($varMatch[2]), 'AES-256-CBC',
                substr(hash('SHA256', $varMatch[3], true), 0, 32), OPENSSL_RAW_DATA, $varMatch[4]);
        }

        $result = Helpers::replaceVarsFromArray($vars, str_replace(' ', '', $matches[7]));
        $result = str_replace($matches[4], str_replace($matches[5], '', "'$matches[6]'"), $result);

        return $this->unwrapFuncs($result);
    }

    public function deobfuscateEvalLoveHateFuncs($str, $matches)
    {
        $result = $matches[7];
        $result .= gzinflate(base64_decode($matches[4]));

        /* hate function */
        $finalPHPCode = null;
        $problems = explode(".", gzinflate(base64_decode($matches[2])));
        for ($mistake = 0, $mistakeMax = count($problems); $mistake < $mistakeMax; $mistake += strlen($matches[6])) {
            for ($hug = 0, $hugMax = strlen($matches[6]); $hug < $hugMax; $hug++) {
                $past = (int)$problems[$mistake + $hug];
                $present = (int)ord(substr($matches[6], $hug, 1));
                $sweet = $past - $present;
                $finalPHPCode .= chr($sweet);
            }
        }

        $finalPHPCode = gzinflate(base64_decode($finalPHPCode));

        $result .= PHP_EOL . $finalPHPCode;

        return $result;
    }

    public function deobfuscateXoredKey($str, $matches)
    {
        $encrypted = base64_decode($matches[4]);
        $key = $matches[7];
        $res = Helpers::xorWithKey($encrypted, $key);
        $res = base64_decode($res);
        return $res;
    }

    public function deobfuscateEvalGzB64($str, $matches)
    {
        $res = '';
        preg_match_all('~eval\(\$\w+\(\$\w+\(\'([^\']+)\'\)+;~msi', $str, $m, PREG_SET_ORDER);
        foreach ($m as $match) {
            $res .= gzuncompress(base64_decode($match[1])) . "\n";
        }
        return $res;
    }

    public function deobfuscateEvalArrayB64($str, $matches)
    {
        if (preg_match('~function\s*(_\d+)\((\$\w+)\)\s*{(\$\w+)=Array\(\'([^)]+)\'\);return\s*base64_decode\(\3\[\2\]\);~msi', $str, $found)) {
            $strlist = explode("','", $found[4]);
            $res = preg_replace_callback(
                '|(\w+)\((\d+)\)|smi',
                function ($m) use ($strlist, $found) {
                    if ($m[1] !== $found[1]) {
                        return $m[0];
                    }
                    return "'" . addcslashes(base64_decode($strlist[$m[2]]), '\\\'') . "'";
                },
                $str
            );
            $res = str_replace($matches[1], '', $res);
            return $res;
        }
    }

    public function deobfuscateManyBase64DecodeContent($str)
    {
        return Helpers::replaceBase64Decode($str, "'");
    }

    public function deobfuscateEvalEscapedCharsContent($str, $matches)
    {
        $res = $matches[2] . "'" . stripcslashes($matches[1]) . "')";

        return $this->unwrapFuncs($res);
    }

    public function deobfuscateEvalFuncBinary($str, $matches)
    {
        $binaryVals = hex2bin($matches[2]);
        $res = Helpers::decodeEvalFuncBinary($binaryVals);

        return $res;
    }

    public function deobfuscateEvalPackFuncs($str, $matches)
    {
        return stripcslashes($matches[3]) . $matches[4];
    }

    public function deobfuscateParseStrFunc($str, $matches)
    {
        parse_str(Helpers::concatStr($matches[1]), $vars);

        $res = Helpers::replaceVarsByArrayName($matches[2], $vars, $matches[4]);
        $res = $this->unwrapFuncs($res . $matches[5] . ')');

        return $res;
    }

    public function deobfuscateEvalGzinflate($str, $match)
    {
        $res = stripcslashes($match[2]);
        $res = str_replace('"."', '', $res);
        return 'eval(' . $res . ');';
    }

    public function deobfuscateFuncVars($str, $matches)
    {
        $key = $matches[3];
        $res = $matches[7];
        $vars = [$matches[4] => preg_replace($matches[5], "", $matches[6])];

        preg_match_all('~(\$\w{1,50})\s?=\s?(?:(\$\w{1,50})\(\)\s?\.\s?)?\w{1,50}\(\\' . $matches[4] .'\(("[^"]+")\)\);~msi',
            $str, $match, PREG_SET_ORDER);
        foreach ($match as $matchVar) {
            $value = Helpers::decodeFuncVars($key,$this->unwrapFuncs($vars[$matches[4]] . '(' . $matchVar[3] . ')'));
            if ($matchVar[2] !== '') {
                $func = $vars[$matchVar[2]] ?? $matchVar[2];
                $value = $func . '() . \'' . $value . '\'';
            }
            $vars[$matchVar[1]] = $value;
        }

        foreach ($vars as $name => $val) {
            $res = str_replace($name, $val, $res);
        }
        return $res;
    }

    public function deobfuscateDictVars($str, $match)
    {
        $res = Helpers::replaceVarsFromDictionary($match[1], $match[2], $match[3]);
        $res = gzinflate(base64_decode(substr($res, 2, -3)));
        return $res;
    }

    public function deobfuscateGotoStrRot13Vars($str, $matches)
    {
        if (isset($matches[2])) {
            $vars = Helpers::collectVars($str);

            preg_match_all('~(\$\w{1,50})\s?=\s?str_rot13\(\1\);~msi', $str, $match, PREG_SET_ORDER);
            foreach ($match as $m) {
                if (isset($vars[$m[1]])) {
                    $vars[$m[1]] = str_rot13($vars[$m[1]]);
                }
            }

            preg_match_all('~(\$\w{1,50})~msi', $matches[2], $match, PREG_SET_ORDER);
            $strToDecode = '';
            foreach ($match as $var) {
                if (isset($vars[$var[1]])) {
                    $strToDecode .= $vars[$var[1]];
                }
            }

            return base64_decode($strToDecode);
        }

        return $str;
    }

    public function deobfuscateDecodedDoubleStrSet($str, $matches)
    {
        $strToDecode1 = '';
        $strToDecode2 = '';

        preg_match_all('~"([^"]+)"~msi', $matches[1], $match, PREG_SET_ORDER);
        foreach ($match as $m) {
            $strToDecode2 .= $m[1];
        }
        preg_match_all('~\'([^\']+)\'~msi', $matches[2], $match, PREG_SET_ORDER);
        foreach ($match as $m) {
            $strToDecode1 .= $m[1];
        }

        return base64_decode($strToDecode1) . PHP_EOL . base64_decode($strToDecode2);
    }

    public function deobfuscateCreateFuncStrrev($str, $matches)
    {
        $res = preg_replace_callback('~strrev\("([^"]+)"\)~msi', static function ($m) {
            return '"' . strrev($m[1]) . '"';
        }, $matches[3]);

        $res = Helpers::concatStringsInContent($res);
        $vars = Helpers::collectVars($res);
        $res = Helpers::replaceVarsFromArray($vars, $res);
        $res = Helpers::removeDuplicatedStrVars($res);

        if (preg_match('~\$\w+=base64_decode\([\'"][^\'"]+[\'"]\);\$\w+=create_function\(\'\$\w+\',\$\w+\);\$\w+\(\$\w+\);~msi',
            $res)) {
            $funcs = base64_decode($matches[5]);
            $res = str_replace($matches[1], '\'' . $matches[2] . '\'', $funcs);
        }

        return $res;
    }

    public function deobfuscateStrrevBase64($str, $matches)
    {
        return strrev($matches[2]);
    }

    public function deobfuscateCustomDecode($str, $matches)
    {
        return str_rot13($matches[2] . $matches[6]);
    }

    public function deobfuscateExpDoorCode($str, $matches)
    {
        $str = str_replace(
                [
                    $matches[1],
                    $matches[3]
                ],
                [
                    str_replace(['"."', "'.'"], '', $matches[1]),
                    "'" . addcslashes(base64_decode($matches[4]), "'") . "'"
                ],
                $str
        );
        return $str;
    }

    public function deobfuscateAgustus1945($str, $matches)
    {
        return str_replace($matches[1], $matches[4] . '"' . $matches[7] . '"' . $matches[5], $str);
    }

    public function deobfuscateIncludeB64($str, $matches)
    {
        return str_replace($matches[1], "'" . base64_decode($matches[2]) . "'", $str);
    }

    public function deobfuscateDecodeFileContent($str, $matches)
    {
        return gzuncompress(base64_decode($matches[3]));
    }

    public function deobfuscateBase64decodedFuncContents($str, $matches)
    {
        $vars   = Helpers::collectVars($matches[2]);
        $res    = str_replace($matches[2], '', $str);
        $res    = Helpers::replaceVarsFromArray($vars, $res);

        return Helpers::replaceBase64Decode($res, '\'');
    }

    public function deobfuscateEvalVarWithComment($str, $matches)
    {
        $res = str_replace($matches[3], '', $matches[2]);
        $vars = Helpers::collectVars($matches[1]);
        $res = Helpers::replaceVarsFromArray($vars, $res);

        return '?> ' . $this->unwrapFuncs($res);
    }

    public function deobfuscateEvalPackPreg($str, $matches)
    {
        $varsStr = Helpers::replaceVarsFromDictionary($matches[1], $matches[2], $matches[3]);
        $vars = Helpers::collectVars($varsStr, "'");
        if (isset($vars[$matches[6]]) && Helpers::isSafeFunc($vars[$matches[6]])) {
            $strToDecode = @$vars[$matches[6]]($matches[2]);
            $strToDecode = preg_replace('~[' . $matches[5] . ']~i', '', $strToDecode);
            $strToDecode = pack('H*', $strToDecode);

            return $strToDecode;
        }

        return $str;
    }

    function deobfuscateNib2xeh($str, $matches)
    {
        $matches[3] = str_replace("'", '', $matches[3]);
        $matches[5] = str_replace("'", '', $matches[5]);
        $matches[7] = str_replace("'", '', $matches[7]);
        $replace_from = explode(',', $matches[5]);
        $replace_from[] = ',';
        $replace_to = explode(',', $matches[7]);
        $replace_to[] = '';
        $hex = str_replace($replace_from, $replace_to, $matches[3]);
        return hex2bin($hex);
    }

    function deobfuscateFun256($str, $matches)
    {
        $need_encode_twice  = !isset($matches[4]);
        $replace            = $need_encode_twice ? $str : $matches[1];
        $code               = $need_encode_twice ? $matches[3] : $matches[4];

        $chr = '';
        for ($i = 0; $i < 120; $i++) {
            $chr .= chr($i);
        }
        $encoded = gzinflate(gzinflate(base64_decode($code)));
        if ($need_encode_twice) {
            $encoded = gzinflate(gzinflate(base64_decode($encoded)));
        }
        $encoded_len = strlen ($encoded);
        $hash = sha1(hash('sha256', md5($chr)));
        $hash_len = strlen($hash);
        $result = '';
        for ($i = 0; $i < $encoded_len; $i += 2) {
            $char = hexdec(base_convert(strrev(substr($encoded, $i, 2)), 36, 16));
            if ($j === $hash_len) {
                $j = 0;
            }
            $delta = ord($hash[$j]);
            $j++;
            $result .= chr ($char - $delta);
        }
        $result = str_replace($replace, $result, $str);
        return $result;
    }

    private function deobfuscateCreateFuncObf($str, $matches)
    {
        $str = Helpers::replaceBase64Decode($matches[7], '\'');
        $str = preg_replace_callback('~str_rot13\(\'([^\']+)\'\)~msi', static function($m) {
            return '\'' . str_rot13($m[1]) . '\'';
        }, $str);
        $str = preg_replace_callback('~chr\(([^\)]+)\)~msi', static function($m) {
            return '\'' . Helpers::calc($m[0]) . '\'';
        }, $str);
        $str = str_replace('\'.\'', '', $str);
        return base64_decode(substr($str,1, -1));
    }

    private function deobfuscateEvalFileContentBySize($str, $matches)
    {
        $res = $str;
        $mainContent = str_replace(["\r", "\n"], '', $str);
        $mainContentLen = strlen($mainContent);
        $main_key = $matches[2] . $mainContentLen;

        $str_to_code = base64_decode($matches[3]);
        $code = Helpers::decodeEvalFileContentBySize($str_to_code, $main_key);

        if (preg_match('~\$\w+=strpos\(\$\w+,((?:chr\(\d+\)\.?)+)\);\$\w+=substr\(\$\w+,0,\$\w+\);eval\(\w+\(\w+\("([^"]+)"\),\$\w+\)\);function\s\w+\(\$\w+\){.*?strpos\(\$\w+,\1\);.*?substr\(\$\w+,\$\w+\+(\d)\)\);~msi',
            $code, $match)) {
            preg_match_all('~chr\((\d+\))~msi', $match[1], $chrMatches, PREG_SET_ORDER);

            $find = '';
            foreach ($chrMatches as $chrMatch) {
                $find .= chr((int)$chrMatch[1]);
            }
            $pos = strpos($mainContent, $find);
            $content = substr($mainContent, 0, $pos);

            $code = Helpers::decodeEvalFileContentBySize(base64_decode($match[2]), $main_key);
            if (preg_match('~\$\w+=md5\(\$\w+\)\.\$\w+;~msi', $code)) {
                $key = md5($content) . $mainContentLen;
                $content = base64_decode(substr($mainContent, $pos + (int)$match[3]));
                $res = Helpers::decodeEvalFileContentBySize($content, $key);
            }
        }

        return '<?php ' . $res;
    }
    
    private function deobfuscateBase64Array($str, $matches)
    {
        $var_name   = $matches[1];
        $el0        = base64_decode($matches[2]);
        $el1        = Helpers::replaceBase64Decode($matches[3], '\'');
        $code       = $matches[4];
        
        $code = str_replace($var_name . '[0]', '\'' . $el0 . '\'', $code);
        $code = str_replace($var_name . '[1]', $el1, $code);
        $code = Helpers::replaceBase64Decode($code, '\'');
        
        return $code;
    }

    private function deobfuscateSimpleVarsAndEval($str, $matches)
    {
        $vars_content = $matches[1];
        $eval_content = $matches[2];
        
        $vars = Helpers::collectVars($vars_content);
        $code = Helpers::replaceVarsFromArray($vars, $eval_content);
        
        return $this->unwrapFuncs($code);
    }
    
    private function deobfuscateReplaceFuncWithBase64DecodeArray($str, $matches)
    {
        $nel_function_content   = $matches[3];
        $other_content          = $matches[1] . $matches[4];
        $array_elements         = str_replace("'.'", '', $nel_function_content);
        
        $elements = array_map('base64_decode', explode(',', $array_elements));
        
        $result = preg_replace_callback('~nel\s*\(\s*(\d+)\s*\)~mis', function($match) use ($elements) { 
                $index = $match[1];
                $value = isset($elements[$index]) ? $elements[$index] : null;
                if (!is_null($value)) {
                    if ($value === "\r") {
                        return '"\\r"';
                    }
                    return "'" . addcslashes($value, "'\\") . "'";
                }
                return $match[0];
            }, $other_content
        );        
        
        return Helpers::replaceMinMaxRound($result);
    }

    private function deobfuscateCreateFuncVars($str, $matches)
    {
        $res = Helpers::concatStringsInContent($matches[1]);
        $vars = Helpers::collectVars($res);
        $res = Helpers::replaceVarsFromArray($vars, $matches[2]);

        return $this->unwrapFuncs($res);
    }

    private function deobfuscateJsonDecodedVar($str, $matches)
    {
        $decodedStr = Helpers::replaceBase64Decode($matches[1], 'QUOTE');
        $decodedStr = str_replace("'", "\'", $decodedStr);
        $decodedStr = str_replace("QUOTE", "'", $decodedStr);

        $res = str_replace($matches[1], $decodedStr, $str);

        return $res;
    }

    private function deobfuscateFilePutPureEncodedContents($str, $matches)
    {
        return $this->deobfuscateJsonDecodedVar($str, $matches);
    }

    private function deobfuscateEvalFuncReverse($str, $matches)
    {
        $decodedContent = $matches[5];
        $decodedContent = preg_replace_callback('~eval\((\w+\(\'([^\']+)\'\))\);~msi', function ($m) {
            $strLen = strlen($m[2]);
            $res = '';

            for ($i = 0; $i <= $strLen - 1; $i++) {
                $res .= $m[2][$strLen - $i - 1];
            }

            return str_replace($m[1], $res, $m[0]);
        }, $decodedContent);

        return str_replace($matches[5], $decodedContent, $str);
    }

    private function deobfuscateBase64decodeFuncs($str, $matches)
    {
        $res = $str;
        $res = preg_replace_callback('~\w+\("([^"]+)"\)~msi', function ($m) {
            return "'" . base64_decode($m[1]) . "'";
        }, $res);

        return $res;
    }

    private function deobfuscateEvalCreateFuncWithDictionaryVar($str, $matches)
    {
        $res = Helpers::replaceVarsFromDictionary($matches[1], $matches[2], $str);
        $vars = Helpers::collectVars($res, "'");
        $func = stripcslashes($matches[5]);

        return sprintf('eval(%s(%s(\'%s\'))));', $vars[$matches[3]] ?? $matches[3], $func, $matches[6]);
    }

    private function deobfuscateEvalCreateFuncWithVars($str, $matches)
    {
        $res = Helpers::concatStringsInContent($str);
        $vars = Helpers::collectVars($res, false);
        $res = Helpers::replaceVarsFromArray($vars, $matches[4]);
        $res = Helpers::concatStringsInContent($res);
        $res = preg_replace_callback('~\w+\(((?:[\'"][^\'"]*[\'"],?)+)\)~msi', function ($m) {
            return str_replace(',', '.', $m[1]);
        }, $res);
        $res = Helpers::concatStringsInContent($res);

        return trim($res, "'");
    }

    private function deobfuscateExplodeSubstrGzinflate($str, $matches)
    {
        $obfuscated = explode($matches[3], gzinflate(substr(stripcslashes($matches[4]), hexdec($matches[5]), (int)$matches[6])));
        $str = str_replace($matches[1], '', $str);
        $str = preg_replace_callback('~\$(?:_GET|GLOBALS)[\{\[][^}]+[\}\]][\{\[]([0-9a-fx]+)[\}\]](\()?~msi', function($m) use ($obfuscated) {
            $index = hexdec($m[1]);
            $func = (isset($m[2]) && $m[2] !== '');
            if ($func) {
                return $obfuscated[$index] . '(';
            } else {
                return '\'' . $obfuscated[$index] . '\'';
            }
        }, $str);
        return $str;
    }

    private function deobfuscateBase64Vars($str, $matches)
    {
        $vars = Helpers::collectVars($matches[2], '\'');
        $code = Helpers::replaceVarsFromArray($vars, $matches[5], false, true);
        $code = Helpers::collectStr($code, '\'');
        $code = base64_decode($code);
        $code = str_replace($matches[1], $code, $str);
        return $code;
    }

    private function deobfuscateChr0b($str, $matches)
    {
        $str = preg_replace_callback('~chr\(((0b|0x)?[0-9a-f]+)\)~msi', function($m) {
            if (isset($m[2]) && $m[2] === '0b') {
                return '\'' . chr(bindec($m[1])) . '\'';
            }
            if (isset($m[2]) && $m[2] === '0x') {
                return '\'' . chr(hexdec($m[1])) . '\'';
            }
            return '\'' . chr($m[1]) . '\'';
        }, $str);

        $str = preg_replace_callback('~\(\'(.)\'\^\'(.)\'\)~msi', function($m) {
            return '\'' . ($m[1] ^ $m[2]) . '\'';
        }, $str);

        $str = str_replace('\'.\'', '', $str);
        $str = preg_replace('~\$\{\'([^\']+)\'\}~msi', '\$\1', $str);
        $str = preg_replace_callback('~(\$\w+)\s*=\s*\'str_rot13\';\s*\1\s*=\s*\1\s*\(\'([^\']+)\'\);~msi', function ($m) {
            return $m[1] . ' = ' . '\'' . str_rot13($m[2]) . '\';';
        }, $str);
        return $str;
    }

    private function deobfuscateCreateFuncPlugin($str, $matches)
    {
        return gzinflate(base64_decode($matches[3]));
    }

    private function deobfuscateStrreplaceEval($str, $matches)
    {
        $vars = Helpers::collectFuncVars($matches[1]);
        return Helpers::replaceVarsFromArray($vars, $matches[2]);
    }

    private function deobfuscateHackM19($str, $matches)
    {
        return gzinflate(base64_decode($matches[6]));
    }

    private function deobfuscateEv404($str, $matches)
    {
        return bzdecompress(base64_decode($matches[4]));
    }

    private function deobfuscateSetVars($str, $matches)
    {
        return str_replace($matches[1], gzinflate(base64_decode($matches[5])), $str);
    }

    private function deobfuscateCreateFuncGzB64($str, $matches)
    {
        return gzuncompress(base64_decode($matches[3]));
    }

    private function deobfuscateCreateFuncGzInflateB64($str, $matches)
    {
        return gzinflate(base64_decode($matches[3]));
    }

    private function deobfuscateWsoShellDictVars($str, $matches)
    {
        $vars[$matches[1]] = stripcslashes($matches[2]);
        $res               = Helpers::replaceVarsFromArray($vars, $matches[3]);
        $vars              = Helpers::collectFuncVars($res, $vars, false);
        $res               = Helpers::replaceVarsFromArray($vars, $matches[5]);
        $finalCode         = $this->unwrapFuncs($res);

        $dictVar = Helpers::replaceVarsFromDictionary($matches[4], $vars[$matches[4]] ?? '', $matches[6]);
        $vars    = Helpers::collectVars($dictVar, "'", $vars);
        if (isset($vars[$matches[9]]) && $vars[$matches[9]] === 'rotencode') {
            $vars[$matches[8]] = Helpers::rotencode(base64_decode($matches[10]), -1);
            $dictVar = Helpers::replaceVarsFromDictionary($matches[8], $vars[$matches[8]] ?? '', $matches[11]);
            $dictVar = Helpers::replaceVarsFromDictionary($matches[4], $vars[$matches[4]] ?? '', $dictVar);
            $vars    = Helpers::collectVars($dictVar, "'", $vars);

            $res = $this->unwrapFuncs(Helpers::replaceVarsFromArray($vars, $matches[12]));

            $count = 10;
            while ($count > 0 && preg_match('~@?eval\(\$\w+\(\$\w+\(["\'][^\'"]+[\'"]\)\)\);~msi', $res, $match)) {
                $res = $this->unwrapFuncs(Helpers::replaceVarsFromArray($vars, $res));
                $count--;
            }

            return $res;
        }

        return $str;
    }

    private function deobfuscateFuncDictVars($str, $matches)
    {
        $vars[$matches[1]] = stripcslashes($matches[2]);

        $vars[$matches[3]] = explode($matches[4], $matches[5]);
        foreach ($vars[$matches[3]] as $i => $k) {
            $temp          = preg_split("//", $k, -1, PREG_SPLIT_NO_EMPTY);
            $vars[$matches[3]][$i] = implode("", array_reverse($temp));
        }

        $iterVar = explode($matches[7], $matches[8]);
        foreach ($iterVar as $i => $k) {
            $vars[$k] = $vars[$matches[3]][$i];
        }

        $vars[$matches[1]] = Helpers::decodefuncDictVars($vars[$matches[1]], -2);
        $dictVar = Helpers::replaceVarsFromDictionary($matches[1], $vars[$matches[1]] ?? '', $matches[15]);
        $vars    = Helpers::collectVars($dictVar, "'", $vars);

        $dictVar = Helpers::getVarsFromDictionaryDynamically($vars, $matches[20]);
        $vars    = Helpers::collectVars($dictVar, "'", $vars);

        $res = Helpers::decodefuncDictVars($matches[23], 1);
        if (isset($vars[$matches[22]]) && Helpers::isSafeFunc($vars[$matches[22]])) {
            $res = @$vars[$matches[22]]($res);
            $res = Helpers::replaceVarsFromArray($vars, $res);
        }

        if (preg_match('~\$\w+="([^"]+)";@eval\(\'\?>\'\.gzuncompress\(base64_decode\(strtr\(substr\(\$\w+,(\d+[+\-*/]\d+)\),substr\(\$\w+,(\d+),(\d+)\),\s?substr\(\$\w+,(\d+),(\d+)\)\)\)\)\);~msi',
                       $res, $match)) {
            $res = '?> ' . gzuncompress(base64_decode(
                strtr(
                    substr($match[1], (int)Helpers::calculateMathStr($match[2])),
                    substr($match[1], (int)$match[3], (int)$match[4]),
                    substr($match[1], (int)$match[5], (int)$match[6])))
                );
        }

        return $res;
    }

    private function deobfuscateSec7or($str, $matches)
    {
        $res = $this->unwrapFuncs($matches[3] . $matches[6] . $matches[4] . ';');
        for($i=0, $iMax = strlen($res); $i < $iMax; $i++) {
            $res[$i] = chr(ord($res[$i]) - (int)$matches[5]);
        }
        return $res;
    }

    private function deobfuscateLinesCond($str, $matches)
    {
        $vars_str = $this->unwrapFuncs($matches[1]);
        preg_match_all('~((?:\$\w+=)+)__LINE__==\s*(?:\d+[-+]?)+\s*\?\s*base64_decode\("([^"]+)"\)~msi', $vars_str, $m, PREG_SET_ORDER);
        $vars = [];
        foreach ($m as $var) {
            $func = base64_decode($var[2]);
            $tmp = explode('=', $var[1]);
            array_pop($tmp);
            $vars[] = array_combine(array_values($tmp), array_fill(0, count($tmp), $func));
        }
        $vars = array_merge(...$vars);
        $res = preg_replace_callback('~eval\(\$\w+\(\$\w+\("[^"]+"\)\)\);~msi', function ($m) use ($vars) {
            while (preg_match('~eval\(\$\w+\(\$\w+\("[^"]+"\)\)\);~msi', $m[0])) {
                $m[0] = $this->unwrapFuncs(Helpers::replaceVarsFromArray($vars, $m[0]));
            }
            return $m[0];
        }, $matches[3]);
        $tmp = [];
        $vars = Helpers::collectVars($res, '"', $tmp, true);
        $res = Helpers::replaceVarsFromArray($vars, $res, false, true);
        $vars = Helpers::collectVars($res, '\'', $tmp, true);
        $res = Helpers::replaceVarsFromArray($vars, $res, false, true);
        return $res;
    }

    private function deobfuscateClassWithArrays($str, $matches)
    {
        preg_match_all('~"[^"]+"=>"([^"]+)"~msi', $matches[2], $m);
        $data = implode('', array_reverse($m[1]));
        $data = gzuncompress(base64_decode($data));

        $numberSubstr = 14;
        if (preg_match('~,\((\d+/\d+)\)\);return~msi', $str, $calcMatch)) {
            $numberSubstr = (int)Helpers::calculateMathStr($calcMatch[1]);

        }
        for ($i = 0, $iMax = strlen($data); $i < $iMax; $i++) {
            if(isset($data[$i])) {
                $param3 = ord($data[$i]);
                $data[$i] = chr($param3 - $numberSubstr);
            }
        }
        $res = gzuncompress(base64_decode(strrev(gzinflate($data))));
        return $res;
    }

    private function deobfuscateGotoBase64Decode($str)
    {
        $res = $str;
        $hop = 5;

        while ($hop > 0 && preg_match(Helpers::REGEXP_BASE64_DECODE, $res)) {
            $res = preg_replace_callback(Helpers::REGEXP_BASE64_DECODE, function ($match) {
                $code = base64_decode(stripcslashes($match[1]));
                return '"' . Helpers::unwrapGoto($code) . '"';
            }, $res);

            $hop--;
        }

        return $res;
    }

    private function deobfuscateGotoB64Xor($str, $matches)
    {
        return Helpers::unwrapGoto($str);
    }

    private function deobfuscateAssertStrrev($str, $matches)
    {
        return str_replace($matches[1], strrev($matches[4]), $str);
    }

    private function deobfuscateB64strtr($str, $matches)
    {
        $code = $matches[4];
        $delta = (int)$matches[1];
        $code = str_split($code);
        foreach ($code as &$c) {
            $c = chr(ord($c) + $delta);
        }
        $code = implode('', $code);
        $code = strtr($code, $matches[2], $matches[3]);
        $code = base64_decode($code);
        preg_match('~(\$\w+)="([^"]+)";@eval\(\'\?>\'\.gzuncompress\((?:\$\w+\()+\$\w+,(\$\w+)\*2\),(\$\w+)\(\1,\3,\3\),\s*\4\(\1,0,\3\)+;~mis', $code, $m);
        $code = gzuncompress(base64_decode(strtr(substr($m[2],52*2),substr($m[2],52,52), substr($m[2],0,52))));
        $res = Helpers::unwrapGoto($code);
        return $res;
    }

    private function deobfuscateGzB64strReplaceDataImage($str, $matches)
    {
        $strToDecode = str_replace([$matches[2], $matches[3]], [$matches[4], $matches[5]], $matches[7]);

        $res = gzinflate(base64_decode($strToDecode));

        return $res;
    }

    private function deobfuscateSerializeFileContent($str, $matches)
    {
        return base64_decode(strrev(str_rot13($matches[2])));
    }

    private function deobfuscateGlobalVarsManyReplace($str, $matches)
    {
        $vars = Helpers::collectVars($matches[1]);

        foreach ($vars as &$var) {
            $var = base64_decode(strrev(str_rot13($var)));
        }

        $res = Helpers::replaceVarsFromArray($vars, $matches[2], true, true);

        return $res;
    }

    private function deobfuscateConcatVarsPregReplace($str, $matches)
    {
        $vars = [];

        $vars = Helpers::collectConcatedVars($str, '"', $vars);
        $res = Helpers::replaceVarsFromArray($vars, $matches[3], true, true);
        $res = $this->unwrapFuncs($res);

        return $res;
    }

    private function deobfuscateFilePutContentsB64Decoded($str, $matches)
    {
        $res = $str;
        $vars = [];

        $vars = Helpers::collectConcatedVars($res, '"', $vars, true);

        $res = Helpers::replaceVarsFromArray($vars, $res, true, true);
        $res = Helpers::replaceBase64Decode($res, '"');

        return $res;
    }

    private function deobfuscateFwriteB64DecodedStr($str, $matches)
    {
        $res = $str;
        $vars = [];

        $vars = Helpers::collectFuncVars($res, $vars, false, true);
        $res = Helpers::replaceVarsFromArray($vars, $res, true, true);

        return $res;
    }

    private function deobfuscateFilePutContentsB64Content($str, $matches)
    {
        $res = Helpers::replaceBase64Decode($str, "'");

        return $res;
    }


    private function deobfuscateChrDictCreateFunc($str, $matches)
    {
        $vars = [];

        preg_match_all('~chr\((\d+)\)~msi', $matches[3], $chrs, PREG_SET_ORDER);

        $dictVar = '';
        foreach ($chrs as $chr) {
            $dictVar .= chr((int)$chr[1]);
        }

        $res = Helpers::replaceVarsFromDictionary($matches[2], $dictVar, $matches[6]);
        $res = str_replace('\\\'', "'", $res);
        $res = Helpers::replaceBase64Decode($res, "'");
        $res = substr($res, 1);
        $res = substr($res, 0, -1);

        return $res;
    }

    private function deobfuscateStrReplaceFuncsEvalVar($str, $matches)
    {
        $func = str_replace($matches[3], '', $matches[2]);

        if ($func === 'base64_decode') {
            return base64_decode($matches[4]);
        }

        return $str;
    }

    private function deobfuscateB64SlashedStr($str, $matches)
    {
        return stripcslashes(base64_decode(stripcslashes($matches[1])));
    }

    private function deobfuscateB64ArrayStrEval($str, $matches)
    {
        return base64_decode($matches[4]);
    }

    private function deobfuscateDictVarsPregReplaceB64($str, $matches)
    {
        $res = Helpers::replaceVarsFromDictionary($matches[1], $matches[2], $str);

        if (strpos($res, 'preg_replace') &&
            strpos($res, 'eval') &&
            strpos($res, 'base64_decode')) {
            return base64_decode($matches[3]);
        }

        return $res;
    }

    private function deobfuscateEvalVarB64($str, $matches)
    {
        return gzinflate(base64_decode($matches[3]));
    }

    private function deobfuscateDecodeAChar($str, $matches)
    {
        $res = str_replace($matches[1], '', $str);
        while (strpos($res, 'eval(' . $matches[2] . '(\'') !== false) {
            $res = preg_replace_callback('~eval\(\w+\(\'([^\']+)\'\)\);~msi', function ($m) {
                return Helpers::decodeACharCustom($m[1]);
            }, $res);
        }
        $vars = Helpers::collectVars($res, '\'');
        foreach ($vars as $var => $value) {
            if (strpos($res, $matches[2] . '(' . $var . ')') !== false) {
                $res = str_replace($var . '=\'' . $value . '\';', '', $res);
                $res = str_replace($matches[2] . '(' . $var . ')', '\'' . addcslashes(Helpers::decodeACharCustom($value), '\'') . '\'', $res);
            }
        }
        return $res;
    }

    private function deobfuscateStrReplaceCreateFunc($str, $matches)
    {
        $res = $matches[7];
        $funcs = str_replace($matches[3], 'str_replace', $matches[4]);
        $vars = Helpers::collectFuncVars($funcs, $vars, false);
        $vars[$matches[1]] = '\'' . $matches[2] . '\'';
        foreach ($vars as $var => $value) {
            $res = str_replace($var, $value, $res);
        }
        return 'eval(' . $res . ');';
    }

    private function deobfuscateEvalbin2hex($str, $matches)
    {
        $res = hex2bin($matches[5]) . $matches[6];
        $res = $this->unwrapFuncs($res);
        if (preg_match('~define\(\'([^\']+)\', \'[^\']+\'\);\$GLOBALS\[\1\]\s*=\s*explode\(\'([^\']+)\',\s*gzinflate\(substr\(\'((?:[^\']*\\\\\')+[^\']+)\',([0-9a-fx]+),\s*([\-0-9a-f]+)\)~msi', $res, $m)) {
            $m[3] = stripcslashes($m[3]);
            $strings = explode($m[2], gzinflate(substr($m[3], hexdec($m[4]), (int)$m[5])));
            $res = str_replace($m[0], '', $res);
            $res = preg_replace_callback('~\$GLOBALS[\{\[].[\}\]][\[\{]([0-9a-fx]+)[\]\}]~msi', function($m) use ($strings) {
                return '\'' . $strings[hexdec($m[1])] . '\'';
            }, $res);
        }

        if (substr_count($res, 'goto ') > 50) {
            $res = Helpers::unwrapGoto($res);
        }
        return $res;
    }

    private function deobfuscateManyFuncsWithCode($str, $matches)
    {
        $funcs = [$matches[1] => 'decode'];

        preg_match_all('~function\s(\w{1,50})\((?:\$\w{1,50},?\s?)+\)\s?{\s?return\s\$\w{1,50};\s?}~msi', $res,
                       $funcMatches, PREG_SET_ORDER);

        foreach ($funcMatches as $funcMatch) {
            $funcs[$funcMatch[1]] = 'single_var';
        }

        $res = preg_replace_callback('~(\w{1,50})\s?\(\s?[\'"]([^\'"]+)[\'"]\s?\)~msi', function ($m) use ($funcs) {
            $func = $funcs[$m[1]] ?? false;
            if (!$func) {
                return $m[0];
            }
            if ($func === 'decode') {
                $decoded = "";
                for ($i = 0; $i < strlen($m[2]) - 1; $i += 2) {
                    $decoded .= chr(hexdec($m[2][$i] . $m[2][$i + 1]) ^ 0x66);
                }

                return '"' . $decoded . '"';
            } elseif ($func === 'single_var') {
                return '"' . $m[2] . '"';
            }
        }, $str);

        return $res;
    }

    private function deobfuscateManyGlobals($str, $matches)
    {
        $vars = [];
        foreach ([$matches[1], $matches[2], $matches[3]] as $m) {
            $hangs = 50;
            $part = $m;
            while (strpos($part, 'base64_decode') !== false && $hangs--) {
                $part = Helpers::replaceVarsFromArray($vars, $part);
                $part = Helpers::replaceBase64Decode($part);
            }
            $ops = explode(';', $part);
            foreach ($ops as $v) {
                if ($v === '') {
                    continue;
                }
                $tmp = explode('=', $v, 2);
                $vars[$tmp[0]] = $tmp[1];
            }
        }
        $res = str_replace([$matches[1], $matches[2], $matches[3]], '', $str);
        $hangs = 50;
        while (strpos($res, '$GLOBALS') !== false && $hangs--) {
            $res = str_replace(array_keys($vars), array_values($vars), $res);
        }
        $res = str_replace('base64_decode(\'\')', '\'\'', $res);
        return $res;
    }

    private function deobfuscateB64xoredkey($str, $matches)
    {
        $b64 = Helpers::collectConcatedVars($matches[2]);
        $b64 = $b64[key($b64)];
        $res = Helpers::xorWithKey(base64_decode($b64), $matches[10]);
        return $matches[1] . $res;
    }

    private function deobfuscateGzB64Func($str, $matches)
    {
        $res = Helpers::normalize($matches[5]);
        $res = str_replace($matches[4], '"' . $matches[6] . '"', $res);
        return $res;
    }

    private function deobfuscateDictArrayFuncVars($str, $matches)
    {
        $dictName = $matches[5];

        $res = preg_replace_callback('~chr\((\d+)\)~msi', static function ($match) {
            return '\'' . chr($match[1]) . '\'';
        }, $matches[6]);


        $vars[$matches[2]] = 'base64_decode';
        $vars[$matches[3]] = base64_decode(Helpers::concatStr($matches[4]));

        $res = Helpers::replaceVarsFromArray($vars, $res, true);
        $res = Helpers::concatStringsInContent($res);
        $res = Helpers::replaceVarsFromArray($vars, $res, true, true);

        $res = preg_replace_callback('~str_rot13\([\'"]([^\'"]+)[\'"]\)~msi', static function ($match) {
            return '\'' . str_rot13($match[1]) . '\'';
        }, $res);

        $res = preg_replace_callback('~(?:[\'"][\w=();*/]*[\'"]\.?){2,}~msi', static function ($m) {
            preg_match_all('~(\.?)\s?[\'"]([\w=\+/%&();*]+)[\'"]\s?~msi', $m[0], $concatStrings);
            $strVar = "";
            foreach ($concatStrings[2] as $index => $concatString) {
                if ($concatStrings[1][$index] === '.') {
                    $strVar .= $concatString;
                } else {
                    $strVar = $concatString;
                }
            }

            return '\'' . $strVar . '\'';
        }, $res);

        $arrayVarDict = [];

        preg_match_all('~[\s\'"]*(.*?\]?)[\s\'"]*(,|$)~msi', $res, $arrMatches, PREG_SET_ORDER);

        foreach ($arrMatches as $arrMatch) {
            if ($arrMatch[1] === '') {
                continue;
            }
            $arrayVarDict[] = $arrMatch[1];
        }

        $res = str_replace([$matches[1], $matches[6]], '', $str);
        $res = preg_replace_callback('~(\$\w{1,50})\[(\d+)\]~msi', static function ($match) use ($dictName, $arrayVarDict) {
            if ($dictName === $match[1]) {
                $res = $arrayVarDict[$match[2]] ?? $match[0];
                if (!Helpers::isSafeFunc($res) && $res !== 'json_decode' && $res !== 'create_function' && strpos($res, '$') === false) {
                    $res = '"' . $res . '"';
                }
                return $res;
            }
            return $match[0];
        }, $res);

        return $res;
    }

    private function deobfuscateCreateFuncPackStrRot13($str, $matches)
    {
        return pack('H*', str_rot13($matches[2]));
    }

    private function deobfuscateDictVarsCreateFunc($str, $matches)
    {
        $res = $str;
        $dictName = $matches[2];
        $dictVal = stripcslashes($matches[3]);
        $vars = [];

        $res = preg_replace_callback('~(\$\w{1,50})\s?=\s?\w{1,50}\((?:(?:\$\w{1,50}\[\d+\]\s?|[\'"]{2}\s?)[.,]?\s?)+\);~msi',
            function($m) use (&$vars, $dictName, $dictVal) {
            $varName = $m[1];
            $dictResultStr = '';

            preg_match_all('~(\$\w{1,50})\[(\d+)\]~msi', $m[0], $dictVars, PREG_SET_ORDER);
            foreach ($dictVars as $dictVar) {
                if ($dictVar[1] !== $dictName) {
                    continue;
                }

                if ((int)$dictVar[2][0] === 0) {
                    $dictResultStr .= $dictVal[octdec($dictVar[2])] ?? '';
                } else {
                    $dictResultStr .= $dictVal[$dictVar[2]] ?? '';
                }
            }

            $vars[$varName] = $dictResultStr;

            return '';
            }, $str);

        $codeStr = '';
        preg_match_all('~(\$\w{1,50})~msi', $res, $varsMatch, PREG_SET_ORDER);
        foreach ($varsMatch as $var) {
            $codeStr .= $vars[$var[1]] ?? '';
        }

        if (strpos($codeStr, 'eval(base64_decode') !== false) {
            return base64_decode($matches[5]);
        }

        if (strpos($codeStr, 'eval(gzinflate(base64_decode') !== false) {
            return gzinflate(base64_decode($matches[5]));
        }

        return $str;
    }

    private function deobfuscateDecodedFileGetContentsWithFunc($str, $matches)
    {
        $res = str_replace($matches[6], '', $str);

        $resCode = implode(' ', @Helpers::unserialize(base64_decode($matches[5])));

        if (preg_match('~\$\w{1,50}\s?=\s?\'([^\']+)\';\s*\$\w{1,50}\s?=\s?\'([^\']+)\';~msi', $resCode, $configs)) {
            $uid = $configs[1];
            $cfg = $configs[2];

            $resCode = preg_replace_callback('~\$this->\w{1,50}\s?=\s?(@unserialize\(\$this->\w{1,50}\(\w{1,50}::\w{1,50}\(\$this->config\),\s?[\'"]([^\'"]+)[\'"]\)\))~msi',
                static function ($m) use ($uid, $cfg) {
                    $configCodeArray = Helpers::decodeFileGetContentsWithFunc(base64_decode($cfg), $m[2]);
                    $configCodeArray = Helpers::decodeFileGetContentsWithFunc($configCodeArray, $uid);
                    $configCodeArray = @Helpers::unserialize($configCodeArray);
                    $configCodeArray = var_export($configCodeArray, true);

                    return str_replace($m[1], $configCodeArray, $m[0]);
                }, $resCode);
        }

        $res = str_replace($matches[8], $resCode, $res);

        return $res;
    }

    private function deobfuscateCreateFuncVarsCode($str, $matches)
    {
        $vars = Helpers::collectConcatedVars(stripcslashes($matches[1]));

        $tempStr = preg_replace_callback('~(\$\w{1,50})=(.*?);~msi', function ($m) use (&$vars) {
            $var = $this->unwrapFuncs(Helpers::replaceVarsFromArray($vars, $m[2], true, true));

            $vars[$m[1]] = $var;
        }, $matches[2]);

        $func = Helpers::replaceVarsFromArray($vars, $matches[7], true);
        $code = $this->unwrapFuncs("$func'$matches[6]))");

        if (preg_match('~(\$\w{1,50})=array\(((?:\d{1,9},?)+)\);\s*(\$\w{1,50})="";for\((\$\w{1,50})=0;\4<sizeof\(\1\);\4\+=2\){if\(\4%4\){\3\.=substr\(\$\w{1,50},\1\[\4\],\1\[\4\+1\]\);}else{\3\.=\$\w{1,50}\(substr\(\$\w{1,50},\1\[\4\].\1\[\4\+1\]\)\);}};.*?return\s\$\w{1,50};~msi',
                       $code, $codeMatches)) {
            $res      = "";
            $arrayNum = [];

            preg_match_all('~(\d{1,9})~msi', $codeMatches[2], $numbers, PREG_SET_ORDER);
            foreach ($numbers as $number) {
                $arrayNum[] = $number[1];
            }

            for ($i = 0; $i < sizeof($arrayNum); $i += 2) {
                if ($i % 4) {
                    $res .= substr($matches[4], $arrayNum[$i], $arrayNum[$i + 1]);
                } else {
                    $res .= strrev(substr($matches[4], $arrayNum[$i], $arrayNum[$i + 1]));
                }
            };

            $res = $this->unwrapFuncs("$func'$res))");
            if ($res) {
                return $res;
            }
        }

        return $str;
    }

    private function deobfuscatePregConcat($str, $matches)
    {
        return Helpers::normalize($matches[2]);
    }

    private function deobfuscateUndefinedDFunc($str, $matches)
    {
        return 'eval(gzinflate(str_rot13(base64_decode(' . $matches[2] . '))));';
    }

    private function deobfuscateXoredStrings($str, $matches)
    {
        $res = preg_replace_callback('~"([^"]+)"\s*\^\s*"([^"]+)"~msi', function($m) {
            return '\'' . (stripcslashes($m[1]) ^ stripcslashes($m[2])) . '\'';
        }, $str);

        $res = preg_replace_callback('~\$\{\'(\w+)\'\}~msi', function($m) {
            return '$' . $m[1];
        }, $res);
        Helpers::collectVars($res, '\'', $vars, true);
        $res = Helpers::replaceVarsFromArray($vars, $res, false, false);

        if (preg_match('~(\$\w+)\s*=\s*(\(?\s*gzinflate\s*\(\s*base64_decode\s*)\(\s*\'([^\']+)\'\s*\)\s*\)\s*\)?\s*;\s*\$\w+\s*=\s*@?create_function\(\'([^\']*)\',\s*(?:\1|\'@?eval\(\4\)[^\']+\')\)\s*;\s*@?\$\w+(?:\(\)|\(\1\));~msi', $res, $m)) {
            $res = $this->deobfuscateCreateFuncGzInflateB64($res, $m);
        }
        $res = preg_replace_callback('~/\*[^\*]+\*/~msi', function($m) {
            return '';
        }, $res);
        $res = str_replace('\\\'', '@@slaapos@@', $res);
        preg_match('~\$\{"[^"]+"\^"[^"]+"\}\s*=\s*\'([^\']+)\'\s*;~msi', $res, $m);
        $res = str_replace('@@slaapos@@', '\\\'', $m[1]);
        $res = stripcslashes($res);

        $res = preg_replace_callback('~\(?"([^"]+)"\)?\s*\^\s*\(?"([^"]+)"\)?~msi', function($m) {
            return '\'' . (stripcslashes($m[1]) ^ stripcslashes($m[2])) . '\'';
        }, $res);

        $res = preg_replace_callback('~\$\{\'(\w+)\'\}~msi', function($m) {
            return '$' . $m[1];
        }, $res);

        $replace = function($m) use (&$vars) {
            if (!isset($vars[$m[1]])) {
                return $m[0];
            }
            if (isset($m[2]) && $m[2] !== '') {
                return $vars[$m[1]] . '(';
            }
            return @($vars[$m[1]][0] !== '\'') ? '\'' . $vars[$m[1]] . '\'' : $vars[$m[1]];
        };

        Helpers::collectVars($res, '\'', $vars, true);
        $res = preg_replace_callback('~(\$\w+)\s*(\()?~msi', $replace, $res);
        Helpers::collectFuncVars($res, $vars, true, true);
        $res = preg_replace_callback('~(\$\w+)\s*(\()?~msi', $replace, $res);

        $res = preg_replace('~;+~msi', ';', $res);
        return $res;
    }

    private function deobfuscateCommentWithAlgo($str, $matches)
    {
        return str_replace($matches[1], addcslashes(base64_decode(gzinflate(str_rot13(convert_uudecode(gzinflate(base64_decode($matches[1])))))), '\''), $str);
    }

    private function deobfuscateFileEncryptor($str, $matches)
    {
        return Helpers::replaceBase64Decode($str);
    }

    private function deobfuscateDefinedB64($str, $matches)
    {
        return str_replace([$matches[1], $matches[6], $matches[8]], ['', '', gzinflate(base64_decode($matches[9]))], $str);
    }

    private function deobfuscateB64Xored($str, $matches)
    {
        return base64_decode(Helpers::xorWithKey(base64_decode($matches[4]), $matches[6]));
    }

    private function deobfuscateB64AssignedVarContent($str, $matches)
    {
        return str_replace($matches[4], "'" . (base64_decode($matches[2])) . "'", $matches[3]);
    }

    private function deobfuscateDictVarsWithMath($str, $matches)
    {
        $dictVal = $matches[2];

        $dictStrs = Helpers::calculateMathStr($matches[3]);
        $vars = Helpers::getVarsFromDictionary($dictVal, $dictStrs);
        $vars = Helpers::collectVars($str, '"', $vars);
        $vars = Helpers::collectConcatedVars($str, '"', $vars);

        return $vars[$matches[4]] ?? $str;
    }

    private function deobfuscateClassDecryptedWithKey($str, $matches)
    {
        $key = 'WebKit#58738Educ';

        $data = hex2bin($matches[2]);
        $res = Helpers::decodeClassDecryptedWithKey($data, 32, $key);

        if (strpos($res, 'error_reporting(') !== false) {
            return $res;
        }

        return $str;
    }

    private function deobfuscatePHPkoru($str, $matches)
    {
        $vars[$matches[2]] = str_rot13(base64_decode($matches[3]));
        $vars[$matches[4]] = str_rot13(base64_decode($matches[5]));
        $code = $matches[6];
        while (strpos($code, 'eval') === 0) {
            $code = str_replace(array_keys($vars), array_values($vars), $code);
            $code = $this->unwrapFuncs($code);
        }
        $decoded = '';
        if (preg_match('~openssl_decrypt\(base64_decode\(trim\(\$\w+\[1\]\)\),\s*"([^"]+)",\s*base64_decode\(str_rot13\("([^"]+)"\)\),\s*(\d+),\s*base64_decode\(str_rot13\("([^"]+)"\)\)\)\);~msi', $code, $openssl_data)) {
            $data = base64_decode(trim($matches[8]));
            $algo = $openssl_data[1];
            $passphrase = base64_decode(str_rot13($openssl_data[2]));
            $iv = base64_decode(str_rot13($openssl_data[4]));
            $flags = $openssl_data[3];
            $decoded = openssl_decrypt($data, $algo, $passphrase, $flags, $iv);
            $decoded = str_rot13(base64_decode(str_rot13($decoded)));
        }
        return ' ?> ' .PHP_EOL . $decoded;
    }

    private function deobfuscateJoomlaInject($str, $matches)
    {
        $vars = Helpers::collectVars($matches[0]);
        preg_match('~function\s*\w+\((\$\w+)\)\s*\{\s*(\$\w+)\s*=\s*array\(((?:\'[^\']+\',?)+)\1\);\s*for\((\$\w+)=0;\s*\4<\d+;\s*\4\+\+\)\s*\{\s*for\((\$\w+)=0;\s*\5<strlen\(\2\[\4\]\);\s*\5\+\+\)\s*\2\[\4\]\[\5\]\s*=\s*chr\(ord\(\2\[\4\]\[\5\]\)\s*([\-\+])\s*(\d+)~msi', $this->full_source, $decode_data);
        preg_match_all('~\$this->\w+\(((?|"[^"]+"|\$\w+))\)~msi', $matches[0], $to_decode);
        foreach ($to_decode[1] as &$item) {
            if ($item[0] === '"' && $item[-1] === '"') {
                $item = substr($item, 1, -1);
            }
            $item = str_replace(array_keys($vars), array_values($vars), $item);
            $item = "'" . Helpers::joomlaInjectDecoder($decode_data[3] . $item, $decode_data[6], $decode_data[7]) . "'";
        }
        $res = str_replace($to_decode[0], $to_decode[1], $str);
        return $res;
    }

    private function deobfuscateFwriteB64Content($str, $matches)
    {
        $res = $str;

        $res = str_replace($matches[1], '', $res);
        $replace = base64_decode($matches[3]);

        $res = str_replace($matches[4], "'" . $replace . "'", $res);

        return $res;
    }

    private function deobfuscateB64concatedVars($str, $matches)
    {
        $res = $matches[6];

        $code = "'" . base64_decode($matches[2]) . base64_decode($matches[5]) . "'";

        $res = str_replace($matches[7], $code, $res);

        return $res;
    }

    private function deobfuscateSlashedCreateFunc($str, $matches)
    {
        $func = stripcslashes($matches[2]);

        if (strpos($func, 'create_function') !== false) {
            $code = stripcslashes($matches[5]);
            $code = str_replace($matches[4], $matches[6], $code);

            return $code;
        }

        return $str;
    }

    private function deobfuscateVarDictCreateFunc($str, $matches)
    {
        $res = Helpers::replaceVarsFromDictionary($matches[1], $matches[2], $matches[3]);

        $vars = [];
        $vars = Helpers::collectVars($res, '"', $vars, true);

        $res = Helpers::replaceVarsFromArray($vars, $res);

        return $res;
    }

    private function deobfuscatecallFuncGzB64($str, $matches)
    {
        return gzinflate(base64_decode($matches[1]));
    }

    private function deobfuscateAssertDictVarEval($str, $matches)
    {
        $dict = $matches[2];
        $arr  = [];
        for ($i = 0; $i < 6; $i++) {
            $arr[] = (int)$matches[4 + $i];
        }

        $assertStr = "";
        for ($i = 0; $i < 6; $i++) {
            $temp      = $arr[$i];
            $assertStr .= $dict[$temp];
        }

        $funcs = Helpers::concatStringsInContent(stripcslashes($matches[13]));
        if ($assertStr === 'assert' && strpos($funcs, 'eval(base64_decode(gzinflate(base64_decode(') !== false) {
            return base64_decode(gzinflate(base64_decode($matches[11])));
        }

        $vars               = [];
        $vars[$matches[10]] = $matches[11];
        $vars[$matches[12]] = $assertStr;

        return Helpers::replaceVarsFromArray($vars, $funcs);
    }

    private function deobfuscateB64FuncEvalGz($str, $matches)
    {
        return base64_decode(gzinflate(base64_decode($matches[4])));
    }

    private function deobfuscateB64Gz($str, $matches)
    {
        $result = gzinflate(base64_decode($matches[2]));
        $break = isset($matches[5]) ? '?>' : '';

        return $break . $result;
    }

    private function deobfuscateSubstrEmpty($str, $matches)
    {
        $str = preg_replace_callback('~substr\("([^"]++)",(\d++),(-?\d++)\)~msi', function ($m) {
            return '"' . substr(stripcslashes($m[1]), (int) $m[2], (int) $m[3]) . '"';
        }, $str);
        $str = str_replace(['"."', '"".'], '', $str);
        return $str;
    }

    private function deobfuscateDeltaOrd($str, $matches)
    {
        $str = gzinflate(base64_decode($matches[4]));
        for($i = 0, $iMax = strlen($str); $i < $iMax; $i++) {
            $str[$i] = chr(ord($str[$i]) + (int) $matches[3]);
        }
        return $str;
    }

    private function deobfuscateOutputBuffer($str, $matches)
    {
        $search = explode(',', str_replace(['\',\'', '\',"', '",\'', '","'], ',', substr($matches[5], 1, -1)));
        $replace = explode(',', str_replace(['\',\'', '\',"', '",\'', '","'], ',', substr($matches[6], 1, -1)));
        $replace = array_map('stripcslashes', $replace);
        $buffer = str_replace($search, $replace, $matches[1] . $matches[9]);
        for ($i = 1, $j = ord($buffer[0]), $iMax = strlen($buffer); $i < $iMax; $i++) {
            $buffer[$i] = chr(ord($buffer[$i]) - $j - $i);
        }
        $buffer[0] = ' ';
        return $buffer;
    }

    private function deobfuscateDoorwayInstaller($str, $matches)
    {
        $vars = [];
        Helpers::collectVars($str, '"', $vars, true);
        $str = preg_replace_callback('~(\$\w+)\((?:"([^"]+)"|(\$\w+))\)~msi', function($m) use ($matches, $vars) {
            if ($m[1] !== $matches[1]) {
                return $m[0];
            }
            if (isset($m[2]) && $m[2] !== '') {
                return '\'' . base64_decode($m[2]) . '\'';
            }
            if (isset($m[3]) && isset($vars[$m[3]])) {
                return '\'' . base64_decode($vars[$m[3]]) . '\'';
            }
        }, $str);
        return $str;
    }

    private function deobfuscateStrReplaceAssert($str, $matches)
    {
        return base64_decode(gzinflate(base64_decode($matches[2])));
    }

    private function deobfuscateAnaLTEAMShell($str, $matches)
    {
        preg_match_all('~\$\{\'GLOBALS\'\}\[\'([^\']+)\'\]=[\'"]([^\'"]+)[\'"];~msi', $str, $m);
        $vars = array_combine($m[1], $m[2]);
        $str = str_replace($m[0], '', $str);
        $str = preg_replace_callback('~\$\{\$\{\'GLOBALS\'\}\[\'([^\']+)\'\]\}~msi', function($m) use ($vars) {
            if (!isset($vars[$m[1]])) {
                return $m[0];
            }
            return '$' . $vars[$m[1]];
        }, $str);
        $str = Helpers::replaceBase64Decode($str);
        $str = preg_replace_callback('~((\$\w+)=\'([^\']+)\';)\$\w+=\$_SERVER\[\'DOCUMENT_ROOT\'\]\.\'/\'\.\'[^\']+\';if\(file_exists\(\$\w+\)\)@?unlink\(\$\w+\);(\$\w+)=(base64_decode\(\2\));~msi', function ($m) {
            $res = str_replace($m[1], '', $m[0]);
            $res = str_replace($m[5], '\'' . base64_decode($m[3]) . '\'', $res);
            return $res;
        }, $str);
        $str = stripcslashes(stripcslashes($str));
        return $str;
    }

    private function deobfuscateZeuraB64Gzinflate($str, $matches)
    {
        return gzinflate(base64_decode($matches[10]));
    }

    private function deobfuscateD5($str, $matches)
    {
        $content = explode(hex2bin($matches[4]), $str)[1];
        $tmp = [];
        for ($i = 0; $i < strlen($content); $i++) {
            $tmp[]=ord($content[$i]) xor $i;
        }
        $content = hex2bin(base64_decode(implode(array_map(hex2bin($matches[8]), $tmp))));
        return $content;
    }

    private function deobfuscateStrReplaceFunc($str, $matches)
    {
        $vars = Helpers::collectFuncVars($matches[3], $vars, false, true);
        $cmd = Helpers::replaceVarsFromArray($vars, $matches[5]);
        if (strpos($cmd, 'create_function') === 0) {
            $cmd = 'eval(' . str_replace('create_function(\'\',', '', $cmd);
        }
        $res = str_replace($matches[6], '\'' . $matches[7] . '\'', $cmd);
        return $res;
    }

    private function deobfuscateArrayMapB64($str, $matches)
    {
        $array = explode('\',\'', substr($matches[2], 1, -1));
        return ' ?>' . base64_decode(str_rot13(implode('', $array))) . '<?php ';
    }

    private function deobfuscatePregReplaceStrReplace($str, $matches)
    {
        return str_replace($matches[1], $matches[2], stripcslashes($matches[3]));
    }

    private function deobfuscateEchoB64($str, $matches)
    {
        return str_replace([$matches[2], $matches[5]], ['\'' . base64_decode($matches[3]) . '\'', '\'' . base64_decode($matches[6]) . '\''], $str);
    }

    private function deobfuscateCreateFuncXored($str, $matches)
    {
        $res = preg_replace_callback('~"([^"]+)"\^"([^"]+)"~msi', function($m) {
            return '\'' . (stripcslashes($m[1]) ^ stripcslashes($m[2])) . '\'';
        }, $str);
        $vars = Helpers::collectVars($res, '\'', $vars, true);
        $res = gzinflate(base64_decode($matches[2]));
        $res = preg_replace('~/\*[^\*]+\*/~msi', '', $res);
        preg_match('~\$\{"[^"]+"\^"[^"]+"\}\s*=\s*\'((?:\\\\.|[^\'])*+)\';~msi', $res, $matches);
        $code = stripcslashes($matches[1]);
        $code = preg_replace_callback('~\(?"([^"]+)"\)?\^\(?"([^"]+)"\)?~msi', function($m) {
            return '\'' . (stripcslashes($m[1]) ^ stripcslashes($m[2])) . '\'';
        }, $code);
        $code = MathCalc::calcRawString($code);
        $vars = [];
        $code = preg_replace_callback('~\$(?:\{\')?(\w+)(?:\'\})?\s*=\s*\'([^\']*)\';+~msi', function($m) use (&$vars) {
            $vars['$' . $m[1] . '('] = $m[2] . '(';
            $vars['$' . $m[1]] = '\'' . $m[2] . '\'';
            return '';
        }, $code);
        $vars['&& !$_0 '] = '&&';
        $vars['if($_0 '] = 'if(';
        krsort($vars);
        $code = str_replace(array_keys($vars), array_values($vars), $code);
        preg_match('~(\$\w+)=base64_decode\(\'([^\']+)\'\);;~msi', $code, $m);
        $code = str_replace($m[0], '', $code);
        $code = str_replace('eval(' . $m[1] . ');', base64_decode($m[2]), $code);
        return $code;
    }

    private function deobfuscateCodeLockDecoder($str, $matches)
    {
        $codelock_stub = base64_decode($matches[1]);
        if (isset($matches[2]) && $matches[2] !== '') {
            $codelock_stub = gzinflate($codelock_stub);
            $hangs = 20;
            while (strpos($codelock_stub, 'eval') === 0 && $hangs--) {
                $codelock_stub = $this->UnwrapFuncs($codelock_stub);
            }
        }

        preg_match('~\$codelock_active_key="([^"]*)";~msi', $codelock_stub, $m);
        $codelock_active_key = $m[1];
        preg_match('~\$codelock_usezlib="([^"]*)";~msi', $codelock_stub, $m);
        $codelock_usezlib = $m[1];
        $codelock_key_data = $matches[3];
        if ($codelock_usezlib === "^") {
            $codelock_key_data = base64_decode($codelock_key_data);
            $codelock_key_data = gzinflate($codelock_key_data);
        }
        if (substr($codelock_active_key, 0, 15) !== "codelock_active") {
            $codelock_key_data = Helpers::codelock_dec_int($codelock_key_data, $codelock_active_key);
        } else {
            preg_match('~\$codelock_unlock="([^"]*)";~msi', $codelock_stub, $m);
            $codelock_active_key = $m[1];
            $codelock_key_data = Helpers::codelock_run($codelock_key_data, $codelock_active_key);
        }

        return $codelock_key_data;
    }

    private function deobfuscateEvalGzStrRotB64($str, $matches)
    {
        return gzinflate(str_rot13(base64_decode($matches[2])));
    }

    private function deobfuscateEvalDictArrayConcat($str, $matches)
    {
        $dictVal = '';
        preg_match_all('~[\'"]([^\'"])[\'"]~msi', $matches[2], $m, PREG_SET_ORDER);
        foreach ($m as $char) {
            $dictVal .= $char[1];
        }

        $replacedStr = Helpers::replaceVarsFromDictionary($matches[1], $dictVal, $str);
        $vars = Helpers::collectVars($replacedStr);

        $funcs = Helpers::replaceVarsFromArray($vars, $matches[4]);
        $funcs = Helpers::concatStringsInContent($funcs);
        $funcs = strtolower($funcs);

        if (strpos($funcs, 'eval(str_rot13(gzinflate(str_rot13(gzinflate(base64_decode(') !== false) {
            return str_rot13(gzinflate(str_rot13(gzinflate(base64_decode($matches[6])))));
        }

        return $str;
    }
    
    private function deobfuscatePregReplaceXored($str, $matches)
    {
        $res = preg_replace_callback('~"([^"]+)"\^"([^"]+)"~msi', function($m) {
            return '\'' . (stripcslashes($m[1]) ^ stripcslashes($m[2])) . '\'';
        }, $str);
        $vars = [];
        $vars = Helpers::collectVars($res, '\"', $vars, true);
        $res = Helpers::replaceVarsFromArray($vars, $res, false, true);
        $res = str_replace('\'.\'', '', $res);
        Helpers::collectVars($res, '\'', $vars, true);
        $res = str_replace(['preg_replace("/' . $matches[2] . '/e",\'\'', '\'\',"' . $matches[2] . '");'], '', $res);
        $res = Helpers::replaceVarsFromArray($vars, $res, false, true);
        return $res;
    }


    private function deobfuscateR4C($str, $matches)
    {
        $vars = [];
        $res = $str;
        $hangs = 20;
        do {
            Helpers::collectConcatedVars($res, '"', $vars, true);
            $res = str_replace('"".$', '$', $res);
            Helpers::collectConcatedVars($res, '\'', $vars, true);
            $res = trim($res);
            $res = Helpers::replaceVarsFromArray($vars, $res, false, true);
            $res = $this->unwrapFuncs($res);
        } while (preg_match('~eval\((?:\w+\()*(?:\$\w+\.?)+\)~', $res) && $hangs--);
        return $res;
    }
    
    
    private function deobfuscateBase64EncryptedGz($str, $matches)
    {
        $text       = $matches[1];
        $hash       = $matches[3];
        $key        = 'asdf';
        $key_len    = strlen($key);

        $text       = base64_decode(str_replace("\n", '', $text));
        $text_len   = strlen($text);

        $w = [];
        for ($i = 0; $i < $key_len; ++$i)
        {
            $w[] = $text_len - $key_len - ord($key[$i]);
        }

        for ($i = 0; $i < $text_len; ++$i) {
            $j          = abs($w[$i % $key_len] - $i);
            $x          = $text[$j];
            $text[$j]   = $text[$i];
            $text[$i]   = $x;
        }

        if ($key_len < 10) {
            $key_len *= $key_len & 1 ? 3 : 2;
        }
    
        if (($text = @gzinflate($text)) && (md5(substr($text, 0, $key_len)) === $hash)) {
            return substr($text, $key_len);
        }
    
        return '';
    }
    /*************************************************************************************************************/
    /*                                          JS deobfuscators                                                 */
    /*************************************************************************************************************/

    private function deobfuscateJS_fromCharCode($str, $matches)
    {
        $result = '';
        $chars = explode(',', $matches[2]);
        foreach ($chars as $char) {
            $result .= chr((int)trim($char));
        }
        if ($matches[1] == 'eval(') {
            return $result;
        }
        return '\''.$result.'\';';
    }

    private function deobfuscateJS_unescapeContentFuncWrapped($str, $matches)
    {
        $result = '';

        $functionCode = urldecode($matches[1]);
        $functionName = urldecode($matches[2]);
        $strDecoded = $matches[3];

        if (preg_match('~function\s?(\w{1,50})\(\w{1,50}\)\s{0,50}{\s{0,50}var\s?\w{1,50}\s?=\s?[\'"]{2};\s{0,50}var\s?\w{1,50}\s?=\s?\w{1,50}\.split\("(\d+)"\);\s{0,50}\w{1,50}\s?=\s?unescape\(\w{1,50}\[0\]\);\s{0,50}\w{1,50}\s?=\s?unescape\(\w{1,50}\[1\]\s?\+\s?"(\d{1,50})"\);\s{0,50}for\(\s?var\s?\w{1,50}\s?=\s?0;\s?\w{1,50}\s?<\s?\w{1,50}\.length;\s?\w{1,50}\+\+\)\s?{\s{0,50}\w{1,50}\s?\+=\s?String\.fromCharCode\(\(parseInt\(\w{1,50}\.charAt\(\w{1,50}%\w{1,50}\.length\)\)\^\w{1,50}\.charCodeAt\(\w{1,50}\)\)\+-2\);\s{0,50}}\s{0,50}return\s\w{1,50};\s{0,50}}~msi',
                $functionCode, $match) && strpos($functionName, $match[1])) {
            $tmp = explode((string)$match[2], $strDecoded);
            $s = urldecode($tmp[0]);
            $k = urldecode($tmp[1] . (string)$match[3]);
            $kLen = strlen($k);
            $sLen = strlen($s);

            for ($i = 0; $i < $sLen; $i++) {
                $result .= chr(((int)($k[$i % $kLen]) ^ ord($s[$i])) - 2);
            }
        } else {
            $result = $matches[3];
            $result = str_replace([$matches[1], $matches[2]], [$functionCode, $functionCode], $result);
        }

        return $result;
    }

    private function deobfuscateJS_ObfuscatorIO($str, $matches)
    {
        $detectPattern = '~((?![^_a-zA-Z$])[\w$]*)\(-?(\'|")(0x[a-f\d]+|\\x30\\x78[\\xa-f\d]+)\2(\s*,\s*(\'|").+?\5)?\)~msi';
        preg_match_all($detectPattern, $str, $detectMatch);
        $detectMatch = array_unique($detectMatch[1]);
        if (count($detectMatch) !== 1) {
            return $str;
        }

        preg_match('~\b(?:var|const|let)\s+' . $detectMatch[0] . '\s*=\s*function\s*\(.*?\)\s*~msi', $str, $index, PREG_OFFSET_CAPTURE);
        $index = $index[0][1];

        $bo = 0;
        $bc = 0;
        $strSize = strlen($str);
        $mainCode = '';
        while ($index < $strSize) {
            if ($str[$index] === '{') {
                $bo++;
            }
            if ($str[$index] === '}') {
                $bc++;
            }
            if ($bc === $bo && $bo !== 0) {
                $mainCode = substr($str, $index + 2);
                break;
            }
            $index++;
        }
        $array = explode('\',\'', substr($matches[2], 1, -1));

        $shuffle = hexdec($matches[3]);
        while ($shuffle--) {
            $array[] = array_shift($array);
        }
        $mainCode = preg_replace_callback('~((?![^_a-zA-Z$])[\w$]*)\(-?(\'|")(0x[a-f\d]+|\\x30\\x78[\\xa-f\d]+)\2(\s*,\s*(\'|")(.+?)\5)?\)~msi', function ($m) use ($array) {
            return '\'' . Helpers::deobfuscatorIO_string($array[hexdec($m[3])], $m[6]) . '\'';
        }, $mainCode);
        return Helpers::normalize($mainCode);
    }

    private function deobfuscateJS_documentWriteUnescapedStr($str, $matches)
    {
        if (strpos($matches[1], '\u00') !== false) {
            $matches[1] = str_replace('\u00', '%', $matches[1]);
        }
        return urldecode($matches[1]);
    }

    private function deobfuscateJS_deanPacker($str, $matches)
    {
        $payload = $matches[1];
        // Words
        $symtab = explode('|', $matches[4]);
        // Radix
        $radix = (int)$matches[2];
        // Words Count
        $count = (int)$matches[3];

        if ($count !== count($symtab)) {
            return $str; // Malformed p.a.c.k.e.r symtab !
        }

        $array = [];

        while ($count--) {
            $tmp = Helpers::jsPackerUnbaser($count, $radix);
            $array[$tmp] = (isset($symtab[$count]) && $symtab[$count] !== '') ? $symtab[$count] : $tmp;
        }

        $result = preg_replace_callback('~\b\w+\b~', function($m) use ($array) {
            return $array[$m[0]];
        }, $payload);
        $result = str_replace('\\', '', $result);
        if (preg_match('~function\(\)\{var\s*(\w+)=\{([\$\w]+):\'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789\+/=\',\w+:function\(\w+\){var\s*\w+=\'\',\w,\w,\w,\w,\w,\w,\w,\w=0;\w=\1\.[\w\$]+\(\w\);while\(\w<\w\.length\)\{[^{]+\{\w=\w=64\}else[^{]+\{\w=64\};[^}]+};return\s*\w},(\w+):function\(\w\)\{var\s*\w+=\'\',\w,\w,\w,\w,\w,\w,\w,\w=0;\w=\w\.replace\(/\[\^A\-Za\-z0\-9\+/=\]/g,\'\'\);while\(\w<\w\.length\){\w=this\.\2\.indexOf\(\w\.charAt\(\w\+\+\)\);~msi', $result, $m)) {
            $class = $m[1];
            $b64_func = $m[3];
            $result = preg_replace_callback('~(?:var\s(\w+)=\'([^\']+)\';\1=(\w+\.\w+)\(\1\)|(\w+\.\w+)\(\'([^\']+)\'\))~msi', function($m) use ($class, $b64_func) {
                if ((isset($m[4]) && $m[4] !== '' && $m[4] !== $class . '.' . $b64_func)
                 || (isset($m[3]) && $m[3] !== '' && $m[3] !== $class . '.' . $b64_func)
                ) {
                    return $m[0];
                }
                if (isset($m[4]) && $m[4] !== '') {
                    return '\'' . base64_decode($m[5]) . '\'';
                }
                if (isset($m[3]) && $m[3] !== '') {
                    return 'var ' . $m[1] . '=\'' . base64_decode($m[2]) . '\'';
                }
            }, $result);
            $result = preg_replace_callback('~\w+=\[((?:\'[^\']+\',?)+)\]~msi', function($m) {
                $arr = explode('\',\'', substr($m[1], 1, -1));
                $arr = array_map('base64_decode', $arr);
                return str_replace($m[1], '\'' . implode('\',\'', $arr) . '\'', $m[0]);
            }, $result);

        }
        return $result;
    }

    private function deobfuscateJS_objectDecode($str, $matches)
    {
        $ciphered = explode('+', $matches[9]);
        $chars = explode('\',\'', substr($matches[13], 1, -1));
        $count = (int)$matches[8];
        $arr = [];
        for ($i = 0; $i < $count; $i++) {
            $arr[Helpers::jsObjectDecodeIndexToString($i)] = $ciphered[$i][0] !== ';' ? '\'' . Helpers::jsObjectStringDecoder($matches[11], $chars, $ciphered[$i]) . '\'' : (float)substr($ciphered[$i], 1);
        }
        $ret = preg_replace_callback('~\$\.\b(\w+)\b~', function($m) use ($arr) {
            if (!isset($arr[$m[1]])) {
                return $m[0];
            }
            return $arr[$m[1]];
        }, $matches[2]);

        return $ret;
    }

    /*************************************************************************************************************/
    /*                                          PYTHON deobfuscators                                             */
    /*************************************************************************************************************/

    private function deobfuscatePY_evalCompileStr($str, $matches)
    {
        return gzuncompress(base64_decode($matches[1]));
    }
}


class ContentObject
{
    private $content = false;
    private $normalized_file_content = false;
    private $unescaped_normalized = false;
    private $unescaped = false;
    private $decoded_converted = false;
    private $decoded_file_content = false;
    private $normalized_decoded = false;
    private $decoded_fragments = false;
    private $decoded_fragments_string = false;
    private $norm_decoded_fragments = false;
    private $norm_decoded_fragments_string = false;
    private $norm_decoded_file_content = false;
    private $converted_file_content = false;
    private $converted_decoded = false;
    private $strip_decoded = false;
    private $type = '';

    private $deobfuscate = false;
    private $unescape = false;


    public function __construct($content, $deobfuscate = false, $unescape = false)
    {
        $this->content = $content;
        $this->deobfuscate = $deobfuscate;
        $this->unescape = $unescape;
    }

    public function getType()
    {
        return $this->type;
    }

    public function getContent()
    {
        if ($this->content !== false) {
            return $this->content;
        }
    }

    public function getUnescaped()
    {
        if (!$this->unescape) {
            $this->unescaped = '';
            $this->unescaped_normalized = '';
        }
        if ($this->unescaped !== false) {
            return $this->unescaped;
        }
        $this->unescaped = Normalization::unescape($this->getContent());
        return $this->unescaped;
    }

    public function getNormalized()
    {
        if ($this->normalized_file_content !== false) {
            return $this->normalized_file_content;
        }
        $this->normalized_file_content = Normalization::strip_whitespace($this->getContent());
        $this->normalized_file_content = Normalization::normalize($this->normalized_file_content);
        return $this->normalized_file_content;
    }

    public function getUnescapedNormalized()
    {
        if (!$this->unescape) {
            $this->unescaped = '';
            $this->unescaped_normalized = '';
        }
        if ($this->unescaped_normalized !== false) {
            return $this->unescaped_normalized;
        }
        $this->unescaped_normalized = Normalization::strip_whitespace(Normalization::unescape($this->getContent()));
        $this->unescaped_normalized = Normalization::normalize($this->unescaped_normalized);
        return $this->unescaped_normalized;
    }

    public function getDecodedFileContent()
    {
        if (!$this->deobfuscate) {
            $this->decoded_file_content = '';
            $this->decoded_fragments = [];
            $this->decoded_fragments_string = '';
            $this->norm_decoded_file_content = '';
        }
        if ($this->decoded_file_content !== false) {
            return $this->decoded_file_content;
        }
        $deobf_obj = new Deobfuscator($this->getContent());
        $deobf_type = $deobf_obj->getObfuscateType($this->getContent());
        if ($deobf_type != '') {
            $this->decoded_file_content = $deobf_obj->deobfuscate();
            $this->decoded_fragments = $deobf_obj->getFragments();
            $this->decoded_fragments_string = is_array($this->decoded_fragments) ? Normalization::normalize(implode($this->decoded_fragments)) : '';
            $this->norm_decoded_file_content = Normalization::normalize($this->decoded_file_content);
        } else {
            $this->decoded_file_content = '';
            $this->decoded_fragments = [];
            $this->decoded_fragments_string = '';
            $this->norm_decoded_file_content = '';
        }
        return $this->decoded_file_content;
    }

    public function getDecodedNormalizedContent()
    {
        if (!$this->deobfuscate) {
            $this->normalized_decoded = '';
            $this->norm_decoded_fragments = [];
            $this->norm_decoded_fragments_string = '';
        }
        if ($this->normalized_decoded !== false) {
            return $this->normalized_decoded;
        }
        $deobf_obj = new Deobfuscator($this->getNormalized());
        $deobf_type = $deobf_obj->getObfuscateType($this->getNormalized());
        if ($deobf_type != '') {
            $this->normalized_decoded = $deobf_obj->deobfuscate();
            $this->norm_decoded_fragments = $deobf_obj->getFragments();
            $this->norm_decoded_fragments_string = is_array($this->norm_decoded_fragments) ? Normalization::normalize(implode($this->norm_decoded_fragments)) : '';
        } else {
            $this->normalized_decoded = '';
            $this->norm_decoded_fragments = [];
            $this->norm_decoded_fragments_string = '';
        }
        return $this->normalized_decoded;
    }

    public function getDecodedFragments()
    {
        if ($this->decoded_fragments !== false) {
            return $this->decoded_fragments;
        }
        $this->getDecodedFileContent();
        return $this->decoded_fragments;
    }

    public function getDecodedFragmentsString()
    {
        if ($this->decoded_fragments_string !== false) {
            return $this->decoded_fragments_string;
        }
        $this->getDecodedFileContent();
        return $this->decoded_fragments_string;
    }

    public function getNormDecodedFragments()
    {
        if ($this->norm_decoded_fragments !== false) {
            return $this->norm_decoded_fragments;
        }
        $this->getDecodedNormalizedContent();
        return $this->norm_decoded_fragments;
    }

    public function getNormDecodedFragmentsString()
    {
        if ($this->norm_decoded_fragments_string !== false) {
            return $this->norm_decoded_fragments_string;
        }
        $this->getDecodedNormalizedContent();
        return $this->norm_decoded_fragments_string;
    }

    public function getNormDecodedFileContent()
    {
        if ($this->norm_decoded_file_content !== false) {
            return $this->norm_decoded_file_content;
        }
        $this->getDecodedNormalizedContent();
        return $this->norm_decoded_file_content;
    }

    public function getConvertedContent()
    {
        if ($this->converted_file_content !== false) {
            return $this->converted_file_content;
        }
        $this->converted_file_content = '';
        $l_UnicodeContent = Encoding::detectUTFEncoding($this->getContent());
        if ($l_UnicodeContent !== false) {
            if (Encoding::iconvSupported()) {
                $this->converted_file_content = Encoding::convertToCp1251($l_UnicodeContent, $this->getContent());
            }
        }
        $this->converted_file_content = Normalization::normalize($this->converted_file_content);
        return $this->converted_file_content;
    }

    public function getConvertedDecodedContent()
    {
        if (!$this->deobfuscate) {
            $this->converted_decoded = '';
        }
        if ($this->converted_decoded !== false) {
            return $this->converted_decoded;
        }
        $strip = Normalization::strip_whitespace($this->getConvertedContent());
        $deobf_obj = new Deobfuscator($strip, $this->getConvertedContent());
        $deobf_type = $deobf_obj->getObfuscateType($strip);
        if ($deobf_type != '') {
            $this->converted_decoded = $deobf_obj->deobfuscate();
        } else {
            $this->converted_decoded = '';
        }
        $this->converted_decoded = Normalization::normalize($this->converted_decoded);
        return $this->converted_decoded;
    }

    public function getStripDecodedContent()
    {
        if (!$this->deobfuscate) {
            $this->strip_decoded = '';
        }
        if ($this->strip_decoded !== false) {
            return $this->strip_decoded;
        }
        $strip = Normalization::strip_whitespace($this->getContent());
        $deobf_obj = new Deobfuscator($strip, $this->getContent());
        $deobf_type = $deobf_obj->getObfuscateType($strip);
        $this->type = $deobf_type;
        if ($deobf_type != '') {
            $this->strip_decoded = $deobf_obj->deobfuscate();
        } else {
            $this->strip_decoded = '';
        }
        $this->strip_decoded = Normalization::normalize($this->strip_decoded);
        return $this->strip_decoded;
    }
}

class CleanUnit
{

    const URL_GRAB = '~<(script|iframe|object|embed|img|a)\s*.{0,300}?((?:https?:)?\/\/(?:www\.)?[-a-zA-Z0-9@:%._\+\~#=]{2,256}\.[a-z]{2,4}\b(?:[-a-zA-Z0-9@:%_\+.\~#?&/=]*)).{0,300}?</\1>~msi';

    public static function CleanContent(&$file_content, $clean_db, $deobfuscate = false, $unescape = false, $signature_converter = null, $precheck = null, $src_file = null, $demapper = false, &$matched_not_cleaned = null)
    {
        $result = false;
        $content_orig = new ContentObject($file_content, $deobfuscate, $unescape);
        $content = new ContentObject($file_content, $deobfuscate, $unescape);
        $terminate  = false;
        $prev_id = '';

        if (isset($src_file) && $demapper && $deobfuscate) {
            if (self::checkFalsePositives($src_file, $content->getStripDecodedContent(), $content->getType(), $demapper)) {
                return $result;
            }
        }

        foreach ($clean_db->getDB() as $rec_index => $rec) {
            if ($terminate) {
                break;
            }

            if (is_callable($precheck) && !$precheck($rec['mask_type'])) {
                continue;
            }

            switch ($rec['sig_type']) {
                case 4: // normalize first line
                case 5: // match deobfuscated content and replace related obfuscated part
                case 0: // simple match
                    if (isset($signature_converter)) {
                        $inj_sign = $signature_converter->getCutSignature($rec_index);
                    }
                    if (!(isset($inj_sign) && $inj_sign)) {
                        $inj_sign = $rec['sig_match'];
                    }
                    $nohang = 20; // maximum 20 iterations
                    $condition_num = 0; // for debug
                    while (
                        (
                            (
                                preg_match('~' . $rec['sig_match'] . '~smi', $content->getContent(), $fnd, PREG_OFFSET_CAPTURE)
                                && $condition_num = 1
                            )
                            || (
                                ($normalized_file_content = $content->getNormalized())
                                && $normalized_file_content != ''
                                && preg_match('~' . $rec['sig_match'] . '~smi', $normalized_file_content, $norm_fnd, PREG_OFFSET_CAPTURE)
                                && $condition_num = 3
                            )
                            || (
                                ($decoded_fragments_string = $content->getDecodedFragmentsString())
                                && $decoded_fragments_string != ''
                                && preg_match('~' . $inj_sign . '~smi', $decoded_fragments_string, $dec_fnd, PREG_OFFSET_CAPTURE)
                                && $condition_num = 2
                            )
                            || (
                                ($norm_decoded_fragments_string = $content->getNormDecodedFragmentsString())
                                && $norm_decoded_fragments_string != ''
                                && preg_match('~' . $inj_sign . '~smi', $norm_decoded_fragments_string, $norm_dec_fnd, PREG_OFFSET_CAPTURE)
                                && $condition_num = 4
                            )
                            || (
                                ($unescaped_norm = $content->getUnescapedNormalized())
                                && $unescaped_norm != ''
                                && preg_match('~' . $rec['sig_match'] . '~smi', $unescaped_norm, $unescaped_norm_fnd, PREG_OFFSET_CAPTURE)
                                && $condition_num = 5
                            )
                            || (
                                ($unescaped = $content->getUnescaped())
                                && $unescaped != ''
                                && preg_match('~' . $rec['sig_match'] . '~smi', $unescaped, $unescaped_fnd, PREG_OFFSET_CAPTURE)
                                && $condition_num = 6
                            )
                        )
                        && ($nohang-- > 0)
                    ) {
                        if (trim($rec['sig_replace']) === '<?php') {
                            $rec['sig_replace'] = '<?php ';
                        }

                        $normal_fnd = isset($norm_fnd[0][0]) ? $norm_fnd[0][0] : false;
                        $unescaped_normal_fnd = isset($unescaped_norm_fnd[0][0]) ? $unescaped_norm_fnd[0][0] : false;
                        $un_fnd = isset($unescaped_fnd[0][0]) ? $unescaped_fnd[0][0] : false;

                        if (!empty($normal_fnd)) {
                            $pos = Normalization::string_pos($file_content, $normal_fnd);
                            if ($pos !== false) {
                                $replace = self::getReplaceFromRegExp($rec['sig_replace'], $norm_fnd);
                                $file_content = self::replaceString($file_content, $replace, $pos[0], $pos[1] - $pos[0] + 1);
                            }
                        }

                        if (!empty($unescaped_normal_fnd)) {
                            $pos = Normalization::string_pos($file_content, $unescaped_normal_fnd, true);
                            if ($pos !== false) {
                                $replace = self::getReplaceFromRegExp($rec['sig_replace'], $unescaped_norm_fnd);
                                $ser = false;
                                $file_content = self::replaceString($file_content, $replace, $pos[0], $pos[1] - $pos[0] + 1, $ser, true);
                            }
                        }

                        if (!empty($un_fnd)) {
                            $pos = Normalization::string_pos($file_content, $un_fnd, true);
                            if ($pos !== false) {
                                $matched_not_cleaned = false;
                                $replace = self::getReplaceFromRegExp($rec['sig_replace'], $unescaped_fnd);
                                $ser = false;
                                $file_content = self::replaceString($file_content, $replace, $pos[0], $pos[1] - $pos[0] + 1, $ser, true);
                            }
                        }
                      
                        if (isset($fnd) && $fnd) {
                            $replace = self::getReplaceFromRegExp($rec['sig_replace'], $fnd);
                            $file_content = self::replaceString($file_content, $replace, $fnd[0][1], strlen($fnd[0][0]));
                        }
                        $decoded_fragments = $content->getDecodedFragments();
                        if (isset($dec_fnd) && $dec_fnd && !empty($decoded_fragments)) {
                            foreach ($decoded_fragments as $obfuscated => $deobfuscated) {
                                if (preg_match('~' . $inj_sign  . '~smi', Normalization::normalize($deobfuscated))) {
                                    $pos = Normalization::string_pos($file_content, $obfuscated);
                                    if ($pos !== false) {
                                        $replace = self::getReplaceFromRegExp($rec['sig_replace'], $dec_fnd);
                                        $file_content = self::replaceString($file_content, $replace, $pos[0], $pos[1] - $pos[0] + 1);
                                    }
                                }
                            }
                        }

                        $norm_decoded_fragments = $content->getNormDecodedFragments();
                        if (isset($norm_dec_fnd) && $norm_dec_fnd && !empty($norm_decoded_fragments)) {
                            foreach ($norm_decoded_fragments as $obfuscated => $deobfuscated) {
                                if (preg_match('~' . $inj_sign  . '~smi', Normalization::normalize($deobfuscated))) {
                                    $pos = Normalization::string_pos($file_content, $obfuscated);
                                    if ($pos !== false) {
                                        $replace = self::getReplaceFromRegExp($rec['sig_replace'], $norm_fnd);
                                        $file_content = self::replaceString($file_content, $replace, $pos[0], $pos[1] - $pos[0] + 1);
                                    }
                                }
                            }
                        }

                        $file_content = preg_replace('~<\?php\s+\?>~smi', '', $file_content);
                        $file_content = preg_replace('~<\?\s+\?>~smi', '', $file_content);
                        $file_content = preg_replace('~\A\s*<\?php\s*\Z~smi', '', $file_content);
                        $file_content = preg_replace('~\A\s*<\?\s*\Z~smi', '', $file_content);
                        $file_content = preg_replace('~\A\s*\?>\s*\Z~smi', '', $file_content);
                        $file_content = preg_replace('~\A\s+<\?~smi', '<?', $file_content);
                        $file_content = preg_replace('~\A\xEF\xBB\xBF\s*\Z~smi', '', $file_content);

                        $empty = (trim($file_content) == '');

                        if ($prev_id !== $rec['id']) {
                            $result[] = ['sig_type' => $rec['sig_type'], 'id' => $rec['id'], 'empty' => $empty];
                        }

                        $matched_not_cleaned = $content_orig->getContent() === $file_content;

                        if ($empty) {
                            $terminate = true;
                        }

                        if ($file_content !== $content->getContent()) {
                            unset($content);
                            $content = new ContentObject($file_content, $deobfuscate, $unescape);
                        }
                        $prev_id = $rec['id'];
                    } // end of while


                    break;
                case 1: // match signature and delete file
                    $condition_num = 0; // for debug
                    if (
                        (
                            $rec['sig_match'] == '-'
                            && $condition_num = 1
                        )
                        || (
                            preg_match('~' . $rec['sig_match'] . '~smi', $content->getContent(), $m, PREG_OFFSET_CAPTURE)
                            && $condition_num = 2
                        )
                        || (
                            ($decoded_file_content = $content->getNormDecodedFileContent())
                            && $decoded_file_content != ''
                            && preg_match('~' . $rec['sig_match'] . '~smi', $decoded_file_content, $m, PREG_OFFSET_CAPTURE)
                            && $condition_num = 3
                        )
                        || (
                            ($converted_file_content = $content->getConvertedContent())
                            && $converted_file_content != ''
                            && preg_match('~' . $rec['sig_match'] . '~smi', $converted_file_content, $m, PREG_OFFSET_CAPTURE)
                            && $condition_num = 4
                        )
                        || (
                            ($decoded_converted = $content->getConvertedDecodedContent())
                            && $decoded_converted != ''
                            && preg_match('~' . $rec['sig_match'] . '~smi', $decoded_converted, $m, PREG_OFFSET_CAPTURE)
                            && $condition_num = 5
                        )
                        || (
                            ($unescaped = $content->getUnescaped())
                            && $unescaped != ''
                            && preg_match('~' . $rec['sig_match'] . '~smi', $unescaped, $m, PREG_OFFSET_CAPTURE)
                            && $condition_num = 6
                        )
                        || (
                            preg_match('~' . $rec['sig_match'] . '~smi', $content_orig->getContent(), $m, PREG_OFFSET_CAPTURE)
                            && $condition_num = 2
                        )
                        || (
                            ($content_orig->getContent() !== $content->getContent())
                            && ($decoded_file_content = $content_orig->getNormDecodedFileContent())
                            && $decoded_file_content != ''
                            && preg_match('~' . $rec['sig_match'] . '~smi', $decoded_file_content, $m, PREG_OFFSET_CAPTURE)
                            && $condition_num = 3
                        )
                        || (
                            ($content_orig->getContent() !== $content->getContent())
                            && ($converted_file_content = $content_orig->getConvertedContent())
                            && $converted_file_content != ''
                            && preg_match('~' . $rec['sig_match'] . '~smi', $converted_file_content, $m, PREG_OFFSET_CAPTURE)
                            && $condition_num = 4
                        )
                        || (
                            ($content_orig->getContent() !== $content->getContent())
                            && ($decoded_converted = $content_orig->getConvertedDecodedContent())
                            && $decoded_converted != ''
                            && preg_match('~' . $rec['sig_match'] . '~smi', $decoded_converted, $m, PREG_OFFSET_CAPTURE)
                            && $condition_num = 5
                        )
                        || (
                            ($content_orig->getContent() !== $content->getContent())
                            && ($unescaped = $content_orig->getUnescaped())
                            && $unescaped != ''
                            && preg_match('~' . $rec['sig_match'] . '~smi', $unescaped, $m, PREG_OFFSET_CAPTURE)
                            && $condition_num = 6
                        )
                    ) {
                        $file_content = self::replaceString($file_content, '', $m[0][1], false, $serialized);
                        if ($serialized) {
                            $result[] = ['sig_type' => $rec['sig_type'], 'id' => $rec['id'], 'empty' => false];
                        } else {
                            $result[] = ['sig_type' => $rec['sig_type'], 'id' => $rec['id'], 'empty' => true];
                            $file_content = '';
                            $terminate = true;
                        }
                        $matched_not_cleaned = false;
                    }

                    break;
                case 3: // match signature against normalized file and delete it
                    $condition_num = 0; // for debug
                    if (
                        (
                            preg_match('~' . $rec['sig_match'] . '~smi', $content->getNormalized(), $m, PREG_OFFSET_CAPTURE)
                            && $condition_num = 1
                        )
                        || (
                            ($normalized_decoded = $content->getStripDecodedContent())
                            && $normalized_decoded != ''
                            && preg_match('~' . $rec['sig_match'] . '~smi', $normalized_decoded, $m, PREG_OFFSET_CAPTURE)
                            && $condition_num = 2
                        )
                        || (
                            ($decoded_converted = $content->getConvertedDecodedContent())
                            && $decoded_converted != ''
                            && preg_match('~' . $rec['sig_match'] . '~smi', $decoded_converted, $m, PREG_OFFSET_CAPTURE)
                            && $condition_num = 3
                        )
                        || (
                            preg_match('~' . $rec['sig_match'] . '~smi', $content_orig->getNormalized(), $m, PREG_OFFSET_CAPTURE)
                            && $condition_num = 1
                        )
                        || (
                            ($unescaped_norm = $content->getUnescapedNormalized())
                            && $unescaped_norm != ''
                            && preg_match('~' . $rec['sig_match'] . '~smi', $unescaped_norm, $m, PREG_OFFSET_CAPTURE)
                            && $condition_num = 5
                        )
                        || (
                            ($content_orig->getContent() !== $content->getContent())
                            && ($normalized_decoded = $content_orig->getStripDecodedContent())
                            && $normalized_decoded != ''
                            && preg_match('~' . $rec['sig_match'] . '~smi', $normalized_decoded, $m, PREG_OFFSET_CAPTURE)
                            && $condition_num = 2
                        )
                        || (
                            ($content_orig->getContent() !== $content->getContent())
                            && ($decoded_converted = $content_orig->getConvertedDecodedContent())
                            && $decoded_converted != ''
                            && preg_match('~' . $rec['sig_match'] . '~smi', $decoded_converted, $m, PREG_OFFSET_CAPTURE)
                            && $condition_num = 3
                        )
                        || (
                            ($content_orig->getContent() !== $content->getContent())
                            && ($unescaped_norm = $content_orig->getUnescapedNormalized())
                            && $unescaped_norm != ''
                            && preg_match('~' . $rec['sig_match'] . '~smi', $unescaped_norm, $m, PREG_OFFSET_CAPTURE)
                            && $condition_num = 5
                        )
                    ) {
                        $file_content = self::replaceString($file_content, '', $m[0][1], false, $serialized);
                        if ($serialized) {
                            $result[] = ['sig_type' => $rec['sig_type'], 'id' => $rec['id'], 'empty' => false];
                        } else {
                            $result[] = ['sig_type' => $rec['sig_type'], 'id' => $rec['id'], 'empty' => true];
                            $file_content = '';
                            $terminate = true;
                        }
                        $matched_not_cleaned = false;
                    }
                    break;
            }
        }
        self::removeBlackUrls($file_content, $clean_db, $result, $deobfuscate, $unescape);
        return $result;
    }

    public static function isEmpty($result)
    {
        foreach ($result as $item) {
            if($item['empty'] === true) {
                return true;
            }
        }
        return false;
    }

    public static function getSAItem($result)
    {
        foreach ($result as $item) {
            if($item['empty'] === true && ($item['sig_type'] == 1 || $item['sig_type'] == 3)) {
                return [$item];
            }
        }
        return $result;
    }

    private static function getReplaceFromRegExp($replace, $matches)
    {
        if (!empty($replace)) {
            if (preg_match('~\$(\d+)~smi', $replace)) {
                $replace = preg_replace_callback('~\$(\d+)~smi', function ($m) use ($matches) {
                    return isset($matches[(int)$m[1]]) ? $matches[(int)$m[1]][0] : '';
                }, $replace);
            }
        }
        return $replace;
    }

    private static function checkFalsePositives($l_Filename, $l_Unwrapped, $l_DeobfType, $deMapper)
    {
        if ($l_DeobfType == '') {
            return false;
        }
        switch ($l_DeobfType) {
            case 'Bitrix':
                foreach ($deMapper as $fkey => $fvalue) {
                    if ((strpos($l_Filename, $fkey) !== false) && (strpos($l_Unwrapped, $fvalue) !== false)) {
                        return true;
                    }
                }
                break;
        }
        return false;
    }

    private static function replaceString($file_content, $replace, $pos, $delta_len, &$serialized = false, $escapes = false)
    {
        $size2fix = self::getSerializedLength($file_content, $pos, $size2fix_pos);
        if ($size2fix) {
            $serialized = true;
            $delta_len = $delta_len ?: $size2fix;
            $quotes = $escapes ? substr_count($file_content, '\\', $pos, $delta_len) : 0;
            $file_content = substr_replace($file_content, $replace, $pos, $delta_len);
            $new_length = $size2fix - ($delta_len - strlen($replace)) + $quotes;
            $file_content = substr_replace($file_content, (string)$new_length, $size2fix_pos[0], $size2fix_pos[1]);
        } else {
            $file_content = substr_replace($file_content, $replace, $pos, $delta_len);
        }
        return $file_content;
    }

    private static function getSerializedLength($content, $offset, &$pos)
    {
        $ser_size = false;
        if (preg_match_all('~s:(\d+):\\\\?"~m', substr($content, 0, (int)$offset + 1), $m, PREG_OFFSET_CAPTURE | PREG_SET_ORDER)) {
            foreach ($m as $ser_chunk) {
                $start_chunk = $ser_chunk[0][1] + strlen($ser_chunk[0][0]);
                $end_chunk = $start_chunk + (int)$ser_chunk[1][0];
                if ($start_chunk <= $offset && $end_chunk > $offset) {
                    $ser_size = (int)$ser_chunk[1][0];
                    $pos[0] = $ser_chunk[1][1];
                    $pos[1] = strlen($ser_chunk[1][0]);
                    break;
                }
            }
        }
        return $ser_size;
    }

    private static function removeBlackUrls(&$file_content, $clean_db, &$result, $deobfuscate, $unescape)
    {
        if ($clean_db->getScanDB() === null || !class_exists('ScanCheckers')) {
            return;
        }
        $offset = 0;

        while (self::findBlackUrl($file_content, $fnd, $offset, $clean_db, $id)) {
            $offset += $fnd[0][1] + 1;
            $file_content = self::replaceString($file_content, '', $fnd[0][1], strlen($fnd[0][0]));
            $result[] = ['sig_type' => 2, 'id' => $clean_db->getScanDB()->blackUrls->getSig($id), 'empty' => false];
        }

        unset($content);
        $content = new ContentObject($file_content, $deobfuscate, $unescape);
        $offset = 0;
        while (self::findBlackUrl($content->getNormalized(), $fnd, $offset, $clean_db, $id)) {
            $offset += $fnd[0][1] + strlen($fnd[0][0]);
            $pos = Normalization::string_pos($file_content, $fnd[0][0]);
            if ($pos !== false) {
                $replace = self::getReplaceFromRegExp('', $content->getNormalized());
                $file_content = self::replaceString($file_content, $replace, $pos[0], $pos[1] - $pos[0] + 1);
                $result[] = ['sig_type' => 2, 'id' => $clean_db->getScanDB()->blackUrls->getSig($id), 'empty' => false];
            }
        }

        $offset = 0;
        unset($content);
        $content = new ContentObject($file_content, $deobfuscate, $unescape);
        while (self::findBlackUrl($content->getDecodedFragmentsString(), $fnd, $offset, $clean_db, $id)) {
            $offset += $fnd[0][1] + 1;
            $decoded_fragments = $content->getDecodedFragments();
            if (!empty($decoded_fragments)) {
                foreach ($decoded_fragments as $obfuscated => $deobfuscated) {
                    if (self::findBlackUrl($deobfuscated, $fnd_tmp, 0, $clean_db, $id)) {
                        $pos_obf = strpos($file_content, $obfuscated);
                        $len = strlen($obfuscated);
                        $file_content = self::replaceString($file_content, '', $pos_obf, $len);
                        $result[] = ['sig_type' => 2, 'id' => $clean_db->getScanDB()->blackUrls->getSig($id), 'empty' => false];
                    }
                }
            }
            unset($content);
            $content = new ContentObject($file_content, $deobfuscate, $unescape);
        }

        $offset = 0;
        unset($content);
        $content = new ContentObject($file_content, $deobfuscate, $unescape);
        while (self::findBlackUrl($content->getNormDecodedFragmentsString(), $fnd, $offset, $clean_db, $id)) {
            $offset += $fnd[0][1] + 1;
            $norm_decoded_fragments = $content->getNormDecodedFragments();
            if (!empty($norm_decoded_fragments)) {
                foreach ($norm_decoded_fragments as $obfuscated => $deobfuscated) {
                    if (self::findBlackUrl(Normalization::normalize($deobfuscated), $fnd_tmp, 0, $clean_db, $id)) {
                        $pos = Normalization::string_pos($file_content, $obfuscated);
                        if ($pos !== false) {
                            $file_content = self::replaceString($file_content, '', $pos[0], $pos[1] - $pos[0] + 1);
                            $result[] = ['sig_type' => 2, 'id' => $clean_db->getScanDB()->blackUrls->getSig($id), 'empty' => false];
                        }
                    }
                }
            }
            unset($content);
            $content = new ContentObject($file_content, $deobfuscate, $unescape);
            $offset = 0;
            while (self::findBlackUrl($content->getUnescaped(), $fnd, $offset, $clean_db, $id)) {
                $offset += $fnd[0][1] + strlen($fnd[0][0]);
                $pos = Normalization::string_pos($file_content, $fnd[0][0]);
                if ($pos !== false) {
                    $replace = self::getReplaceFromRegExp('', $content->getUnescaped());
                    $file_content = self::replaceString($file_content, $replace, $pos[0], $pos[1] - $pos[0] + 1);
                    $result[] = ['sig_type' => 2, 'id' => $clean_db->getScanDB()->blackUrls->getSig($id), 'empty' => false];
                }
            }

            unset($content);
            $content = new ContentObject($file_content, $deobfuscate, $unescape);
            $offset = 0;
            while (self::findBlackUrl($content->getUnescapedNormalized(), $fnd, $offset, $clean_db, $id)) {
                $offset += $fnd[0][1] + strlen($fnd[0][0]);
                $pos = Normalization::string_pos($file_content, $fnd[0][0]);
                if ($pos !== false) {
                    $replace = self::getReplaceFromRegExp('', $content->getUnescapedNormalized());
                    $file_content = self::replaceString($file_content, $replace, $pos[0], $pos[1] - $pos[0] + 1);
                    $result[] = ['sig_type' => 2, 'id' => $clean_db->getScanDB()->blackUrls->getSig($id), 'empty' => false];
                }
            }
            unset($content);
            $content = new ContentObject($file_content, $deobfuscate, $unescape);
        }
    }

    private static function findBlackUrl($item, &$fnd, $offset, $clean_db, &$id)
    {
        return preg_match(self::URL_GRAB, $item, $fnd, PREG_OFFSET_CAPTURE, $offset)
            && !ScanCheckers::isOwnUrl($fnd[0][0], $clean_db->getScanDB()->getOwnUrl())
            && (isset($clean_db->getScanDB()->whiteUrls) && !ScanCheckers::isUrlInList($fnd[0][0],
                    $clean_db->getScanDB()->whiteUrls->getDb()))
            && ($id = ScanCheckers::isUrlInList($fnd[0][0], $clean_db->getScanDB()->blackUrls->getDb()));
    }
}
class SignatureConverter {
    
    private $signatures         = [];
    private $cuted_signatures   = [];
    private $count_convert      = 0;
    
    public function __construct($clean_db) 
    {
        $this->signatures = $clean_db;
    }
    
    public function getCutSignature($sig_index) 
    {
        if (!isset($this->signatures[$sig_index])) {
            return false;
        }
        $signature = $this->signatures[$sig_index]['sig_match'];
        if (!isset($this->cuted_signatures[$sig_index])) {
            $cuted_signature = $this->cut($signature);
            if ($signature != $cuted_signature) {
                $this->cuted_signatures[$sig_index] = $cuted_signature;
            }
            else {
                $this->cuted_signatures[$sig_index] = false;
            }
            return $cuted_signature;
        }
        elseif ($this->cuted_signatures[$sig_index] === false) {
            return $signature;
        }
        return $this->cuted_signatures[$sig_index];
    }
    
    public function getCountConverted()
    {
        return $this->count_convert;
    }

    // /////////////////////////////////////////////////////////////////////////
    
    private function cut($signature)
    {
        $this->count_convert++;
        $regexp = '^'
        . '(?:\\\A)?'
        . '(?:\\\s\*)?'
        . '<\\\\\?'
        . '(?:\\\s\*)?'
        . '(?:\\\s\+)?'            
        . '(?:'
            .'php'
            . '|\(\?:php\)\?'
            . '|='
            . '|\(\?:php\|=\)\??'
            . '|\(\?:=\|php\)\??'
        . ')?'
        . '(?:\\\s\+)?'
    
        . '(.*?)'

        . '(?:\(\??:?\|?)?'
        . '\\\\\?>'
        . '(?:\\\s\*)?'
        . '(?:\|?\\\Z\)?)?'
        . '$';
    
        return preg_replace('~' . $regexp . '~smi', '\1', $signature);
    }
}

class Logger
{
    /**
     * $log_file - path and log file name
     * @var string
     */
    protected $log_file;
    /**
     * $file - file
     * @var string
     */
    protected $file;
    /**
     * dateFormat
     * @var string
     */
    protected $dateFormat = 'd-M-Y H:i:s';

    /**
     * @var array
     */
    const LEVELS  = ['ERROR' => 1, 'DEBUG' => 2,  'INFO' => 4, 'ALL' => 7];

    /**
     * @var int
     */
    private $level;

    /**
     * Class constructor
     *
     * @param string       $log_file - path and filename of log
     * @param string|array $level    - Level of logging
     *
     * @throws Exception
     */
    public function __construct($log_file = null, $level = 'INFO')
    {
        if (!$log_file) {
            return;
        }
        if (is_array($level)) {
            foreach ($level as $v) {
                if (!isset(self::LEVELS[$v])) {
                    $v = 'INFO';
                }
                $this->level |= self::LEVELS[$v];
            }
        } else {
            if (isset(self::LEVELS[$level])) {
                $this->level = self::LEVELS[$level];
            } else {
                $this->level = self::LEVELS['INFO'];
            }
        }

        $this->log_file = $log_file;
        //Create log file if it doesn't exist.
        if (!file_exists($log_file)) {
            fopen($log_file, 'w') or exit("Can't create $log_file!");
        }
        //Check permissions of file.
        if (!is_writable($log_file)) {
            //throw exception if not writable
            throw new Exception('ERROR: Unable to write to file!', 1);
        }
    }

    /**
     * Info method (write info message)
     * @param string $message
     * @return void
     */
    public function info($message)
    {
        if ($this->level & self::LEVELS['INFO']) {
            $this->writeLog($message, 'INFO');
        }

    }
    /**
     * Debug method (write debug message)
     * @param string $message
     * @return void
     */
    public function debug($message)
    {
        if ($this->level & self::LEVELS['DEBUG']) {
            $this->writeLog($message, 'DEBUG');
        }
    }
    /**
     * Error method (write error message)
     * @param string $message
     * @return void
     */
    public function error($message)
    {
        if ($this->level & self::LEVELS['ERROR']) {
            $this->writeLog($message, 'ERROR');
        }
    }

    /**
     * Write to log file
     * @param string $message
     * @param string $level
     * @return void
     */
    public function writeLog($message, $level)
    {
        if (!$this->log_file) {
            return;
        }
        // open log file
        if (!is_resource($this->file)) {
            $this->openLog();
        }
        //Grab time - based on timezone in php.ini
        $time = date($this->dateFormat);
        // Write time & message to end of file
        fwrite($this->file, "[$time] : [$level] - $message" . PHP_EOL);
    }
    /**
     * Open log file
     * @return void
     */
    private function openLog()
    {
        $openFile = $this->log_file;
        // 'a' option = place pointer at end of file
        $this->file = fopen($openFile, 'a') or exit("Can't open $openFile!");
    }
    /**
     * Class destructor
     */
    public function __destruct()
    {
        if ($this->file) {
            fclose($this->file);
        }
    }
}