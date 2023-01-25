<?php
/**
 * Update adminer
 *
 * @author    Hesham A. Meneisi heshammeneisi@gmail.com
 * @copyright 2019 Hesham Meneisi
 * @license   http://www.opensource.org/licenses/mit-license.php MIT
 */

namespace Evgrbk\Lum\Console;

use Illuminate\Console\Command;
use Evgrbk\Lum\Helpers\ShellHelper;

/**
 * A command to update the file for adminer.php
 *
 * @author Charles A. Peterson <artistan@gmail.com>
 */
class UpdateCommand extends Command
{
    /**
     * @var String $version
     */
    protected $version;

    /**
     * @var String $filename
     */
    protected $filename;

    /**
     * The name and signature of the console command.
     *
     * @var string
     */
    protected $signature = 'lumener:update {--force}';

    public function __construct()
    {
        parent::__construct();

        $this->filename = LUMENER_STORAGE.'/adminer.php';
    }

    /**
     * Execute the console command.
     *
     * @return void
     */
    public function handle()
    {
        $force = $this->option('force', false);
        if ($force) {
            $this->error("Force mode active.");
        }
        $current_version = $this->_getCurrentAdminerVersion();
        if ($current_version) {
            $this->info("Lumener: Current ".$current_version);
        } else {
            $this->error("Lumener: Adminer not found.");
        }
        $version = $this->_getRequiredAdminerVersion();
        if ($force || !file_exists($this->filename)
            || $version != $current_version) {
            $this->_downloadVersion($version);
        } else {
            $this->info('Lumener: Up to date.');
        }
    }

    private function _getCurrentAdminerVersion()
    {
        $current_version = false;
        try {
            if (file_exists($this->filename)) {
                $fn = fopen($this->filename, "r");
                if ($fn !== false) {
                    for ($i = 0; !$current_version && $i < 20 && !feof($fn); $i++) {
                        $line = fgets($fn, 30);
                        preg_match_all("/@version ((\d([\.-]|$))+)/", $line, $m);
                        if (!empty($m[1])) {
                            $current_version = $m[1][0];
                        }
                    }
                }
            }
        } catch (\Throwable $e) {
            // Just return false
        }
        return $current_version;
    }

    private function _getRequiredAdminerVersion()
    {
        $vsource = config(
            'lumener.adminer_version',
            'https://api.github.com/repos/vrana/adminer/releases/latest'
        );
        if (config('lumener.adminer.version_type', 'url') == 'url') {
            $version = $this->_getLatestAdminerVersion($vsource);
            $this->info("Lumener: Latest Adminer Version ".$version);
        } else {
            $version = $vsource;
            $this->info("Lumener: Required Adminer Version ".$version);
        }
        return $version;
    }

    /**
     * Rename functions already defined in Laravel/Lumen public helper
     */
    private function _patchAdminer()
    {
        foreach (config(
            'lumener.adminer.rename_list',
            ['redirect', 'cookie', 'view', 'exit', 'ob_flush', 'ob_end_clean']
        ) as $var) {
            ShellHelper::rename($var, $this->filename);
        }
    }

    /**
     * Retreives the most recent adminer release version
     * @return string Version
     */
    private function _getLatestAdminerVersion($vsource)
    {
        $this->info("Lumener: Checking latest adminer version...");
        $response = ShellHelper::get($vsource);
        if (!$response || $response->getStatusCode() != '200') {
            $this->error(
                'Lumener: Could not retrieve version information from url.'
                .
                (
                    $response ? "\r\n[{$response->getStatusCode()}]
                    {$response->getReasonPhrase()} {(string)$response->getBody()}"
                    : "Connection Failed.\r\n" . ShellHelper::$LastError
                )
            );
            return;
        }
        return
            ltrim(json_decode((string) $response->getBody())->tag_name, 'v');
    }

    /**
     * Downloads the speicifed adminer.php version
     * @param  string $version
     * @return bool Success
     */
    private function _downloadVersion($version)
    {
        $this->info("Lumener: Downloading...");
        $url = config(
            'lumener.adminer.source',
            'https://github.com/vrana/adminer/releases/download/v{version}/adminer-{version}.php'
        );
        $url = str_replace("{version}", ltrim($version, 'v'), $url);
        $response = ShellHelper::get($url, ['sink' => $this->filename]);
        if ($response && $response->getStatusCode() == '200') {
            $this->info("Lumener: Patching adminer.php...");
            $this->_patchAdminer();
            $this->info("Lumener: Updated!");
            return true;
        } else {
            $this->error(
                'Lumener: Could not download adminer.php.'
                .
                (
                    $response ? "\r\n[{$response->getStatusCode()}]
                    {$response->getReasonPhrase()} {(string)$response->getBody()}"
                    : "Connection Failed.\r\n".ShellHelper::$LastError
                )
            );
            return false;
        }
    }
}
