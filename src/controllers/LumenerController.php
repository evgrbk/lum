<?php
namespace Evgrbk\Lum\Controllers;

use Illuminate\Routing\Controller;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Artisan;

class LumenerController extends Controller
{
    protected $adminer;
    protected $adminer_object;
    protected $plugins_path;
    protected $allowed_dbs;
    protected $protected_dbs;
    protected $request;
    protected $mimes;

    public function __construct(Request $request)
    {
        if (method_exists(\Route::class, 'hasMiddlewareGroup')
        && \Route::hasMiddlewareGroup('lumener')) {
            $this->middleware('lumener');
        }
        // LumenerServiceProvider::register holds the middleware register
        // so it does not need to be addeed manually.
        // User-defined middleware is handled during route definition for Lumen
        $this->allowed_dbs = config('lumener.security.allowed_db');
        $this->protected_dbs = config('lumener.security.protected_db');
        $this->adminer = LUMENER_STORAGE.'/adminer.php';
        $this->adminer_object = __DIR__.'/../logic/adminer_object.php';
        $this->plugins_path = LUMENER_STORAGE.'/plugins';
        $this->request = $request;
        $this->mimes = new \Mimey\MimeTypes;
    }

    public function __call($method, $params)
    {
        if (strncasecmp($method, "get", 3) === 0) {
            $var = preg_replace_callback('/[A-Z]/', function ($c) {
                return '_'.strtolower($c[0]);
            }, lcfirst(substr($method, 3)));
            return $this->$var;
        }
    }

    public function index()
    {
        if ($this->request->cookie('adminer_logged_out')
            && config('lumener.logout_redirect')) {
            return redirect(config('lumener.logout_redirect'));
        }
        if (isset($_POST['logout'])) {
            $t = encrypt(time());
            $h = "Set-Cookie: adminer_logged_out={$t}; expires=".gmdate(
                "D, d M Y H:i:s",
                time() + config('lumener.logout_cooldown', 10)
            )." GMT; path=".preg_replace('~\?.*~', '', $_SERVER["REQUEST_URI"]);
            header($h);
        }
        if (file_exists($this->adminer)) {
            return $this->_runAdminer();
        } else {
            return '<div style="text-align:center;color: red;
                                margin-top: 200px;font-weight:bold;">
                      Adminer was NOT found.
                      Run <span style="color:lightgreen;background:black;
                                       padding: 5px;border: 5px dashed white;">
                                       php artisan lumener:update --force</span>
                                       to fix any issues.
                    </div>
            ';
        }
    }

    public function update()
    {
        Artisan::call('lumener:update');
        return nl2br(Artisan::output());
    }

    public function getResource()
    {
        $file = $this->request->get('file');
        $path = realpath(LUMENER_STORAGE."/{$file}");
        // Prevent risky file fetching
        // This check is very important, it's a major security risk to allow
        // Fetching files outside the LUMENER_STORAGE directory
        if (
            $path === false
            || strncmp($path, LUMENER_STORAGE, strlen(LUMENER_STORAGE)) !== 0
        ) {
            abort(403);
        }
        $type = $this->request->get('type', mime_content_type($path));
        return response()->download($path, $file, ["Content-Type"=>$type]);
    }

    public function isDBBlocked($db)
    {
        return
        (
            $this->allowed_dbs !== null
            && !in_array($db, $this->allowed_dbs)
        )
        ||
        (
            $this->protected_dbs !== null
            && in_array($db, $this->protected_dbs)
        );
    }

    private function _runAdminer()
    {
        $this->_handleAdminerAutoLogin();

        // Known Issues
        $this->_patchAdminerRequest();

        // Security Check
        $this->_verifyAdminerRequest();

        $content =
            $this->_runGetBuffer(
                [$this->adminer_object, $this->adminer],
                [E_WARNING],
                "/LUMENER_OVERRIDE_exit/"
            );
        $pos = strpos($content, "<!DOCTYPE html>");
        if ($pos === false) {
            die($content);
        }

        // This is a work-around for a strange issue where the error
        // that happens in place of exit does not stop execution and the html
        // is rendered after the CSS/JS/Image file
        if ($pos != 0) {
            if (isset($_GET['file'])) {
                $type = $this->_guessFileType($_GET['file']);
                header("Content-Type: {$type}");
            }
            die(substr($content, 0, $pos));
        }

        return $content;
    }

    private function _guessFileType($name)
    {
        $ext = end(explode('.', $name));
        return $this->mimes->getMimeType($ext);
    }

    private function _handleAdminerAutoLogin()
    {
        if (!isset($_GET['username']) && !isset($_POST['auth'])
            && config('lumener.auto_login')
            && !$this->request->cookie('adminer_logged_out')) {
            // Skip login screen
            $_GET['username'] =
                config('lumener.db.username', env("DB_USERNAME"));
            $_GET['db'] =
                config('lumener.db.database', env("DB_DATABASE"));
            // Password is set in the adminer extension
        }
    }

    private function _verifyAdminerRequest()
    {
        if ((isset($_GET['db']) && $_GET['db']
            && $this->isDBBlocked($_GET['db']))
        || (isset($_POST['auth']['db']) && $_POST['auth']['db']
            && $this->isDBBlocked($_POST['auth']['db']))) {
            abort(403);
        }
    }

    private function _patchAdminerRequest()
    {
        if (!isset($_SERVER['HTTP_IF_MODIFIED_SINCE'])) {
            $_SERVER['HTTP_IF_MODIFIED_SINCE'] = null;
        }
    }

    private function _runGetBuffer(
        $files,
        $termination_errors,
        $err_pattern
    ) {
        // Prepare for unhandled errors
        // Termination errors are not necessarily going to be thrown
        $this->_setupErrorHandling($termination_errors, $err_pattern);
        // Require files
        ob_implicit_flush(0);
        ob_start();
        try {
            foreach ($files as $file) {
                // require because include will not throw the adminer_exit error
                require($file);
            }
        } catch (\ErrorException $e) {
            if (config('lumener.debug')
            || !in_array($e->getSeverity(), $termination_errors)) {
                throw $e;
            }
        }
        $this->_stopErrorHandling();
        $content = "";
        while ($level = ob_get_clean()) {
            $content = $level . $content;
        }
        return $content;
    }

    private function _setupErrorHandling($termination_errors, $pattern)
    {
        $handled = 0;
        foreach ($termination_errors as $code) {
            $handled |= $code;
        }
        set_error_handler(
            function ($err_severity, $err_msg, $err_file, $err_line) use ($pattern) {
                // Check if suppressed with the @-operator
                if (0 === error_reporting()) {
                    return false;
                }
                if (preg_match($pattern, $err_msg)) {
                    throw new \ErrorException($err_msg, $err_severity, $err_severity, $err_file, $err_line);
                }
                return false;
            },
            $handled
        );
    }

    private function _stopErrorHandling()
    {
        set_error_handler(null);
    }
}
