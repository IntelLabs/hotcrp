<?php
// Hotcrapi.php -- Hotcrapi command-line tool interacts with HotCRP APIs
// Copyright (c) 2006-2025 Eddie Kohler; see LICENSE.

if (realpath($_SERVER["PHP_SELF"]) === __FILE__) {
    require_once(dirname(__DIR__) . "/src/init.php");
}

interface CLIBatchCommand {
    /** @return int */
    function run(Hotcrapi_Batch $clib);
}

class Hotcrapi_Batch_Site {
    /** @var string */
    public $site;
    /** @var string */
    public $apitoken;
}

class Hotcrapi_File {
    /** @var resource */
    public $stream;
    /** @var string */
    public $filename;
    /** @var string */
    public $input_filename;
    /** @var ?int */
    public $size;

    /** @param string $fn
     * @return Hotcrapi_File */
    static function make($fn, $mode = "rb") {
        if ($fn === "") {
            throw new CommandLineException("Empty filename");
        }
        $cf = new Hotcrapi_File;
        if ($fn === "-") {
            $cf->stream = STDIN;
            $cf->filename = null;
            $cf->input_filename = "<stdin>";
        } else if (($cf->stream = @fopen($fn, $mode))) {
            $cf->filename = preg_replace('/\A.*\/(?=[^\/]+\z)/', "", $fn);
            $cf->input_filename = $fn;
        } else {
            throw CommandLineException::make_file_error($fn);
        }
        if (($stat = fstat($cf->stream)) && $stat["size"] > 0) {
            $cf->size = $stat["size"];
        }
        return $cf;
    }

    /** @param string $data
     * @return Hotcrapi_File */
    static function make_data($data) {
        $cf = new Hotcrapi_File;
        $cf->stream = fopen("php://temp", "w+b");
        fwrite($cf->stream, $data);
        rewind($cf->stream);
        $cf->input_filename = "<data>";
        $cf->size = strlen($data);
        return $cf;
    }
}

class Hotcrapi_Batch extends MessageSet {
    /** @var string
     * @readonly */
    public $site;
    /** @var string
     * @readonly */
    public $apitoken;
    /** @var bool
     * @readonly */
    public $quiet = false;
    /** @var bool
     * @readonly */
    public $verbose = false;
    /** @var int
     * @readonly */
    public $chunk = 8 << 20;

    /** @var CurlHandle */
    public $curlh;
    /** @var resource */
    public $headerf;
    /** @var int */
    public $status_code;
    /** @var string */
    public $content_string;
    /** @var ?object */
    public $content_json;

    /** @var CLIBatchCommand */
    private $command;
    /** @var ?string */
    private $output;

    /** @var array<string,Hotcrapi_Batch_Site> */
    private $siteconfig = [];
    /** @var ?Hotcrapi_Batch_Site */
    private $default_siteconfig;

    function __construct() {
        $this->curlh = curl_init();
        curl_setopt($this->curlh, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($this->curlh, CURLOPT_CUSTOMREQUEST, "POST");
        curl_setopt($this->curlh, CURLOPT_HTTPAUTH, CURLAUTH_BEARER);
        $this->headerf = fopen("php://memory", "w+b");
        curl_setopt($this->curlh, CURLOPT_WRITEHEADER, $this->headerf);
        curl_setopt($this->curlh, CURLOPT_SAFE_UPLOAD, true);
    }

    /** @param bool $x
     * @suppress PhanAccessReadOnlyProperty
     * @return $this */
    function set_quiet($x) {
        $this->quiet = $x;
        return $this;
    }

    /** @param bool $x
     * @suppress PhanAccessReadOnlyProperty
     * @return $this */
    function set_verbose($x) {
        $this->verbose = $x;
        return $this;
    }

    /** @param int $x
     * @suppress PhanAccessReadOnlyProperty
     * @return $this */
    function set_chunk($x) {
        $this->chunk = $x;
        return $this;
    }

    /** @suppress PhanAccessReadOnlyProperty
     * @return $this */
    function set_command(CLIBatchCommand $command) {
        $this->command = $command;
        return $this;
    }

    /** @param ?string $s
     * @suppress PhanAccessReadOnlyProperty
     * @return $this */
    function set_output($s) {
        $this->output = $s;
        return $this;
    }

    /** @param mixed $x
     * @suppress PhanAccessReadOnlyProperty
     * @return $this */
    function set_json_output($x) {
        $this->output = json_encode_db($x, JSON_PRETTY_PRINT) . "\n";
        return $this;
    }

    /** @param string $s
     * @return string */
    static private function unquote($s) {
        return str_starts_with($s, "\"") ? substr($s, 1, -1) : $s;
    }

    /** @param ?string $f
     * @suppress PhanAccessReadOnlyProperty
     * @return $this */
    function load_config_file($f) {
        if ($f === "none") {
            return $this;
        }
        if (!isset($f)) {
            $f = getenv("HOME") . "/.hotcrapi.conf";
            if (!file_exists($f)) {
                return $this;
            }
        }
        if ($f === "-") {
            $s = stream_get_contents(STDIN);
            $fname = "<stdin>";
        } else {
            $s = file_get_contents($f);
            if ($s === false) {
                throw CommandLineException::make_file_error($f);
            }
            $fname = $f;
        }

        $sn = null;
        $line = 0;
        foreach (preg_split('/\r\n?|\n/', $s) as $l) {
            ++$line;
            if (preg_match('/\A\s*+\[\s*+site\s*+(\w+|\".*?\"|(?=\]))\s*+\]\s*+\z/', $l, $m)) {
                $sn = self::unquote($m[1]);
                $this->siteconfig[$sn] = $this->siteconfig[$sn] ?? new Hotcrapi_Batch_Site;
            } else if (preg_match('/\A\s*+\[/', $l)) {
                $sn = null;
            } else if ($sn === null) {
                continue;
            } else if (preg_match('/\A\s*+(?:site|url)\s*+=\s*+([^\"]++|\".*?\")\s*+\z/', $l, $m)) {
                $s = self::unquote($m[1]);
                if (!preg_match('/\Ahttps?:\/\//', $s)) {
                    throw new CommandLineException("{$fname}:{$line}: Invalid `site`");
                }
                $this->siteconfig[$sn]->site = $s;
            } else if (preg_match('/\A\s*+apitoken\s*+=\s*+([^\"]++|\".*?\")\s*+\z/', $l, $m)) {
                $s = self::unquote($m[1]);
                if (!preg_match('/\Ahct_[A-Za-z0-9]{30,}/', $s)) {
                    throw new CommandLineException("{$fname}:{$line}: Invalid `apitoken`");
                }
                $this->siteconfig[$sn]->apitoken = $s;
            } else if (preg_match('/\A\s*+default\s*+=\s*+true\s*+\z/', $l, $m)) {
                $this->default_siteconfig = $this->siteconfig[$sn];
            }
        }

        if (($dsc = $this->default_siteconfig)) {
            if ($this->site !== null && $dsc->site !== null) {
                $this->site = $dsc->site;
            }
            if ($this->apitoken !== null && $dsc->apitoken !== null) {
                $this->set_apitoken($dsc->apitoken);
            }
        }
    }

    /** @return ?Hotcrapi_Batch_Site */
    function default_site() {
        return $this->default_siteconfig;
    }

    /** @param string|Hotcrapi_Batch_Site $s
     * @return $this
     * @suppress PhanAccessReadOnlyProperty */
    function set_site($s) {
        if ($s instanceof Hotcrapi_Batch_Site) {
            if ($s->site !== null) {
                $this->site = $s->site;
            }
            if ($s->apitoken !== null) {
                $this->set_apitoken($s->apitoken);
            }
        } else {
            $this->site = $s;
        }
        if (!$this->site) {
            $this->site = null;
            return $this;
        }
        if (!str_starts_with($this->site, "http://")
            && !str_starts_with($this->site, "https://")) {
            $this->site = "https://{$this->site}";
        }
        if (!preg_match('/\/api(?:\.php|)\z/', $this->site)) {
            $this->site .= (str_ends_with($this->site, "/") ? "" : "/") . "api";
        }
        return $this;
    }

    /** @return bool */
    function has_site() {
        return $this->site !== null;
    }

    /** @param string $t
     * @return $this
     * @suppress PhanAccessReadOnlyProperty */
    function set_apitoken($t) {
        if (!preg_match('/\Ahct_[A-Za-z0-9]{30,}\z/', $t)) {
            throw new CommandLineException("Invalid APITOKEN");
        }
        $this->apitoken = $t;
        curl_setopt($this->curlh, CURLOPT_XOAUTH2_BEARER, $this->apitoken);
        return $this;
    }

    /** @return bool */
    function has_apitoken() {
        return $this->apitoken !== null;
    }

    /** @param ?callable(Hotcrapi_Batch):bool $skip_function
     * @return bool */
    function exec_api($skip_function = null) {
        if ($this->verbose) {
            fwrite(STDERR, curl_getinfo($this->curlh, CURLINFO_EFFECTIVE_URL));
        }
        rewind($this->headerf);
        ftruncate($this->headerf, 0);
        $this->content_string = curl_exec($this->curlh);
        $this->status_code = curl_getinfo($this->curlh, CURLINFO_RESPONSE_CODE);
        if ($this->verbose) {
            fwrite(STDERR, ": {$this->status_code}\n");
        }
        $this->content_json = json_decode($this->content_string);
        if (!is_object($this->content_json)) {
            $this->content_json = null;
        }
        if ($skip_function && call_user_func($skip_function, $this)) {
            return true;
        }
        if (!$this->content_json) {
            $this->error_at(null, "<0>Invalid response from server");
            if ($this->verbose) {
                fwrite(STDERR, $this->content_string);
            }
            return false;
        }
        if (($this->content_json->ok ?? null) === false
            && isset($this->content_json->status_code)
            && is_int($this->content_json->status_code)
            && $this->content_json->status_code >= 100
            && $this->content_json->status_code <= 599) {
            $this->status_code = $this->content_json->status_code;
        }
        foreach ($this->content_json->message_list ?? [] as $mj) {
            $this->append_item(MessageItem::from_json($mj));
        }
        if ($this->status_code === 429) {
            rewind($this->headerf);
            $hdata = stream_get_contents($this->headerf);
            if (preg_match('/^x-ratelimit-reset:\s*(\d+)\s*/mi', $hdata, $m)) {
                $this->append_item(MessageItem::inform("<0>The rate limit will reset in " . plural(intval($m[1]) - Conf::$now, "second") . "."));
            }
        }
        if ($this->status_code <= 299
            && ($this->content_json->ok ?? false)) {
            return true;
        }
        if (!$this->has_error()) {
            $this->error_at(null, "<0>Server returned {$this->status_code} error response");
        }
        return false;
    }

    /** @return int */
    function run() {
        if (!$this->has_site()) {
            throw new CommandLineException("`-S SITE` required");
        }
        if (!$this->has_apitoken()) {
            throw new CommandLineException("`-T APITOKEN` required");
        }
        $status = $this->command->run($this);
        if (!$this->quiet) {
            fwrite(STDERR, $this->full_feedback_text(true));
        }
        if (($this->output ?? "") !== "") {
            fwrite(STDOUT, $this->output);
        }
        return $status;
    }

    /** @param list<string> $argv
     * @return Hotcrapi_Batch */
    static function make_args($argv) {
        $getopt = (new Getopt)->long(
            "help::,h:: !",
            "S:,siteurl:,url: =SITE Site URL",
            "T:,token: =APITOKEN API token",
            "F:,config: =FILE Set configuration file [~/.hotcrapi.conf]",
            "verbose,V Be verbose",
            "quiet Do not print error messages",
            "chunk: =CHUNKSIZE Maximum upload chunk size [8M]"
        )->description("Interact with HotCRP site using APIs
Usage: php batch/hotcrapi.php -S SITEURL -T APITOKEN SUBCOMMAND ARGS...")
         ->helpopt("help")
         ->subcommand(true);
        Paper_CLIBatch::register_options($getopt);
        Upload_CLIBatch::register_options($getopt);
        $arg = $getopt->parse($argv);

        $hcli = new Hotcrapi_Batch;
        $hcli->load_config_file($arg["F"] ?? null);

        if (isset($arg["S"])) {
            $hcli->set_site($arg["S"]);
        } else if (isset($_ENV["HOTCRAPI_SITE"])) {
            $hcli->set_site($_ENV["HOTCRAPI_SITE"]);
        }

        if (isset($arg["T"])) {
            if (str_starts_with($arg["T"], "<")) {
                $t = @file_get_contents(substr($arg["T"], 1));
                if ($t === false) {
                    throw CommandLineException::make_file_error(substr($arg["T"], 1));
                }
            } else {
                $t = $arg["T"];
            }
            $hcli->set_apitoken($t);
        } else if (isset($_ENV["HOTCRAPI_TOKEN"])) {
            $hcli->set_apitoken($_ENV["HOTCRAPI_TOKEN"]);
        }

        if (isset($arg["quiet"])) {
            $hcli->set_quiet(true);
        }
        if (isset($arg["verbose"])) {
            $hcli->set_verbose(true);
        }
        if (isset($arg["chunk"])) {
            if (!preg_match('/\A([\d+]\.?\d*|\.\d+)([kmg]i?b?|)\z/i', $arg["chunk"], $m)) {
                throw new CommandLineException("Invalid `--chunk`");
            }
            $n = (float) $m[1];
            if ($m[2] !== "") {
                /** @phan-suppress-next-line PhanParamSuspiciousOrder */
                $x = (int) strpos(".kmg", strtolower($m[2][0]));
                if (strlen($m[2]) === 2) {
                    $n *= 10 ** (3 * $x);
                } else {
                    $n *= 1 << (10 * $x);
                }
            }
            $hcli->set_chunk((int) $n);
        }

        if ($arg["_subcommand"] === "upload") {
            $hcli->set_command(Upload_CLIBatch::make_arg($hcli, $getopt, $arg));
        } else if ($arg["_subcommand"] === "paper") {
            $hcli->set_command(Paper_CLIBatch::make_arg($hcli, $getopt, $arg));
        } else {
            throw new CommandLineException("Subcommand required");
        }

        return $hcli;
    }
}

if (realpath($_SERVER["PHP_SELF"]) === __FILE__) {
    exit(Hotcrapi_Batch::make_args($argv)->run());
}
