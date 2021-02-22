<?php
// src/settings/s_reviewform.php -- HotCRP review form definition page
// Copyright (c) 2006-2020 Eddie Kohler; see LICENSE.

class ReviewForm_SettingParser extends SettingParser {
    private $nrfj;
    private $byname;
    private $option_error;

    private function check_options(SettingValues $sv, $fid, $fj) {
        $text = cleannl($sv->reqv("rf_{$fid}_options"));
        $letters = ($text && ord($text[0]) >= 65 && ord($text[0]) <= 90);
        $expect = ($letters ? "[A-Z]" : "[1-9][0-9]*");

        $opts = array();
        $lowonum = 10000;
        $allow_empty = false;

        foreach (explode("\n", $text) as $line) {
            $line = trim($line);
            if ($line != "") {
                if (preg_match("/^($expect)[\\.\\s]\\s*(\\S.*)/", $line, $m)
                    && !isset($opts[$m[1]])) {
                    $onum = $letters ? ord($m[1]) : intval($m[1]);
                    $lowonum = min($lowonum, $onum);
                    $opts[$onum] = $m[2];
                } else if (preg_match('/^(?:0\.\s*)?No entry$/i', $line)) {
                    $allow_empty = true;
                } else {
                    return false;
                }
            }
        }

        // numeric options must start from 1
        if (!$letters && count($opts) > 0 && $lowonum != 1) {
            return false;
        }

        $text = "";
        $seqopts = array();
        for ($onum = $lowonum; $onum < $lowonum + count($opts); ++$onum) {
            if (!isset($opts[$onum]))       // options out of order
                return false;
            $seqopts[] = $opts[$onum];
        }

        unset($fj->option_letter, $fj->allow_empty);
        if ($letters) {
            $seqopts = array_reverse($seqopts, true);
            $fj->option_letter = chr($lowonum);
        }
        $fj->options = array_values($seqopts);
        if ($allow_empty) {
            $fj->allow_empty = true;
        }
        return true;
    }

    private function populate_field($fj, ReviewField $f, SettingValues $sv, $fid) {
        $sn = $fj->name;
        if ($sv->has_reqv("rf_{$fid}_name")) {
            $sn = simplify_whitespace($sv->reqv("rf_{$fid}_name"));
        }
        if (in_array($sn, ["<None>", "<New field>", "Field name", ""], true)) {
            $sn = "";
        } else {
            $fj->name = $sn;
        }
        $error_sn = $sn ? : "<Unnamed field>";

        if ($sv->has_reqv("rf_{$fid}_position")) {
            $pos = cvtnum($sv->reqv("rf_{$fid}_position"));
        } else {
            $pos = $fj->position ?? -1;
        }
        if ($pos > 0 && $sn == ""
            && $sv->has_reqv("rf_{$fid}_description")
            && trim($sv->reqv("rf_{$fid}_description")) === ""
            && (!$f->has_options
                || ($sv->has_reqv("rf_{$fid}_options")
                    ? trim($sv->reqv("rf_{$fid}_options")) === ""
                    : empty($fj->options)))) {
            $pos = -1;
        }
        if ($pos > 0) {
            if ($sn === "") {
                $sv->error_at("rf_{$fid}_name", "Missing review field name.");
            } else if (isset($this->byname[strtolower($sn)])) {
                $sv->error_at("rf_{$fid}_name", "Cannot reuse review field name “" . htmlspecialchars($sn) . "”.");
                $sv->error_at("rf_" . $this->byname[strtolower($sn)] . "_name", false);
            } else if (ReviewField::clean_name($sn) !== $sn
                       && $sn !== $f->name
                       && !$sv->reqv("rf_{$fid}_forcename")) {
                $lparen = strrpos($sn, "(");
                $sv->error_at("rf_{$fid}_name", "Don’t include “" . htmlspecialchars(substr($sn, $lparen)) . "” in the review field name. Visibility descriptions are added automatically.");
            } else {
                $this->byname[strtolower($sn)] = $fid;
            }
        }

        if ($sv->has_reqv("rf_{$fid}_visibility")) {
            $fj->visibility = $sv->reqv("rf_{$fid}_visibility");
        }

        if ($sv->has_reqv("rf_{$fid}_description")) {
            $x = CleanHTML::basic_clean($sv->reqv("rf_{$fid}_description"), $err);
            if ($x !== false) {
                $fj->description = trim($x);
                if ($fj->description === "")
                    unset($fj->description);
            } else if ($pos > 0) {
                $sv->error_at("rf_{$fid}_description", htmlspecialchars($error_sn) . " description: " . $err);
            }
        }

        if ($pos > 0) {
            $fj->position = $pos;
        } else {
            unset($fj->position);
        }

        if ($f->has_options) {
            $ok = true;
            if ($sv->has_reqv("rf_{$fid}_options")) {
                $ok = $this->check_options($sv, $fid, $fj);
            }
            if ((!$ok || count($fj->options) < 2) && $pos > 0) {
                $sv->error_at("rf_{$fid}_options", htmlspecialchars($error_sn) . ": Invalid choices.");
                if ($this->option_error) {
                    $sv->error_at(null, $this->option_error);
                }
                $this->option_error = false;
            }
            if ($sv->has_reqv("rf_{$fid}_colors")) {
                $prefixes = ["sv", "svr", "sv-blpu", "sv-publ", "sv-viridis", "sv-viridisr"];
                $pindex = array_search($sv->reqv("rf_{$fid}_colors"), $prefixes) ? : 0;
                if ($sv->reqv("rf_{$fid}_colorsflipped")) {
                    $pindex ^= 1;
                }
                $fj->option_class_prefix = $prefixes[$pindex];
            }
        }

        if ($sv->has_reqv("rf_{$fid}_rounds")) {
            $fj->round_mask = 0;
            foreach (explode(" ", trim($sv->reqv("rf_{$fid}_rounds"))) as $round_name) {
                if (strcasecmp($round_name, "all") === 0) {
                    $fj->round_mask = 0;
                } else if ($round_name !== "") {
                    $fj->round_mask |= 1 << (int) $sv->conf->round_number($round_name, false);
                }
            }
        }
    }

    static function requested_fields(SettingValues $sv) {
        $fs = [];
        $max_fields = ["s" => "s00", "t" => "t00"];
        foreach ($sv->conf->review_form()->fmap as $fid => $f) {
            $fs[$f->short_id] = true;
            if (strcmp($f->short_id, $max_fields[$f->short_id[0]]) > 0) {
                $max_fields[$f->short_id[0]] = $f->short_id;
            }
        }
        for ($i = 1; ; ++$i) {
            $fid = sprintf("s%02d", $i);
            if ($sv->has_reqv("rf_{$fid}_name") || $sv->has_reqv("rf_{$fid}_position")) {
                $fs[$fid] = true;
            } else if (strcmp($fid, $max_fields["s"]) > 0) {
                break;
            }
        }
        for ($i = 1; ; ++$i) {
            $fid = sprintf("t%02d", $i);
            if ($sv->has_reqv("rf_{$fid}_name") || $sv->has_reqv("rf_{$fid}_position")) {
                $fs[$fid] = true;
            } else if (strcmp($fid, $max_fields["t"]) > 0) {
                break;
            }
        }
        return $fs;
    }

    function parse(SettingValues $sv, Si $si) {
        $this->nrfj = (object) array();
        $this->byname = [];
        $this->option_error = "Score fields must have at least two choices, numbered sequentially from 1 (higher numbers are better) or lettered with consecutive uppercase letters (lower letters are better). Example: <pre>1. Low quality
2. Medium quality
3. High quality</pre>";

        $rf = $sv->conf->review_form();
        foreach (self::requested_fields($sv) as $fid => $x) {
            if (($finfo = ReviewInfo::field_info($fid))) {
                $f = $rf->fmap[$finfo->id] ?? new ReviewField($finfo, $sv->conf);
                $fj = $f->unparse_json(true);
                $this->populate_field($fj, $f, $sv, $fid);
                $xf = clone $f;
                $xf->assign($fj);
                $this->nrfj->{$finfo->id} = $xf->unparse_json(true);
            } else if ($sv->has_reqv("rf_{$fid}_position")
                       && $sv->reqv("rf_{$fid}_position") > 0) {
                $sv->error_at("rf_{$fid}_name", "Too many review fields. You must delete some other fields before adding this one.");
            }
        }

        $sv->request_write_lock("PaperReview");
        return true;
    }

    private function clear_existing_fields($fields, Conf $conf) {
        // clear fields from main storage
        $clear_sfields = $clear_tfields = [];
        foreach ($fields as $f) {
            if ($f->main_storage) {
                if ($f->has_options)
                    $result = $conf->qe("update PaperReview set {$f->main_storage}=0");
                else
                    $result = $conf->qe("update PaperReview set {$f->main_storage}=null");
            }
            if ($f->json_storage) {
                if ($f->has_options)
                    $clear_sfields[] = $f;
                else
                    $clear_tfields[] = $f;
            }
        }
        if (!$clear_sfields && !$clear_tfields) {
            return;
        }

        // clear fields from json storage
        $clearf = Dbl::make_multi_qe_stager($conf->dblink);
        $result = $conf->qe("select * from PaperReview where sfields is not null or tfields is not null");
        while (($rrow = ReviewInfo::fetch($result, null, $conf))) {
            $cleared = false;
            foreach ($clear_sfields as $f) {
                if (isset($rrow->{$f->id})) {
                    unset($rrow->{$f->id}, $rrow->{$f->short_id});
                    $cleared = true;
                }
            }
            if ($cleared) {
                $clearf("update PaperReview set sfields=? where paperId=? and reviewId=?", [$rrow->unparse_sfields(), $rrow->paperId, $rrow->reviewId]);
            }
            $cleared = false;
            foreach ($clear_tfields as $f) {
                if (isset($rrow->{$f->id})) {
                    unset($rrow->{$f->id}, $rrow->{$f->short_id});
                    $cleared = true;
                }
            }
            if ($cleared) {
                $clearf("update PaperReview set tfields=? where paperId=? and reviewId=?", [$rrow->unparse_tfields(), $rrow->paperId, $rrow->reviewId]);
            }
        }
        $clearf(null);
    }

    private function clear_nonexisting_options($fields, Conf $conf) {
        $updates = [];

        // clear options from main storage
        $clear_sfields = [];
        foreach ($fields as $f) {
            if ($f->main_storage) {
                $result = $conf->qe("update PaperReview set {$f->main_storage}=0 where {$f->main_storage}>" . count($f->options));
                if ($result && $result->affected_rows > 0)
                    $updates[$f->name] = true;
            }
            if ($f->json_storage) {
                $clear_sfields[] = $f;
            }
        }

        if ($clear_sfields) {
            // clear options from json storage
            $clearf = Dbl::make_multi_qe_stager($conf->dblink);
            $result = $conf->qe("select * from PaperReview where sfields is not null");
            while (($rrow = ReviewInfo::fetch($result, null, $conf))) {
                $cleared = false;
                foreach ($clear_sfields as $f) {
                    if (isset($rrow->{$f->id}) && $rrow->{$f->id} > count($f->options)) {
                        unset($rrow->{$f->id}, $rrow->{$f->short_id});
                        $cleared = $updates[$f->name] = true;
                    }
                }
                if ($cleared) {
                    $clearf("update PaperReview set sfields=? where paperId=? and reviewId=?", [$rrow->unparse_sfields(), $rrow->paperId, $rrow->reviewId]);
                }
            }
            $clearf(null);
        }

        return array_keys($updates);
    }

    function save(SettingValues $sv, Si $si) {
        if (!$sv->update("review_form", json_encode_db($this->nrfj))) {
            return;
        }
        $reqk = [];
        foreach ($sv->req as $k => $v) {
            if (str_starts_with($k, "rf_")
                && ($colon = strpos($k, "_", 3)) !== false)
                $reqk[substr($k, 0, $colon)][] = $k;
        }

        $oform = $sv->conf->review_form();
        $nform = new ReviewForm($this->nrfj, $sv->conf);
        $clear_fields = $clear_options = [];
        $reset_wordcount = $assign_ordinal = $reset_view_score = false;
        foreach ($nform->all_fields() as $nf) {
            $of = $oform->fmap[$nf->id] ?? null;
            if ($nf->displayed && (!$of || !$of->displayed)) {
                $clear_fields[] = $nf;
            } else if ($nf->displayed
                       && $nf->has_options
                       && count($nf->options) < count($of->options)) {
                $clear_options[] = $nf;
            }
            if ($of
                && $of->include_word_count() != $nf->include_word_count()) {
                $reset_wordcount = true;
            }
            if ($of
                && $of->displayed
                && $nf->displayed
                && $of->view_score != $nf->view_score) {
                $reset_view_score = true;
            }
            if ($of
                && $of->displayed
                && $nf->displayed
                && $of->view_score < VIEWSCORE_AUTHORDEC
                && $nf->view_score >= VIEWSCORE_AUTHORDEC) {
                $assign_ordinal = true;
            }
            foreach ($reqk["rf_" . $nf->short_id] ?? [] as $k) {
                $sv->unset_req($k);
            }
        }
        $sv->conf->invalidate_caches(["rf" => true]);
        // reset existing review values
        if (!empty($clear_fields)) {
            $this->clear_existing_fields($clear_fields, $sv->conf);
        }
        // ensure no review has a nonexisting option
        if (!empty($clear_options)) {
            $updates = $this->clear_nonexisting_options($clear_options, $sv->conf);
            if (!empty($updates)) {
                sort($updates);
                $sv->warning_at(null, "Your changes invalidated some existing review scores. The invalid scores have been reset to “Unknown”.  The relevant fields were: " . join(", ", $updates) . ".");
            }
        }
        // assign review ordinals if necessary
        if ($assign_ordinal) {
            $rrows = [];
            $result = $sv->conf->qe("select * from PaperReview where reviewOrdinal=0 and reviewSubmitted>0");
            while (($rrow = ReviewInfo::fetch($result, null, $sv->conf))) {
                $rrows[] = $rrow;
            }
            Dbl::free($result);
            $locked = false;
            foreach ($rrows as $rrow) {
                if ($nform->nonempty_view_score($rrow) >= VIEWSCORE_AUTHORDEC) {
                    if (!$locked) {
                        $sv->conf->qe("lock tables PaperReview write");
                        $locked = true;
                    }
                    $max_ordinal = $sv->conf->fetch_ivalue("select coalesce(max(reviewOrdinal), 0) from PaperReview where paperId=? group by paperId", $rrow->paperId);
                    if ($max_ordinal !== null) {
                        $sv->conf->qe("update PaperReview set reviewOrdinal=?, timeDisplayed=? where paperId=? and reviewId=?", $max_ordinal + 1, Conf::$now, $rrow->paperId, $rrow->reviewId);
                    }
                }
            }
            if ($locked) {
                $sv->conf->qe("unlock tables");
            }
        }
        // reset all word counts if author visibility changed
        if ($reset_wordcount) {
            $sv->conf->qe("update PaperReview set reviewWordCount=null");
        }
        // reset all view scores if view scores changed
        if ($reset_view_score) {
            // XXX should lock out other setting changes
            $sv->conf->qe("lock tables PaperReview write");
            $sv->conf->qe("update PaperReview set reviewViewScore=" . ReviewInfo::VIEWSCORE_RECOMPUTE);
            $nform->compute_view_scores();
            $sv->conf->qe("unlock tables");
        }
    }
}

class ReviewForm_SettingRenderer {
    static function render(SettingValues $sv) {
        $samples = json_decode(file_get_contents(SiteLoader::find("etc/reviewformlibrary.json")));

        $rf = $sv->conf->review_form();
        $req = [];
        if ($sv->use_req()) {
            foreach ($sv->req as $k => $v) {
                if (str_starts_with($k, "rf_")
                    && ($colon = strpos($k, "_", 3)) !== false)
                    $req[$k] = $v;
            }
        }

        Ht::stash_html('<div id="review_form_caption_description" class="hidden">'
          . '<p>Enter an HTML description for the review form.
    Include any guidance you’d like to provide for reviewers.
    Note that complex HTML will not appear on offline review forms.</p></div>'
          . '<div id="review_form_caption_options" class="hidden">'
          . '<p>Enter one option per line, numbered starting from 1 (higher numbers
    are better). For example:</p>
    <pre class="entryexample dark">1. Reject
    2. Weak reject
    3. Weak accept
    4. Accept</pre>
    <p>Or use consecutive capital letters (lower letters are better).</p>
    <p>Normally scores are mandatory: a review with a missing score cannot be
    submitted. Add a “<code>No entry</code>” line to make the score optional.</p></div>');

        $rfj = [];
        foreach ($rf->fmap as $f) {
            $rfj[$f->short_id] = $f->unparse_json();
        }

        // track whether fields have any nonempty values
        $where = ["false", "false"];
        foreach ($rf->fmap as $f) {
            $fj = $rfj[$f->short_id];
            $fj->internal_id = $f->id;
            $fj->has_any_nonempty = false;
            if ($f->json_storage) {
                if ($f->has_options) {
                    $where[0] = "sfields is not null";
                } else {
                    $where[1] = "tfields is not null";
                }
            } else {
                if ($f->has_options) {
                    $where[] = "{$f->main_storage}!=0";
                } else {
                    $where[] = "coalesce({$f->main_storage},'')!=''";
                }
            }
        }

        $unknown_nonempty = array_values($rfj);
        $limit = 0;
        while (!empty($unknown_nonempty)) {
            $result = $sv->conf->qe("select * from PaperReview where " . join(" or ", $where) . " limit $limit,100");
            $expect_limit = $limit + 100;
            while (($rrow = ReviewInfo::fetch($result, null, $sv->conf))) {
                for ($i = 0; $i < count($unknown_nonempty); ++$i) {
                    $fj = $unknown_nonempty[$i];
                    $fid = $fj->internal_id;
                    if (isset($rrow->$fid)
                        && (isset($fj->options) ? (int) $rrow->$fid !== 0 : $rrow->$fid !== "")) {
                        $fj->has_any_nonempty = true;
                        array_splice($unknown_nonempty, $i, 1);
                    } else {
                        ++$i;
                    }
                }
                ++$limit;
            }
            Dbl::free($result);
            if ($limit !== $expect_limit) { // ran out of reviews
                break;
            }
        }

        // output settings json
        Ht::stash_script("hotcrp.settings.review_form({"
            . "fields:" . json_encode_browser($rfj)
            . ", samples:" . json_encode_browser($samples)
            . ", errf:" . json_encode_browser($sv->message_field_map())
            . ", req:" . json_encode_browser($req)
            . ", stemplate:" . json_encode_browser(ReviewField::make_template(true, $sv->conf))
            . ", ttemplate:" . json_encode_browser(ReviewField::make_template(false, $sv->conf))
            . "})");

        echo Ht::hidden("has_review_form", 1);
        if (!$sv->conf->can_some_author_view_review()) {
            echo '<div class="feedback is-note mb-4">Authors cannot see reviews at the moment.</div>';
        }
        echo "<div id=\"reviewform_container\"></div>",
            "<div id=\"reviewform_removedcontainer\"></div>",
            Ht::button("Add score field", ["class" => "ui js-settings-add-review-field score"]),
            "<span class=\"sep\"></span>",
            Ht::button("Add text field", ["class" => "ui js-settings-add-review-field"]);
    }
}
