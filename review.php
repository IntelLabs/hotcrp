<?php 
// review.php -- HotCRP paper review display/edit page
// HotCRP is Copyright (c) 2006-2008 Eddie Kohler and Regents of the UC
// Distributed under an MIT-like license; see LICENSE

require_once("Code/header.inc");
require_once("Code/papertable.inc");
$Me = $_SESSION["Me"];
$Me->goIfInvalid();
$rf = reviewForm();
$useRequest = isset($_REQUEST["afterLogin"]);
$forceShow = (defval($_REQUEST, "forceShow") && $Me->privChair);
$linkExtra = ($forceShow ? "&amp;forceShow=1" : "");
$Error = array();
if (defval($_REQUEST, "mode") == "edit")
    $_REQUEST["mode"] = "re";
else if (defval($_REQUEST, "mode") == "view")
    $_REQUEST["mode"] = "r";


// header
function confHeader() {
    global $prow, $Conf, $linkExtra, $CurrentList;
    if ($prow)
	$title = "Paper #$prow->paperId Reviews";
    else
	$title = "Paper Reviews";
    $Conf->header($title, "review", actionBar($prow, false, "r"), false);
    if (isset($CurrentList) && $CurrentList > 0
	&& strpos($linkExtra, "ls=") === false)
	$linkExtra .= "&amp;ls=" . $CurrentList;
}

function errorMsgExit($msg) {
    global $Conf;
    confHeader();
    $Conf->errorMsgExit($msg);
}


// collect paper ID
function loadRows() {
    global $Conf, $Me, $ConfSiteSuffix, $linkExtra, $prow, $paperTable,
	$editRrowLogname;
    if (!($prow = PaperTable::paperRow($whyNot)))
	errorMsgExit(whyNotText($whyNot, "view"));
    $paperTable = new PaperTable($prow);
    $paperTable->resolveReview();

    if ($paperTable->editrrow && $paperTable->editrrow->contactId == $Me->contactId)
	$editRrowLogname = "Review " . $paperTable->editrrow->reviewId;
    else if ($paperTable->editrrow)
	$editRrowLogname = "Review " . $paperTable->editrrow->reviewId . " by " . $paperTable->editrrow->email;
}

loadRows();


// general error messages
if (isset($_REQUEST["post"]) && $_REQUEST["post"] && !count($_POST))
    $Conf->errorMsg("It looks like you tried to upload a gigantic file, larger than I can accept.  The file was ignored.");
else if (isset($_REQUEST["post"]) && isset($_REQUEST["default"])) {
    if (fileUploaded($_FILES["uploadedFile"], $Conf))
	$_REQUEST["uploadForm"] = 1;
    else
	$_REQUEST["update"] = 1;
}


// upload review form action
if (isset($_REQUEST['uploadForm']) && fileUploaded($_FILES['uploadedFile'], $Conf)) {
    // parse form, store reviews
    $tf = $rf->beginTextForm($_FILES['uploadedFile']['tmp_name'], $_FILES['uploadedFile']['name']);

    if (!($req = $rf->parseTextForm($tf, $Conf)))
	/* error already reported */;
    else if (isset($req['paperId']) && $req['paperId'] != $prow->paperId)
	$rf->tfError($tf, "This review form is for paper #" . $req['paperId'] . ", not paper #$prow->paperId; did you mean to upload it here?  I have ignored the form.<br /><a class='button_small' href='review$ConfSiteSuffix?p=" . $req['paperId'] . "'>Review paper #" . $req['paperId'] . "</a> <a class='button_small' href='offline$ConfSiteSuffix'>General review upload site</a>");
    else if (!$Me->canSubmitReview($prow, $paperTable->editrrow, $Conf, $whyNot))
	$rf->tfError($tf, whyNotText($whyNot, "review"));
    else {
	$req['paperId'] = $prow->paperId;
	if ($rf->checkRequestFields($req, $paperTable->editrrow, $tf)) {
	    if ($rf->saveRequest($req, $paperTable->editrrow, $prow, $Me->contactId))
		$tf['confirm'][] = "Uploaded review for paper #$prow->paperId.";
	}
    }

    if (count($tf['err']) == 0 && $rf->parseTextForm($tf, $Conf))
	$rf->tfError($tf, "Only the first review form in the file was parsed.  <a href='offline$ConfSiteSuffix'>Upload multiple-review files here.</a>");

    $rf->textFormMessages($tf, $Conf);
    loadRows();
} else if (isset($_REQUEST['uploadForm']))
    $Conf->errorMsg("Select a review form to upload.");


// check review submit requirements
if (isset($_REQUEST['update']) && $paperTable->editrrow && $paperTable->editrrow->reviewSubmitted)
    if (isset($_REQUEST["ready"]))
	/* do nothing */;
    else if (!$Me->privChair)
	$_REQUEST["ready"] = 1;
    else {
	$while = "while unsubmitting review";
	$Conf->qe("lock tables PaperReview write", $while);
	$needsSubmit = 1;
	if ($paperTable->editrrow->reviewType == REVIEW_SECONDARY) {
	    $result = $Conf->qe("select count(reviewSubmitted), count(reviewId) from PaperReview where requestedBy=" . $paperTable->editrrow->contactId . " and paperId=$prow->paperId", $while);
	    if (($row = edb_row($result)) && $row[0])
		$needsSubmit = 0;
	    else if ($row && $row[1])
		$needsSubmit = -1;
	}
	$result = $Conf->qe("update PaperReview set reviewSubmitted=null, reviewNeedsSubmit=$needsSubmit where reviewId=" . $paperTable->editrrow->reviewId, $while);
	$Conf->qe("unlock tables", $while);
	if ($result) {
	    $Conf->log("$editRrowLogname unsubmitted", $Me, $prow->paperId);
	    $Conf->confirmMsg("Unsubmitted review.");
	}
	loadRows();
    }


// review rating action
if (isset($_REQUEST["rating"]) && $paperTable->rrow) {
    if (!$Me->canRateReview($prow, $paperTable->rrow, $Conf)
	|| !$Me->canViewReview($prow, $paperTable->rrow, $Conf))
	$Conf->errorMsg("You can't rate that review.");
    else if ($Me->contactId == $paperTable->rrow->contactId)
	$Conf->errorMsg("You can't rate your own review.");
    else if ($_REQUEST["rating"] != "n" && $_REQUEST["rating"] != "0"
	     && $_REQUEST["rating"] != "1")
	$Conf->errorMsg("Invalid rating.");
    else if ($_REQUEST["rating"] == "n")
	$Conf->qe("delete from ReviewRating where reviewId=" . $paperTable->rrow->reviewId . " and contactId=$Me->contactId", "while updating rating");
    else
	$Conf->qe("insert into ReviewRating (reviewId, contactId, rating) values (" . $paperTable->rrow->reviewId . ", $Me->contactId, " . $_REQUEST["rating"] . ") on duplicate key update rating=" . $_REQUEST["rating"], "while updating rating");
    if (defval($_REQUEST, "ajax", 0))
	if ($OK)
	    $Conf->ajaxExit(array("ok" => 1, "result" => "Thanks! Your feedback has been recorded."));
	else
	    $Conf->ajaxExit(array("ok" => 0, "result" => "There was an error while recording your feedback."));
    if (isset($_REQUEST["allr"])) {
	$_REQUEST["paperId"] = $paperTable->rrow->paperId;
	unset($_REQUEST["reviewId"]);
	unset($_REQUEST["r"]);
    }
    loadRows();
}


// update review action
if (isset($_REQUEST['update'])) {
    if (!$Me->canSubmitReview($prow, $paperTable->editrrow, $Conf, $whyNot)) {
	$Conf->errorMsg(whyNotText($whyNot, "review"));
	$useRequest = true;
    } else if ($rf->checkRequestFields($_REQUEST, $paperTable->editrrow)) {
	if ($rf->saveRequest($_REQUEST, $paperTable->editrrow, $prow, $Me->contactId)) {
	    $Conf->confirmMsg(isset($_REQUEST['ready']) ? "Review submitted." : "Review saved.");
	    loadRows();
	} else
	    $useRequest = true;
    } else
	$useRequest = true;
}


// delete review action
if (isset($_REQUEST['delete']) && $Me->privChair)
    if (!$paperTable->editrrow)
	$Conf->errorMsg("No review to delete.");
    else {
	archiveReview($paperTable->editrrow);
	$while = "while deleting review";
	$result = $Conf->qe("delete from PaperReview where reviewId=" . $paperTable->editrrow->reviewId, $while);
	if ($result) {
	    $Conf->log("$editRrowLogname deleted", $Me, $prow->paperId);
	    $Conf->confirmMsg("Deleted review.");

	    // perhaps a delegatee needs to redelegate
	    if ($paperTable->editrrow->reviewType == REVIEW_EXTERNAL && $paperTable->editrrow->requestedBy > 0) {
		$result = $Conf->qe("select count(reviewSubmitted), count(reviewId) from PaperReview where requestedBy=" . $paperTable->editrrow->requestedBy . " and paperId=" . $paperTable->editrrow->paperId, $while);
		if (!($row = edb_row($result)) || $row[0] == 0)
		    $Conf->qe("update PaperReview set reviewNeedsSubmit=" . ($row && $row[1] ? -1 : 1) . " where reviewType=" . REVIEW_SECONDARY . " and paperId=" . $paperTable->editrrow->paperId . " and contactId=" . $paperTable->editrrow->requestedBy . " and reviewSubmitted is null", $while);
	    }
	    
	    unset($_REQUEST["reviewId"]);
	    unset($_REQUEST["r"]);
	    $_REQUEST["paperId"] = $paperTable->editrrow->paperId;
	}
	loadRows();
    }


// download review form action
function downloadView($prow, $rr, $editable) {
    global $rf, $Me, $Conf;
    if ($editable && $prow->reviewType > 0
	&& (!$rr || $rr->contactId == $Me->contactId))
	return $rf->textForm($prow, $rr, $Me, $Conf, $_REQUEST, true) . "\n";
    else if ($editable)
	return $rf->textForm($prow, $rr, $Me, $Conf, null, true) . "\n";
    else
	return $rf->prettyTextForm($prow, $rr, $Me, $Conf, false) . "\n";
}

function downloadForm($editable) {
    global $rf, $Conf, $Me, $prow, $paperTable, $Opt;
    if ($paperTable->rrow)
	$downrrows = array($paperTable->rrow);
    else if ($editable)
	$downrrows = array();
    else
	$downrrows = $paperTable->rrows;
    $text = "";
    foreach ($downrrows as $rr)
	if ($rr->reviewSubmitted
	    && $Me->canViewReview($prow, $rr, $Conf, $whyNot))
	    $text .= downloadView($prow, $rr, $editable);
    foreach ($downrrows as $rr)
	if (!$rr->reviewSubmitted
	    && $Me->canViewReview($prow, $rr, $Conf, $whyNot))
	    $text .= downloadView($prow, $rr, $editable);
    if (count($downrrows) == 0)
	$text .= downloadView($prow, null, $editable);
    if (!$editable && !$paperTable->rrow) {
	$paperTable->resolveComments();
	foreach ($paperTable->crows as $cr)
	    if ($Me->canViewComment($prow, $cr, $Conf, $whyNot, true))
		$text .= $rf->prettyTextComment($prow, $cr, $Me, $Conf) . "\n";
    }
    if (!$text)
	return $Conf->errorMsg(whyNotText($whyNot, "review"));
    if ($editable)
	$text = $rf->textFormHeader($Conf, count($downrrows) > 1, $Me->viewReviewFieldsScore($prow, null, $Conf)) . $text;
    downloadText($text, $Opt['downloadPrefix'] . "review-" . $prow->paperId . ".txt", "review form", !$editable);
    exit;
}
if (isset($_REQUEST['downloadForm']))
    downloadForm(true);
else if (isset($_REQUEST['text']))
    downloadForm(false);


// refuse review action
function archiveReview($rrow) {
    global $Conf;
    $rf = reviewForm();
    $fields = "reviewId, paperId, contactId, reviewType, requestedBy,
		requestedOn, reviewModified, reviewSubmitted,
		reviewNeedsSubmit, "
	. join(", ", array_keys($rf->reviewFields));
    if ($Conf->setting("allowPaperOption") >= 11)
	$fields .= ", reviewRound";
    // compensate for 2.12 schema error
    if ($Conf->setting("allowPaperOption") == 8)
	$fields = str_replace(", textField7, textField8", "", $fields);
    $Conf->qe("insert into PaperReviewArchive ($fields) select $fields from PaperReview where reviewId=$rrow->reviewId", "while archiving review");
}

function refuseReview() {
    global $Conf, $Opt, $Me, $prow, $paperTable;
    
    $while = "while refusing review";
    $Conf->qe("lock tables PaperReview write, PaperReviewRefused write, PaperReviewArchive write", $while);

    $rrow = $paperTable->rrow;
    if ($rrow->reviewModified > 0)
	archiveReview($rrow);

    $result = $Conf->qe("delete from PaperReview where reviewId=$rrow->reviewId", $while);
    if (!$result)
	return;
    $reason = defval($_REQUEST, 'reason', "");
    $result = $Conf->qe("insert into PaperReviewRefused (paperId, contactId, requestedBy, reason) values ($rrow->paperId, $rrow->contactId, $rrow->requestedBy, '" . sqlqtrim($reason) . "')", $while);
    if (!$result)
	return;

    // now the requester must potentially complete their review
    if ($rrow->reviewType == REVIEW_EXTERNAL && $rrow->requestedBy > 0) {
	$result = $Conf->qe("select count(reviewSubmitted), count(reviewId) from PaperReview where requestedBy=$rrow->requestedBy and paperId=$rrow->paperId", $while);
	if (!($row = edb_row($result)) || $row[0] == 0)
	    $Conf->qe("update PaperReview set reviewNeedsSubmit=" . ($row && $row[1] ? -1 : 1) . " where reviewType=" . REVIEW_SECONDARY . " and paperId=$rrow->paperId and contactId=$rrow->requestedBy and reviewSubmitted is null", $while);
    }

    // send confirmation email
    require_once("Code/mailtemplate.inc");
    $Requester = (object) array("firstName" => $rrow->reqFirstName, "lastName" => $rrow->reqLastName, "email" => $rrow->reqEmail);
    Mailer::send("@refusereviewrequest", $prow, $Requester, $rrow, array("reason" => $reason));

    // confirmation message
    $Conf->confirmMsg("The request for you to review paper #$prow->paperId has been removed.  Mail was sent to the person who originally requested the review.");
    $Conf->qe("unlock tables");

    $prow = null;
    confHeader();
    exit;
}

if (isset($_REQUEST['refuse'])) {
    if (!$paperTable->rrow
	|| ($paperTable->rrow->contactId != $Me->contactId && !$Me->privChair))
	$Conf->errorMsg("This review was not assigned to you, so you cannot refuse it.");
    else if ($paperTable->rrow->reviewType >= REVIEW_SECONDARY)
	$Conf->errorMsg("PC members cannot refuse reviews that were explicitly assigned to them.  Contact the PC chairs directly if you really cannot finish this review.");
    else if ($paperTable->rrow->reviewSubmitted)
	$Conf->errorMsg("This review has already been submitted; you can't refuse it now.");
    else {
	refuseReview();
	$Conf->qe("unlock tables");
	loadRows();
    }
}


// paper actions
if (isset($_REQUEST["setdecision"])) {
    require_once("Code/paperactions.inc");
    PaperActions::setDecision($prow);
    loadRows();
}
if (isset($_REQUEST["setrevpref"])) {
    require_once("Code/paperactions.inc");
    PaperActions::setReviewPreference($prow);
    loadRows();
}
if (isset($_REQUEST["setlead"])) {
    require_once("Code/paperactions.inc");
    PaperActions::setLeadOrShepherd($prow, "lead");
    loadRows();
}
if (isset($_REQUEST["setshepherd"])) {
    require_once("Code/paperactions.inc");
    PaperActions::setLeadOrShepherd($prow, "shepherd");
    loadRows();
}


// set tags action (see also comment.php)
if (isset($_REQUEST["settags"])) {
    if ($Me->canSetTags($prow, $Conf, $forceShow)) {
	require_once("Code/tags.inc");
	setTags($prow->paperId, defval($_REQUEST, "tags", ""), 'p', $Me->privChair);
	loadRows();
    } else
	$Conf->errorMsg("You cannot set tags for paper #$prow->paperId." . ($Me->privChair ? "  (<a href=\"" . htmlspecialchars(selfHref(array("forceShow" => 1))) . "\">Override conflict</a>)" : ""));
}


// can we view/edit reviews?
$viewAny = $Me->canViewReview($prow, null, $Conf, $whyNotView);
$editAny = $Me->canReview($prow, null, $Conf, $whyNotEdit);


// can we see any reviews?
if (!$viewAny && !$editAny) {
    if (!$Me->canViewPaper($prow, $Conf, $whyNotPaper))
	errorMsgExit(whyNotText($whyNotPaper, "view"));
    if (!isset($_REQUEST["reviewId"]) && !isset($_REQUEST["ls"])) {
	$Conf->errorMsg("You can't see the reviews for this paper.  " . whyNotText($whyNotView, "review"));
	$Conf->go("paper$ConfSiteSuffix?p=$prow->paperId$linkExtra");
    }
}


// page header
confHeader();


// mode
if ($paperTable->mode == "r" || $paperTable->mode == "re")
    $paperTable->fixReviewMode();


// paper table
$paperTable->initialize(false, false, true, "review");
$paperTable->paptabBegin($prow);
$paperTable->resolveComments();

if (!$viewAny && !$editAny
    && (!$paperTable->rrow
	|| !$Me->canViewReview($prow, $paperTable->rrow, $Conf, $whyNot))) {
    $paperTable->paptabEndWithReviewMessage();

} else if ($paperTable->mode == "r" && !$paperTable->rrow) {
    $paperTable->paptabEndWithReviews();

} else
    $paperTable->paptabEndWithEditableReview();

echo foldsessionpixel("paper9", "foldpaperp"), foldsessionpixel("paper5", "foldpapert"), foldsessionpixel("paper6", "foldpaperb");
$Conf->footer();
