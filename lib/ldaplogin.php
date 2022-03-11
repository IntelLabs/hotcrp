<?php
// ldaplogin.php -- HotCRP helper function for LDAP login
// Copyright (c) 2009-2022 Eddie Kohler; see LICENSE.

class LDAPLogin {
    static function ldap_login_info(Conf $conf, Qrequest $qreq) {
		$ldapURI = $conf->opt("ldapServerURI");

		if (!preg_match('/([^*]+)\*(.*?)\s*\z/s',
			$conf->opt("ldapFilter"), $m)) {
			return [
				"ok" => false, "ldap" => true, "internal" => true, "email" => true,
				"detail_html" => "Internal error: <code>" . htmlspecialchars($conf->opt("ldapFilter")) . "</code> syntax error; expected “<code><i>ldapfilter</i></code>”, where <code><i>ldapfilter</i></code> contains a <code>*</code> character to be replaced by the user's email address.  Logins will fail until this error is fixed. "
			];
		}

		if ((string) $qreq->password === "") {
			return [
				"ok" => false, "ldap" => true, "internal" => true, "email" => true,
				"detail_html" => "No Password provided."
			];
		}

		// connect to the LDAP server
		$ldapc = @ldap_connect($ldapURI);
		
		if (!$ldapc) {
			return [
				"ok" => false, "ldap" => true, "internal" => true, "email" => true,
				"detail_html" => "Internal error: ldap_connect. Logins disabled until this error is fixed."
			];
		}

		// bind as faceless account
		@ldap_set_option($ldapc, LDAP_OPT_PROTOCOL_VERSION, 3);
		$dn = $conf->opt("ldapLoginDN");
		$pwd = $conf->opt("ldapLoginDNPassword");

		$success = @ldap_bind($ldapc, $dn, $pwd);
		if (!$success && @ldap_errno($ldapc) == 2) {
			@ldap_set_option($ldapc, LDAP_OPT_PROTOCOL_VERSION, 2);
			$success = @ldap_bind($ldapc, $dn, $pwd);
		}
		if (!$success) {
			return [
				"ok" => false, "ldap" => true, "internal" => true, "email" => true,
				"detail_html" => "Internal error: ldap_bind Failed!"
			];
		}

		// search for user DN value in Workers LDAP directory
        $qemail = addcslashes((string) $qreq->email, ',=+<>#;\"');
        $dn = $m[1] . $qemail . $m[2];

		$result = ldap_search($ldapc, 'DC=corp,DC=intel,DC=com', $dn, array("dn", "cn", "mail"), 0, 1);

		$entries = ldap_get_entries($ldapc, $result);
		if ($entries['count'] == 1) {
			$success = ldap_bind($ldapc, $entries[0]['dn'], $qreq->password);
			if ($success) {
				$e = ($entries["count"] == 1 ? $entries[0] : array());
				if (isset($e["cn"]) && $e["cn"]["count"] == 1) {
					list($qreq->firstName, $qreq->lastName) = Text::split_name($e["cn"][0]);
				}
				if (isset($e["sn"]) && $e["sn"]["count"] == 1) {
					$qreq->lastName = $e["sn"][0];
				}
				if (isset($e["givenname"]) && $e["givenname"]["count"] == 1) {
					$qreq->firstName = $e["givenname"][0];
				}
				if (isset($e["mail"]) && $e["mail"]["count"] == 1) {
					$qreq->preferredEmail = $e["mail"][0];
				}

				ldap_close($ldapc);
				return ["ok" => true];
			}
			else {
				return [
					"ok" => false, "ldap" => true, "internal" => true, "email" => true,
					"detail_html" => "Email Bind Failed!" . "Result:" . ldap_errno($ldapc)
				];	
			}
		}
		else {
			$lerrno = ldap_errno($ldapc);
			return [
				"ok" => false, "ldap" => true, "internal" => true, "email" => true,
				"detail_html" => "Didn't find User Data - Error: " . $lerrno . " search filter: " . $dn
			];
		}
	// Success!  Get user data


        // $qemail = addcslashes((string) $qreq->email, ',=+<>#;\"');
        // $dn = $m[3] . $qemail . $m[4];

        // $success = @ldap_bind($ldapc, $dn, (string) $qreq->password);
        // if (!$success && @ldap_errno($ldapc) == 2) {
        //     @ldap_set_option($ldapc, LDAP_OPT_PROTOCOL_VERSION, 2);
        //     $success = @ldap_bind($ldapc, $dn, (string) $qreq->password);
        // }
        // if (!$success) {
        //     return self::fail($conf, $qreq, $ldapc);
        // }

        // use LDAP information to prepopulate the database with names
        // $sr = @ldap_search($ldapc, $dn, "(cn=*)",
        //                    array("sn", "givenname", "cn", "mail", "telephonenumber"));
        // if ($sr) {
        //     $e = @ldap_get_entries($ldapc, $sr);
        //     $e = ($e["count"] == 1 ? $e[0] : array());
        //     if (isset($e["cn"]) && $e["cn"]["count"] == 1) {
        //         list($qreq->firstName, $qreq->lastName) = Text::split_name($e["cn"][0]);
        //     }
        //     if (isset($e["sn"]) && $e["sn"]["count"] == 1) {
        //         $qreq->lastName = $e["sn"][0];
        //     }
        //     if (isset($e["givenname"]) && $e["givenname"]["count"] == 1) {
        //         $qreq->firstName = $e["givenname"][0];
        //     }
        //     if (isset($e["mail"]) && $e["mail"]["count"] == 1) {
        //         $qreq->preferredEmail = $e["mail"][0];
        //     }
        //     if (isset($e["telephonenumber"]) && $e["telephonenumber"]["count"] == 1) {
        //         $qreq->phone = $e["telephonenumber"][0];
        //     }
        // }

        // ldap_close($ldapc);
        // return ["ok" => true];
    }

    static private function fail(Conf $conf, Qrequest $qreq, $ldapc) {
        // connection failed, report error
        $lerrno = ldap_errno($ldapc);
        $suffix = "";
        if ($lerrno != 49) {
            $suffix = "<br><span class='hint'>(LDAP error $lerrno: " . htmlspecialchars(ldap_err2str($lerrno)) . ")</span>";
        }

        if ($lerrno < 5) {
            return [
                "ok" => false, "ldap" => true, "internal" => true, "email" => true,
                "detail_html" => "LDAP protocol error. Logins will fail until this error is fixed.$suffix"
            ];
        } else if ((string) $qreq->password === "") {
            return [
                "ok" => false, "ldap" => true, "nopw" => true,
                "detail_html" => "Password missing." . ($lerrno == 53 ? "" : $suffix)
            ];
        } else {
            return [
                "ok" => false, "ldap" => true, "invalid" => true,
                "email" => true, "password" => true,
                "detail_html" => "Invalid credentials. Please use your LDAP username and password.$suffix"
            ];
        }
    }

}
