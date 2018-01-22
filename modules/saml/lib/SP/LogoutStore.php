<?php

/**
 * A directory over logout information.
 *
 * @package SimpleSAMLphp
 */
class sspmod_saml_SP_LogoutStore {

	/**
	 * Create logout table in SQL, if it is missing.
	 *
	 * @param \SimpleSAML\Store\SQL $store  The datastore.
	 */
	private static function createLogoutTable(\SimpleSAML\Store\SQL $store) {

		$tableVer = $store->getTableVersion('saml_LogoutStore');
		if ($tableVer === 2) {
			return;
		} elseif ($tableVer === 1) {
			/* TableVersion 2 increased the column size to 255 which is the maximum length of a FQDN. */
			$query = 'ALTER TABLE ' . $store->prefix . '_saml_LogoutStore MODIFY _authSource VARCHAR(255) NOT NULL';
			try {
				$ret = $store->pdo->exec($query);
			} catch (Exception $e) {
				SimpleSAML\Logger::warning($store->pdo->errorInfo());
				return;
			}
			$store->setTableVersion('saml_LogoutStore', 2);
			return;
		}

		$query = 'CREATE TABLE ' . $store->prefix . '_saml_LogoutStore (
			_authSource VARCHAR(255) NOT NULL,
			_nameId VARCHAR(40) NOT NULL,
			_sessionIndex VARCHAR(50) NOT NULL,
			_expire TIMESTAMP NOT NULL,
			_sessionId VARCHAR(50) NOT NULL,
			UNIQUE (_authSource, _nameID, _sessionIndex)
		)';
		$store->pdo->exec($query);

		$query = 'CREATE INDEX ' . $store->prefix . '_saml_LogoutStore_expire ON '  . $store->prefix . '_saml_LogoutStore (_expire)';
		$store->pdo->exec($query);

		$query = 'CREATE INDEX ' . $store->prefix . '_saml_LogoutStore_nameId ON '  . $store->prefix . '_saml_LogoutStore (_authSource, _nameId)';
		$store->pdo->exec($query);

		$store->setTableVersion('saml_LogoutStore', 2);
	}


	/**
	 * Clean the logout table of expired entries.
	 *
	 * @param \SimpleSAML\Store\SQL $store  The datastore.
	 */
	private static function cleanLogoutStore(\SimpleSAML\Store\SQL $store) {

		SimpleSAML\Logger::debug('saml.LogoutStore: Cleaning logout store.');

		$query = 'DELETE FROM ' . $store->prefix . '_saml_LogoutStore WHERE _expire < :now';
		$params = array('now' => gmdate('Y-m-d H:i:s'));

		$query = $store->pdo->prepare($query);
		$query->execute($params);
	}


	/**
	 * Register a session in the SQL datastore.
	 *
	 * @param \SimpleSAML\Store\SQL $store  The datastore.
	 * @param string $authId  The authsource ID.
	 * @param string $nameId  The hash of the users NameID.
	 * @param string $sessionIndex  The SessionIndex of the user.
	 */
	private static function addSessionSQL(\SimpleSAML\Store\SQL $store, $authId, $nameId, $sessionIndex, $expire, $sessionId) {
		assert('is_string($authId)');
		assert('is_string($nameId)');
		assert('is_string($sessionIndex)');
		assert('is_string($sessionId)');
		assert('is_int($expire)');

		self::createLogoutTable($store);

		if (rand(0, 1000) < 10) {
			self::cleanLogoutStore($store);
		}

		$data = array(
			'_authSource' => $authId,
			'_nameId' => $nameId,
			'_sessionIndex' => $sessionIndex,
			'_expire' => gmdate('Y-m-d H:i:s', $expire),
			'_sessionId' => $sessionId,
		);
		$store->insertOrUpdate($store->prefix . '_saml_LogoutStore', array('_authSource', '_nameId', '_sessionIndex'), $data);
	}


	/**
	 * Retrieve sessions from the SQL datastore.
	 *
	 * @param \SimpleSAML\Store\SQL $store  The datastore.
	 * @param string $authId  The authsource ID.
	 * @param string $nameId  The hash of the users NameID.
	 * @return array  Associative array of SessionIndex =>  SessionId.
	 */
	private static function getSessionsSQL(\SimpleSAML\Store\SQL $store, $authId, $nameId) {
		assert('is_string($authId)');
		assert('is_string($nameId)');

		self::createLogoutTable($store);

		$params = array(
			'_authSource' => $authId,
			'_nameId' => $nameId,
			'now' => gmdate('Y-m-d H:i:s'),
		);

		// We request the columns in lowercase in order to be compatible with PostgreSQL
		$query = 'SELECT _sessionIndex AS _sessionindex, _sessionId AS _sessionid FROM ' . $store->prefix . '_saml_LogoutStore' .
			' WHERE _authSource = :_authSource AND _nameId = :_nameId AND _expire >= :now';
		$query = $store->pdo->prepare($query);
		$query->execute($params);

		$res = array();
		while ( ($row = $query->fetch(PDO::FETCH_ASSOC)) !== FALSE) {
			$res[$row['_sessionindex']] = $row['_sessionid'];
		}

		return $res;
	}


	/**
	 * Retrieve all session IDs from a key-value store.
	 *
	 * @param \SimpleSAML\Store $store  The datastore.
	 * @param string $authId  The authsource ID.
	 * @param string $nameId  The hash of the users NameID.
	 * @param array $sessionIndexes  The session indexes.
	 * @return array  Associative array of SessionIndex =>  SessionId.
	 */
	private static function getSessionsStore(\SimpleSAML\Store $store, $authId, $nameId, array $sessionIndexes) {
		assert('is_string($authId)');
		assert('is_string($nameId)');

		$res = array();
		foreach ($sessionIndexes as $sessionIndex) {
			$sessionId = $store->get('saml.LogoutStore', $nameId . ':' . $sessionIndex);
			if ($sessionId === NULL) {
				continue;
			}
			assert('is_string($sessionId)');
			$res[$sessionIndex] = $sessionId;
		}

		return $res;
	}


	/**
	 * Register a new session in the datastore.
	 *
	 * Please observe the change of the signature in this method. Previously, the second parameter ($nameId) was forced
	 * to be an array. However, it has no type restriction now, and the documentation states it must be a
	 * \SAML2\XML\saml\NameID object. Currently, this function still accepts an array passed as $nameId, and will
	 * silently convert it to a \SAML2\XML\saml\NameID object. This is done to keep backwards-compatibility, though will
	 * no longer be possible in the future as the $nameId parameter will be required to be an object.
	 *
	 * @param string $authId  The authsource ID.
	 * @param \SAML2\XML\saml\NameID $nameId The NameID of the user.
	 * @param string|NULL $sessionIndex  The SessionIndex of the user.
	 */
	public static function addSession($authId, $nameId, $sessionIndex, $expire) {
		assert('is_string($authId)');
		assert('is_string($sessionIndex) || is_null($sessionIndex)');
		assert('is_int($expire)');

		if ($sessionIndex === NULL) {
			/* This IdP apparently did not include a SessionIndex, and thus probably does not
			 * support SLO. We still want to add the session to the data store just in case
			 * it supports SLO, but we don't want an LogoutRequest with a specific
			 * SessionIndex to match this session. We therefore generate our own session index.
			 */
			$sessionIndex = SimpleSAML\Utils\Random::generateID();
		}

		$store = \SimpleSAML\Store::getInstance();
		if ($store === FALSE) {
			// We don't have a datastore.
			return;
		}

		// serialize and anonymize the NameID
        // TODO: remove this conditional statement
		if (is_array($nameId)) {
			$nameId = \SAML2\XML\saml\NameID::fromArray($nameId);
		}
		$strNameId = serialize($nameId);
		$strNameId = sha1($strNameId);

		/* Normalize SessionIndex. */
		if (strlen($sessionIndex) > 50) {
			$sessionIndex = sha1($sessionIndex);
		}

		$session = SimpleSAML_Session::getSessionFromRequest();
		$sessionId = $session->getSessionId();

		if ($store instanceof \SimpleSAML\Store\SQL) {
			self::addSessionSQL($store, $authId, $strNameId, $sessionIndex, $expire, $sessionId);
		} else {
			$store->set('saml.LogoutStore', $strNameId . ':' . $sessionIndex, $sessionId, $expire);
		}
	}

	/**
	 * Can the store be used to log out (the given) sessions?
	 *
	 * A valid store must be configured and either indexes must be known or a queryable datastore must be used.
	 *
	 * @param array $sessionIndexes
	 * @return bool
	 */
    public static function canLogoutSessions($sessionIndexes = array())
    {
        $store = \SimpleSAML\Store\SQL::getInstance();
        if ($store === FALSE) {
            /* We don't have a datastore. */
            return FALSE;
        }
        if (empty($sessionIndexes) && !$store instanceof \SimpleSAML\Store\SQL) {
            /* We cannot fetch all sessions without a SQL store. */
            return FALSE;
        }
        return TRUE;
    }


	/**
	 * Get all associations for all given session indexes.
	 *
	 * @param string $authId		AuthSource ID
	 * @param array $nameId			Name Identifier to get the sessions for.
	 * @param array $sessionIndexes	SessionIndexes (Session IDs) to get the sessions for.
	 * @return array
	 */
	public static function collectSessionAssociations($authId, array $nameId, array $sessionIndexes = array()) {
    		$associations = array();

    		self::foreachSessionIndex(
        			$authId,
        			$nameId,
        			$sessionIndexes,
        			function ($sessions, $sessionIndex) use (&$associations, $authId) {
        				if (!isset($sessions[$sessionIndex])) {
            					return;
 				}

 				$sessionId = $sessions[$sessionIndex];

 				$session = SimpleSAML_Session::getSession($sessionId);
 				if ($session === NULL) {
            					return;
 				}

 				if (!$session->isValid($authId)) {
            					return;
 				}

 				$associations = array_merge_recursive($associations, $session->getAllAssociations());
 			}
 		);
 		return $associations;
 	}

    /**
     * Log out of the given sessions.
     *
     * @param string $authId The authsource ID.
     * @param array $nameId The NameID of the user.
     * @param array $sessionIndexes The SessionIndexes we should log out of. Logs out of all if this is empty.
     * @returns int|FALSE  Number of sessions logged out, or FALSE if not supported.
     */
    public static function logoutSessions($authId, array $nameId, array $sessionIndexes) {
        $numLoggedOut = 0;
        self::foreachSessionIndex(
            $authId,
            $nameId,
            $sessionIndexes,
            function ($sessions, $sessionIndex) use ($authId, &$numLoggedOut) {
                $numLoggedOut += sspmod_saml_SP_LogoutStore::logoutSession($authId, $sessions, $sessionIndex);
            }
        );
        return $numLoggedOut;
    }

    protected static function logoutSession($authId, $sessions, $sessionIndex) {
        if (!isset($sessions[$sessionIndex])) {
            \SimpleSAML\Logger::info('saml.LogoutStore: Logout requested for unknown SessionIndex.');
            return 0;
        }

        $sessionId = $sessions[$sessionIndex];

        $session = SimpleSAML_Session::getSession($sessionId);
        if ($session === NULL) {
            \SimpleSAML\Logger::info('saml.LogoutStore: Skipping logout of missing session.');
            return 0;
        }

        if (!$session->isValid($authId)) {
            \SimpleSAML\Logger::info('saml.LogoutStore: Skipping logout of session because it isn\'t authenticated.');
            return 0;
        }

        \SimpleSAML\Logger::info('saml.LogoutStore: Logging out of session with trackId [' . $session->getTrackID() . '].');
        $session->doLogout($authId);
        return 1;
    }


    protected static function foreachSessionIndex($authId, array $nameId, array $sessionIndexes, $callback) {
        assert('is_string($authId)');

        $store = SimpleSAML\Store::getInstance();
        if ($store === FALSE) {
            /* We don't have a datastore. */
            return FALSE;
        }

        // serialize and anonymize the NameID
        // TODO: remove this conditional statement
        if (is_array($nameId)) {
            $nameId = \SAML2\XML\saml\NameID::fromArray($nameId);
        }
        $strNameId = serialize($nameId);
        $strNameId = sha1($strNameId);

        /* Normalize SessionIndexes. */
        foreach ($sessionIndexes as &$sessionIndex) {
            assert('is_string($sessionIndex)');
            if (strlen($sessionIndex) > 50) {
                $sessionIndex = sha1($sessionIndex);
            }
        }
        unset($sessionIndex); // Remove reference

        if ($store instanceof \SimpleSAML\Store\SQL) {
            $sessions = self::getSessionsSQL($store, $authId, $strNameId);
        } elseif (empty($sessionIndexes)) {
            /* We cannot fetch all sessions without a SQL store. */
            return FALSE;
        } else {
            $sessions = self::getSessionsStore($store, $authId, $strNameId, $sessionIndexes);

        }

        if (empty($sessionIndexes)) {
            $sessionIndexes = array_keys($sessions);
        }

        $sessionHandler = \SimpleSAML\SessionHandler::getSessionHandler();

        foreach ($sessionIndexes as $sessionIndex) {
            $callback($sessionIndex, $sessions);
        }
        return true;
    }
}
