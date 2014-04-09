<?php

/**
 * Resume logging out, including out of all known associations (IdPs that have logged in SPs).
 *
 * This endpoint concerns it's self only with a already received LogoutRequest.
 */

if (!isset($_REQUEST['id'])) {
	throw new SimpleSAML_Error_BadRequest('Missing id-parameter.');
}
$id = (string)$_REQUEST['id'];

$state = SimpleSAML_Auth_State::loadState($id, 'saml:LogoutAssociations');
$idpAssociations = &$state['saml:LogoutAssociations:remaining'];

if (!empty($idpAssociations)) {
	$idpId = array_shift($idpAssociations);

	$id = SimpleSAML_Auth_State::saveState($state, 'saml:LogoutAssociations');
	$url = SimpleSAML_Module::getModuleURL('saml/sp/saml2-logout-resume.php', array('id' => $id));

	$idp = SimpleSAML_IdP::getById($idpId);
	return $idp->doLogoutRedirect($url);
}

/** @var sspmod_saml_Auth_Source_SP $source */
$source = $state['saml:LogoutAssociations:authSource'];
/** @var SAML2_LogoutRequest $message */
$message = $state['saml:LogoutAssociations:logoutRequest'];
/** @var SimpleSAML_Configuration $spMetadata */
$spMetadata = $state['saml:LogoutAssociations:spMetadata'];
/** @var SimpleSAML_Configuration $idpMetadata */
$idpMetadata = $state['saml:LogoutAssociations:idpMetadata'];
/** @var SAML2_Binding $binding */
$binding = $state['saml:LogoutAssociations:binding'];

$sessionIndexes = $message->getSessionIndexes();
$numLoggedOut = sspmod_saml_SP_LogoutStore::logoutSessions($source->getAuthId(), $message->getNameId(), $sessionIndexes);
if ($numLoggedOut === FALSE) {
	/* This type of logout was unsupported. Use the old method. */
	$source->handleLogout($message->getIssuer());
	$numLoggedOut = count($sessionIndexes);
}

/* Create an send response. */
$lr = sspmod_saml_Message::buildLogoutResponse($spMetadata, $idpMetadata);
$lr->setRelayState($message->getRelayState());
$lr->setInResponseTo($message->getId());

if ($numLoggedOut < count($sessionIndexes)) {
	SimpleSAML_Logger::warning('Logged out of ' . $numLoggedOut  . ' of ' . count($sessionIndexes) . ' sessions.');
}

$binding->send($lr);