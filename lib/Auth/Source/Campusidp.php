<?php

declare(strict_types=1);

namespace SimpleSAML\Module\campusmultiauth\Auth\Source;

use Exception;
use SimpleSAML\Auth;
use SimpleSAML\Auth\Source;
use SimpleSAML\Auth\State;
use SimpleSAML\Configuration;
use SimpleSAML\Error;
use SimpleSAML\Error\UnserializableException;
use SimpleSAML\Metadata\MetaDataStorageHandler;
use SimpleSAML\Module;
use SimpleSAML\Module\core\Auth\UserPassBase;
use SimpleSAML\Session;
use SimpleSAML\Utils;

class Campusidp extends Source
{
    public const AUTHID = '\SimpleSAML\Module\campusidp\Auth\Source\Campusidp.AuthId';

    public const STAGEID_USERPASS = '\SimpleSAML\Module\core\Auth\UserPassBase.state';

    public const SOURCESID = '\SimpleSAML\Module\campusidp\Auth\Source\Campusidp.SourceId';

    public const SESSION_SOURCE = 'campusmultiauth:selectedSource';

    public const USER_PASS_SOURCE_NAME = 'userPassSourceName';

    public const SP_SOURCE_NAME = 'spSourceName';

    public const COOKIE_PREVIOUS_IDPS = 'previous_idps';

    public const COOKIE_PREFIX = 'campusidp_';

    public const COOKIE_USERNAME = 'username';

    public const COOKIE_PASSWORD = 'password';

    private $sources;

    private $userPassSourceName;

    private $spSourceName;

    public function __construct($info, $config)
    {
        parent::__construct($info, $config);

        $this->sources = [];

        $this->userPassSourceName = !empty($config['userPassSource']['name']) ? $config['userPassSource']['name'] : 'campus-userpass';

        $userPassClassRef = [];
        if (!empty($config['userPassSource']['AuthnContextClassRef'])) {
            $ref = $config['userPassSource']['AuthnContextClassRef'];
            if (is_string($ref)) {
                $userPassClassRef = [$ref];
            } else {
                $userPassClassRef = $ref;
            }
        }

        $this->sources[] = [
            'source' => $this->userPassSourceName,
            'AuthnContextClassRef' => $userPassClassRef,
        ];

        $this->spSourceName = !empty($config['spSource']['name']) ? $config['spSource']['name'] : 'default-sp';

        $spClassRef = [];
        if (!empty($config['spSource']['AuthnContextClassRef'])) {
            $ref = $config['spSource']['AuthnContextClassRef'];
            if (is_string($ref)) {
                $spClassRef = [$ref];
            } else {
                $spClassRef = $ref;
            }
        }

        $this->sources[] = [
            'source' => $this->spSourceName,
            'AuthnContextClassRef' => $spClassRef,
        ];
    }

    public function authenticate(&$state)
    {
        if (array_key_exists('aarc_idp_hint', $_REQUEST)) {
            $state['aarc_idp_hint'] = $_REQUEST['aarc_idp_hint'];
        }

        if (array_key_exists('aarc_discovery_hint', $_REQUEST)) {
            $state['aarc_discovery_hint'] = $_REQUEST['aarc_discovery_hint'];
        }

        if (array_key_exists('aarc_discovery_hint_uri', $_REQUEST)) {
            $state['aarc_discovery_hint_uri'] = $_REQUEST['aarc_discovery_hint_uri'];
        }

        if (array_key_exists('idphint', $_REQUEST)) {
            $state['idphint'] = $_REQUEST['idphint'];
        }

        $state[self::AUTHID] = $this->authId;
        $state[self::SOURCESID] = $this->sources;
        $state[self::USER_PASS_SOURCE_NAME] = $this->userPassSourceName;
        $state[self::SP_SOURCE_NAME] = $this->spSourceName;

        // Save the $state array, so that we can restore if after a redirect
        $id = State::saveState($state, self::STAGEID_USERPASS);

        /* Redirect to the select source page. We include the identifier of the
         * saved state array as a parameter to the login form
         */
        $url = Module::getModuleURL('campusmultiauth/selectsource.php');
        $params = [
            'AuthState' => $id,
        ];

        Utils\HTTP::redirectTrustedURL($url, $params);

        // The previous function never returns, so this code is never executed
        assert(false);
    }

    public static function delegateAuthentication($authId, $state)
    {
        $as = Auth\Source::getById($authId);
        $valid_sources = array_map(function ($src) {
            return $src['source'];
        }, $state[self::SOURCESID]);
        if ($as === null || !in_array($authId, $valid_sources, true)) {
            throw new Exception('Invalid authentication source: ' . $authId);
        }

        // Save the selected authentication source for the logout process.
        $session = Session::getSessionFromRequest();
        $session->setData(self::SESSION_SOURCE, $state[self::AUTHID], $authId, Session::DATA_TIMEOUT_SESSION_END);

        try {
            if (!empty($_POST['username']) && !empty($_POST['password']) && is_subclass_of(
                $as,
                '\SimpleSAML\Module\core\Auth\UserPassBase'
            )) {
                $state[UserPassBase::AUTHID] = $authId;

                try {
                    UserPassBase::handleLogin(
                        State::saveState($state, UserPassBase::STAGEID),
                        $_POST['username'],
                        $_POST['password']
                    );
                } catch (\SimpleSAML\Error\Error $e) {
                    if ($e->getMessage() === 'WRONGUSERPASS') {
                        $id = State::saveState($state, self::STAGEID_USERPASS);
                        $url = Module::getModuleURL('campusmultiauth/selectsource.php');
                        $params = [
                            'AuthState' => $id,
                            'wrongUserPass' => true,
                        ];

                        Utils\HTTP::redirectTrustedURL($url, $params);
                    } else {
                        throw $e;
                    }
                }
            } else {
                $as->authenticate($state);
            }
        } catch (Error\Exception $e) {
            Auth\State::throwException($state, $e);
        } catch (Exception $e) {
            $e = new UnserializableException($e);
            Auth\State::throwException($state, $e);
        }
        Auth\Source::completeAuth($state);
    }

    public static function getCookie($name)
    {
        $prefixedName = self::COOKIE_PREFIX . $name;
        if (array_key_exists($prefixedName, $_COOKIE)) {
            return $_COOKIE[$prefixedName];
        }
        return null;
    }

    public static function setCookie($name, $value)
    {
        $prefixedName = self::COOKIE_PREFIX . $name;

        $params = [
            // we save the cookies for 90 days
            'lifetime' => (60 * 60 * 24 * 90),
            // the base path for cookies. This should be the installation directory for SimpleSAMLphp
            'path' => Configuration::getInstance()->getBasePath(),
            'httponly' => false,
        ];

        Utils\HTTP::setCookie($prefixedName, $value, $params, false);
    }

    public static function getMostSquareLikeImg($idpentry)
    {
        if (!empty($idpentry['UIInfo']['Logo'])) {
            if (count($idpentry['UIInfo']['Logo']) === 1) {
                $item['image'] = $idpentry['UIInfo']['Logo'][0]['url'];
            } else {
                $logoSizeRatio = 1; // impossible value
                $candidateLogoUrl = null;

                foreach ($idpentry['UIInfo']['Logo'] as $logo) {
                    $ratio = abs($logo['height'] - $logo['width']) / ($logo['height'] + $logo['width']);

                    if ($ratio < $logoSizeRatio) { // then we found more square-like logo
                        $logoSizeRatio = $ratio;
                        $candidateLogoUrl = $logo['url'];
                    }
                }

                $item['image'] = $candidateLogoUrl;
            }

            return $item['image'];
        }
        return '';
    }

    public static function getHintedIdps($hint)
    {
        if ($hint === null) {
            return null;
        }

        $metadataStorageHandler = MetaDataStorageHandler::getMetadataHandler();
        $metadata = $metadataStorageHandler->getList();

        $idps = [];

        if (array_key_exists('include', $hint)) {
            if (empty($hint['include'])) {
                return [];
            } else {
                foreach ($hint['include'] as $key => $value) {
                    if ($key === 'all_of') {
                        $idps[] = self::getAllOfIdps($value, $metadata);
                    } elseif ($key === 'any_of') {
                        $idps[] = self::getAnyOfIdps($value, $metadata);
                    }
                }
            }
        } else {
            $idps = $metadata;
        }

        if (!empty($hint['exclude'])) {
            foreach ($hint['exclude'] as $key => $value) {
                if ($key === 'all_of') {
                    $idps = array_diff($idps, self::getAllOfIdps($value, $metadata));
                } elseif ($key === 'any_of') {
                    $idps = array_diff($idps, self::getAnyOfIdps($value, $metadata));
                }
            }
        }

        // TODO preferred

        return $idps;
    }

    public static function getAllOfIdps($claim, $metadata)
    {
        $result = [];
        $index = 0;

        foreach ($claim as $key => $value) {
            switch ($key) {
                case 'all_of':
                    $index === 0 ?
                        array_push($result, self::getAllOfIdps($value, $metadata)) :
                        $result = array_intersect($result, self::getAllOfIdps($value, $metadata));
                    break;
                case 'any_of':
                    $index === 0 ?
                        array_push($result, self::getAnyOfIdps($value, $metadata)) :
                        $result = array_intersect($result, self::getAnyOfIdps($value, $metadata));
                    break;
                case 'entity_category':
                    $index === 0 ?
                        array_push($result, self::getEntityCategoryIdps($value, $metadata)) :
                        $result = array_intersect($result, self::getEntityCategoryIdps($value, $metadata));
                    break;
                case 'assurance_certification':
                    $index === 0 ?
                        array_push($result, self::getAssuranceCertificationIdps($value, $metadata)) :
                        $result = array_intersect($result, self::getAssuranceCertificationIdps($value, $metadata));
                    break;
                case 'registration_authority':
                    $index === 0 ?
                        array_push($result, self::getRegistrationAuthorityIdps($value, $metadata)) :
                        $result = array_intersect($result, self::getRegistrationAuthorityIdps($value, $metadata));
                    break;
            }

            $index++;
        }

        return $result;
    }

    public static function getAnyOfIdps($claim, $metadata)
    {
        $result = [];

        foreach ($claim as $key => $value) {
            switch ($key) {
                case 'all_of':
                    $result[] = self::getAllOfIdps($value, $metadata);
                    break;
                case 'any_of':
                    $result[] = self::getAnyOfIdps($value, $metadata);
                    break;
                case 'entity_category':
                    $result[] = self::getEntityCategoryIdps($value, $metadata);
                    break;
                case 'assurance_certification':
                    $result[] = self::getAssuranceCertificationIdps($value, $metadata);
                    break;
                case 'registration_authority':
                    $result[] = self::getRegistrationAuthorityIdps($value, $metadata);
                    break;
            }
        }

        return $result;
    }

    public static function getEntityCategoryIdps($value, $metadata)
    {
        // TODO
        return [];
    }

    public static function getAssuranceCertificationIdps($value, $metadata)
    {
        // TODO
        return [];
    }

    public static function getRegistrationAuthorityIdps($value, $metadata)
    {
        $result = [];

        foreach ($metadata as $entityid => $idpMetadata) {
            if (!empty($idpMetadata['RegistrationInfo']['registrationAuthority'])) {
                switch (array_key_first($value)) {
                    case 'contains':
                        if (strpos($idpMetadata['RegistrationInfo']['registrationAuthority'], $value['contains']) !== false) {
                            $result[] = $entityid;
                        }
                        break;
                    case 'equals':
                        if ($idpMetadata['RegistrationInfo']['registrationAuthority'] === $value['equals']) {
                            $result[] = $entityid;
                        }
                        break;
                    case 'matches':
                        if (preg_match($value['matches'], $idpMetadata['RegistrationInfo']['registrationAuthority']) === 1) {
                            $result[] = $entityid;
                        }
                        break;
                }
            }
        }

        return $result;
    }

    public static function isIdpInCookie($idps, $entityid)
    {
        foreach ($idps as $idp) {
            if ($idp['entityid'] === $entityid) {
                return true;
            }
        }

        return false;
    }

    public function logout(&$state)
    {
        assert(is_array($state));

        // Get the source that was used to authenticate
        $session = Session::getSessionFromRequest();
        $authId = $session->getData(self::SESSION_SOURCE, $this->authId);

        $source = Auth\Source::getById($authId);
        if ($source === null) {
            throw new Exception('Invalid authentication source during logout: ' . $authId);
        }
        // Then, do the logout on it
        $source->logout($state);
    }
}
