<?php

declare(strict_types=1);

use Firebase\JWT\JWT;
use League\CommonMark\CommonMarkConverter;
use SimpleSAML\Auth\State;
use SimpleSAML\Configuration;
use SimpleSAML\Error\BadRequest;
use SimpleSAML\Metadata\MetaDataStorageHandler;
use SimpleSAML\Module;
use SimpleSAML\Module\campusmultiauth\Auth\Source\Campusidp;
use SimpleSAML\XHTML\Template;

if (!array_key_exists('AuthState', $_REQUEST) && !array_key_exists('authstate', $_POST)) {
    throw new BadRequest('Missing AuthState parameter.');
}

empty($_REQUEST['AuthState']) ? $authStateId = $_POST['authstate'] : $authStateId = $_REQUEST['AuthState'];
$state = State::loadState($authStateId, Campusidp::STAGEID_USERPASS);

$metadataStorageHandler = MetaDataStorageHandler::getMetadataHandler();
$metadata = $metadataStorageHandler->getList();

$wayfConfig = Configuration::getConfig('module_campusmultiauth.php')->toArray();

if (array_key_exists('aarc_idp_hint', $state)) {
    $parts = explode('?', urldecode($state['aarc_idp_hint']), 2);

    if (!empty($metadata[$parts[0]])) {
        $state['saml:idp'] = $parts[0];
        Campusidp::delegateAuthentication($state[Campusidp::SP_SOURCE_NAME], $state);
    }
}

if (array_key_exists('aarc_discovery_hint_uri', $state)) {
    $discoveryHint = JWT::jsonDecode(file_get_contents($state['aarc_discovery_hint_uri']));
} elseif (array_key_exists('aarc_discovery_hint', $state)) {
    $discoveryHint = JWT::jsonDecode($state['aarc_discovery_hint']);
} else {
    $discoveryHint = null;
}

$discoveryHint = Campusidp::getHintedIdps($discoveryHint);

if (array_key_exists('idphint', $state)) {
    $parts = explode(',', $state['idphint']);

    if (count($parts) === 1) {
        $state['saml:idp'] = urldecode($parts[0]);
        Campusidp::delegateAuthentication($state[Campusidp::SP_SOURCE_NAME], $state);
    }
}

if (array_key_exists('source', $_POST)) {
    if (array_key_exists('searchbox', $_POST)) {
        $state['saml:idp'] = $_POST['searchbox'];

        if (!empty($metadata[$_POST['searchbox']]) &&
            !empty($wayfConfig['components'][$_POST['componentIndex']]) &&
            $wayfConfig['components'][$_POST['componentIndex']]['name'] === 'searchbox') {
            $prevIdps = Campusidp::getCookie(Campusidp::COOKIE_PREVIOUS_IDPS) === null ?
                [] :
                json_decode(
                    gzinflate(base64_decode(Campusidp::getCookie(Campusidp::COOKIE_PREVIOUS_IDPS), true)),
                    true
                );

            if (!Campusidp::isIdpInCookie($prevIdps, $_POST['searchbox'])) {
                $chosenIdp = [];
                $chosenIdp['entityid'] = $_POST['searchbox'];
                $chosenIdp['name'] = $metadata[$_POST['searchbox']]['name'];
                $chosenIdp['img'] = $wayfConfig['components'][$_POST['componentIndex']]['logos'][$_POST['searchbox']]
                    ?? Campusidp::getMostSquareLikeImg($metadata[$_POST['searchbox']]);
                $chosenIdp['index'] = $_POST['componentIndex'];


                $prevIdps[] = $chosenIdp;

                while (strlen(base64_encode(gzdeflate(json_encode($prevIdps)))) > 4093) {
                    array_shift($prevIdps);
                }

                Campusidp::setCookie(Campusidp::COOKIE_PREVIOUS_IDPS, base64_encode(gzdeflate(json_encode($prevIdps))));
            }
        }

        Campusidp::delegateAuthentication($_POST['source'], $state);
    } elseif (array_key_exists('idpentityid', $_POST)) {
        $state['saml:idp'] = $_POST['idpentityid'];
        Campusidp::delegateAuthentication($_POST['source'], $state);
    } elseif (array_key_exists('username', $_POST) && array_key_exists('password', $_POST)) {
        if (empty($_POST['username']) || empty($_POST['password'])) {
            $_REQUEST['wrongUserPass'] = true;
        } else {
            if (
                array_key_exists('remember_me', $_POST) &&
                $_POST['remember_me'] === 'Yes' &&
                Configuration::getInstance()->getBoolean('session.rememberme.enable', false)
            ) {
                Campusidp::setCookie(Campusidp::COOKIE_USERNAME, $_POST['username']);
                Campusidp::setCookie(Campusidp::COOKIE_PASSWORD, $_POST['password']);
            }

            Campusidp::delegateAuthentication($_POST['source'], $state);
        }
    }
}

if (!empty($wayfConfig['footer']['format']) && $wayfConfig['footer']['format'] === 'markdown') {
    $converter = new CommonMarkConverter();

    foreach ($wayfConfig['footer']['sections'] as $key => $value) {
        if (is_array($value)) {
            foreach ($wayfConfig['footer']['sections'][$key] as $subKey => $subValue) {
                $wayfConfig['footer']['sections'][$key][$subKey] = $converter->convertToHtml($subValue);
            }
        } else {
            $wayfConfig['footer']['sections'][$key] = $converter->convertToHtml($value);
        }
    }
}

$idps = null;
if (!empty($_POST['q'])) {
    $ch = curl_init();

    curl_setopt(
        $ch,
        CURLOPT_URL,
        Module::getModuleURL(
            'campusmultiauth/idpSearch.php?q=' . $_POST['q'] . '&index=' . $_POST['componentIndex'] . '&language=' . $_POST['currentLanguage']
        )
    );
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);

    $idps = json_decode(curl_exec($ch));
    curl_close($ch);
}

$globalConfig = Configuration::getInstance();
$t = new Template($globalConfig, 'campusmultiauth:selectsource.php');

array_key_exists('wrongUserPass', $_REQUEST) ? $t->data['wrongUserPass'] = true : $t->data['wrongUserPass'] = false;
$t->data['authstate'] = $authStateId;
$t->data['currentUrl'] = htmlentities($_SERVER['PHP_SELF']);
$t->data['wayf_config'] = $wayfConfig;
$t->data['rememberme_enabled'] = Configuration::getInstance()->getBoolean('session.rememberme.enable', false);
$t->data['muni_jvs'] = ($wayfConfig['css_framework'] ?? 'bootstrap5') === 'muni_jvs';
$t->data['idps'] = $idps;
$t->data['no_js_display_index'] = !empty($_POST['componentIndex']) ? $_POST['componentIndex'] : null;
$t->data['user_pass_source_name'] = $state[Campusidp::USER_PASS_SOURCE_NAME];
$t->data['sp_source_name'] = $state[Campusidp::SP_SOURCE_NAME];
$t->data['cookie_username'] = Campusidp::getCookie(Campusidp::COOKIE_USERNAME);
$t->data['cookie_password'] = Campusidp::getCookie(Campusidp::COOKIE_PASSWORD);
$t->data['discovery_hint'] = $discoveryHint;
$t->data['searchbox_indexes'] = json_encode(array_values(array_filter(array_map(function ($config, $index) {
    return $config['name'] === 'searchbox' ? $index : null;
}, $wayfConfig['components'], array_keys($wayfConfig['components'])), function ($a) {
    return $a !== null;
})));
$currentLanguage = $t->getTranslator()
    ->getLanguage()
    ->getLanguage();
$t->data['searchbox_placeholders'] = json_encode(array_map(function ($config) use ($currentLanguage) {
    if ($config['name'] !== 'searchbox') {
        return null;
    }
    if (isset($config['placeholder'][$currentLanguage])) {
        return $config['placeholder'][$currentLanguage];
    }
    if (!empty($config['placeholder']) && is_array($config['placeholder'])) {
        return reset($config['placeholder']);
    }
    if (!empty($config['placeholder'])) {
        return $config['placeholder'];
    }
    return null;
}, $wayfConfig['components']));

if (Campusidp::getCookie(Campusidp::COOKIE_PREVIOUS_IDPS) === null) {
    $t->data['prev_idps'] = [];
} else {
    $t->data['prev_idps'] = json_decode(
        gzinflate(base64_decode(Campusidp::getCookie(Campusidp::COOKIE_PREVIOUS_IDPS), true))
    );
}

$t->show();
exit();
