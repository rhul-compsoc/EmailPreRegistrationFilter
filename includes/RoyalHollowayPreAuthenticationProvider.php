<?php

use MediaWiki\Auth\AbstractPreAuthenticationProvider;
use MediaWiki\Auth\AuthenticationRequest;
use MediaWiki\Auth\UserDataAuthenticationRequest;
use MediaWiki\Auth\AuthenticationResponse;
use MediaWiki\MediaWikiServices;
use MediaWiki\Status;

class RoyalHollowayPreAuthenticationProvider extends AbstractPreAuthenticationProvider {
  public function testForAccountCreation( $user, $creator, array $reqs ) {
    $config = MediaWiki\MediaWikiServices::getInstance()->getConfigFactory()->makeConfig( 'EmailRegistrationFilter' );
    $patterns = $config->get( 'PatternList' );
    $is_whitelist = $config->get( 'IsWhiteList' );
    $error_msg = $config->get( 'ErrorMessage' );
    $ret = StatusValue::newGood();

    $userdata_req = AuthenticationRequest::getRequestByClass( $reqs, UserDataAuthenticationRequest::class );
    if ( $userdata_req->email == null ) {
      /* Nothing to do on no email. Might want to set $wgEmailConfirmToEdit=true;
        * or something like that */
      return $ret;
    }

    $email = $userdata_req->email;
    $matched = false;
    foreach ($patterns as $pattern) {
      if (preg_match($pattern, $email)) {
        $matched = true;
        if ( !$is_whitelist ){
          $ret->fatal($error_msg);
          return $ret;
        }
      }
    }

    if ($is_whitelist && !$matched) {
      $ret->fatal($error_msg);
      return $ret;
    }

    return $ret;
  }
}
