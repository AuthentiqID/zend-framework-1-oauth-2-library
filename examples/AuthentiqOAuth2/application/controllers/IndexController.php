<?php

class IndexController extends Zend_Controller_Action
{

    public function init()
    {
        /* Initialize action controller here */
    }

    /**
     * Authentiq oauth 2 workflow start
     */

    public function indexAction()
    {
        $signInButton = new Zend_Form_Element_Submit("button", array('class' => 'authentiq-button')); //button
        $signInButton->setLabel("Sign in with Authentiq");
        $this->view->authentiqButton = $signInButton;
    }

    public function signinAction()
    {
        // retrieve the authentiq api configuration
        $authentiqOauth2Config = new Zend_Config_Ini(APPLICATION_PATH . '/configs/authentiq_api.ini');

        // create a secret state, insert it in the options an put it into the
        // session to validate it during the next step
        $state = $authentiqOauth2Config -> stateSecret.md5(uniqid(rand(), TRUE));
        
        $oauthSessionNamespace = new Zend_Session_Namespace('oauthSessionNamespace');
        $oauthSessionNamespace->state = $state;

        $authentiqOauth2ConfigArray = $authentiqOauth2Config->toArray();
        $authentiqOauth2ConfigArray['state'] = $state;
        // print_r($authentiqOauth2ConfigArray);
        // start the authentiq oauth 2 workflow
        $chriswebOauth2 = new Chrisweb_Oauth2($authentiqOauth2ConfigArray);

        $chriswebOauth2->authorizationRedirect();
    }

    /**
     * Authentiq oauth 2 redirect_uri call
     *
     * If you get an error like: Unable to Connect to ssl://....
     * ensure open_ssl extension is enabled in your php.ini, then restart apache
     */
    public function authorizedAction()
    {

        $rawCode = $this->_request->getParam('code', null);
        $stateParameter = $this->_request->getParam('state', null);
        $errorReason = $this->_request->getParam('error_reason', null);

        $oauthSessionNamespace = new Zend_Session_Namespace('oauthSessionNamespace');
        


        if (is_null($stateParameter)) {

            // user refused to grant permission(s)
            Zend_Debug::dump('dialog no valid state found');
            exit;

        } else if ($stateParameter !== $oauthSessionNamespace->state) {

            Zend_Debug::dump('dialog state values don\'t match ' . $oauthSessionNamespace->state . ' vs ' . $stateParameter);
            exit;

        }

        if (!is_null($errorReason)) {

            // user refused to grant permission(s)
            Zend_Debug::dump('user refused to grant permission(s): ' . $errorReason);
            exit;

        }

        $filterChain = $this->getFilterChain();

        $verificationCode = $filterChain->filter($rawCode);

        $authentiqOauth2Config = new Zend_Config_Ini(APPLICATION_PATH . '/configs/authentiq_api.ini');

        $chriswebOauth2 = new Chrisweb_Oauth2($authentiqOauth2Config);

        $oauthResponse = null;

        try {

            /**
             * if you try to exchange an expired or invalid token, authentiq will
             * reply "invalid_grant"
             */
            $oauthResponse = $chriswebOauth2->requestAccessToken($verificationCode);

        } catch (Exception $e) {

            Zend_Debug::dump($e->getMessage(), 'error');

        }

        if (is_array($oauthResponse)) {

            //Zend_Debug::dump($oauthResponse, '$oauthResponse: ');

            // save OAuth Response
            $oauthSessionNamespace->oauthResponse = $oauthResponse;


            // request user info with a simple get request
            $client = new Zend_Http_Client();
            $client->setUri($authentiqOauth2Config->oauthEndpoint . $authentiqOauth2Config->userInfo);
            $client->setConfig(array(
                'maxredirects' => 0,
                'timeout' => 30));
            $client->setHeaders(array(
                'Authorization: Bearer ' . $oauthResponse['access_token'],
                'Accept: application/json'));

            $response = $client->request();
            $json = json_decode($response->getBody());

            // pass data from response to view
            $this->view->assign('first', $json->First);
            $this->view->assign('last', $json->Last);
            $this->view->assign('email', $json->email);

            // show actual response contents
            Zend_Debug::dump($json, 'full json response: ');
        }

    }

    /**
     *
     * @return \Zend_Filter
     */
    protected function getFilterChain()
    {

        $filterStripTags = new Zend_Filter_StripTags();
        $filterHtmlEntities = new Zend_Filter_HtmlEntities();
        $filterStripNewLines = new Zend_Filter_StripNewLines();
        $filterStringTrim = new Zend_Filter_StringTrim();

        $filterChain = new Zend_Filter();

        $filterChain->addFilter($filterStripTags)
            ->addFilter($filterHtmlEntities)
            ->addFilter($filterStripNewLines)
            ->addFilter($filterStringTrim);

        return $filterChain;

    }
}