<?php

/**
 * The Drupal Service Provider class to facilitate SAML authentication.
 */
class DrupalServiceProvider {
  private $config = array();

  public function __construct($config) {
    $this->config = $config;
  }

  /**
   * Helper function to attempt to authenticate through a SAML response.
   * If the response is missing, redirect to the configured SAML IDP.
   */
  public function authenticate($providerids = array()) {
    if (isset($_POST['SAMLResponse'])) {
      // Handle SAML response.
      $message = base64_decode($_POST['SAMLResponse']);
      $document = new DOMDocument();
      $document->loadXML($message);
      $xp = new DomXPath($document);
      $xp->registerNamespace('ds', 'http://www.w3.org/2000/09/xmldsig#');
      $xp->registerNamespace('samlp', 'urn:oasis:names:tc:SAML:2.0:protocol');
      $xp->registerNamespace('saml', 'urn:oasis:names:tc:SAML:2.0:assertion');
      $this->verifySignature($xp, TRUE);
      $this->validateResponse($xp);

      return array(
        'attributes' => $this->extractAttributes($xp),
        'response' => $message,
      );
    }
    else {
      // Handle SAML request.
      $id = '_' . sha1(uniqid(mt_rand(), TRUE));
      $issueInstant = gmdate('Y-m-d\TH:i:s\Z', time());
      $sp = $this->config['entityid'];
      $asc = $this->config['asc'];
      $sso = $this->config['sso'];

      // Add scoping.
      $scoping = '';
      foreach ($providerids as $provider) {
        $scoping .= "<samlp:IDPEntry ProviderID=\"$provider\"/>";
      }
      if ($scoping) {
        $scoping = '<samlp:Scoping><samlp:IDPList>' . $scoping . '</samlp:IDPList></samlp:Scoping>';
      }

      // Construct request.
      $request = <<<eof
<?xml version="1.0"?>
<samlp:AuthnRequest
    ID="$id"
    Version="2.0"
    IssueInstant="$issueInstant"
    Destination="$sso"
    AssertionConsumerServiceURL="$asc" 
    ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
    xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol">
    <saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">$sp</saml:Issuer>
    $scoping
</samlp:AuthnRequest>
eof;

      // Construct request.
      $queryString = "SAMLRequest=" . urlencode(base64_encode(gzdeflate($request)));
      $queryString .= '&SigAlg=' . urlencode('http://www.w3.org/2000/09/xmldsig#rsa-sha1');

      // Get private key.
      $key = openssl_pkey_get_private("-----BEGIN RSA PRIVATE KEY-----\n" . chunk_split($this->config['private_key'], 64) . "-----END RSA PRIVATE KEY-----");
      if (!$key) {
        throw new DrupalServiceProviderException('Invalid private key used');
      }

      // Sign the request.
      $signature = "";
      openssl_sign($queryString, $signature, $key, OPENSSL_ALGO_SHA1);
      openssl_free_key($key);

      // Send request.
      header('Location: ' . $this->config['sso'] . "?" . $queryString . '&Signature=' . urlencode(base64_encode($signature)));
      exit;
    }
  }

  /**
   * Helper function to prepare the metadata of the SP to import into the IDP.
   */
  public function getMetadata() {
    // Prepare metadata body.
    $entity_id = $this->config['entityid'];
    $public_key = $this->config['public_key'];
    $asc = $this->config['asc'];
    $response = <<<eof
<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="$entity_id">
  <md:SPSSODescriptor AuthnRequestsSigned="true" WantAssertionsSigned="true" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <md:KeyDescriptor use="signing">
      <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
        <ds:X509Data>
          <ds:X509Certificate>
            $public_key
          </ds:X509Certificate>
        </ds:X509Data>
      </ds:KeyInfo>
    </md:KeyDescriptor>
    <md:KeyDescriptor use="encryption">
      <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
        <ds:X509Data>
          <ds:X509Certificate>
            $public_key
          </ds:X509Certificate>
        </ds:X509Data>
      </ds:KeyInfo>
    </md:KeyDescriptor>
    <md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:transient</md:NameIDFormat>
    <md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact" Location="$asc" index="0"/>
  </md:SPSSODescriptor>
</md:EntityDescriptor>
eof;
    return $response;
  }

  /**
   * Helper function to extract attributes from the SAML response.
   */
  private function extractAttributes($xp) {
    $res = array();
    // Grab attributes from AttributeSattement.
    $attributes = $xp->query("/samlp:Response/saml:Assertion/saml:AttributeStatement/saml:Attribute");
    foreach ($attributes as $attribute) {
      $valuearray = array();
      $values = $xp->query('./saml:AttributeValue', $attribute);
      foreach ($values as $value) {
        $valuearray[] = $value->textContent;
      }
      $res[$attribute->getAttribute('Name')] = $valuearray;
    }
    return $res;
  }

  private function verifySignature($xp, $assertion = TRUE) {
    if ($assertion) {
      $context = $xp->query('/samlp:Response/saml:Assertion')->item(0);
    }
    else {
      $context = $xp->query('/samlp:Response')->item(0);
    }

    // Get signature and digest value.
    $signatureValue = base64_decode($xp->query('ds:Signature/ds:SignatureValue', $context)->item(0)->textContent);
    $digestValue = base64_decode($xp->query('ds:Signature/ds:SignedInfo/ds:Reference/ds:DigestValue', $context)
      ->item(0)->textContent);
    $id = $xp->query('@ID', $context)->item(0)->value;

    $signedElement = $context;
    $signature = $xp->query("ds:Signature", $signedElement)->item(0);
    $signedInfo = $xp->query("ds:SignedInfo", $signature)->item(0)->C14N(TRUE, FALSE);
    $signature->parentNode->removeChild($signature);
    $canonicalXml = $signedElement->C14N(TRUE, FALSE);

    // Get IdP certificate.
    $publicKey = openssl_get_publickey("-----BEGIN CERTIFICATE-----\n" . chunk_split($this->config['idp_certificate'], 64) . "-----END CERTIFICATE-----");
    if (!$publicKey) {
      throw new DrupalServiceProviderException('Invalid public key used');
    }

    // Verify signature.
    if (!((sha1($canonicalXml, TRUE) == $digestValue) && @openssl_verify($signedInfo, $signatureValue, $publicKey) == 1)) {
      throw new DrupalServiceProviderException('Error verifying incoming SAMLResponse');
    }
  }

  /**
   * Helper function to validate the origin of the SAML response.
   */
  private function validateResponse($xp) {
    $issues = array();

    // Verify destination.
    $destination = $xp->query('/samlp:Response/@Destination')->item(0)->value;
    if ($destination != NULL && $destination != $this->config['asc']) { // Destination is optional
      $issues[] = "Destination: {$destination} is not here; message not destined for us";
    }

    // Verify time stamps.
    $skew = 60;
    $aShortWhileAgo = gmdate('Y-m-d\TH:i:s\Z', time() - $skew);
    $inAShortWhile = gmdate('Y-m-d\TH:i:s\Z', time() + $skew);

    $assertion = $xp->query('/samlp:Response/saml:Assertion')->item(0);
    $subjectConfirmationData_NotBefore = $xp->query('./saml:Subject/saml:SubjectConfirmation/saml:SubjectConfirmationData/@NotBefore', $assertion);
    if ($subjectConfirmationData_NotBefore->length && $aShortWhileAgo < $subjectConfirmationData_NotBefore->item(0)->value) {
      $issues[] = 'SubjectConfirmation not valid yet';
    }

    $subjectConfirmationData_NotOnOrAfter = $xp->query('./saml:Subject/saml:SubjectConfirmation/saml:SubjectConfirmationData/@NotOnOrAfter', $assertion);
    if ($subjectConfirmationData_NotOnOrAfter->length && $inAShortWhile >= $subjectConfirmationData_NotOnOrAfter->item(0)->value) {
      $issues[] = 'SubjectConfirmation too old';
    }

    $conditions_NotBefore = $xp->query('./saml:Conditions/@NotBefore', $assertion);
    if ($conditions_NotBefore->length && $aShortWhileAgo > $conditions_NotBefore->item(0)->value) {
      $issues[] = 'Assertion Conditions not yet valid';
    }

    $conditions_NotOnOrAfter = $xp->query('./saml:Conditions/@NotOnOrAfter', $assertion);
    if ($conditions_NotOnOrAfter->length && $aShortWhileAgo >= $conditions_NotOnOrAfter->item(0)->value) {
      $issues[] = 'Assertions Condition too old';
    }

    $authStatement_SessionNotOnOrAfter = $xp->query('./saml:AuthStatement/@SessionNotOnOrAfter', $assertion);
    if ($authStatement_SessionNotOnOrAfter->length && $aShortWhileAgo >= $authStatement_SessionNotOnOrAfter->item(0)->value) {
      $issues[] = 'AuthnStatement Session too old';
    }

    if (!empty($issues)) {
      throw new DrupalServiceProviderException('Problems detected with response. ' . PHP_EOL . 'Issues: ' . PHP_EOL . implode(PHP_EOL, $issues));
    }
  }
}
