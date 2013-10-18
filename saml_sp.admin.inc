<?php
/**
 * @file
 * Admin pages for the Drupal Service Provider for SAML module.
 */

/**
 * Configure the SAML IDP/SP.
 *
 * @ingroup forms
 */
function saml_sp_configuration_form($form, &$form_state) {
  $form['idp'] = array(
    '#type' => 'fieldset',
    '#title' => t('Identity provider'),
    '#description' => t('The Identity Provider settings.'),
  );

  $form['idp']['idpcert'] = array(
    '#type' => 'textarea',
    '#title' => t('Certificate'),
    '#description' => t('The x.509 certificate of the IDP.'),
    '#default_value' => variable_get('idpcert'),
    '#required' => TRUE,
  );

  $form['idp']['idpurl'] = array(
    '#type' => 'textfield',
    '#title' => t('SSO'),
    '#description' => t('The url of the IDP.'),
    '#default_value' => variable_get('idpurl'),
    '#required' => TRUE,
  );

  $form['sp'] = array(
    '#type' => 'fieldset',
    '#title' => t('Service provider'),
    '#description' => t('The Service Provider settings.'),
  );

  $form['sp']['spprivkey'] = array(
    '#type' => 'textarea',
    '#title' => t('Private key'),
    '#required' => TRUE,
    '#default_value' => variable_get('spprivkey'),
  );

  $form['sp']['sppubkey'] = array(
    '#type' => 'textarea',
    '#title' => t('Public key'),
    '#required' => TRUE,
    '#default_value' => variable_get('sppubkey'),
  );

  $form['sp']['acs'] = array(
    '#type' => 'textfield',
    '#title' => t('Assertion Consumer Service'),
    '#required' => TRUE,
    '#default_value' => variable_get('acs'),
  );

  $form['sp']['eid'] = array(
    '#type' => 'textfield',
    '#title' => t('Entity Identifier'),
    '#required' => TRUE,
    '#default_value' => variable_get('eid'),
  );

  return system_settings_form($form);
}

/**
 * Settings form to map attributes from SAML to Drupal users.
 */
function saml_sp_user_mapping_form($form, &$form_state) {
  $form['userfields'] = array(
    '#type' => 'fieldset',
    '#title' => t('User fields'),
    '#description' => t('The user fields mappings with SAML IDP attributes.'),
  );

  $form['userfields']['spmap_username'] = array(
    '#type' => 'textfield',
    '#title' => t('Username'),
    '#description' => t('The attribute mapped to the username'),
    '#default_value' => variable_get('spmap_username'),
  );

  $form['userfields']['spmap_email'] = array(
    '#type' => 'textfield',
    '#title' => t('Mail'),
    '#description' => t('The attribute mapped to the mail address.'),
    '#default_value' => variable_get('spmap_email'),
  );

  $form['userfields']['spmap_role'] = array(
    '#type' => 'textfield',
    '#title' => t('Roles'),
    '#description' => t('The attribute mapped to the roles.'),
    '#default_value' => variable_get('spmap_role'),
  );

  $form['roles'] = array(
    '#type' => 'fieldset',
    '#title' => t('User roles'),
    '#description' => t('The roles mapped to IDP roles.'),
  );

  foreach (user_roles(TRUE) as $key => $hr) {
    $form['roles']['spmap_' . $key] = array(
      '#type' => 'textfield',
      '#title' => $hr,
      '#default_value' => variable_get('spmap_' . $key),
    );
  }

  return system_settings_form($form);
}
