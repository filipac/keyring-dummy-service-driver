<?php
/**
 * Plugin Name: Keyring - Dummy Service
 * Description: Adds a dummy service to Keyring providers
 * Version: 1.0
 * Author: Filip Pacurar
 */
/**
 * Fires after WordPress has finished loading but before any headers are sent.
 *
 */
add_action('plugins_loaded', function() : void {
    require_once __DIR__.'/service.php';
}, 11 );