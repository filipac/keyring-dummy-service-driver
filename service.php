<?php
if(!class_exists('Keyring_Service_OAuth2')) {
    return;
}
class Keyring_Service_Dummy extends Keyring_Service_OAuth2 {
	const NAME       = 'dummy-service';
	const LABEL      = 'Dummy Service';
	const API_BASE   = 'https://dummy-service.pacurar.dev/api/';
	const OAUTH_BASE = 'https://dummy-service.pacurar.dev/oauth/';
	function __construct() {
		parent::__construct();

        $this->callback_url = admin_url('tools.php?page=keyring&action=verify&service=dummy-service');
        $this->access_token_method = 'POST';

        add_action( 'pre_keyring_' . $this->get_name() . '_verify', array( $this, 'redirect_incoming_verify' ) );

		$this->set_endpoint( 'authorize', self::OAUTH_BASE . 'authorize', 'GET' );
		$this->set_endpoint( 'access_token', self::OAUTH_BASE . 'token', 'POST' );
		$this->set_endpoint( 'self', self::API_BASE . 'user', 'GET' );

		// Enable "basic" UI for entering key/secret
		if ( ! KEYRING__HEADLESS_MODE ) {
			add_action( 'keyring_dummy-service_manage_ui', array( $this, 'basic_ui' ) );
			add_filter( 'keyring_dummy-service_basic_ui_intro', array( $this, 'basic_ui_intro' ) );
		}

        add_action('keyring_' . $this->get_name() . '_request_token_params', function($params) {
            $creds = $this->get_credentials();
            if(isset($creds['id'])) {
                $params['client_id'] = $creds['id'];
            }
            $params['scope'] = 'read-user-info';
            return $params;
        });
        add_action('keyring_' . $this->get_name() . '_verify_token_params', function($params) {
            $creds = $this->get_credentials();
            if(isset($creds['id'])) {
                $params['client_id'] = $creds['id'];
            }
            return $params;
        });
        add_action('keyring_' . $this->get_name() . '_verify_token_post_params', function($params) {
            $params['headers'] = [
                'Content-Type' => 'application/x-www-form-urlencoded',
            ];
            $params['body'] = http_build_query($params['body']);
            return $params;
        });

		$creds = $this->get_credentials();
		if ( is_array( $creds ) ) {
			$this->app_id = $creds['id'];
			// $this->key    = $creds['key'];
			$this->secret = $creds['secret'];
		}

		$this->authorization_header    = 'Bearer';
		$this->authorization_parameter = false;
	}

	function basic_ui_intro() {
		/* translators: url */
		echo '<p>
            You can use the following tokens that should work for Pistachio in Docker as well on port 8083: <br/>
            <strong>Client ID: </strong> 6 <br/>
            <strong>Secret: </strong> Tp4ZeLoCg46lXmDudJTno3RudhKUT2Ov4KZPqghB
        </p>';
	}

	function build_token_meta( $token ) {
		$this->set_token(
			new Keyring_Access_Token(
				$this->get_name(),
				$token['access_token'],
				array()
			)
		);
		$response = $this->request( $this->self_url, array( 'method' => $this->self_method ) );
		$meta     = array();
		if ( ! Keyring_Util::is_error( $response ) ) {
			if ( isset( $response->email ) ) {
				$meta['username'] = $response->email;
			}

			if ( isset( $response->id ) ) {
				$meta['user_id'] = $response->id;
			}

			if ( isset( $response->name ) ) {
				$meta['name'] = $response->name;
			}
		}

		return apply_filters( 'keyring_access_token_meta', $meta, $this->get_name(), $token, null, $this );
	}

	function get_display( Keyring_Access_Token $token ) {
		return $token->get_meta( 'name' );
	}

	function parse_response( $response ) {
		return json_decode( $response );
	}

	function test_connection() {
		$res = $this->request( $this->self_url, array( 'method' => $this->self_method ) );
		if ( ! Keyring_Util::is_error( $res ) ) {
			return true;
		}

		return $res;
	}

    function basic_ui() {
		if ( ! isset( $_REQUEST['nonce'] ) || ! wp_verify_nonce( $_REQUEST['nonce'], 'keyring-manage-' . $this->get_name() ) ) {
			Keyring::error( __( 'Invalid/missing management nonce.', 'keyring' ) );
			exit;
		}

		// Common Header
		echo '<div class="wrap">';
		echo '<h2>' . __( 'Keyring Service Management', 'keyring' ) . '</h2>';
		echo '<p><a href="' . Keyring_Util::admin_url( false, array( 'action' => 'services' ) ) . '">' . __( '&larr; Back', 'keyring' ) . '</a></p>';
		/* translators: %s: The name of the service being connected */
		echo '<h3>' . sprintf( __( '%s API Credentials', 'keyring' ), esc_html( $this->get_label() ) ) . '</h3>';

		// Handle actually saving credentials
		if ( isset( $_POST['app_id'] ) && isset( $_POST['secret'] ) ) {
			// Store credentials against this service
			$this->update_credentials(
				array(
					'id'          => stripslashes( trim( $_POST['app_id'] ) ),
					'secret'       => stripslashes( trim( $_POST['secret'] ) ),
				)
			);
			echo '<div class="updated"><p>' . __( 'Credentials saved.', 'keyring' ) . '</p></div>';
		}

		$app_id      = '';
		$secret   = '';

		$creds = $this->get_credentials();
		if ( $creds ) {
			$app_id      = $creds['id'];
			$secret   = $creds['secret'];
		}

		echo apply_filters( 'keyring_' . $this->get_name() . '_basic_ui_intro', '' );

		// Output basic form for collecting key/secret
		echo '<form method="post" action="">';
		echo '<input type="hidden" name="service" value="' . esc_attr( $this->get_name() ) . '" />';
		echo '<input type="hidden" name="action" value="manage" />';
		wp_nonce_field( 'keyring-manage', 'kr_nonce', false );
		wp_nonce_field( 'keyring-manage-' . $this->get_name(), 'nonce', false );
		echo '<table class="form-table">';
		echo '<tr><th scope="row">' . __( 'Client ID', 'keyring' ) . '</th>';
		echo '<td><input type="text" name="app_id" value="' . esc_attr( $app_id ) . '" id="app_id" class="regular-text"></td></tr>';
		echo '<tr><th scope="row">' . __( 'Client Secret', 'keyring' ) . '</th>';
		echo '<td><input type="text" name="secret" value="' . esc_attr( $secret ) . '" id="secret" class="regular-text"></td></tr>';
		echo '</table>';
		echo '<p class="submitbox">';
		echo '<input type="submit" name="submit" value="' . __( 'Save Changes', 'keyring' ) . '" id="submit" class="button-primary">';
		echo '<a href="' . esc_url( Keyring_Util::admin_url( null, array( 'action' => 'services' ) ) ) . '" class="submitdelete" style="margin-left:2em;">' . __( 'Cancel', 'keyring' ) . '</a>';
		echo '</p>';
		echo '</form>';
		echo '</div>';
	}

    function is_configured() {
		$creds = $this->get_credentials();
		return ! empty( $creds['id'] ) && ! empty( $creds['secret'] );
	}

    function redirect_incoming_verify( $request ) {
		if ( ! isset( $request['kr_nonce'] ) ) {
			$kr_nonce = wp_create_nonce( 'keyring-verify' );
			$nonce    = wp_create_nonce( 'keyring-verify-' . $this->get_name() );
			wp_safe_redirect(
				Keyring_Util::admin_url(
					$this->get_name(),
					array(
						'action'   => 'verify',
						'kr_nonce' => $kr_nonce,
						'nonce'    => $nonce,
						'state'    => $request['state'],
						'code'     => $request['code'], // Auth code from successful response (maybe)
					)
				)
			);
			exit;
		}
	}
}

add_action( 'keyring_load_services', array( 'Keyring_Service_Dummy', 'init' ) );