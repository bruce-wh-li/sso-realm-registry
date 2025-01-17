/** @type {import('next').NextConfig} */
module.exports = {
  reactStrictMode: true,
  serverRuntimeConfig: {
    app_env: process.env.APP_ENV || 'development',
    sso_configuration_url: process.env.SSO_CONFIGURATION_URL,
    sso_url: process.env.SSO_URL || 'http://localhost:8080',
    sso_client_id: process.env.SSO_CLIENT_ID || '',
    sso_client_secret: process.env.SSO_CLIENT_SECRET || '',
    sso_redirect_uri: process.env.SSO_REDIRECT_URI || 'http://localhost:3000',
    sso_logout_redirect_uri: process.env.SSO_LOGOUT_REDIRECT_URI || 'http://localhost:3000',
    sso_authorization_response_type: process.env.SSO_AUTHORIZATION_RESPONSE_TYPE || 'code',
    sso_authorization_scope: process.env.SSO_AUTHORIZATION_SCOPE || 'openid',
    sso_token_grant_type: process.env.SSO_TOKEN_GRANT_TYPE || 'authorization_code',
    jwt_secret: process.env.JWT_SECRET || 'verysecuresecret',
    jwt_token_expiry: process.env.JWT_TOKEN_EXPIRY || '1h',
    pg_host: process.env.PGHOST || 'localhost',
    pg_port: process.env.PGPORT || '5432',
    pg_user: process.env.PGUSER,
    pg_password: process.env.PGPASSWORD,
    pg_database: process.env.PGDATABASE || 'realm_profile',
    pg_ssl: process.env.PGSSL === 'true',

    dev_kc_url: process.env.DEV_KC_URL || 'https://dev.oidc.gov.bc.ca',
    dev_kc_client_id: process.env.DEV_KC_CLIENT_ID || 'script-cli',
    dev_kc_client_secret: process.env.DEV_KC_CLIENT_SECRET,

    test_kc_url: process.env.TEST_KC_URL || 'https://dev.oidc.gov.bc.ca',
    test_kc_client_id: process.env.TEST_KC_CLIENT_ID || 'script-cli',
    test_kc_client_secret: process.env.TEST_KC_CLIENT_SECRET,

    prod_kc_url: process.env.PROD_KC_URL || 'https://dev.oidc.gov.bc.ca',
    prod_kc_client_id: process.env.PROD_KC_CLIENT_ID || 'script-cli',
    prod_kc_client_secret: process.env.PROD_KC_CLIENT_SECRET,

    ches_api_endpoint: process.env.CHES_API_ENDPOINT || 'https://ches-dev.apps.silver.devops.gov.bc.ca/api/v1/email',
    ches_token_endpoint:
      process.env.CHES_TOKEN_ENDPOINT || 'https://dev.oidc.gov.bc.ca/auth/realms/xxxxxxx/protocol/openid-connect/token',
    ches_username: process.env.CHES_USERNAME,
    ches_password: process.env.CHES_PASSWORD,
  },
  publicRuntimeConfig: {},
};
