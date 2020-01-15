# ievv_api_key
> The ievv_api_key app will introduce basic models for api keys

API key format: `{prefix}.{secret}`

`AbstractAPIKey` consists of:
* prefix: api key prefix (prefix).(secret), used to identify the api key.
* hashed_key: The hashed secret keys.
* name: name the api key, used to identify the recipient.
* revoked: This field can be set to true to revoke the api key, after this is set to True it cannot be set to False again.
* created: created datetime
* expiration_datetime: expiration datetime, after this timestamp the api key cannot be used.
* authentication_log: a json field for logging authentication attempts.

## ScopedAPIKey
The intended use of the `ScopedAPIKey` model is together with jwt.
In addition to the `AbstractAPIKey`, `ScopedAPIKey` consists of two more fields:
* jwt_backend_name: The name of the jwt backend which will be used to issue and verify the token.
* base_jwt_payload: Additional payload for the jwt token, this can for instance be used to define access scope.

ScopedAPIkey can be created through django admin. The api key itself with prefix and secret will only be displayed once in a message after creation.
