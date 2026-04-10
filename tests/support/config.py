"""Build test configuration for Gafaelfawr."""

from pydantic import SecretStr

from gafaelfawr.config import OIDCClient

__all__ = ["build_oidc_client"]


def build_oidc_client(
    id: str, secret: str | SecretStr, return_uri: str
) -> OIDCClient:
    """Construct the configuration object for one OpenID Connect client.

    Pydantic makes it a little difficult to build this object, so this wrapper
    function streamlines it.

    Parameters
    ----------
    id
        Client identifier.
    secret
        Client secret.
    return_uri
        Return URI for this client.

    Returns
    -------
    OIDCConfig
        Configuration for the client.
    """
    if isinstance(secret, SecretStr):
        secret = secret.get_secret_value()
    return OIDCClient.model_validate(
        {"id": id, "secret": secret, "return_uri": return_uri}
    )
