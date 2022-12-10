import hvac
from loguru import logger

from configs import settings


class VaultClient:

    def __init__(
        self,
        host: str,
        auth_method: str,
        kv_mountpoint: str,
        port: int = 443,
        https: bool = True,
        ssl_verify: bool = True,
        token: str = None,
        role_id: str = None,
        secret_id: str = None,
        approle_mountpoint: str = None
    ):

        self.host = host
        self.port = port
        self.auth_method = auth_method
        self.https = https
        self.kv_mountpoint = kv_mountpoint
        self.approle_mountpoint = approle_mountpoint

        if not approle_mountpoint:
            self.approle_mountpoint = f"approle-{self.kv_mountpoint}"

        self.ssl_verify = ssl_verify

        self._client = self._get_client(
            token=token,
            role_id=role_id,
            secret_id=secret_id
        )

    @property
    def vault_url(self):
        mode = "https" if self.https else "http"
        return f"{mode}://{self.host}:{self.port}"

    def _get_client(self, token: str, role_id: str, secret_id: str):

        logger.debug(
            f"[vault-client] Init vault client from {self.vault_url} "
            f"(SSL:{self.ssl_verify}, Auth Method:{self.auth_method})"
        )

        try:
            client = hvac.Client(
                url=self.vault_url,
                verify=self.ssl_verify,
            )

            if self.auth_method == "token":
                client.token = token

            elif self.auth_method == "approle":
                client.auth.approle.login(
                    role_id=role_id,
                    secret_id=secret_id,
                    mount_point=self.approle_mountpoint
                )

        except Exception as ex:
            logger.error(
                f"[vault-client] Problem with vault client from "
                f"{self.vault_url} (Auth Method:{self.auth_method})"
            )
            exit(10)

        return client

    def get_secret(self, path: str, key: str = None, version: int = None):
        logger.debug(
            f"[vault-client] Read secret '{path}' (KV:"
            f"{self.kv_mountpoint}) from {self.vault_url}"
        )

        parameters = dict(
            mount_point=self.kv_mountpoint,
            path=path
        )

        if version:
            parameters.update(dict(
                version=version
            ))

        try:
            response = self._client.secrets.kv.v2.read_secret_version(**parameters)

            data = response["data"]["data"]

            if key:
                data = data[key]

        except Exception as ex:
            logger.error(
                f"[vault-client] Failed to read secret '{path}' (KV:"
                f"{self.kv_mountpoint}) from {self.vault_url}"
            )
            exit(8)

        return data


