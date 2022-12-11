import re
import os
from hashlib import md5
from string import Template
from pprint import pprint

import yaml
from loguru import logger


BASE_PATH = "/home/django/config-maker"

CONFIG_VAULT_PATH_SUFFIX = "vault!"
CONFIG_ENV_VAR_SUFFIX = "env!"

def get_hosts_from_input_file(input_file: str):
    """
    This function returns a list of hosts from an input file.
    """

    logger.debug(f"[hosts] Get hosts from file: {input_file}")

    if input_file.startswith("$BASE_PATH"):
        input_file = Template(input_file).substitute(
            BASE_PATH=settings.BASE_PATH
        )

    if not os.path.exists(input_file):
        logger.error(f"[hosts] Input host file not found: {input_file}")
        exit(1)

    try:
        with open(input_file, "r") as f:
            data = f.readlines()
        hosts = set([
            s.replace("\n", "").lower()
            for s in data
        ])

    except Exception as ex:
        logger.error(f"[hosts] Failed to get hosts from {input_file}: {ex}")
        exit(1)

    if not hosts:
        logger.error(f"[hosts] No hosts found from {input_file}")
        exit(1)

    return list(sorted(hosts))

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

        # self._client = self._get_client(
        #     token=token,
        #     role_id=role_id,
        #     secret_id=secret_id
        # )

    def get_secret(self, path: str, key: str = None, version: int = None):
        logger.debug(
            f"[vault-client] Read secret '{path}' (KV:"
            f"{self.kv_mountpoint})"
        )
        return "my-secret"



class ResourceConfigs:

    def __init__(self, config_file: str, resource_names: list, tmp_path: str = None):
        self.config_file = config_file
        self.resource_names = resource_names
        self.tmp_path = tmp_path
    
        self.config_type_map = {
            "text": str,
            "number": int,
            "list": list,
            "map": dict,
        }
    
        # Get configs data from file
        self._configs_data = self._get_configs_data()
    
        # Get Vault status
        self.enable_vault = self._get_vault_status()
    
        # Init secret counter
        self._vault_secrets = {}
        self.vault_secrets_count = 0
        self.env_secrets_count = 0
    
        # Init vault client
        self.vault_client = None
    
        if self.enable_vault:
            # Get vault config
            vault_config = self._get_resource_configs(
                resource="vault"
            )
            # Init vault client
            self.vault_client = VaultClient(**vault_config)
    
        self._configs, \
        self._exceptions_hosts = self._get_configs()

    
    def _get_vault_status(self):
        enable_vault = self._configs_data.get("enable_vault")
    
        if type(enable_vault) != bool:
            logger.warning(f"[configs] enable_vault parameter not found. Switch to 'False'")
            enable_vault = False
    
        return enable_vault
    
    @property
    def data(self):
        return self._configs
    
    @property
    def exceptions_hosts(self):
        return self._exceptions_hosts
    
    @property
    def tools_mode(self):
        # Get mode: test or prod
        return self._configs_data.get("mode", "prod")
    
    def _get_configs(self):
        configs = {}
        exceptions_hosts = {}
        for resource in self.resource_names:
            # Ignore app_codes (same creds of servicenow)
            if resource in ["app_codes"]:
                resource = "servicenow"
    
            configs[resource] = self._get_resource_configs(
                resource=resource
            )
            # Get host exceptions for some resources
            exceptions_hosts[resource] = configs[resource].get(
                "exceptions_hosts", []
            )
    
            # Build Class attribute for each resource
            setattr(self, resource, configs[resource])
    
        logger.info(
            f"[configs] Get configs done (From Vault: "
            f"{self.vault_secrets_count}, From Env: {self.env_secrets_count})"
        )
    
        return configs, exceptions_hosts
    
    def _get_configs_data(self):
        logger.debug(f"[configs] Get config from file: {self.config_file}")
    
        if not os.path.exists(self.config_file):
            logger.error(f"[configs] Config file not found: {self.config_file}")
            exit(1)
    
        try:
            with open(self.config_file, "r") as f:
                data = yaml.full_load(f)
        except:
            logger.error(f"[configs] Problem with parsing of config file: {self.config_file}")
            exit(1)
    
        configs = data.get("configs")
    
        if not configs:
            logger.error(f"[configs] configs attribute not found: {self.config_file}")
            exit(1)
    
        return configs
    
    def _write_private_key(self, resource: str, vault_secret: str, private_key: str):
        # Check tmp_path
        if not self.tmp_path:
            logger.error(f"[configs] Define tmp_path for write private key !")
            exit(1)
        # Create uniq file name with vault path
        private_key_hash = md5(vault_secret.encode()).hexdigest()
        private_key_name = f"{resource}-{private_key_hash}"
        # Get private key tmp path
        private_key_path = os.path.join(self.tmp_path, private_key_name)
        # Write private key
        with open(private_key_path, "w") as f:
            f.write(private_key)
        # Change permission
        os.chmod(private_key_path, 0o400)
        # Return private key path
        logger.debug(f"[configs] Private key write to file: {private_key_path}")
        return private_key_path
    
    def _get_secrets(self, resource: str, config: dict):
    
        formatted_config = dict(config)
    
        for key, value in config.items():
            if type(value) != str:
                continue
    
            formatted_value = value
    
            # Get vault secret
            if value.startswith(CONFIG_VAULT_PATH_SUFFIX):
                if not self.enable_vault:
                    logger.error(
                        f"[configs] Enable vault with 'enable_vault=true' "
                        f"to download secret (Resource:{resource}.{key})"
                    )
                    exit(1)
    
                if resource == "vault":
                    logger.error(
                        f"[configs] You can't retrieve vault config secret on vault !..."
                    )
                    exit(1)
    
                vault_secret = value[len(CONFIG_VAULT_PATH_SUFFIX):]
    
                if self._vault_secrets.get(vault_secret):
                    formatted_value = self._vault_secrets[vault_secret]
    
                else:
                    splitted_vault_secret = vault_secret.split(":")
    
                    if len(splitted_vault_secret) != 2:
                        logger.error(
                            f"[configs] Bad format for vault secret: "
                            f"'{CONFIG_VAULT_PATH_SUFFIX}"
                            f"/path/to/secret:secret_key' "
                            f"(Resource:{resource}.{key})"
                        )
                        exit(1)
    
                    vault_path, vault_key = splitted_vault_secret
    
                    formatted_value = self.vault_client.get_secret(
                        path=vault_path,
                        key=vault_key
                    )
    
                    # Write private key
                    if key == "private_key":
                        formatted_value = self._write_private_key(
                            resource=resource,
                            vault_secret=vault_secret,
                            private_key=formatted_value
                        )
    
                    self._vault_secrets[vault_secret] = formatted_value
                    self.vault_secrets_count += 1
    
            # Get environement vars
            if value.startswith(CONFIG_ENV_VAR_SUFFIX):
                environment_key = value[len(CONFIG_ENV_VAR_SUFFIX):]
                formatted_value = os.getenv(environment_key, None)
    
                if not formatted_value:
                    logger.error(
                        f"[configs] Environment vars not found: "
                        f"{environment_key} (Resource:{resource}.{key})"
                    )
                    exit(1)
    
                self.env_secrets_count += 1
    
            formatted_config[key] = formatted_value
    
        return formatted_config
   
    def _get_sub_configs(self, resource: str, configs_maps: dict, config: dict):

        for config_key, config_map in configs_maps.items():
            # Get config value
            config_value = config.get(config_key)

            if config_map["required"] and not config_value:
                logger.error(
                    f"[configs] Config parameter '{resource}.{config_key}' missing"
                )
                exit(2)

            if not config_value:
                continue

            formatted_config_type = config_map["type"]
            config_type = self.config_type_map.get(formatted_config_type)

            if type(config_value) != config_type:
                logger.error(
                    f"[configs] Config parameter '{resource}.{config_key}' "
                    f"bad format: '{formatted_config_type}' required"
                )
                exit(2)

            if type(config_value) == list:

                formatted_data_type = config_map["data_type"]
                data_type = self.config_type_map.get(formatted_data_type)

                if type(config_value[0]) != data_type:
                    logger.error(
                        f"[configs] Config parameter '{resource}.{config_key}.[]' "
                        f"bad list format: '{formatted_data_type}' required"
                    )
                    exit(2)

                if data_type == dict:

                    for index, config_data in enumerate(config_value):

                        config[config_key][index] = self._get_sub_configs(
                            resource=f"{resource}.{config_key}.[{index}]",
                            configs_maps=config_map["parameters"],
                            config=config_data
                        )

            if config_type == dict:

                config[config_key] = self._get_sub_configs(
                    resource=f"{resource}.{config_key}",
                    configs_maps=config_map["parameters"],
                    config=config[config_key],
                )

        return self._get_secrets(
            resource=resource,
            config=config
        )

    def _get_resource_configs(self, resource: str):
    
        logger.debug(f"[configs] Get config parameters for resource: '{resource}'")
    
        CONFIG_MAPS = {
            "vault": {
                "host": {"required": True, "type": "text"},
                "auth_method": {"required": True, "type": "text"},
                "kv_mountpoint": {"required": True, "type": "text"},
                "token": {"required": True, "type": "text"},
            },
            "s3": {
                "endpoint_url": {"required": True, "type": "text"},
                "access_key": {"required": True, "type": "text"},
                "secret_key": {"required": True, "type": "text"},
            }
        }

        formatted_config = {}
        config = self._configs_data.get(resource)
    
        if not config:
            logger.error(f"[configs] No config parameters found for '{resource}'")
            exit(2)

        formatted_config = self._get_sub_configs(
            resource=resource,
            configs_maps=CONFIG_MAPS[resource],
            config=config
        )

        return formatted_config


configs = ResourceConfigs(
    config_file=f"{BASE_PATH}/config.yml",
    resource_names=["s3"],
    tmp_path=f"{BASE_PATH}/tmp"
)

pprint(configs.data)
