import re
import os
from hashlib import md5

import yaml
from loguru import logger

from configs import settings
from collectaz import utils
from collectaz.cores.vault import VaultClient


class ResourceConfigs:

    def __init__(self, config_file: str, resource_names: list, tmp_path: str = None):
        self.config_file = config_file
        self.resource_names = resource_names
        self.tmp_path = tmp_path

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
            # Ex: self.hmc, self.servicenow, ...
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
            if value.startswith(settings.CONFIG_VAULT_PATH_SUFFIX):
                if not self.enable_vault:
                    logger.error(
                        f"[configs] Enable vault with 'enable_vault=true' "
                        f"to download secret (Resource:{resource})"
                    )
                    exit(1)

                if resource == "vault":
                    logger.error(
                        f"[configs] You can't retrieve vault config secret on vault !..."
                    )
                    exit(1)

                vault_secret = value[len(settings.CONFIG_VAULT_PATH_SUFFIX):]

                if self._vault_secrets.get(vault_secret):
                    formatted_value = self._vault_secrets[vault_secret]

                else:
                    splitted_vault_secret = vault_secret.split(":")

                    if len(splitted_vault_secret) != 2:
                        logger.error(
                            f"[configs] Bad format for vault secret: "
                            f"'{settings.CONFIG_VAULT_PATH_SUFFIX}"
                            f"/path/to/secret:secret_key'"
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
            if value.startswith(settings.CONFIG_ENV_VAR_SUFFIX):
                environment_key = value[len(settings.CONFIG_ENV_VAR_SUFFIX):]
                formatted_value = os.getenv(environment_key, None)

                if not formatted_value:
                    logger.error(
                        f"[configs] Environment vars not found: {environment_key} (Resource:{resource})"
                    )
                    exit(1)

                self.env_secrets_count += 1

            formatted_config[key] = formatted_value

        return formatted_config

    def _get_resource_configs(self, resource: str):

        logger.debug(f"[configs] Get config parameters for resource: '{resource}'")

        formatted_config = {}
        config = self._configs_data.get(resource)

        if not config:
            logger.error(f"[configs] No config parameters found for '{resource}'")
            exit(2)

        elif resource == "dns":

            if not config.get("domains"):
                logger.error(f"[configs] dns.domains missing in config")
                exit(2)

            if type(config["domains"]) != list:
                logger.error(f"[configs] dns.domains bad format. list is required")
                exit(2)

        elif resource == "ssh":

            private_keys = []

            if not config.get("global"):
                logger.error(f"[configs] ssh.global missing in config")
                exit(2)

            if (
                not config["global"].get("user")
                or not config["global"].get("private_key")
            ):
                logger.error(f"[configs] ssh.global.(user|private_key) missing in config")
                exit(2)

            # Get secret from global config
            config["global"] = self._get_secrets(
                resource=resource,
                config=config["global"]
            )

            private_keys.append(
                config["global"]["private_key"]
            )

            if config.get("exceptions"):
                if type(config["exceptions"]) != list:
                    logger.error(f"[configs] ssh.exceptions bad format. list is required")
                    exit(2)

                for index, exception in enumerate(config["exceptions"]):
                    if not exception.get("user") or not exception.get("private_key"):
                        logger.error(f"[configs] ssh.global.(user|private_key) missing in config")
                        exit(2)

                    if not exception.get("hosts"):
                        logger.error(
                            f"[configs] Please defined a file with hosts "
                            f"for exception: ssh.exceptions[].hosts"
                        )
                        exit(2)

                    if type(exception["hosts"]) != str:
                        logger.error(f"[configs] ssh.exceptions[].hosts bad format. path is required")
                        exit(2)

                    # Update secrets from exception
                    exception = self._get_secrets(
                        resource=resource,
                        config=exception
                    )

                    exception["hosts"] = utils.get_hosts_from_input_file(
                        input_file=exception["hosts"]
                    )

                    private_keys.append(exception["private_key"])

                    # Update dict
                    config["exceptions"][index].update(exception)

            # Check all founded private keys
            for private_key in private_keys:
                if not os.path.exists(private_key):
                    logger.error(f"[configs] Private key not found: {private_key}")
                    exit(2)

        if resource in ["prometheus", "s3", "vault"]:

            resource_keys = {
                "s3": ["endpoint_url", "access_key", "secret_key", "bucket_name", "s3_path", "ssl_verify"],
                "prometheus": ["gateway_host", "gateway_port", "job_name"],
                "vault": ["host", "kv_mountpoint", "auth_method"],
                "nim": ["host", "user", "private_key"],
            }

            keys = resource_keys[resource]
    
            for key in keys:
                value = config.get(key)
                if not value:
                    logger.error(f"[configs] {resource}.{key} missing")
                    exit(2)

            if resource == "vault":

                if config["auth_method"] not in settings.VAULT_AVAILABLE_AUTH_METHOD:
                    logger.error(f"[configs] {resource}.auth_method not available: {config['auth_method']}")
                    exit(2)

                if config["auth_method"] == "token" and not config.get("token"):
                    logger.error(f"[configs] {resource}.token missing with Auth Method: token")
                    exit(2)

                if config["auth_method"] == "approle" and not (config.get("role_id") and config.get("secret_id")):
                    logger.error(
                        f"[configs] {resource}.(role_id|secret_id) missing with Auth Method: approle"
                    )
                    exit(2)

        formatted_config = self._get_secrets(
            resource=resource,
            config=config
        )

        if resource in ["vsphere", "esx", "satellite", "servicenow", "hmc", "satellite"]:

            if not config.get("hosts"):
                logger.error(f"[configs] {resource}.hosts missing in config")
                exit(2)

            if type(config["hosts"]) != list:
                logger.error(f"[configs] {resource}.hosts bad format. list is required")
                exit(2)

            row_to_retrieve = ["user", "password"]

            if resource == "satellite":
                row_to_retrieve.append("org_id")

            global_config = config.get("global", {})

            # Get hosts
            hosts = []
            for host in config["hosts"]:

                for row in ["user", "password"]:
                    if host.get(row):
                        continue

                    # If creds not found in host, retrieve it from global
                    global_row = global_config.get(row)

                    if not global_row:
                        logger.error(
                            f"[configs] {resource}.global.{row} missing in "
                            f"config. You must declare row in global or per host"
                        )
                        exit(2)

                    host[row] = global_row

                formatted_host_config = self._get_secrets(
                    resource=resource,
                    config=host
                )

                hosts.append(formatted_host_config)

            # Update config with hosts list
            formatted_config["hosts"] = hosts

            # Check if exceptions exists
            exceptions_hosts = config.get("exceptions", {}).get("hosts", "")
    
            if type(exceptions_hosts) != str:
                logger.error(f"[configs] {resource}.exceptions.hosts bad format. path is required")
                exit(2)

            # Update config with exceptions hosts list
            if exceptions_hosts:
                formatted_config["exceptions_hosts"] = utils.get_hosts_from_input_file(
                    input_file=exceptions_hosts
                )
                del(formatted_config["exceptions"])

            # Remove global if present
            if global_config:
                del(formatted_config["global"])

        return formatted_config


