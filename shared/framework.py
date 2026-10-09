"""Public connection and framework request contracts."""

import ipaddress
from typing import Literal

from pydantic import Field, SecretStr, field_validator

from shared.schemas import SchemaModel


class RpcConnect(SchemaModel):
    host: str = "127.0.0.1"
    port: int = Field(default=55553, ge=1, le=65535)
    username: str = Field(default="msf", min_length=1, max_length=200)
    password: SecretStr | None = None
    ca_pem: str = Field(min_length=1, max_length=32768)
    remember_password: bool = False

    @field_validator("host")
    @classmethod
    def literal_host(cls, value: str) -> str:
        if value == "localhost":
            return "127.0.0.1"
        address = ipaddress.ip_address(value)
        if address.is_multicast or address.is_unspecified or "%" in value:
            raise ValueError("Use a literal unicast RPC address.")
        return str(address)

    @field_validator("password")
    @classmethod
    def bounded_password(cls, value: SecretStr | None) -> SecretStr | None:
        if value is not None and not 1 <= len(value.get_secret_value()) <= 4096:
            raise ValueError("RPC password length must be between one and4096 characters.")
        return value


class ConnectionStatus(SchemaModel):
    state: Literal["RPCConnected", "PTYFallback", "Offline"] = "Offline"
    instance_id: str | None = None
    endpoint: str = ""
    message: str = "Connect to your dedicated Toolkit-MSF installation."
    owned: bool = False


class Confirmation(SchemaModel):
    confirmed: bool = False
