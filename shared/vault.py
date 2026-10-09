"""Vault transport models. Explicit response fields are the only plaintext reveal boundary."""

from pydantic import Field, SecretStr

from shared.schemas import Identifier, SchemaModel


class SecretRequest(SchemaModel):
    def transport_dump(self) -> dict[str, object]:
        result = self.model_dump(mode="json")
        for name in type(self).model_fields:
            value = getattr(self, name)
            if isinstance(value, SecretStr):
                result[name] = value.get_secret_value()
        return result


class VaultPassword(SecretRequest):
    password: SecretStr = Field(min_length=1, max_length=4096)


class VaultUnlock(VaultPassword):
    initialize: bool = False


class VaultChange(VaultPassword):
    new_password: SecretStr = Field(min_length=12, max_length=4096)


class VaultToken(SchemaModel):
    token: str = Field(repr=False)
    expires_in: int = 900
    idle_seconds: int = 300


class VaultStatus(SchemaModel):
    initialized: bool
    unlocked: bool
    workspace_id: Identifier


class CredentialInput(SecretRequest):
    service: str = Field(min_length=1, max_length=200)
    username: str = Field(max_length=200)
    secret: SecretStr = Field(min_length=1, max_length=8192)
    notes: str = Field(default="", max_length=10000)
    target_id: Identifier | None = None


class CredentialSummary(SchemaModel):
    id: Identifier
    service: str
    username: str
    target_id: Identifier | None = None


class CredentialList(SchemaModel):
    credentials: list[CredentialSummary]
    candidates: list[CredentialSummary]


class CredentialSaved(SchemaModel):
    id: Identifier


class CredentialReveal(CredentialSummary):
    secret: str = Field(repr=False)
    notes: str = Field(repr=False)


class VaultExport(SchemaModel):
    content: str = Field(repr=False)
