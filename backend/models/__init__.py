"""Separate catalog/workspace ORM metadata; no foreign keys span SQLite files."""

from datetime import datetime

from pydantic import JsonValue
from sqlalchemy import (
    JSON,
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Integer,
    LargeBinary,
    String,
    Text,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


class CatalogBase(DeclarativeBase):
    """Catalog-only schema, including durable mutation identities without workspace cascade."""


class WorkspaceBase(DeclarativeBase):
    """Metadata contained independently in each UUID-named workspace SQLite file."""


class Workspace(CatalogBase):
    """Stable catalog identity; names are display data, never filesystem paths."""

    __tablename__ = "workspaces"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    name: Mapped[str] = mapped_column(String(100))
    description: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class Selection(CatalogBase):
    """Singleton active selection; its FK is enforced inside the catalog file."""

    __tablename__ = "selection"
    __table_args__ = (CheckConstraint("id = 1"),)
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    workspace_id: Mapped[str] = mapped_column(ForeignKey("workspaces.id"))


class MutationOutcome(CatalogBase):
    """Request fingerprints/results retained after workspace deletion, without request bodies."""

    __tablename__ = "mutation_outcomes"
    __table_args__ = (CheckConstraint("state IN ('pending', 'complete', 'unknown')"),)
    workspace_id: Mapped[str] = mapped_column(String(36), primary_key=True, index=True)
    request_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    operation: Mapped[str] = mapped_column(String(200))
    fingerprint: Mapped[str] = mapped_column(String(64))
    state: Mapped[str] = mapped_column(String(16))
    result: Mapped[JsonValue] = mapped_column(JSON, nullable=True)


class Target(WorkspaceBase):
    """One IPv4 address per workspace; open port records are validated JSON."""

    __tablename__ = "targets"
    __table_args__ = (
        CheckConstraint("status IN ('not_scanned','open','exploited','session_active')"),
    )
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    address: Mapped[str] = mapped_column(String(15), unique=True)
    hostname: Mapped[str] = mapped_column(String(253), index=True)
    ports: Mapped[list[dict[str, object]]] = mapped_column(JSON)
    status: Mapped[str] = mapped_column(String(24), index=True)
    notes: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    sessions: Mapped[list["RemoteSession"]] = relationship(back_populates="target")
    jobs: Mapped[list["JobAssociation"]] = relationship(back_populates="target")


class Notes(WorkspaceBase):
    """Singleton workspace notes independent of target notes."""

    __tablename__ = "notes"
    __table_args__ = (CheckConstraint("id = 1"),)
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    text: Mapped[str] = mapped_column(Text)


class FrameworkInstance(WorkspaceBase):
    """Explicit remote identity prevents numeric sessions being confused across frameworks."""

    __tablename__ = "framework_instances"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    identity: Mapped[str] = mapped_column(String(253), unique=True)
    endpoint: Mapped[str] = mapped_column(String(253))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    sessions: Mapped[list["RemoteSession"]] = relationship(back_populates="framework")


class RemoteSession(WorkspaceBase):
    """Session belongs to this database, a framework instance and optionally a target/job."""

    __tablename__ = "remote_sessions"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    framework_id: Mapped[str] = mapped_column(ForeignKey("framework_instances.id"), index=True)
    remote_id: Mapped[str] = mapped_column(String(100))
    target_id: Mapped[str | None] = mapped_column(
        ForeignKey("targets.id", ondelete="SET NULL"), index=True
    )
    job_id: Mapped[str | None] = mapped_column(
        ForeignKey("job_associations.id", ondelete="SET NULL"), index=True
    )
    status: Mapped[str] = mapped_column(String(24))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    target: Mapped[Target | None] = relationship(back_populates="sessions")
    framework: Mapped[FrameworkInstance] = relationship(back_populates="sessions")


class JobAssociation(WorkspaceBase):
    """Local job UUID is recorded in its captured workspace, never relabeled on switch."""

    __tablename__ = "job_associations"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    target_id: Mapped[str | None] = mapped_column(
        ForeignKey("targets.id", ondelete="SET NULL"), index=True
    )
    framework_id: Mapped[str | None] = mapped_column(
        ForeignKey("framework_instances.id"), index=True
    )
    module_id: Mapped[str] = mapped_column(String(200))
    remote_job_id: Mapped[str | None] = mapped_column(String(20))
    execution_id: Mapped[str | None] = mapped_column(String(64))
    status: Mapped[str] = mapped_column(String(24))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    target: Mapped[Target | None] = relationship(back_populates="jobs")


class ModuleFavorite(WorkspaceBase):
    """Favorite module identifier within this workspace."""

    __tablename__ = "module_favorites"
    module_id: Mapped[str] = mapped_column(String(200), primary_key=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class ModuleRecent(WorkspaceBase):
    """Recent module history containing identifiers only, never option secrets."""

    __tablename__ = "module_recent"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    module_id: Mapped[str] = mapped_column(String(200), index=True)
    used_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)


class ConsoleHistory(WorkspaceBase):
    """Only redacted console text may be written; raw commands are not accepted here."""

    __tablename__ = "console_history"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    framework_id: Mapped[str | None] = mapped_column(
        ForeignKey("framework_instances.id"), index=True
    )
    redacted_text: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)


class VaultConfig(WorkspaceBase):
    """Versioned vault KDF parameters and encrypted password-verification marker."""

    __tablename__ = "vault_config"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    kdf: Mapped[str] = mapped_column(String(50), default="Argon2id")
    parameters: Mapped[dict[str, object]] = mapped_column(JSON)
    salt: Mapped[bytes] = mapped_column(LargeBinary)
    encrypted_check: Mapped[bytes] = mapped_column(LargeBinary)
    credentials: Mapped[list["EncryptedCredential"]] = relationship(back_populates="vault")


class EncryptedCredential(WorkspaceBase):
    """Ciphertext only, associated with local vault configuration and optional target."""

    __tablename__ = "encrypted_credentials"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    vault_id: Mapped[int] = mapped_column(ForeignKey("vault_config.id"))
    target_id: Mapped[str | None] = mapped_column(
        ForeignKey("targets.id", ondelete="SET NULL"), index=True
    )
    ciphertext: Mapped[bytes] = mapped_column(LargeBinary)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    vault: Mapped[VaultConfig] = relationship(back_populates="credentials")


class Report(WorkspaceBase):
    """Report metadata only; no renderer or secret payload lives in this slice."""

    __tablename__ = "reports"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    title: Mapped[str] = mapped_column(String(200))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    artifacts: Mapped[list["Artifact"]] = relationship(back_populates="report")


class Artifact(WorkspaceBase):
    """Relative storage identity and digest; paths never leave through target exports."""

    __tablename__ = "artifacts"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    report_id: Mapped[str | None] = mapped_column(ForeignKey("reports.id"), index=True)
    job_id: Mapped[str | None] = mapped_column(ForeignKey("job_associations.id"), index=True)
    name: Mapped[str] = mapped_column(String(200))
    media_type: Mapped[str] = mapped_column(String(200))
    relative_path: Mapped[str] = mapped_column(String(253))
    size_bytes: Mapped[int] = mapped_column(Integer)
    sha256: Mapped[str] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    report: Mapped[Report | None] = relationship(back_populates="artifacts")


class SecDeskAudit(WorkspaceBase):
    """Local native launch acknowledgment; never command arguments or output."""

    __tablename__ = "secdesk_audit"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    tool_id: Mapped[str] = mapped_column(String(64))
    mode: Mapped[str] = mapped_column(String(16))
    event: Mapped[str] = mapped_column(String(16))
    authorized: Mapped[bool] = mapped_column(Boolean)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class SecDeskFinding(WorkspaceBase):
    """Explicit normalized observations, redacted before persistence."""

    __tablename__ = "secdesk_findings"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    identity: Mapped[str] = mapped_column(String(64), unique=True)
    tool_id: Mapped[str] = mapped_column(String(64))
    title: Mapped[str] = mapped_column(String(200))
    severity: Mapped[str] = mapped_column(String(16))
    target: Mapped[str] = mapped_column(String(200))
    evidence: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
