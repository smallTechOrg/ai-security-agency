from datetime import datetime
from sqlalchemy import Boolean, DateTime, Float, ForeignKey, Integer, String, Text, JSON
from sqlalchemy.orm import Mapped, mapped_column, relationship
from .db import Base
class Client(Base):
    __tablename__='clients'; id:Mapped[int]=mapped_column(Integer, primary_key=True); name:Mapped[str]=mapped_column(String(200)); created_at:Mapped[datetime]=mapped_column(DateTime, default=datetime.utcnow)
class Workspace(Base):
    __tablename__='workspaces'; id:Mapped[int]=mapped_column(Integer, primary_key=True); client_id:Mapped[int]=mapped_column(ForeignKey('clients.id')); name:Mapped[str]=mapped_column(String(200)); risk_appetite:Mapped[str]=mapped_column(String(50), default='safe'); budget_usd:Mapped[float]=mapped_column(Float, default=2.0); client=relationship('Client')
class Asset(Base):
    __tablename__='assets'; id:Mapped[int]=mapped_column(Integer, primary_key=True); workspace_id:Mapped[int]=mapped_column(ForeignKey('workspaces.id')); url:Mapped[str]=mapped_column(String(1000)); authorized:Mapped[bool]=mapped_column(Boolean, default=False); scope_note:Mapped[str]=mapped_column(Text, default='')
class AuditRun(Base):
    __tablename__='audit_runs'; id:Mapped[int]=mapped_column(Integer, primary_key=True); workspace_id:Mapped[int]=mapped_column(ForeignKey('workspaces.id')); asset_id:Mapped[int]=mapped_column(ForeignKey('assets.id')); status:Mapped[str]=mapped_column(String(50), default='queued'); stage:Mapped[str]=mapped_column(String(80), default='intake'); progress:Mapped[int]=mapped_column(Integer, default=0); cost_estimate_usd:Mapped[float]=mapped_column(Float, default=0); app_model:Mapped[dict]=mapped_column(JSON, default=dict); created_at:Mapped[datetime]=mapped_column(DateTime, default=datetime.utcnow); updated_at:Mapped[datetime]=mapped_column(DateTime, default=datetime.utcnow)
class Evidence(Base):
    __tablename__='evidence'; id:Mapped[int]=mapped_column(Integer, primary_key=True); run_id:Mapped[int]=mapped_column(ForeignKey('audit_runs.id')); kind:Mapped[str]=mapped_column(String(80)); title:Mapped[str]=mapped_column(String(300)); data:Mapped[dict]=mapped_column(JSON, default=dict); created_at:Mapped[datetime]=mapped_column(DateTime, default=datetime.utcnow)
class Finding(Base):
    __tablename__='findings'; id:Mapped[int]=mapped_column(Integer, primary_key=True); run_id:Mapped[int]=mapped_column(ForeignKey('audit_runs.id')); severity:Mapped[str]=mapped_column(String(30)); title:Mapped[str]=mapped_column(String(300)); description:Mapped[str]=mapped_column(Text); evidence:Mapped[str]=mapped_column(Text, default=''); remediation:Mapped[str]=mapped_column(Text, default=''); compliance:Mapped[dict]=mapped_column(JSON, default=dict)
class Approval(Base):
    __tablename__='approvals'; id:Mapped[int]=mapped_column(Integer, primary_key=True); run_id:Mapped[int]=mapped_column(ForeignKey('audit_runs.id')); action:Mapped[str]=mapped_column(String(120)); status:Mapped[str]=mapped_column(String(30), default='pending'); reason:Mapped[str]=mapped_column(Text, default=''); decided_by:Mapped[str]=mapped_column(String(120), default=''); created_at:Mapped[datetime]=mapped_column(DateTime, default=datetime.utcnow)
class AuditLog(Base):
    __tablename__='audit_logs'; id:Mapped[int]=mapped_column(Integer, primary_key=True); workspace_id:Mapped[int]=mapped_column(Integer, default=0); run_id:Mapped[int]=mapped_column(Integer, default=0); actor:Mapped[str]=mapped_column(String(80), default='system'); action:Mapped[str]=mapped_column(String(200)); detail:Mapped[dict]=mapped_column(JSON, default=dict); created_at:Mapped[datetime]=mapped_column(DateTime, default=datetime.utcnow)
class Playbook(Base):
    __tablename__='playbooks'; id:Mapped[int]=mapped_column(Integer, primary_key=True); name:Mapped[str]=mapped_column(String(200)); trigger:Mapped[str]=mapped_column(String(200)); steps:Mapped[dict]=mapped_column(JSON, default=dict); confidence:Mapped[float]=mapped_column(Float, default=0.5)

class User(Base):
    __tablename__='users'; id:Mapped[int]=mapped_column(Integer, primary_key=True); workspace_id:Mapped[int]=mapped_column(Integer, default=0); email:Mapped[str]=mapped_column(String(240)); role:Mapped[str]=mapped_column(String(40), default='analyst')
class ScopeRule(Base):
    __tablename__='scope_rules'; id:Mapped[int]=mapped_column(Integer, primary_key=True); workspace_id:Mapped[int]=mapped_column(Integer); include_pattern:Mapped[str]=mapped_column(String(500)); exclude_pattern:Mapped[str]=mapped_column(String(500), default=''); test_level:Mapped[str]=mapped_column(String(40), default='passive_only')
class ScannerTask(Base):
    __tablename__='scanner_tasks'; id:Mapped[int]=mapped_column(Integer, primary_key=True); run_id:Mapped[int]=mapped_column(Integer); module:Mapped[str]=mapped_column(String(120)); target:Mapped[str]=mapped_column(String(1000)); status:Mapped[str]=mapped_column(String(40), default='queued'); summary:Mapped[str]=mapped_column(Text, default=''); error:Mapped[str]=mapped_column(Text, default=''); started_at:Mapped[datetime]=mapped_column(DateTime, default=datetime.utcnow); completed_at:Mapped[datetime]=mapped_column(DateTime, nullable=True)
class CostEvent(Base):
    __tablename__='cost_events'; id:Mapped[int]=mapped_column(Integer, primary_key=True); run_id:Mapped[int]=mapped_column(Integer); provider:Mapped[str]=mapped_column(String(60)); operation:Mapped[str]=mapped_column(String(120)); estimated_tokens:Mapped[int]=mapped_column(Integer, default=0); estimated_usd:Mapped[float]=mapped_column(Float, default=0); detail:Mapped[dict]=mapped_column(JSON, default=dict); created_at:Mapped[datetime]=mapped_column(DateTime, default=datetime.utcnow)
class ReportVersion(Base):
    __tablename__='report_versions'; id:Mapped[int]=mapped_column(Integer, primary_key=True); run_id:Mapped[int]=mapped_column(Integer); status:Mapped[str]=mapped_column(String(40), default='draft'); content:Mapped[dict]=mapped_column(JSON, default=dict); created_at:Mapped[datetime]=mapped_column(DateTime, default=datetime.utcnow)
