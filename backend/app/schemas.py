from pydantic import BaseModel, HttpUrl
from typing import Any
class BootstrapRequest(BaseModel):
    client_name: str='Vanguard Client'; workspace_name: str='Zer0 Security Program'; target_url: HttpUrl; scope_note: str='Authorized public website baseline scan.'; budget_usd: float=2.0; scan_tier: str='free'; payment_reference: str=''; access_key: str=''
class AccessKeyRequest(BaseModel):
    plan: str='vanguard'; note: str=''
class RunOut(BaseModel):
    run_id:int; workspace_id:int; asset_id:int; status:str; stage:str; progress:int; needs_approval: bool=False
class ApprovalRequest(BaseModel):
    decided_by: str='reviewer'; reason: str='Approved safe passive baseline scan.'
class DashboardOut(BaseModel):
    workspaces:list[dict[str,Any]]; runs:list[dict[str,Any]]; findings:list[dict[str,Any]]; approvals:list[dict[str,Any]]; cost:dict[str,Any]; provider:dict[str,Any]; commerce:dict[str,Any]={}
class PaymentIntentRequest(BaseModel):
    target_url: HttpUrl; scan_tier: str='detailed'
class SubscribeRequest(BaseModel):
    workspace_id:int; plan:str='vanguard'; payment_reference:str=''
class TicketStatusRequest(BaseModel):
    status:str='closed'
class UserUpsertRequest(BaseModel):
    workspace_id:int=0; email:str; role:str='analyst'
class BillingWebhookRequest(BaseModel):
    workspace_id:int; event:str='checkout.session.completed'; plan:str='vanguard'; payment_reference:str=''
class IntelligenceModeRequest(BaseModel):
    mode:str='deterministic'
class RepoAnalyzeRequest(BaseModel):
    repo_path:str=''  # local checkout path (server-side) OR
    repo_url:str=''   # public git URL to clone (safe, read-only)
    deep:bool=False   # include insecure-code SAST patterns
    workspace_id:int=0
class InterventionResumeRequest(BaseModel):
    solved: bool = True          # human confirms they solved the CAPTCHA / logged in
    note: str = ''               # optional: what the human did (e.g. "solved captcha", "logged in as test user")
class CredentialVaultRequest(BaseModel):
    label:str='Vanguard managed test account'; username:str='security-admin@example.com'; secret_ref:str='external-secret-not-stored'; role_name:str='standard_user'; allowed_use:str='authorized-authenticated-testing-only'
class AuthSessionRequest(BaseModel):
    credential_id:int=0; asset_id:int=0; login_url:str=''; success_indicator:str='dashboard'; status:str='needs_human_setup'
class ScopeRuleRequest(BaseModel):
    include_pattern:str='/*'; exclude_pattern:str='/logout,/delete,/billing'; test_level:str='safe_forms_dry_run'
class AuthenticatedFormTestRequest(BaseModel):
    credential_id:int=0; auth_session_id:int=0; dry_run:bool=True; reviewer:str='reviewer'; reason:str='Authorized authenticated safe-form dry run.'
class RetestRequest(BaseModel):
    reviewer:str='analyst'; outcome:str='ready_for_retest'; evidence_note:str='Remediation submitted for validation.'
