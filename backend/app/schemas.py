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
