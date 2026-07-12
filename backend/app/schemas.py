from pydantic import BaseModel, HttpUrl
from typing import Any
class BootstrapRequest(BaseModel):
    client_name: str='Hackathon Client'; workspace_name: str='Website Security Program'; target_url: HttpUrl; scope_note: str='Authorized public website baseline scan.'; budget_usd: float=2.0
class RunOut(BaseModel):
    run_id:int; workspace_id:int; asset_id:int; status:str; stage:str; progress:int; needs_approval: bool=False
class ApprovalRequest(BaseModel):
    decided_by: str='reviewer'; reason: str='Approved safe passive baseline scan.'
class DashboardOut(BaseModel):
    workspaces:list[dict[str,Any]]; runs:list[dict[str,Any]]; findings:list[dict[str,Any]]; approvals:list[dict[str,Any]]; cost:dict[str,Any]; provider:dict[str,Any]
