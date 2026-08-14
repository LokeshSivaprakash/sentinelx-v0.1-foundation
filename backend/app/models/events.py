from datetime import datetime
from typing import Any, Literal
from uuid import UUID
from pydantic import BaseModel, Field
Severity=Literal["informational","low","medium","high","critical"]
class ResourceRef(BaseModel):
    type:str
    id:str
    name:str|None=None
class Finding(BaseModel):
    id:str|None=None
    package:str|None=None
    installed_version:str|None=None
    fixed_version:str|None=None
    cvss:float|None=Field(default=None,ge=0,le=10)
    metadata:dict[str,Any]=Field(default_factory=dict)
class SecurityEvent(BaseModel):
    event_id:UUID
    schema_version:str="0.1"
    source:str
    event_type:str
    severity:Severity
    timestamp:datetime
    tenant_id:str
    resource:ResourceRef
    finding:Finding|None=None
    evidence:list[dict[str,Any]]=Field(default_factory=list)
    relationships:list[dict[str,Any]]=Field(default_factory=list)
    metadata:dict[str,Any]=Field(default_factory=dict)
    raw_reference:str|None=None
