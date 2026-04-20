"""Pydantic configuration models for the demo data generator."""

from __future__ import annotations

from enum import Enum
from typing import List, Optional

from pydantic import BaseModel, Field


class DeviceTypeEnum(str, Enum):
    IoMT = "IoMT"
    IoT = "IoT"
    Workstation = "Workstation"
    Server = "Server"
    Network = "Network"
    Unknown = "Unknown"


class VlanConfig(BaseModel):
    vlan_id: int = Field(..., ge=1, le=4094)
    name: str
    subnet: str  # CIDR e.g. "10.10.10.0/24"
    device_type: DeviceTypeEnum
    device_count: int = Field(..., ge=1, le=500)
    gateway_ip: Optional[str] = None  # auto-generate if None


class NetworkConfig(BaseModel):
    org_name: str = "Benh vien Da khoa"
    domain: str = "hospital.local"
    dns_server: str = "10.0.0.1"
    vlans: List[VlanConfig]
    simulate_days: int = Field(default=1, ge=1, le=7)
    events_per_device: int = Field(default=50, ge=10, le=500)


class GenerateResult(BaseModel):
    status: str
    files_written: List[str]
    device_counts: dict  # { "IoMT": 10, "Workstation": 30, ... }
    total_devices: int
    total_events: int
    log_dir: str
    message: str
