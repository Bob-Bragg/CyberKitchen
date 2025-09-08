from __future__ import annotations
import json, base64, io
from dataclasses import dataclass, asdict
from typing import Any, Dict, List, Optional
from urllib.parse import urlencode, parse_qs
import streamlit as st

# ✅ Fixed, complete import — no dangling comma
from ck_ops import (
    OPS,
    Operation,
    to_bytes,
    try_decode_utf8,
    bytes_to_hex,
    clamp_bytes,
    magic_detect,
)

APP = "CyberKitchen"
st.set_page_config(page_title=APP, page_icon="🍳", layout="wide")

# ------------------------------
# Session model
# ------------------------------
@dataclass
class Step:
    op_key: str
    enabled: bool = True
    params: Dict[str, Any] = None

    def to_json(self): return {"op_key": self.op_key, "enabled": self.enabled, "params": self.params or {}}

@dataclass
class Recipe:
    steps: List[Step]

    def to_json(self):
        return {"steps": [s.to_json() for s in self.steps]}

# Defaults
if "recipe" not in st.session_state:
    st.session_state.recipe = Recipe(steps=[])

if "input_bytes" not in st.session_state:
    st.session_state.input_bytes = b""

# ------------------------------
# Helpers: recipe encode/decode
# -----------------
