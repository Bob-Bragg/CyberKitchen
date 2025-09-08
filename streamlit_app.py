from __future__ import annotations
import json, base64, io, re
from dataclasses import dataclass
from typing import Any, Dict, List
import streamlit as st

# ---- Robust import: fall back if ck_ops lacks `magic_detect`
try:
    from ck_ops import (
        OPS,
        Operation,
        to_bytes,
        try_decode_utf8,
        bytes_to_hex,
        clamp_bytes,
        magic_detect,   # may not exist in your ck_ops
    )
except ImportError:
    # Re-import everything except magic_detect
    from ck_ops import (
        OPS,
        Operation,
        to_bytes,
        try_decode_utf8,
        bytes_to_hex,
        clamp_bytes,
    )
    # Minimal local magic_detect fallback
    def magic_detect(sample: str):
        hints = []
        s = (sample or "").strip()
        # Base64 heuristic
        if re.fullmatch(r"[A-Za-z0-9+/=\s]{8,}", s):
            try:
                base64.b64decode(s, validate=True)
                hints.append(("Base64", 0.90))
            except Exception:
                pass
        # Hex heuristic
        if re.fullmatch(r"[0-9A-Fa-f]{2,}", s) and len(s) % 2 == 0:
            hints.append(("Hex", 0.80))
        # JWT heuristic
        parts = s.split(".")
        if len(parts) in (2, 3) and all(re.fullmatch(r"[A-Za-z0-9_\-]+", p or "") for p in parts):
            hints.append(("JWT", 0.95))
        # URL-encoding heuristic
        if "%" in s or "+" in s:
            hints.append(("URL-Encoded", 0.60))
        return sorted(hints, key=lambda x: x[1], reverse=True)

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
    def to_json(self): 
        return {"op_key": self.op_key, "enabled": self.enabled, "params": self.params or {}}

@dataclass
class Recipe:
    steps: List[Step]
    def to_json(self):
        return {"steps": [s.to_json() for s in self.steps]}

if "recipe" not in st.session_state:
    st.session_state.recipe = Recipe(steps=[])
if "input_bytes" not in st.session_state:
    st.session_state.input_bytes = b""

# ------------------------------
# Helpers: recipe encode/decode
# ------------------------------
def recipe_to_b64url(recipe: Recipe) -> str:
    raw = json.dumps(recipe.to_json(), separators=(",",":")).encode("utf-8")
    return base64.urlsafe_b64encode(raw).decode("ascii")

def recipe_from_b64url(s: str) -> Recipe:
    data = base64.urlsafe_b64decode(s.encode("ascii"))
    obj = json.loads(data.decode("utf-8"))
    steps = [Step(op_key=it["op_key"], enabled=bool(it.get("enabled", True)), params=it.get("params") or {}) 
             for it in obj.get("steps",[])]
    return Recipe(steps=steps)

def load_recipe_from_url_if_any():
    q = st.experimental_get_query_params()
    if "r" in q:
        try:
            r = recipe_from_b64url(q["r"][0])
            st.session_state.recipe = r
            st.toast("Loaded recipe from URL", icon="✅")
        except Exception as e:
            st.toast(f"Failed to load recipe: {e}", icon="⚠️")

load_recipe_from_url_if_any()

# ------------------------------
# Top toolbar
# ------------------------------
c1, c2, c3, c4 = st.columns([1.2, 2.2, 2.6, 1.8])
with c1:
    st.markdown("### 🍳 CyberKitchen")

with c2:
    if st.button("🎯 Magic Detect", use_container_width=True):
        sample = try_decode_utf8(st.session_state.input_bytes)[:4000]
        hints = magic_detect(sample)
        if hints:
            st.info("\n".join([f"- {name} (confidence {int(conf*100)}%)" for name, conf in hints]))
        else:
            st.info("No obvious patterns detected.")

with c3:
    export_col1, export_col2 = st.columns(2)
    with export_col1:
        if st.button("💾 Save Recipe JSON", use_container_width=True):
            data = json.dumps(st.session_state.recipe.to_json(), indent=2).encode("utf-8")
            st.download_button("Download recipe.json", data, file_name="recipe.json", mime="application/json", use_container_width=True)
    with export_col2:
        if st.button("🔗 Copy Share URL", use_container_width=True):
            b64 = recipe_to_b64url(st.session_state.recipe)
            url = st.experimental_get_url()
            glue = "&" if "?" in url else "?"
            share_url = f"{url}{glue}r={b64}"
            st.code(share_url)

with c4:
    uploaded = st.file_uploader("Load Recipe JSON", type=["json"])
    if uploaded:
        try:
            obj = json.loads(uploaded.read().decode("utf-8"))
            steps = [Step(op_key=s["op_key"], enabled=bool(s.get("enabled",True)), params=s.get("params") or {}) 
                     for s in obj.get("steps",[])]
            st.session_state.recipe = Recipe(steps=steps)
            st.success("Recipe loaded.")
        except Exception as e:
            st.error(f"Load failed: {e}")

st.divider()

# ------------------------------
# Workspace layout
# ------------------------------
left, middle, right = st.columns([2,3,2])

# --- Left: Input
with left:
    st.subheader("📝 Input")
    mode = st.radio("Input Type", ["Text", "File (bytes)"], horizontal=True)
    MAX = 2_000_000

    if mode == "Text":
        txt = st.text_area("Paste text/data", height=220, value=try_decode_utf8(st.session_state.input_bytes))
        st.session_state.input_bytes = clamp_bytes(txt.encode("utf-8", errors="replace"), MAX)
    else:
        f = st.file_uploader("Upload a file (≤ 2 MB)", accept_multiple_files=False)
        if f:
            content = f.read()
            st.session_state.input_bytes = clamp_bytes(content, MAX)
            st.info(f"Loaded {len(st.session_state.input_bytes)} bytes.")

    with st.expander("Preview & Formats"):
        t1, t2 = st.tabs(["Text", "Hex"])
        with t1: st.code(try_decode_utf8(st.session_state.input_bytes)[:4000] or "∅", language="text")
        with t2: st.code(bytes_to_hex(st.session_state.input_bytes)[:8000] or "∅", language="text")

# --- Middle: Operations builder
with middle:
    st.subheader("🔧 Recipe Builder")

    cols = st.columns([2,1,1,1])
    with cols[0]:
        new_op = st.selectbox("Add operation", ["—"] + [f"{o.category} · {o.name} ({k})" for k,o in OPS.items()])
    with cols[1]:
        if st.button("➕ Add"):
            if new_op != "—":
                key = new_op.split("(")[-1].rstrip(")")
                st.session_state.recipe.steps.append(Step(op_key=key, enabled=True, params={}))
                st.rerun()
    with cols[2]:
        if st.button("🧹 Clear"):
            st.session_state.recipe = Recipe(steps=[])
            st.rerun()
    with cols[3]:
        if st.button("▶ Run"):
            pass

    for idx, step in enumerate(st.session_state.recipe.steps):
        op = OPS.get(step.op_key)
        with st.expander(f"Step {idx+1}: {op.name} [{op.category}]  ({step.op_key})", expanded=False):
            top = st.columns([0.9,0.7,0.7,0.7,1.1])
            with top[0]:
                step.enabled = st.checkbox("Enabled", value=step.enabled, key=f"en_{idx}")
            with top[1]:
                if st.button("⬆️ Up", key=f"up_{idx}") and idx>0:
                    st.session_state.recipe.steps[idx-1], st.session_state.recipe.steps[idx] = st.session_state.recipe.steps[idx], st.session_state.recipe.steps[idx-1]
                    st.rerun()
            with top[2]:
                if st.button("⬇️ Down", key=f"down_{idx}") and idx < len(st.session_state.recipe.steps)-1:
                    st.session_state.recipe.steps[idx+1], st.session_state.recipe.steps[idx] = st.session_state.recipe.steps[idx], st.session_state.recipe.steps[idx+1]
                    st.rerun()
            with top[3]:
                if st.button("🗑️ Remove", key=f"rm_{idx}"):
                    del st.session_state.recipe.steps[idx]
                    st.rerun()
            with top[4]:
                st.caption(op.name)

            step.params = step.params or {}
            schema = op.params_schema or {}
            cols2 = st.columns(3)
            slot = 0
            for pname, default in schema.items():
                with cols2[slot % 3]:
                    if isinstance(default, list):
                        step.params[pname] = st.selectbox(pname, options=default, index=0, key=f"{pname}_{idx}")
                    elif isinstance(default, bool):
                        step.params[pname] = st.checkbox(pname, value=default, key=f"{pname}_{idx}")
                    else:
                        step.params[pname] = st.text_input(pname, value=step.params.get(pname, default), key=f"{pname}_{idx}")
                    slot += 1

# --- Right: Output
with right:
    st.subheader("📤 Output")
    data = st.session_state.input_bytes
    errors: List[str] = []
    intermediate_previews = st.checkbox("Show intermediate outputs", value=False)

    for idx, step in enumerate(st.session_state.recipe.steps):
        if not step.enabled: 
            continue
        op = OPS.get(step.op_key)
        try:
            data, meta = op.fn(data, step.params or {})
            data = clamp_bytes(data)
            if intermediate_previews:
                with st.expander(f"After step {idx+1}: {op.name}"):
                    t1, t2 = st.tabs(["Text", "Hex"])
                    with t1: st.code(try_decode_utf8(data)[:4000] or "∅")
                    with t2: st.code(bytes_to_hex(data)[:8000] or "∅")
        except Exception as e:
            errors.append(f"Step {idx+1} ({op.name}): {e}")
            break

    if errors:
        st.error("\n".join(errors))
    else:
        vt, vh = st.tabs(["Text", "Hex / JSON"])
        with vt: st.code(try_decode_utf8(data)[:8000] or "∅")
        with vh: st.code(bytes_to_hex(data)[:16000] or "∅")

    st.caption(f"Bytes out: {len(data)}")

st.markdown("---")
st.caption("CyberKitchen • MVP — share feedback for next ops (AES/Vigenère/EXIF/QR/etc.)")
