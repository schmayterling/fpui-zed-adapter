"""lldb step-tracer for the Path B div-hunt.

Loaded into an lldb attached to the clone. Sets a breakpoint on RENDER_FN; on hit it walks
RENDER_FN's body, stepping OVER each bl/blr, snapshotting the sret buffer (x8) before + after
each call. A call that writes a big struct (>=96 of 256 sampled bytes change) is a div()/v_flex()
candidate — div returns a ~500B Div via sret, every other call returns small (ptr/len pairs,
SharedStrings) or nothing. Prints the ordered call table with the candidates flagged, then
auto-continues so the host doesn't freeze.

Usage (from an .lldb command file):
    command script import .../re/div_tracer.py
    breakpoint set -a <RENDER_FN_runtime_addr>
    breakpoint command add -F div_tracer.on_render
    continue
"""
import lldb

SAMPLE = 256          # bytes of the sret buffer to diff per call
BIG = 96              # >= this many changed bytes => big-struct constructor (div/v_flex)
MAX_STEPS = 4000      # safety cap on instructions walked inside RENDER_FN


def _fn_bounds(frame, target):
    fn = frame.GetFunction()
    if fn and fn.IsValid():
        a = fn.GetStartAddress().GetLoadAddress(target)
        b = fn.GetEndAddress().GetLoadAddress(target)
        if a != lldb.LLDB_INVALID_ADDRESS and b != lldb.LLDB_INVALID_ADDRESS:
            return a, b
    sym = frame.GetSymbol()
    if sym and sym.IsValid():
        a = sym.GetStartAddress().GetLoadAddress(target)
        b = sym.GetEndAddress().GetLoadAddress(target)
        if a != lldb.LLDB_INVALID_ADDRESS and b != lldb.LLDB_INVALID_ADDRESS:
            return a, b
    pc = frame.GetPC()
    return pc, pc + 0x8000


_TRACED = False


def on_render(frame, bp_loc, extra, internal_dict):
    global _TRACED
    if _TRACED:
        return False  # already traced the first woah render; ignore further hits
    _TRACED = True
    thread = frame.GetThread()
    process = thread.GetProcess()
    target = process.GetTarget()
    # Stepping inside a breakpoint callback only works synchronously — in async mode the first
    # StepInstruction returns while the process is still running and the next read races.
    target.GetDebugger().SetAsync(False)
    err = lldb.SBError()

    # RENDER_FN's entry is an adrp;br thunk that jumps to the real body — but lldb groups the
    # thunk with trailing dead code into one 0x368 symbol, so a size check won't detect it.
    # Inspect the opcodes and step the thunk so the br lands us in the real render body.
    ins = target.ReadInstructions(lldb.SBAddress(frame.GetPC(), target), 2)
    m0 = ins.GetInstructionAtIndex(0).GetMnemonic(target).strip() if ins.GetSize() >= 1 else ""
    m1 = ins.GetInstructionAtIndex(1).GetMnemonic(target).strip() if ins.GetSize() >= 2 else ""
    if m0 == "adrp" and m1 == "br":
        thread.StepInstruction(False)   # adrp
        thread.StepInstruction(False)   # br  -> real body
    elif m0 in ("b", "br"):
        thread.StepInstruction(False)   # bare branch -> real body
    frame = thread.GetFrameAtIndex(0)
    lo, hi = _fn_bounds(frame, target)
    print("=== div_tracer: RENDER_FN body [%#x, %#x), entry pc=%#x ===" % (lo, hi, frame.GetPC()))

    calls = []
    for _ in range(MAX_STEPS):
        f = thread.GetFrameAtIndex(0)
        pc = f.GetPC()
        if pc < lo or pc >= hi:          # stepped/returned out of RENDER_FN's body
            break
        insts = target.ReadInstructions(lldb.SBAddress(pc, target), 1)
        if insts.GetSize() == 0:
            break
        inst = insts.GetInstructionAtIndex(0)
        mnem = inst.GetMnemonic(target).strip()
        if mnem in ("bl", "blr"):
            ops = inst.GetOperands(target)
            x8 = f.FindRegister("x8").GetValueAsUnsigned()
            before = process.ReadMemory(x8, SAMPLE, err) if x8 > 0x100000000 else None
            thread.StepInstruction(True)  # step OVER the call
            after = process.ReadMemory(x8, SAMPLE, err) if x8 > 0x100000000 else None
            changed = sum(1 for a, b in zip(before, after) if a != b) if (before and after) else -1
            preview = after[:32].hex() if (after and changed >= BIG) else ""
            calls.append((pc, ops, x8, changed, preview))
        else:
            thread.StepInstruction(True)

    for pc, ops, x8, changed, preview in calls:
        flag = "   <<< DIV/V_FLEX CANDIDATE" if changed >= BIG else ""
        line = "CALL %#x  %-24s x8=%#x changed=%d%s" % (pc, ops, x8, changed, flag)
        print(line)
        if preview:
            print("     sret[0:32]=%s" % preview)
    print("=== div_tracer: %d calls traced, %d candidates ===" % (
        len(calls), sum(1 for c in calls if c[3] >= BIG)))
    process.Detach()  # resume the host + remove the breakpoint cleanly (no stale traps on restart)
    return False


def __lldb_init_module(debugger, internal_dict):
    pass
