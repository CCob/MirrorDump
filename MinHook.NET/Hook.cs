using System;
using System.Runtime.InteropServices;
using static MinHook.Trampoline;
using static MinHook.Utils;

namespace MinHook {
    internal class Hook
    {
        public bool Enabled { get; private set; } = false;
        public bool QueueEnabled { get; private set; } = false;
        public IntPtr Original { get; private set; }

        Trampoline trampoline;
        
        public Hook(IntPtr target, IntPtr detour, MemorySlot memorySlot) {
            trampoline = new Trampoline(target, detour, memorySlot);
            Original = trampoline.Tramp;
        }

        public void Enable(bool enable = true) {

            MemoryProtection oldProtect;
            long patchSize = Marshal.SizeOf(typeof(JMPCALL_REL));
            IntPtr patchTarget = trampoline.Target;

            if (trampoline.PatchAbove) {
                patchTarget = patchTarget - Marshal.SizeOf(typeof(JMPCALL_REL));
                patchSize += Marshal.SizeOf(typeof(JMP_REL_SHORT));
            }

            if(!VirtualProtect(patchTarget, (UIntPtr)patchSize, MemoryProtection.ExecuteReadWrite, out oldProtect)) {
                throw new Exception("Failed to change memory protection");
            }

            if (enable) {

                JMPCALL_REL jmp = new JMPCALL_REL(0xE9);

                if (IntPtr.Size == 8) {
                    long rel = ((long)trampoline.Relay - ((long)patchTarget + Marshal.SizeOf(jmp)));
                    jmp.SetOperand((uint)rel);
                } else {
                    jmp.SetOperand((uint)((ulong)trampoline.Detour - ((ulong)patchTarget + (ulong)Marshal.SizeOf(jmp))));
                }

                Marshal.StructureToPtr(jmp, patchTarget, false);

                if (trampoline.PatchAbove) {
                    JMP_REL_SHORT shortJmp = new JMP_REL_SHORT(0xEB, (byte)(0 - (Marshal.SizeOf(typeof(JMP_REL_SHORT)) + Marshal.SizeOf(jmp))));
                    Marshal.StructureToPtr(shortJmp, trampoline.Target, false);
                }
            } else {

                if (trampoline.PatchAbove) {
                    Marshal.Copy(trampoline.Backup, 0, patchTarget, Marshal.SizeOf(typeof(JMPCALL_REL)) + Marshal.SizeOf(typeof(JMP_REL_SHORT)));
                } else {
                    Marshal.Copy(trampoline.Backup, 0, patchTarget, Marshal.SizeOf(typeof(JMPCALL_REL)));
                }
            }

            VirtualProtect(patchTarget, (UIntPtr)patchSize, oldProtect, out _);

            //TODO: flush instruction cache
            Enabled = true; 
        }
    }
}
