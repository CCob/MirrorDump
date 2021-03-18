using SharpDisasm;
using SharpDisasm.Udis86;
using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Linq;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Text;
using static MinHook.Utils;

namespace MinHook {
    internal class Trampoline {

        public interface AddressSupport {
            void SetAddress(IntPtr address);
        }

        public interface OperandSupport {
            void SetOperand(uint operand);
        }

        public interface OpcodeSupport {
            void SetOpcode(byte opcode);
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct JMP_REL_SHORT {
            byte opcode;      // EB xx: JMP +2+xx
            byte operand;

            public JMP_REL_SHORT(byte opcode, byte operand) {
                this.opcode = opcode;
                this.operand = operand;
            }
        }

        // 32-bit direct relative jump/call.
        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct JMPCALL_REL : OperandSupport {
            byte opcode;             // E9/E8 xxxxxxxx: JMP/CALL +5+xxxxxxxx
            public uint operand;     // Relative destination address

            public JMPCALL_REL(byte opcode) {
                this.opcode = opcode;
                operand = 0;
            }
 
            public void SetOperand(uint operand) {
                this.operand = operand;
            }
        }

        // 64-bit indirect absolute jump.
        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        struct JMP_ABS : AddressSupport {
            byte opcode0;     // FF25 00000000: JMP [+6]
            byte opcode1;
            uint dummy;
            public ulong address;     // Absolute destination address

            public JMP_ABS(IntPtr addr) {
                opcode0 = 0xFF;
                opcode1 = 0x25;
                dummy = 0;
                address = (ulong)addr;
            }

            public void SetAddress(IntPtr address) {
                this.address = (ulong)address;
            }
        }

        // 64-bit indirect absolute call.
        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        struct CALL_ABS : AddressSupport {
            byte opcode0;     // FF15 00000002: CALL [+6]
            byte opcode1;
            uint dummy0;
            byte dummy1;      // EB 08:         JMP +10
            byte dummy2;
            public ulong address;    // Absolute destination address

            public CALL_ABS(IntPtr addr) {
                opcode0 = 0xFF;
                opcode1 = 0x15;
                dummy0 = 0x000000002;
                dummy1 = 0xEB;
                dummy2 = 0x08;
                address = (ulong)addr;
            }

            public void SetAddress(IntPtr address) {
                this.address = (ulong)address;
            }
        }

        // 32-bit direct relative conditional jumps.
        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        struct JCC_REL : OperandSupport, OpcodeSupport {
            byte opcode0;     // 0F8* xxxxxxxx: J** +6+xxxxxxxx
            byte opcode1;
            uint operand;     // Relative destination address

            public JCC_REL(uint operand) {
                opcode0 = 0x0F;
                opcode1 = 0x80;
                this.operand = operand;
            }

            public void SetOpcode(byte opcode) {
                this.opcode1 = opcode;
            }

            public void SetOperand(uint operand) {
                this.operand = operand;
            }
        }

        // 64bit indirect absolute conditional jumps that x64 lacks.
        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        struct JCC_ABS : AddressSupport, OpcodeSupport {
            byte opcode;      // 7* 0E:         J** +16
            byte dummy0;
            byte dummy1;      // FF25 00000000: JMP [+6]
            byte dummy2;
            uint dummy3;
            public ulong address;    // Absolute destination address

            public JCC_ABS(IntPtr addr) {
                opcode = 0x70;
                dummy0 = 0x0E;
                dummy1 = 0xFF;
                dummy2 = 0x25;
                dummy3 = 0;
                address = (ulong)addr;
            }

            public void SetAddress(IntPtr address) {
                this.address = (ulong)address;
            }

            public void SetOpcode(byte opcode) {
                this.opcode = opcode;
            }
        }  
                
        public IntPtr Target { get; private set; }
        public IntPtr Detour { get; private set; }
        public IntPtr Tramp { get; private set; } 
        public IntPtr Relay { get; private set; }
        public bool PatchAbove { get; private set; }
        public uint InstructionBoundaries { get; private set; }
        public byte[] OldInstructionBoundaries { get; private set; } = new byte[64];
        public byte[] NewInstructionBoundaries { get; private set; } = new byte[64];
        public byte[] Backup { get; private set; } = new byte[8];

        public int TrampolineMaxSize = 32;

        static int PAGE_EXECUTE = 0x10;
        static int PAGE_EXECUTE_READ = 0x20;
        static int PAGE_EXECUTE_READWRITE = 0x40;
        static int PAGE_EXECUTE_WRITECOPY = 0x80;
        static int PAGE_EXECUTE_FLAGS = (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY);

        [SuppressMessage("CodeQuality", "IDE0052:Remove unread private members", Justification = "MemorySlot has unmanged resources that we need to hold onto to prevent GC")]
        readonly MemorySlot memorySlot;

        public Trampoline(IntPtr target, IntPtr detour, MemorySlot memorySlot ) {

            Target = target;
            Detour = detour;
            Tramp = memorySlot.Address;
            this.memorySlot = memorySlot;

            uint oldPos = 0;
            uint newPos = 0;
            IntPtr jmpDest = IntPtr.Zero;
            IntPtr instBuf = Marshal.AllocHGlobal(16);
            bool finished = false;
            bool is64 = IntPtr.Size == 8;
            object jmp;
            object call;
            object jcc;
           
            if (is64) {
                call = new CALL_ABS(IntPtr.Zero);
                jmp = new JMP_ABS(IntPtr.Zero);
                jcc = new JCC_ABS(IntPtr.Zero);
            } else {
                call = new JMPCALL_REL(0xE8);
                jmp = new JMPCALL_REL(0xE9);
                jcc = new JCC_REL(0);
            }            

            do {
                object srcObj = null;
                uint copySize;
                IntPtr copySrc;
                IntPtr oldInst = (IntPtr)((long)Target + oldPos);
                IntPtr newInst = (IntPtr)((long)Tramp + newPos);
               
                Disassembler disasm = new Disassembler(oldInst, 16, is64 ? ArchitectureMode.x86_64 : ArchitectureMode.x86_32, 0, true);
                disasm.Disassemble();
                
                Instruction inst = disasm.NextInstruction();

                if (inst.Error)
                    throw new Exception(inst.ErrorMessage);

                copySrc = oldInst;
                copySize = (uint)inst.Length;

                if(oldPos >= Marshal.SizeOf(typeof(JMPCALL_REL))) {

                    if (is64) {
                        ((AddressSupport)jmp).SetAddress(oldInst);
                    } else {
                        ((OperandSupport)jmp).SetOperand((uint)((uint)oldInst - ((uint)newInst + Marshal.SizeOf(jmp))));
                    }

                    srcObj = jmp;
                    copySize = (uint)Marshal.SizeOf(jmp);
                    finished = true;

                }else if (is64 && inst.HasModRM && ((inst.ModRM & 0xC7) == 0x5)) {

                    byte modRMReg = (byte)((inst.ModRM & 0x3f) >> 3);                    
                    copySrc = instBuf;
                    CopyMemory(instBuf, oldInst, (int)copySize);

                    //TODO: figure out how to calculate imm length with udisasm engine
                    uint immLen = 0;
                    IntPtr relAddr = (IntPtr)((long)instBuf + inst.Length - immLen - 4);
                    uint updatedRel = (uint)((ulong)oldInst + (ulong)inst.Length + inst.Operands[0].LvalUDWord - ((ulong)newInst + (ulong)inst.Length));
                    Marshal.WriteInt32(relAddr, (int)updatedRel);
                    
                    // Complete function if JMP (FF /4)
                    if (inst.Bytes[0] == 0xFF & modRMReg == 4)
                        finished = true;
              
                } else if(inst.Mnemonic == ud_mnemonic_code.UD_Icall) {

                    IntPtr dest = (IntPtr)((long)oldInst + inst.Length + inst.Operands[0].LvalSDWord);

                    if (is64) {
                        ((AddressSupport)call).SetAddress(dest);
                    } else {
                        ((OperandSupport)call).SetOperand((uint)dest - (uint)(newInst + Marshal.SizeOf(call)));
                    }

                    srcObj = call;
                    copySize = (uint)Marshal.SizeOf(call);

                }else if( (inst.Bytes[0] & 0xFD) == 0xE9) {

                    IntPtr dest = oldInst + inst.Length;

                    if ((inst.Bytes[0] == 0xE9)) { //short JMP
                        dest = IntPtr.Add(dest, inst.Operands[0].LvalByte);
                    } else {
                        dest = IntPtr.Add(dest, inst.Operands[0].LvalSDWord);
                    }

                    if((long)Target <= (long)dest && (long)dest < ( (long)Target + Marshal.SizeOf(typeof(JMPCALL_REL)))) {
                        if((long)jmpDest < (long)dest) {
                            jmpDest = dest;
                        }
                    } else {

                        if (is64) {
                            ((AddressSupport)jmp).SetAddress(dest);
                        } else {
                            ((OperandSupport)jmp).SetOperand((uint)((uint)dest - ((uint)newInst + Marshal.SizeOf(jmp))));
                        }

                        srcObj = jmp;
                        copySize = (uint)Marshal.SizeOf(jmp);
                        finished = ((long)oldInst >= (long)jmpDest);
                    }


                }else if(inst.Length >= 2 && 
                            ( (inst.Bytes[0] & 0xF0) == 0x70) || 
                            ( (inst.Bytes[0] & 0xFC) == 0xE0) ||
                            ( inst.Bytes[0] == 0xF0 && (inst.Bytes[1] & 0xF0) == 0x80) ){
                    //Jcc Handler

                    IntPtr dest = oldInst + inst.Length;

                    if( (inst.Bytes[0] & 0xF0) == 0x70 ||
                        (inst.Bytes[0] & 0xFC) == 0xE0) {

                        dest = IntPtr.Add(dest, inst.Operands[0].LvalByte);
                    } else {
                        dest = IntPtr.Add(dest, (int)inst.Operands[0].LvalUDWord);
                    }

                    if((long)Target <= (long)dest && (long)dest < ((long)Target + Marshal.SizeOf(typeof(JMPCALL_REL)))){
                        if((long)jmpDest < (long)dest) {
                            jmpDest = dest;
                        }
                    }else if( (inst.Bytes[0] & 0xFC) == 0xE0) {
                        throw new Exception("LOOPx/Jxx to the outside not supported");
                    } else {

                        byte cond = (byte)((inst.Bytes[0] != 0x0F ? inst.Bytes[0] : inst.Bytes[1]) & 0xF0);

                        if (is64) {
                            ((OpcodeSupport)jcc).SetOpcode((byte)(0x71 ^ cond));
                            ((AddressSupport)jcc).SetAddress(dest);
                        } else {
                            ((OpcodeSupport)jcc).SetOpcode((byte)(0x80 ^ cond));
                            ((OperandSupport)jcc).SetOperand((uint)((uint)dest - ((uint)newInst + Marshal.SizeOf(jcc))));
                        }

                        srcObj = jcc;
                        copySize = (uint)Marshal.SizeOf(jcc);
                    }

                }else if(inst.Mnemonic == ud_mnemonic_code.UD_Iret || inst.Mnemonic == ud_mnemonic_code.UD_Iretf) {

                    finished = ((long)oldInst >= (long)jmpDest);
                }

                if((long)oldInst < (long)jmpDest && copySize != inst.Length) {
                    throw new Exception("Can't alter intruction length in a branch");
                }

                if((newPos + copySize) > TrampolineMaxSize) {
                    throw new Exception("Trampoline function too big");
                }

                if(InstructionBoundaries > OldInstructionBoundaries.Length) {
                    throw new Exception("Trampoline has too many instructions");
                }

                OldInstructionBoundaries[InstructionBoundaries] = (byte)oldPos;
                NewInstructionBoundaries[InstructionBoundaries] = (byte)newPos;
                InstructionBoundaries++;

                if (srcObj != null) { 
                    IntPtr data = Marshal.AllocHGlobal((int)copySize);
                    Marshal.StructureToPtr(srcObj, data, false);
                    CopyMemory((IntPtr)((long)Tramp + newPos), data, (int)copySize);
                    Marshal.FreeHGlobal(data);
                } else {
                    CopyMemory((IntPtr)((long)Tramp + newPos), copySrc, (int)copySize);
                }
               
                newPos += copySize;
                oldPos += (uint)inst.Length;            

            } while (!finished);


            if (oldPos < Marshal.SizeOf(typeof(JMPCALL_REL))

                && IsCodePadding((IntPtr)((long)Target + oldPos), (int)(Marshal.SizeOf(typeof(JMPCALL_REL)) - oldPos))) {

                if (oldPos < Marshal.SizeOf(typeof(JMP_REL_SHORT))
                    && IsCodePadding((IntPtr)((long)Target + oldPos), (int)(Marshal.SizeOf(typeof(JMP_REL_SHORT)) - oldPos))) {

                    throw new Exception("Not enough space for patch");
                }

                if (!IsExecutableAddress( (IntPtr) ( (long)Target - Marshal.SizeOf(typeof(JMPCALL_REL))))) {
                    throw new Exception("Not enought space for patch");
                }

                if (!IsCodePadding((IntPtr)((long)Target - Marshal.SizeOf(typeof(JMPCALL_REL))), Marshal.SizeOf(typeof(JMPCALL_REL)))) {
                    throw new Exception("Not enought space for patch");
                }

                PatchAbove = true;
            }

            if (is64) {
                ((AddressSupport)jmp).SetAddress(Detour);
                Relay = (IntPtr)((long)Tramp + newPos);

                IntPtr data = Marshal.AllocHGlobal((int)Marshal.SizeOf(jmp));
                Marshal.StructureToPtr(jmp, data, false);
                CopyMemory(Relay, data, Marshal.SizeOf(jmp));
                Marshal.FreeHGlobal(data);              
            }

            BackupPrologue();
        }

        void BackupPrologue() {
            
            if (PatchAbove) {

                Marshal.Copy((IntPtr)((long)Target - Marshal.SizeOf(typeof(JMPCALL_REL))), 
                    Backup, 0, Marshal.SizeOf(typeof(JMPCALL_REL)) + Marshal.SizeOf(typeof(JMP_REL_SHORT)));

            } else {
                Marshal.Copy(Target, Backup, 0, Marshal.SizeOf(typeof(JMPCALL_REL)));
            }
        }

        bool IsExecutableAddress(IntPtr address) {
            MEMORY_BASIC_INFORMATION mi = new MEMORY_BASIC_INFORMATION();
            VirtualQuery(address, ref mi, Marshal.SizeOf(mi));
            return (mi.State == MemoryState.Commited && (mi.Protect & PAGE_EXECUTE_FLAGS) > 0);
        }

        bool IsCodePadding(IntPtr codePtr, int len) {

            var code = new byte[len];
            Marshal.Copy(codePtr, code, 0, len);

            if(code[0] != 0x00 && code[0] != 0x90 && code[0] != 0xCC) {
                return false;
            }

            for(int idx = 1; idx < code.Length; ++idx) {
                if (code[idx] != code[0])
                    return false;
            }

            return true;
        }
    }
}
