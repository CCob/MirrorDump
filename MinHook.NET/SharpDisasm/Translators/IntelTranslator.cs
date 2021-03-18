// --------------------------------------------------------------------------------
// SharpDisasm (File: SharpDisasm\inteltranslator.cs)
// Copyright (c) 2014-2015 Justin Stenning
// http://spazzarama.com
// https://github.com/spazzarama/SharpDisasm
// https://sharpdisasm.codeplex.com/
//
// SharpDisasm is distributed under the 2-clause "Simplified BSD License".
//
// Portions of SharpDisasm are ported to C# from udis86 a C disassembler project
// also distributed under the terms of the 2-clause "Simplified BSD License" and
// Copyright (c) 2002-2012, Vivek Thampi <vivek.mt@gmail.com>
// All rights reserved.
// UDIS86: https://github.com/vmt/udis86
//
// Redistribution and use in source and binary forms, with or without modification, 
// are permitted provided that the following conditions are met:
// 
// 1. Redistributions of source code must retain the above copyright notice, 
//    this list of conditions and the following disclaimer.
// 2. Redistributions in binary form must reproduce the above copyright notice, 
//    this list of conditions and the following disclaimer in the documentation 
//    and/or other materials provided with the distribution.
// 
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND 
// ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED 
// WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE 
// DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR 
// ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES 
// (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; 
// LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON 
// ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT 
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS 
// SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
// --------------------------------------------------------------------------------

using SharpDisasm.Udis86;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace SharpDisasm.Translators
{
    /// <summary>
    /// Translates instructions to Intel ASM syntax
    /// </summary>
    /// <threadsafety static="true" instance="false"/>
    public class IntelTranslator: Translator
    {
        /// <summary>
        /// Translate the instruction into Intel syntax
        /// </summary>
        /// <param name="insn"></param>
        protected override void TranslateInstruction(Instruction insn)
        {
            ud_translate_intel(insn);
        }

        /* -----------------------------------------------------------------------------
         * opr_cast() - Prints an operand cast.
         * -----------------------------------------------------------------------------
         */
        void opr_cast(Instruction insn, Operand op)
        {
            if (insn.br_far > 0)
            {
                Content.Append("far ");
            }
            switch (op.Size)
            {
                case 8: Content.Append("byte "); break;
                case 16: Content.Append("word "); break;
                case 32: Content.Append("dword "); break;
                case 64: Content.Append("qword "); break;
                case 80: Content.Append("tword "); break;
                default: break;
            }
        }

        /* -----------------------------------------------------------------------------
         * gen_operand() - Generates assembly output for each operand.
         * -----------------------------------------------------------------------------
         */
        void gen_operand(Instruction insn, Operand op, int syn_cast)
        {
            switch (op.Type)
            {
                case ud_type.UD_OP_REG:
                    Content.AppendFormat("{0}", RegisterForType(op.Base));
                    break;

                case ud_type.UD_OP_MEM:
                    if (syn_cast > 0)
                    {
                        opr_cast(insn, op);
                    }
                    Content.Append("[");
                    if (insn.pfx_seg > 0)
                    {
                        Content.AppendFormat("{0}:", RegisterForType((ud_type)insn.pfx_seg));
                    }
                    
                    // don't print out the base register rip if resolve rip option is enabled
                    if (op.Base > 0 && !(ResolveRip && op.Base == ud_type.UD_R_RIP && op.Index == ud_type.UD_NONE))
                    {
                        Content.AppendFormat("{0}", RegisterForType(op.Base));
                    }
                    if (op.Index > 0)
                    {
                        Content.AppendFormat("{0}{1}", op.Base != ud_type.UD_NONE ? "+" : "",
                                                RegisterForType(op.Index));
                        if (op.Scale > 0)
                        {
                            Content.AppendFormat("*{0}", op.Scale);
                        }
                    }
                    if (op.Offset != 0)
                    {
                        ud_syn_print_mem_disp(insn, op, (op.Base != ud_type.UD_NONE ||
                                                    op.Index != ud_type.UD_NONE) ? 1 : 0);
                    }
                    Content.Append("]");
                    break;

                case ud_type.UD_OP_IMM:
                    ud_syn_print_imm(insn, op);
                    break;


                case ud_type.UD_OP_JIMM:
                    ud_syn_print_addr(insn, (long)ud_syn_rel_target(insn, op));
                    break;

                case ud_type.UD_OP_PTR:
                    switch (op.Size)
                    {
                        case 32:
                            Content.AppendFormat("word 0x{0:x}:0x{1:x}", op.PtrSegment,
                              op.PtrOffset & 0xFFFF);
                            break;
                        case 48:
                            Content.AppendFormat("dword 0x{0:x}:0x{1:x}", op.PtrSegment,
                              op.PtrOffset);
                            break;
                    }
                    break;

                case ud_type.UD_OP_CONST:
                    if (syn_cast > 0) opr_cast(insn, op);
                    Content.AppendFormat("{0}", op.LvalUDWord);
                    break;

                default: return;
            }
        }

        /* =============================================================================
         * translates to intel syntax 
         * =============================================================================
         */
        void ud_translate_intel(Instruction insn)
        {
            /* check if P_OSO prefix is used */
            if (BitOps.P_OSO(insn.itab_entry.Prefix) == 0 && insn.pfx_opr > 0)
            {
                switch (insn.dis_mode)
                {
                    case ArchitectureMode.x86_16: Content.Append("o32 "); break;
                    case ArchitectureMode.x86_32:
                    case ArchitectureMode.x86_64: Content.Append("o16 "); break;
                }
            }

            /* check if P_ASO prefix was used */
            if (BitOps.P_ASO(insn.itab_entry.Prefix) == 0 && insn.pfx_adr > 0)
            {
                switch (insn.dis_mode)
                {
                    case ArchitectureMode.x86_16: Content.Append("a32 "); break;
                    case ArchitectureMode.x86_32: Content.Append("a16 "); break;
                    case ArchitectureMode.x86_64: Content.Append("a32 "); break;
                }
            }

            if (insn.pfx_seg > 0 &&
                insn.Operands.Length > 1 &&
                insn.Operands[0].Type != ud_type.UD_OP_MEM &&
                insn.Operands[1].Type != ud_type.UD_OP_MEM)
            {
                Content.AppendFormat("{0} ", RegisterForType((ud_type)insn.pfx_seg));
            }

            if (insn.pfx_lock > 0)
            {
                Content.Append("lock ");
            }
            if (insn.pfx_rep > 0)
            {
                Content.Append("rep ");
            }
            else if (insn.pfx_repe > 0)
            {
                Content.Append("repe ");
            }
            else if (insn.pfx_repne > 0)
            {
                Content.Append("repne ");
            }

            /* print the instruction mnemonic */
            Content.AppendFormat("{0}", Udis86.udis86.ud_lookup_mnemonic(insn.Mnemonic));

            if (insn.Operands.Length > 0 && insn.Operands[0].Type != ud_type.UD_NONE)
            {
                int cast = 0;
                Content.Append(" ");
                if (insn.Operands[0].Type == ud_type.UD_OP_MEM)
                {
                    if ((insn.Operands.Length > 1 && 
                        (insn.Operands[1].Type == ud_type.UD_OP_IMM ||
                        insn.Operands[1].Type == ud_type.UD_OP_CONST)) ||
                        insn.Operands.Length < 2 || //insn.Operands[1].Type == ud_type.UD_NONE) ||
                        (insn.Operands.Length > 1 && 
                         insn.Operands[0].Size != insn.Operands[1].Size &&
                         insn.Operands[1].Type != ud_type.UD_OP_REG))
                    {
                        cast = 1;
                    }
                    else if (insn.Operands[1].Type == ud_type.UD_OP_REG &&
                             insn.Operands[1].Base == ud_type.UD_R_CL)
                    {
                        switch (insn.Mnemonic)
                        {
                            case ud_mnemonic_code.UD_Ircl:
                            case ud_mnemonic_code.UD_Irol:
                            case ud_mnemonic_code.UD_Iror:
                            case ud_mnemonic_code.UD_Ircr:
                            case ud_mnemonic_code.UD_Ishl:
                            case ud_mnemonic_code.UD_Ishr:
                            case ud_mnemonic_code.UD_Isar:
                                cast = 1;
                                break;
                            default: break;
                        }
                    }
                }
                gen_operand(insn, insn.Operands[0], cast);
            }

            if (insn.Operands.Length > 1 && insn.Operands[1].Type != ud_type.UD_NONE)
            {
                int cast = 0;
                Content.Append(", ");
                if (insn.Operands[1].Type == ud_type.UD_OP_MEM &&
                    insn.Operands[0].Size != insn.Operands[1].Size &&
                    !Udis86.udis86.ud_opr_is_sreg(ref insn.Operands[0].UdOperand))
                {
                    cast = 1;
                }
                gen_operand(insn, insn.Operands[1], cast);
            }

            if (insn.Operands.Length > 2 && insn.Operands[1].Type != ud_type.UD_NONE)
            {
                int cast = 0;
                Content.Append(", ");
                if (insn.Operands[2].Type == ud_type.UD_OP_MEM &&
                    insn.Operands[2].Size != insn.Operands[1].Size)
                {
                    cast = 1;
                }
                gen_operand(insn, insn.Operands[2], cast);
            }

            if (insn.Operands.Length > 3 && insn.Operands[3].Type != ud_type.UD_NONE)
            {
                Content.Append(", ");
                gen_operand(insn, insn.Operands[3], 0);
            }
        }
    }
}
