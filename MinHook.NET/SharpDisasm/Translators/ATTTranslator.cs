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

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace SharpDisasm.Translators
{
    /// <summary>
    /// Translates to AT&amp;T syntax
    /// </summary>
    public class ATTTranslator : Translator
    {
        /// <summary>
        /// Translate the instruction into ATT syntax
        /// </summary>
        /// <param name="insn"></param>
        protected override void TranslateInstruction(Instruction insn)
        {
            ud_translate_att(insn);
        }

        /* -----------------------------------------------------------------------------
         * opr_cast() - Prints an operand cast.
         * -----------------------------------------------------------------------------
         */
        /// <summary>
        /// Prints an operand cast.
        /// </summary>
        /// <param name="insn"></param>
        /// <param name="op"></param>
        void
        opr_cast(Instruction insn, Operand op)
        {
            switch (op.Size)
            {
                case 16:
                case 32:
                    Content.Append("*");
                    break;
                default: break;
            }
        }

        /* -----------------------------------------------------------------------------
         * gen_operand() - Generates assembly output for each operand.
         * -----------------------------------------------------------------------------
         */
        /// <summary>
        /// Generates assembly output for each operand
        /// </summary>
        /// <param name="u"></param>
        /// <param name="op"></param>
        void
        gen_operand(Instruction u, Operand op)
        {
            switch (op.Type)
            {
                case Udis86.ud_type.UD_OP_CONST:
                    Content.AppendFormat("$0x{0:x4}", op.LvalUDWord);
                    break;

                case Udis86.ud_type.UD_OP_REG:
                    Content.AppendFormat("%{0}", RegisterForType(op.Base));
                    break;

                case Udis86.ud_type.UD_OP_MEM:
                    if (u.br_far != 0)
                    {
                        opr_cast(u, op);
                    }
                    if (u.pfx_seg != 0)
                    {
                        Content.AppendFormat("%{0}:", RegisterForType((Udis86.ud_type)u.pfx_seg));
                    }
                    if (op.Offset != 0)
                    {
                        ud_syn_print_mem_disp(u, op, 0);
                    }

                    // don't print out the base register rip if resolve rip option is enabled
                    bool resolvingRip = ResolveRip && op.Base == Udis86.ud_type.UD_R_RIP && op.Index == Udis86.ud_type.UD_NONE;
                    if (op.Base != Udis86.ud_type.UD_NONE && !resolvingRip)
                    {
                        Content.AppendFormat("(%{0}", RegisterForType(op.Base));
                    }
                    if (op.Index != Udis86.ud_type.UD_NONE)
                    {
                        if (op.Base != Udis86.ud_type.UD_NONE)
                        {
                            Content.Append(",");
                        }
                        else
                        {
                            Content.Append("(");
                        }
                        Content.AppendFormat("%{0}", RegisterForType(op.Index));
                    }
                    if (op.Scale != 0)
                    {
                        Content.AppendFormat(",{0}", op.Scale);
                    }
                    if (!resolvingRip && (op.Base != Udis86.ud_type.UD_NONE || op.Index != Udis86.ud_type.UD_NONE))
                    {
                        Content.Append(")");
                    }
                    break;

                case Udis86.ud_type.UD_OP_IMM:
                    Content.Append("$");
                    ud_syn_print_imm(u, op);
                    break;

                case Udis86.ud_type.UD_OP_JIMM:
                    ud_syn_print_addr(u, (long)ud_syn_rel_target(u, op));
                    break;

                case Udis86.ud_type.UD_OP_PTR:
                    switch (op.Size)
                    {
                        case 32:
                            Content.AppendFormat("$0x{0:x}, $0x{1:x}", op.PtrSegment,
                              op.PtrOffset & 0xFFFF);
                            break;
                        case 48:
                            Content.AppendFormat("$0x{0:x}, $0x{1:x}", op.PtrSegment,
                              op.PtrOffset);
                            break;
                    }
                    break;

                default: return;
            }
        }

        /* =============================================================================
         * translates to AT&T syntax 
         * =============================================================================
         */
        /// <summary>
        /// Translates to AT&amp;T syntax 
        /// </summary>
        /// <param name="u"></param>
        void
        ud_translate_att(Instruction u)
        {
            int size = 0;
            bool star = false;

            /* check if P_OSO prefix is used */
            if (SharpDisasm.Udis86.BitOps.P_OSO(u.itab_entry.Prefix) == 0 && u.pfx_opr != 0)
            {
                switch (u.dis_mode)
                {
                    case ArchitectureMode.x86_16:
                        Content.Append("o32 ");
                        break;
                    case ArchitectureMode.x86_32:
                    case ArchitectureMode.x86_64:
                        Content.Append("o16 ");
                        break;
                }
            }

            /* check if P_ASO prefix was used */
            if (SharpDisasm.Udis86.BitOps.P_ASO(u.itab_entry.Prefix) == 0 && u.pfx_adr != 0)
            {
                switch (u.dis_mode)
                {
                    case ArchitectureMode.x86_16:
                        Content.Append("a32 ");
                        break;
                    case ArchitectureMode.x86_32:
                        Content.Append("a16 ");
                        break;
                    case ArchitectureMode.x86_64:
                        Content.Append("a32 ");
                        break;
                }
            }

            if (u.pfx_lock != 0)
                Content.Append("lock ");
            if (u.pfx_rep != 0)
            {
                Content.Append("rep ");
            }
            else if (u.pfx_repe != 0)
            {
                Content.Append("repe ");
            }
            else if (u.pfx_repne != 0)
            {
                Content.Append("repne ");
            }

            /* special instructions */
            switch (u.Mnemonic)
            {
                case Udis86.ud_mnemonic_code.UD_Iretf:
                    Content.Append("lret ");
                    size = -1;
                    break;
                case Udis86.ud_mnemonic_code.UD_Idb:
                    Content.AppendFormat(".byte 0x{0:x2}", u.Operands[0].LvalByte);
                    return;
                case Udis86.ud_mnemonic_code.UD_Ijmp:
                case Udis86.ud_mnemonic_code.UD_Icall:
                    if (u.br_far != 0)
                    {
                        Content.Append("l");
                        size = -1;
                    }
                    if (u.Operands[0].Type == Udis86.ud_type.UD_OP_REG)
                    {
                        star = true;
                    }
                    Content.AppendFormat("{0}", Udis86.udis86.ud_lookup_mnemonic(u.Mnemonic));
                    break;
                case Udis86.ud_mnemonic_code.UD_Ibound:
                case Udis86.ud_mnemonic_code.UD_Ienter:
                    Content.AppendFormat("{0}", Udis86.udis86.ud_lookup_mnemonic(u.Mnemonic));
                    if (u.Operands.Length > 0 && u.Operands[0].Type != Udis86.ud_type.UD_NONE)
                    {
                        Content.Append(" ");
                        gen_operand(u, u.Operands[0]);
                    }
                    if (u.Operands.Length > 1 && u.Operands[1].Type != Udis86.ud_type.UD_NONE)
                    {
                        Content.Append(",");
                        gen_operand(u, u.Operands[1]);
                    }
                    return;
                default:
                    Content.AppendFormat("{0}", Udis86.udis86.ud_lookup_mnemonic(u.Mnemonic));
                    break;
            }

            if (size != -1 && u.Operands.Length > 0 && u.Operands.Any(o => o.Type == Udis86.ud_type.UD_OP_MEM))
                size = u.Operands[0].Size;

            if (size == 8)
            {
                Content.Append("b");
            }
            else if (size == 16)
            {
                Content.Append("w");
            }
            else if (size == 32)
            {
                Content.Append("l");
            }
            else if (size == 64)
            {
                Content.Append("q");
            }
            else if (size == 80)
            {
                Content.Append("t");
            }

            if (star)
            {
                Content.Append(" *");
            }
            else
            {
                Content.Append(" ");
            }

            if (u.Operands.Length > 3 && u.Operands[3].Type != Udis86.ud_type.UD_NONE)
            {
                gen_operand(u, u.Operands[3]);
                Content.Append(", ");
            }
            if (u.Operands.Length > 2 && u.Operands[2].Type != Udis86.ud_type.UD_NONE)
            {
                gen_operand(u, u.Operands[2]);
                Content.Append(", ");
            }
            if (u.Operands.Length > 1 && u.Operands[1].Type != Udis86.ud_type.UD_NONE)
            {
                gen_operand(u, u.Operands[1]);
                Content.Append(", ");
            }
            if (u.Operands.Length > 0 && u.Operands[0].Type != Udis86.ud_type.UD_NONE)
            {
                gen_operand(u, u.Operands[0]);
            }
        }
    }
}
