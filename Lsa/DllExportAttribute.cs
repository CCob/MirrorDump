/*
 * The MIT License (MIT)
 * 
 * Copyright (c) 2016-2021  Denis Kuzmin <x-3F@outlook.com> github/3F
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
*/

using System;
using System.Runtime.InteropServices;

namespace MirrorDump
{
    /// <summary>
    /// To export this as __cdecl C-exported function. Named as current method where is used attribute.
    /// [.NET DllExport]
    /// 
    /// About our meta-information in user-code:
    /// https://github.com/3F/DllExport/issues/16
    /// </summary>
    [AttributeUsage(AttributeTargets.Method, AllowMultiple = false, Inherited = false)]
    public sealed class DllExportAttribute : Attribute {
        /// <summary>
        /// Specified calling convention.
        /// 
        /// __cdecl is the default convention in .NET DllExport like for other C/C++ programs (Microsoft Specific).
        /// __stdCall mostly used with winapi.
        /// 
        /// https://msdn.microsoft.com/en-us/library/zkwh89ks.aspx
        /// https://msdn.microsoft.com/en-us/library/56h2zst2.aspx
        /// https://github.com/3F/Conari also uses __cdecl by default
        /// </summary>
        public CallingConvention CallingConvention {
            get;
            set;
        } = CallingConvention.Cdecl;

        /// <summary>
        /// Optional name for C-exported function.
        /// </summary>
        public string ExportName {
            get;
            set;
        }

        /* Available signatures */

        /// <param name="function">Optional name for C-exported function.</param>
        /// <param name="convention">Specified calling convention. __cdecl is the default convention in .NET DllExport.</param>
        public DllExportAttribute(string function, CallingConvention convention) { }

        /// <param name="function">Optional name for C-exported function.</param>
        public DllExportAttribute(string function) { }

        /// <param name="convention">Specified calling convention. __cdecl is the default convention in .NET DllExport.</param>
        public DllExportAttribute(CallingConvention convention) { }

        /// <summary>
        /// To export this as __cdecl C-exported function. Named as current method where is used attribute.
        /// </summary>
        public DllExportAttribute() { }
    }
}
