using System;
using System.Runtime.InteropServices;

namespace MirrorDump {
    internal static class WinAPI {

        internal enum MINIDUMP_TYPE : uint {
            MiniDumpNormal,
            MiniDumpWithDataSegs,
            MiniDumpWithFullMemory,
            MiniDumpWithHandleData,
            MiniDumpFilterMemory,
            MiniDumpScanMemory,
            MiniDumpWithUnloadedModules,
            MiniDumpWithIndirectlyReferencedMemory,
            MiniDumpFilterModulePaths,
            MiniDumpWithProcessThreadData,
            MiniDumpWithPrivateReadWriteMemory,
            MiniDumpWithoutOptionalData,
            MiniDumpWithFullMemoryInfo,
            MiniDumpWithThreadInfo,
            MiniDumpWithCodeSegs,
            MiniDumpWithoutAuxiliaryState,
            MiniDumpWithFullAuxiliaryState,
            MiniDumpWithPrivateWriteCopyMemory,
            MiniDumpIgnoreInaccessibleMemory,
            MiniDumpWithTokenInformation,
            MiniDumpWithModuleHeaders,
            MiniDumpFilterTriage,
            MiniDumpWithAvxXStateContext,
            MiniDumpWithIptTrace,
            MiniDumpScanInaccessiblePartialPages,
            MiniDumpValidTypeFlags
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
        internal class SECURITY_PACKAGE_OPTIONS {
            public ulong Size;
            public ulong Type;
            public ulong Flags;
            public ulong SignatureSize;
            public IntPtr Signature;
        }

        internal static readonly uint ERROR_DISK_FULL = 0x70;

        [DllImport("Dbghelp.dll", SetLastError = true)]
        internal static extern bool MiniDumpWriteDump(IntPtr hProcess, uint ProcessId, IntPtr hFile, MINIDUMP_TYPE DumpType, IntPtr ExceptionParam, IntPtr UserStreamParam, IntPtr CallbackParam);

        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern void SetLastError(uint dwErrorCode);

        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern bool CloseHandle(IntPtr hObject);

        [DllImport("secur32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        internal static extern uint AddSecurityPackage(string pszPackageName, SECURITY_PACKAGE_OPTIONS Options);

        [DllImport("secur32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        internal static extern uint DeleteSecurityPackage(string pszPackageName);
    }
}
