using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.InteropServices;

namespace MirrorDump {

    /// <summary>
    /// https://www.geoffchappell.com/studies/windows/km/ntoskrnl/api/ex/sysinfo/handle_table_entry.htm?ts=0,242
    /// https://stackoverflow.com/questions/54872228/c-sharp-how-to-find-all-handles-associated-with-current-process
    /// </summary>
    public class ProcessUtility {

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct SYSTEM_HANDLE_INFORMATION {
            // Information Class 16
            public int ProcessID;
            public byte ObjectTypeNumber;
            public byte Flags; // 0x01 = PROTECT_FROM_CLOSE, 0x02 = INHERIT
            public ushort Handle;
            public int Object_Pointer;
            public UInt32 GrantedAccess;
        }

        public class ProcessHandle {
            public IntPtr Handle;
            public Process Process;
        }

        [DllImport("kernel32.dll", SetLastError= true)]
        public static extern uint GetProcessId(IntPtr handle);

        [DllImport("ntdll.dll")]
        public static extern uint NtQuerySystemInformation(int SystemInformationClass, IntPtr SystemInformation, int SystemInformationLength, ref int returnLength);

        [DllImport("kernel32.dll", EntryPoint = "RtlCopyMemory")]
        static extern void CopyMemory(byte[] Destination, IntPtr Source, uint Length);

        private const uint STATUS_INFO_LENGTH_MISMATCH = 0xC0000004;
        private const int CNST_SYSTEM_HANDLE_INFORMATION = 0x10;
        private const int OBJECT_TYPE_PROCESS = 0x7;

        static bool Is64Bits() {
            return Marshal.SizeOf(typeof(IntPtr)) == 8 ? true : false;
        }

        static List<SYSTEM_HANDLE_INFORMATION> GetHandles(Process process, int? type) {
            uint nStatus;
            int nHandleInfoSize = 0x10000;
            IntPtr ipHandlePointer = Marshal.AllocHGlobal(nHandleInfoSize);
            int nLength = 0;
            IntPtr ipHandle = IntPtr.Zero;
            List<SYSTEM_HANDLE_INFORMATION> lstHandles = new List<SYSTEM_HANDLE_INFORMATION>();

            while ((nStatus = NtQuerySystemInformation(CNST_SYSTEM_HANDLE_INFORMATION, ipHandlePointer, nHandleInfoSize, ref nLength)) == STATUS_INFO_LENGTH_MISMATCH) {
                nHandleInfoSize = nLength;
                Marshal.FreeHGlobal(ipHandlePointer);
                ipHandlePointer = Marshal.AllocHGlobal(nLength);
            }

            if(nStatus != 0) {
                Console.WriteLine($"[!] Failed to query handle information with error 0x{nStatus:x}");
                return lstHandles;
            }

            byte[] baTemp = new byte[nLength];
            CopyMemory(baTemp, ipHandlePointer, (uint)nLength);

            long lHandleCount = 0;
            if (Is64Bits()) {
                lHandleCount = Marshal.ReadInt32(ipHandlePointer);
                ipHandle = new IntPtr(ipHandlePointer.ToInt64() + 8);
            } else {
                lHandleCount = Marshal.ReadInt32(ipHandlePointer);
                ipHandle = new IntPtr(ipHandlePointer.ToInt32() + 4);
            }

            SYSTEM_HANDLE_INFORMATION shHandle;
            
            for (long lIndex = 0; lIndex < lHandleCount; lIndex++) {
                shHandle = new SYSTEM_HANDLE_INFORMATION();
                if (Is64Bits()) {
                    shHandle = (SYSTEM_HANDLE_INFORMATION)Marshal.PtrToStructure(ipHandle, shHandle.GetType());
                    ipHandle = new IntPtr(ipHandle.ToInt64() + Marshal.SizeOf(shHandle) + 8);
                } else {
                    ipHandle = new IntPtr(ipHandle.ToInt64() + Marshal.SizeOf(shHandle));
                    shHandle = (SYSTEM_HANDLE_INFORMATION)Marshal.PtrToStructure(ipHandle, shHandle.GetType());
                }
                if (shHandle.ProcessID != process.Id) continue;
                if(!type.HasValue)
                    lstHandles.Add(shHandle);
                else if(type.Value == shHandle.ObjectTypeNumber)
                    lstHandles.Add(shHandle);
            }
            return lstHandles;
        }

        public static IEnumerable<ProcessHandle> GetProcessHandles(Process process) {

            var processHandles = GetHandles(process, OBJECT_TYPE_PROCESS);
            var result = new List<ProcessHandle>();

            foreach(var item in processHandles) {

                var procHandle = new ProcessHandle();
                var procId = (int)GetProcessId((IntPtr)item.Handle);
                procHandle.Handle = (IntPtr)item.Handle;
                if (procId > 0)
                    procHandle.Process = Process.GetProcessById(procId);
                result.Add(procHandle);
            }

            return result;  
        }
    }
}
