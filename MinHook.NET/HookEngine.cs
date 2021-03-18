using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.InteropServices;
using static MinHook.Utils;

namespace MinHook {
    public class HookEngine {

        MemoryAllocator memoryAllocator = new MemoryAllocator();
        Dictionary<Delegate, Hook> hooks = new Dictionary<Delegate, Hook>();
        List<IntPtr> suspendedThreads = new List<IntPtr>();

        public Func CreateHook<Func>(string dll, string function, Func detour) where Func : Delegate {

            IntPtr target = GetProcAddress(GetModuleHandle(dll), function);

            if (target == IntPtr.Zero)
                throw new EntryPointNotFoundException($"Function {function} could not be found in DLL {dll}");

            lock (this) {
                var hook = new Hook(target, Marshal.GetFunctionPointerForDelegate(detour), memoryAllocator.AllocateBuffer(target));
                Func original = (Func)Marshal.GetDelegateForFunctionPointer(hook.Original, typeof(Func));
                hooks.Add(original, hook);
                return original;
            }
        }

        public void EnableHooks() {
            foreach(var hook in hooks) {
                EnableHook(hook.Key);
            }
        }

        public void DisableHooks() {
            foreach (var hook in hooks) {
                DisableHook(hook.Key);
            }
        }

        public void EnableHook(Delegate original) {
            lock (this) {
                if (!hooks.ContainsKey(original)) {
                    throw new KeyNotFoundException("Hook not found, was this delegate create with CreateHook?");
                }

                SuspendThreads();
                hooks[original].Enable(true);
                ResumeThreads();
            }
        }

        public void DisableHook(Delegate original) {
            lock (this) {
                if (!hooks.ContainsKey(original)) {
                    throw new KeyNotFoundException("Hook not found, was this delegate create with CreateHook?");
                }

                SuspendThreads();
                hooks[original].Enable(false);
                ResumeThreads();
            }
        }

        void SuspendThreads() {

            //Suspending all threads when debugging causes deadlocks.
            if (Debugger.IsAttached) {
                return;
            }

            //TODO: Currently doesn't move thread IP if any of the threads
            //are executing within the location of a hook prologue at the time.
            //This will probably crash the program if that scenario happens

            Process currentProc = Process.GetCurrentProcess();

            foreach(ProcessThread thread in currentProc.Threads) {
                if(thread.Id != GetCurrentThreadId()) {                    
                    IntPtr threadHandle = OpenThread(ThreadAccess.SUSPEND_RESUME, false, (uint)thread.Id);
                    SuspendThread(threadHandle);
                    suspendedThreads.Add(threadHandle);                                       
                }             
            }
        }

        void ResumeThreads() {

            foreach(var handle in suspendedThreads) {
                ResumeThread(handle);
                CloseHandle(handle);                    
            }

            suspendedThreads.Clear();
        }
    }
}
