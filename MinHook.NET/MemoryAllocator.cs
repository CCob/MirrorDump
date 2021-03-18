using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using static MinHook.Utils;

namespace MinHook {
    internal class MemorySlot : IDisposable {

        public IntPtr Address { get; private set; }
        public int Index { get; private set; }

        MemoryBlock ownerBlock;

        public MemorySlot(MemoryBlock ownerBlock, IntPtr address, int index) {
            this.ownerBlock = ownerBlock;
            Address = address;
            Index = index;
        }

        public void Dispose() {
            ownerBlock.FreeSlot(this);            
        }
    }

    internal class MemoryBlock : IDisposable {

        // Page size for Windows
        static readonly uint MEMORY_BLOCK_SIZE = 0x1000;
        static readonly uint MEMORY_SLOT_SIZE = 64;

        public IntPtr BaseAddress { get; private set; }
        ulong freeBitMap;

        public MemoryBlock(IntPtr baseAddress) {
            this.BaseAddress = baseAddress;
            freeBitMap = ulong.MaxValue;
        }

        ~MemoryBlock() {
            Dispose(false);
        }

        protected void Dispose(bool disposing) {
            if(BaseAddress != IntPtr.Zero) {                
                VirtualFree(BaseAddress, (int)MEMORY_BLOCK_SIZE, FreeType.Release);
                BaseAddress = IntPtr.Zero;
            }
        }
      
        public bool IsFull() {
            return freeBitMap == 0;
        }

        public MemorySlot AllocateSlot() {

            if (IsFull()) {
                throw new OutOfMemoryException("No free slots available");
            }
            
            for(int idx = 0; idx < 64; idx++) {
                if( ((freeBitMap >> idx) & 1) == 1) {
                    freeBitMap ^= (1ul << idx);
                    return new MemorySlot(this, (IntPtr)((long)BaseAddress + (idx * MEMORY_SLOT_SIZE)), idx);
                }
            }

            throw new InvalidOperationException("Unexpected memory block state");
        }

        public void FreeSlot(MemorySlot memorySlot) {

            if((ulong)memorySlot.Address < (ulong)BaseAddress || (ulong)memorySlot.Address >= (ulong)BaseAddress + MEMORY_BLOCK_SIZE) {
                throw new ArgumentException("memorySlot does not belong to this block");
            }

            freeBitMap |= (1ul << memorySlot.Index);
        }

        public void Dispose() {
            Dispose(true);
            GC.SuppressFinalize(this);
        }      
    }

    internal class MemoryAllocator {

        // Page size for Windows
        static uint MEMORY_BLOCK_SIZE = 0x1000;

        // Max range for seeking a memory block. (= 1024MB)
        static uint MAX_MEMORY_RANGE = 0x40000000;

        static List<MemoryBlock> memoryBlocks = new List<MemoryBlock>();

        public MemoryAllocator() {

        }

        public MemorySlot AllocateBuffer(IntPtr origin) {
            MemoryBlock block = GetMemoryBlock(origin);               
            return block.AllocateSlot();
        }

        MemoryBlock GetMemoryBlock(IntPtr origin) {

            IntPtr minAddr = IntPtr.Zero;
            IntPtr maxAddr = IntPtr.Zero;
            MemoryBlock result = null;
            SYSTEM_INFO si = new SYSTEM_INFO();
            GetSystemInfo(ref si);

            if (IntPtr.Size == 8) {

                minAddr = si.lpMinimumApplicationAddress;
                maxAddr = si.lpMaximumApplicationAddress;

                if ((ulong)origin > MAX_MEMORY_RANGE && (ulong)minAddr < (ulong)origin - MAX_MEMORY_RANGE)
                    minAddr = (IntPtr)((ulong)origin - MAX_MEMORY_RANGE);

                if ((ulong)maxAddr > (ulong)origin + MAX_MEMORY_RANGE)
                    maxAddr = (IntPtr)((ulong)origin + MAX_MEMORY_RANGE);

                maxAddr = (IntPtr)((ulong)maxAddr - MEMORY_BLOCK_SIZE - 1);
            }

            foreach(var memoryBlock in memoryBlocks) {

                if(IntPtr.Size == 8 && ((ulong)memoryBlock.BaseAddress < (ulong)minAddr || (ulong)memoryBlock.BaseAddress >= (ulong)maxAddr)) {
                    continue;                   
                }

                if (!memoryBlock.IsFull()) {
                    return memoryBlock;
                }
            }

            //Couldn't find a free block, lets allocate another

            if(IntPtr.Size == 8) {

                IntPtr alloc = origin;
                while((ulong)alloc >= (ulong)minAddr) {

                    alloc = FindPrevFreeRegion(alloc, minAddr, si.dwAllocationGranularity);

                    if(alloc == IntPtr.Zero) {
                        break;
                    }

                    IntPtr baseAddr = VirtualAlloc(alloc, (IntPtr)MEMORY_BLOCK_SIZE, AllocationType.Commit | AllocationType.Reserve, MemoryProtection.ExecuteReadWrite);

                    if (baseAddr != IntPtr.Zero) {
                        result = new MemoryBlock(baseAddr);
                        break;
                    }
                }

                if(result == null) {

                    alloc = origin;
                    while((ulong)alloc <= (ulong)maxAddr) {
                        alloc = FindNextFreeRegion(alloc, maxAddr, si.dwAllocationGranularity);

                        if (alloc == IntPtr.Zero)
                            break;

                        IntPtr baseAddr = VirtualAlloc(alloc, (IntPtr)MEMORY_BLOCK_SIZE, AllocationType.Commit | AllocationType.Reserve, MemoryProtection.ExecuteReadWrite);

                        if (baseAddr != IntPtr.Zero) {
                            result = new MemoryBlock(baseAddr);
                            break;
                        }
                    }
                }
            } else {

                IntPtr baseAddr = VirtualAlloc(IntPtr.Zero, (IntPtr)MEMORY_BLOCK_SIZE, AllocationType.Commit | AllocationType.Reserve, MemoryProtection.ExecuteReadWrite);
                if(baseAddr == IntPtr.Zero) {
                    throw new OutOfMemoryException("Failed to allocate new block of memory");
                }

                result = new MemoryBlock(baseAddr);
            }

            if(result == null) {
                throw new OutOfMemoryException("Failed to allocate new block of memory");
            }
                
            memoryBlocks.Add(result);
            return result;
        }

        IntPtr FindPrevFreeRegion(IntPtr address, IntPtr minAddress, uint allocationGranularity) {

            IntPtr tryAddr = (IntPtr) ((ulong)address - ( ((ulong)address % allocationGranularity) - allocationGranularity));
            
            while((ulong)tryAddr >= (ulong)minAddress) {

                MEMORY_BASIC_INFORMATION mbi = new MEMORY_BASIC_INFORMATION();

                if (VirtualQuery(tryAddr, ref mbi, Marshal.SizeOf(mbi)) == 0)
                    break;
              
                if(mbi.State == MemoryState.Free) 
                    return tryAddr;

                if ((ulong)mbi.AllocationBase < allocationGranularity)
                    break;

                tryAddr = (IntPtr)((ulong)mbi.AllocationBase - allocationGranularity);
            }

            return IntPtr.Zero;
        }

        IntPtr FindNextFreeRegion(IntPtr address, IntPtr maxAddress, uint allocationGranularity) {

            IntPtr tryAddr = (IntPtr)((ulong)address - (((ulong)address % allocationGranularity) + allocationGranularity));

            while ((ulong)tryAddr <= (ulong)maxAddress) {

                MEMORY_BASIC_INFORMATION mbi = new MEMORY_BASIC_INFORMATION();

                if (VirtualQuery(tryAddr, ref mbi, Marshal.SizeOf(mbi)) == 0)
                    break;

                if (mbi.State == MemoryState.Free)
                    return tryAddr;

                if ((ulong)mbi.AllocationBase < allocationGranularity)
                    break;

                tryAddr = (IntPtr)((ulong)mbi.BaseAddress + (ulong)mbi.RegionSize);

                tryAddr = (IntPtr)((long)tryAddr + (allocationGranularity - 1));
                tryAddr = (IntPtr)((ulong)tryAddr - ((ulong)tryAddr % allocationGranularity));
            }

            return IntPtr.Zero;
        }
    }
}
