using SharpDisasm.Udis86;
using System;
using System.Reflection.Emit;
using System.Runtime.InteropServices;

namespace FindCiOptions
{
    class Program
    {
        private enum MatchType
        {
            MATCH_CALL_OR_JMP,
            MATCH_MOV_ECX
        }

        private static IntPtr GetOperandOffset(IntPtr address, MatchType matchType)
        {            
            var buffer = new byte[100];
            IntPtr bytesRead = IntPtr.Zero, result = IntPtr.Zero;

            if (! ReadProcessMemory(GetCurrentProcess(), address, buffer, buffer.Length, out bytesRead))
            {
                throw GetWin32Exception("ReadProcessMemory()");
            }

            var offset = address.ToInt64();
            var disasm = new SharpDisasm.Disassembler(buffer, SharpDisasm.ArchitectureMode.x86_64, 0, true);
            foreach (var insn in disasm.Disassemble())
            {
                offset += insn.Length;

                if (matchType == MatchType.MATCH_CALL_OR_JMP 
                    && insn.Mnemonic == ud_mnemonic_code.UD_Ijmp)
                {
                    result = new IntPtr(offset + insn.Operands[0].Value);
                    break;
                }
                else if (matchType == MatchType.MATCH_MOV_ECX
                    && insn.Mnemonic == ud_mnemonic_code.UD_Imov)
                {
                    if (insn.Operands[1].Base == ud_type.UD_R_ECX)
                    {
                        result = new IntPtr(offset + insn.Operands[0].Value);
                        break;
                    }
                }

                if (insn.Mnemonic == ud_mnemonic_code.UD_Iint3)
                {
                    break;
                }
            }

            return result;
        }

        private static IntPtr GetProcdureAddress(string dllname, string procname)
        {
            IntPtr dll = LoadLibraryEx(dllname, IntPtr.Zero, LoadLibraryFlags.DONT_RESOLVE_DLL_REFERENCES);
            if (dll == IntPtr.Zero)
            {
                throw GetWin32Exception("LoadLibraryEx() of " + dllname);
            }

            IntPtr proc = GetProcAddress(dll, procname);
            if (proc == IntPtr.Zero)
            {
                throw GetWin32Exception("GetProcAddress() of " + procname);
            }

            return proc;
        }

        static void Main(string[] args)
        {
            IntPtr ciInitialize  = GetProcdureAddress("ci.dll", "CiInitialize");
            
            IntPtr ciPInitialize = GetOperandOffset(ciInitialize, MatchType.MATCH_CALL_OR_JMP);
            if (ciPInitialize == IntPtr.Zero)
            {
                throw new Exception("Failed to locate CiPInitialize()");
            }
            Console.WriteLine(String.Format("CiPInitialize at 0x{0:X8}", ciPInitialize.ToInt64()));

            IntPtr ciOptions = GetOperandOffset(ciPInitialize, MatchType.MATCH_MOV_ECX);
            if (ciOptions == IntPtr.Zero)
            {
                throw new Exception("Failed to locate ci.dll!g_CiOptions");
            }
            Console.WriteLine(String.Format("ci.dll!g_CiOptions at 0x{0:X8}", ciOptions.ToInt64()));
            
        }

        public static Exception GetWin32Exception(string reason)
        {
            string msg = new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error()).Message;
            string err = String.Format("{0} failed: {1}: {2}", reason, Marshal.GetLastWin32Error(), msg);
            return new Exception(err);
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr GetCurrentProcess();

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool ReadProcessMemory(
            IntPtr hProcess,
            IntPtr lpBaseAddress,
            [Out] byte[] lpBuffer,
            int dwSize,
            out IntPtr lpNumberOfBytesRead);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr LoadLibraryEx(string lpFileName, IntPtr hReservedNull, LoadLibraryFlags dwFlags);

        [DllImport("kernel32", CharSet = CharSet.Ansi, ExactSpelling = true, SetLastError = true)]
        static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

        [System.Flags]
        enum LoadLibraryFlags : uint
        {
            None = 0,
            DONT_RESOLVE_DLL_REFERENCES = 0x00000001,
            LOAD_IGNORE_CODE_AUTHZ_LEVEL = 0x00000010,
            LOAD_LIBRARY_AS_DATAFILE = 0x00000002,
            LOAD_LIBRARY_AS_DATAFILE_EXCLUSIVE = 0x00000040,
            LOAD_LIBRARY_AS_IMAGE_RESOURCE = 0x00000020,
            LOAD_LIBRARY_SEARCH_APPLICATION_DIR = 0x00000200,
            LOAD_LIBRARY_SEARCH_DEFAULT_DIRS = 0x00001000,
            LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR = 0x00000100,
            LOAD_LIBRARY_SEARCH_SYSTEM32 = 0x00000800,
            LOAD_LIBRARY_SEARCH_USER_DIRS = 0x00000400,
            LOAD_WITH_ALTERED_SEARCH_PATH = 0x00000008
        }
    }
}
