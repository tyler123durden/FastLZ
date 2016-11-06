using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace _6unpack
{
    class Program
    {
        [DllImport("6pack.dll", EntryPoint="unpack", CallingConvention=CallingConvention.Cdecl)]
        public static unsafe extern void unpack(int argc, String[] argv);

        public unsafe static void Main(string[] args)
        {
            string[] argsNew = new string[args.Length+1];
            for (int i = 0; i < args.Length; i++)
            {
                argsNew[i + 1] = args[i];
            }
            argsNew[0] = "test";

            unpack(argsNew.Length, argsNew);
        }
    }
}
