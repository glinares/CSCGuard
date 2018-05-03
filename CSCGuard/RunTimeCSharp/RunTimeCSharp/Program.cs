using Microsoft.CSharp;
using System.CodeDom.Compiler;
using System.Reflection;
using System.Text;

namespace System
{
    public static class CompileCSCAtRuntime
    {
        public static void Main()
        {
            byte[] data = Convert.FromBase64String("UnVudGltZSBDb2RlIEV4ZWN1dGVk");
            string decodedString = System.Text.ASCIIEncoding.ASCII.GetString(data);
            string code = @"
                using System;
                using System.Windows.Forms;

                namespace Runtime
                {
                    public class Program
                    {
                        public static void Main()
                        {
                        " +
                            "MessageBox.Show(\"" + decodedString + "\");"  
                          + @"
                        }
                    }
                }
            ";

            CSharpCodeProvider provider = new CSharpCodeProvider();
            CompilerParameters parameters = new CompilerParameters();
            parameters.ReferencedAssemblies.Add("System.Drawing.dll");
            parameters.ReferencedAssemblies.Add("System.Windows.Forms.dll");
            parameters.TempFiles.KeepFiles = true;
            parameters.GenerateExecutable = false;
            parameters.GenerateInMemory = true;
            parameters.CompilerOptions = " ";


            CompilerResults results = provider.CompileAssemblyFromSource(parameters, code);

            if (results.Errors.HasErrors)
            {
                StringBuilder sb = new StringBuilder();

                foreach (CompilerError error in results.Errors)
                {
                    sb.AppendLine(String.Format("Error ({0}): {1}", error.ErrorNumber, error.ErrorText));
                }

                throw new InvalidOperationException(sb.ToString());
            }
            Assembly assembly = results.CompiledAssembly;
            Type program = assembly.GetType("Runtime.Program");
            MethodInfo main = program.GetMethod("Main");
            main.Invoke(null, null);
        }

    }
}