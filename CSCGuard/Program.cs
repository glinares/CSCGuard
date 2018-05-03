using System;


using System.Diagnostics;
using System.IO;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;
using System.Reflection;
using System.Collections.Generic;
// Note: I had to manually add a reference for System.Configuration to get this to work properly in VS2017 .NET 3.5
using System.Configuration;

namespace CSCGuard
{
    class Program
    {
        public class ThreatStatus
        {
            private int level = 0;

            /// <summary>
            /// Increase threat level of CSCGuard event
            /// </summary>
            public void Increase()
            {
                this.level++;
                DebugWarning("Threat Level Increased");
            }

            /// <summary>
            /// Decrease threat level of CSCGuard event
            /// </summary>
            public void Decrease()
            {
                this.level--;
                DebugInfo("Threat Level Decreased");
            }

            /// <summary>
            /// Get the current threat level of the CSCGuard event
            /// </summary>
            public int Level
            {
                get
                {
                    return level;
                }
            }
        }

        public class ParentProcessInfo
        {
            private string name = "";
            private string id = "";
            private string cmdline = "";
            private string filename = "";
            private string signature = "";
            private bool issigned = false;
            private bool selfsigned = false;
            private bool validsigned = false;

            /// <summary>
            /// Does the parent process calling CSC.exe have a valid & secure digital signature chain
            /// </summary>
            public bool ValidSigned
            {
                get
                {
                    return validsigned;
                }
                set
                {
                    validsigned = value;
                }
            }

            /// <summary>
            /// Is the parent process calling CSC.exe signed
            /// </summary>
            public bool IsSigned
            {
                get
                {
                    return issigned;
                }
                set
                {
                    issigned = value;
                }
            }

            /// <summary>
            /// Is the parent process calling CSC.exe self-signed
            /// </summary>
            public bool SelfSigned
            {
                get
                {
                    return selfsigned;
                }
                set
                {
                    selfsigned = value;
                    if (value == true)
                    {
                        Heuristic.Threat.Increase();
                    }
                    else
                    {
                        Heuristic.Threat.Decrease();
                    }
                    
                }
            }
            /// <summary>
            /// The digital signature information of the parent process
            /// </summary>
            public string Signature
            {
                get
                {
                    return signature;
                }
                set
                {
                    signature = value;
                }
            }

            /// <summary>
            /// Parent process name as it would appear in task manager
            /// </summary>
            public string Name
            {
                get
                {
                    return name;
                }

                set
                {
                    name = value;
                    DebugInfo("Parent Process Name: " + value);
                }
            }

            /// <summary>
            /// Parent process Id
            /// </summary>
            public string Id
            {
                get
                {
                    return id;
                }

                set
                {
                    id = value;
                    DebugInfo("Parent Process Id: " + value);
                }
            }

            /// <summary>
            /// Parent Process Command Line - Not Implemented at this time.
            /// </summary>
            public string Cmdline
            {
                get
                {
                    return cmdline;
                }

                set
                {
                    cmdline = value;
                    DebugInfo("Parent Process Command-line: " + value);
                }
            }

            /// <summary>
            /// Parent process full path filename
            /// </summary>
            public string Filename
            {
                get
                {
                    return filename;
                }

                set
                {
                    filename = value;
                    DebugInfo("Parent Process Filename: " + value);
                }
            }
        }

        public class Heuristics
        {

            
            private string sourcefile = "";
            private string outputfile = "";
            private string outputtype = "EXE";

            private string[] cmdline;
            private string[] runtimecmdline;

            private List<string> sourcefiles = new List<string>();

            private bool tempexec = false;
            private bool runtimecompiled = false;

            /// <summary>
            /// Get or Set the full path filename of the compiled binary result of CSC.exe
            /// </summary>
            public string OutputFile
            {
                get
                {
                    return outputfile;
                }
                set
                {
                    outputfile = value;
                }
            }

            /// <summary>
            /// Get or Set the sourcefile(s) that will be compiled by CSC.exe
            /// </summary>
            public string SourceFile
            {
                get
                {
                    return sourcefile;
                }
                set
                {
                    sourcefile = value;
                    sourcefiles.Add(value);
                }
            }

            public void AddSource(string sourcefile)
            {
                sourcefiles.Add(sourcefile);
            }

            public List<string> SourceFiles()
            {
                return sourcefiles;
            }

            public bool TempExec
            {
                get
                {
                    return tempexec;
                }
                set
                {
                    tempexec = value;
                    this.Threat.Increase();
                    LogWarning("Source File Is Being Compiled From %Temp% Folder");
                }
            }

            public bool RunTimeCompiled
            {
                get
                {
                    return runtimecompiled;
                }
                set
                {
                    runtimecompiled = value;
                    LogWarning("Source Appears To Be Using Compiled At Runtime Methods");
                    this.Threat.Increase();
                }
            }

            public string[] RuntimeCmdLine
            {
                get
                {
                    return runtimecmdline;
                }

                set
                {
                    runtimecmdline = value;
                }
            }

            public string OutputType
            {
                get
                {
                    return outputtype;
                }

                set
                {
                    outputtype = value;
                }
            }
            
            public string[] CmdLine
            {
                get
                {
                    return cmdline;
                }

                set
                {
                    cmdline = value;
                }
            }

            public Heuristics()
            {
                this.Threat = new ThreatStatus();
                this.ParentProcess = new ParentProcessInfo();
            }
            public ThreatStatus Threat { get; set; }
            public ParentProcessInfo ParentProcess { get; set; }

        }

        public static X509Certificate2 fileCert = new X509Certificate2();

        public static DateTime ExecutionTime = DateTime.Now;

        public static string Arguments = "";
        public static string LogFolder = "";
        public static string crlf = System.Environment.NewLine;
        public static string LogData = "";
        
        public static bool DEBUGMODE = true;

        public static Heuristics Heuristic = new Heuristics();

        public static int MaxThreatLevel = 0;
        public static string OriginalCSC = "CSCGuard.exe";
        public static bool CreateEventLog = true;

        static void Main(string[] args)
        {
            CreateLogFolder();
            Heuristic.CmdLine = args;

            MaxThreatLevel = Int32.Parse(ReadSetting("MaxThreatLevel"));
            OriginalCSC = ReadSetting("OriginalCSC");
            CreateEventLog = Convert.ToBoolean(ReadSetting("CreateEventLog"));

            string curDir = new FileInfo(Assembly.GetExecutingAssembly().Location).DirectoryName;
            LogInfo("Executed at " + ExecutionTime);
            LogInfo("Parameter Count [" + args.Length + "]");
            LogInfo("Original Cmdline: " + String.Join(" ", args));
            if (RuntimeDetection())
            {
                LogInfo("Attempting Runtime Cmdline Relaunch...");
                
                string CmdFile = File.ReadAllText(Heuristic.CmdLine[2].Trim(new char[] { '@' }));
                //string[] NewArgs = new[] { CmdFile };
                Heuristic.RuntimeCmdLine = SplitArguments(CmdFile);
            }
            ParentProcessUtilities.GetParentProcessInfo();
            GetParentProcessSig();
            try
            {
                LogInfo("Collecting Parent Process File");
                CollectFile(Heuristic.ParentProcess.Filename);
            }
            catch (Exception Ex)
            {
                LogInfo("Error Collecting Parent Process: " + Ex.Message);
            }
            
            if (Heuristic.RunTimeCompiled)
            {
                ParseArgs(Heuristic.RuntimeCmdLine);
            }
            else
            {
                ParseArgs(args);
            }
            LogWarning("Threat Level: [" + Heuristic.Threat.Level + "]");

            if (CreateEventLog)
            {
                CreateEventLogEntry();
                LogInfo("Windows Event Log Entry Created");
            }

            if (Heuristic.Threat.Level < MaxThreatLevel)
            {
                LogInfo("Executing: " + curDir + "\\" + OriginalCSC + " " + Arguments);
                //File.WriteAllText(LogFolder + "cscguard.txt", LogData);

                var CSC = Process.Start(curDir + "\\" + OriginalCSC, Arguments);
                CSC.WaitForExit();
                if (Heuristic.OutputFile.Length > 0)
                {
                    CollectFile(Heuristic.OutputFile);
                    LogInfo("Collecting: " + Heuristic.OutputFile);
                }
                string SourceFolder = Path.GetDirectoryName(Heuristic.SourceFile);
                string SourceFileNames = Path.GetFileNameWithoutExtension(Heuristic.SourceFile);
                SourceFileNames = SourceFileNames.Split('.')[0] + "*";
                LogInfo("Source Folder: " + SourceFolder);
                LogInfo("Source Search: " + SourceFileNames);


                string[] allGenFiles = Directory.GetFiles(SourceFolder, SourceFileNames, SearchOption.TopDirectoryOnly);
                foreach (string filename in allGenFiles)
                {
                    LogInfo("Collecting File: " + filename);
                    try
                    {
                        CollectFile(filename);
                    }
                    catch (Exception Ex)
                    {
                        LogInfo("Error: " + Ex.Message);
                    }
                }
            }
            else
            {
                LogWarning("Current Threat Level [" + Heuristic.Threat.Level.ToString() + "] Exceeds Max Threat Level [" + MaxThreatLevel + "]");
                LogWarning("CSCGuard Will Not Pass Execution To Original CSC.exe");
            }

            
            
        }

        static string ReadSetting(string key)
        {
            string retVal = "";
            try
            {
                var appsettings = ConfigurationManager.AppSettings;
                retVal = appsettings[key];
                if (String.IsNullOrEmpty(retVal))
                { 
                    switch (key)
                    {
                        case "MaxThreatLevel":
                            retVal = "2";
                            break;

                        case "OriginalCSC":
                            retVal = "CSCGuard.exe";
                            break;

                        case "CreateEventLog":
                            retVal = "true";
                            break;

                        default:
                            retVal = "";
                            break;
                    }
                }
            }
            catch
            {
                retVal = "";
            }
            return retVal;
        }

        public static string[] SplitArguments(string commandLine)
        {
            var parmChars = commandLine.ToCharArray();
            var inSingleQuote = false;
            var inDoubleQuote = false;
            for (var index = 0; index < parmChars.Length; index++)
            {
                if (parmChars[index] == '"' && !inSingleQuote)
                {
                    inDoubleQuote = !inDoubleQuote;
                }
                if (parmChars[index] == '\'' && !inDoubleQuote)
                {
                    inSingleQuote = !inSingleQuote;
                }
                if (!inSingleQuote && !inDoubleQuote && parmChars[index] == ' ')
                    parmChars[index] = '\n';
            }
            return (new string(parmChars)).Split(new[] { '\n' }, StringSplitOptions.RemoveEmptyEntries);
        }

        static void CreateEventLogEntry()
        {

            string Msg = "CSCGuard Intercept Event: " + crlf + crlf;
            Msg += Heuristic.ParentProcess.Filename + " Attempted to Execute CSC.EXE with the following parameters: " + crlf;
            Msg += "{" + crlf;
            Msg += Arguments + crlf;
            Msg += "}" + crlf + crlf;
            Msg += "CSCGuard Log Folder For This Event: " + LogFolder + crlf;
            Msg += "CSCGuard Passed Execution To Original CSC.exe: ";
            if (Heuristic.Threat.Level < MaxThreatLevel)
            {
                Msg += "true" + crlf;
            }
            else
            {
                Msg += "false" + crlf;
            }
            Msg += "CSCGuard Heuristic Threat Level: " + Heuristic.Threat.Level + crlf;
            Msg += "CSCGuard Detected Runtime Compilation: " + Heuristic.RunTimeCompiled + crlf;
            Msg += "CSCGuard Parent Process Signed: " + Heuristic.ParentProcess.IsSigned + crlf;
            Msg += "CSCGuard Parent Process Has Valid Signature: " + Heuristic.ParentProcess.ValidSigned + crlf; ;
            Msg += "CSCGuard Code Executed From %TEMP% Folder: " + Heuristic.TempExec + crlf;
            Msg += "CSCGuard v0.3 by Greg Linares (@Laughing_Mantis)" + crlf;
            if (Heuristic.Threat.Level > 1)
            {
                LogEventWarning(Msg);
            }
            else
            {
                LogEventInfo(Msg);
            }
            
        }

        static void GetParentProcessSig()
        {
            
            bool ValidChain = false;
            try
            {
                X509Certificate SignedCert = X509Certificate.CreateFromSignedFile(Heuristic.ParentProcess.Filename);
                fileCert = new X509Certificate2(SignedCert);
            }
            catch
            {
                LogInfo("No Digital Signature Found for [" + Heuristic.ParentProcess.Filename + "]");
                Heuristic.ParentProcess.IsSigned = false;
                return;
            }
            var CertChain = new X509Chain();
            CertChain.ChainPolicy.RevocationFlag = X509RevocationFlag.ExcludeRoot;
            CertChain.ChainPolicy.RevocationMode = X509RevocationMode.Online;
            CertChain.ChainPolicy.UrlRetrievalTimeout = new TimeSpan(0, 0, 10);
            CertChain.ChainPolicy.VerificationFlags = X509VerificationFlags.NoFlag;
            ValidChain = CertChain.Build(fileCert);
            if (ValidChain)
            {
                Heuristic.ParentProcess.ValidSigned = true;
                LogInfo("Parent Process Cert Chain Is Valid:");
                LogInfo("\tPublisher Information : " + fileCert.SubjectName.Name);
                Heuristic.ParentProcess.Signature += "Publisher Info: " + fileCert.SubjectName.Name;
                LogInfo("\tValid From: " + fileCert.GetEffectiveDateString());
                Heuristic.ParentProcess.Signature += "Valid From: " + fileCert.GetEffectiveDateString();
                LogInfo("\tValid To: " + fileCert.GetExpirationDateString());
                Heuristic.ParentProcess.Signature += "Valid To: " + fileCert.GetExpirationDateString();
                LogInfo("\tIssued By: " + fileCert.Issuer);
                Heuristic.ParentProcess.Signature += "Issued By: " + fileCert.Issuer;
            }
            else
            {
                LogWarning("Chain Not Valid (File is Self-Signed or Insecure)");
                Heuristic.ParentProcess.SelfSigned = true;
                Heuristic.ParentProcess.ValidSigned = false;
            }
        }

        static void CreateLogFolder()
        {
            string DateTimeFolders = ExecutionTime.ToString("yyyy") + "\\" + ExecutionTime.ToString("MMMM-dd") + "\\" + ExecutionTime.ToString("HH-mm-ss.fffffff");
            LogFolder = System.Environment.ExpandEnvironmentVariables("%USERPROFILE%\\CSCGuard\\Log\\" + DateTimeFolders + "\\");
            
            if (!Directory.Exists(LogFolder))
            {
                try
                {
                    Directory.CreateDirectory(LogFolder);
                }
                catch (Exception Ex)
                {
                    Console.WriteLine(Ex.Message);
                }
            }
            LogInfo("Log Folder: [" + LogFolder + "]");
        }

        static void ParseArgs(string[] args)
        {
            for (int i = 0; i < args.Length; i++)
            {
                Arguments += args[i] + " ";
                string expandArg = System.Environment.ExpandEnvironmentVariables(args[i].ToString());
                LogInfo("Arg[" + i.ToString() + "] = [" + expandArg + "]");
                AnalyzeArg(expandArg);
            }
            File.WriteAllText(LogFolder + "cmdline.txt", Arguments.TrimEnd());
        }

        static bool RuntimeDetection()
        {
            if (Heuristic.CmdLine.Length == 3)
            {
                if (Heuristic.CmdLine[0].ToLower() == "/noconfig")
                {
                    if (Heuristic.CmdLine[1].ToLower() == "/fullpaths")
                    {
                        string TempFolder = System.Environment.GetEnvironmentVariable("TEMP");
                        if (Heuristic.CmdLine[2].Contains(TempFolder))
                        { 
                            if (Heuristic.CmdLine[2].EndsWith(".cmdline"))
                            {
                                Heuristic.RunTimeCompiled = true;
                                return true;
                            }
                        }
                    }
                }
            }
            return false;
        }

        static void AnalyzeArg(string arg)
        {
            string param = arg.ToLower();
            if (param[0].ToString() != "/")
            {
                if (arg.StartsWith("@"))
                {
                    arg = arg.Substring(1);
                }
                Heuristic.SourceFile = arg.Trim(new char[] { '"' });
                LogWarning("SourceFile: " + Heuristic.SourceFile);
                string TempFolder = System.Environment.GetEnvironmentVariable("TEMP");
                if (arg.Contains(TempFolder))
                {
                    Heuristic.TempExec = true;
                }
                CollectFile(Heuristic.SourceFile);
            }

            if (param.Contains("/out:"))
            {
                int index = param.IndexOf(":");
                string outFile = arg.Substring(index + 1).Trim(new char[] { '"' });
                LogInfo("Output File: " + outFile);
                Heuristic.OutputFile = outFile;
            }
            

            if (param.Contains("/r:") || param.Contains("/resource:"))
            {
                int index = param.IndexOf(":");
                string ResFile = arg.Substring(index + 1).Trim(new char[] { '"' });
                LogInfo("Resource File: " + ResFile);
                CollectFile(ResFile);
            }


            // Detect the output type of the CS code 
            if (param.Contains("/target:") || param.Contains("/t:"))
            {
                //DebugWarning("Target Output Detected: " + arg);
                if (param.Contains(":exe"))
                {
                    Heuristic.OutputType = "Console EXE";
                    DebugWarning("Console EXE Output Detected: " + arg);
                    Heuristic.Threat.Increase();
                }
                if (param.Contains(":winexe"))
                {
                    Heuristic.OutputType = "Windows EXE";
                    DebugWarning("Windows GUI EXE Output Detected: " + arg);
                    Heuristic.Threat.Increase();
                }
                if (param.Contains(":library"))
                {
                    Heuristic.OutputType = "DLL";
                    DebugWarning("DLL Output Detected: " + arg);
                    Heuristic.Threat.Increase();
                }
                if (param.Contains(":module"))
                {
                    Heuristic.OutputType = "NETMODULE";
                    DebugWarning("NETMODULE Output Detected: " + arg);
                }
            }
        }

        static void CollectFile(string FileName)
        {
            if (File.Exists(FileName))
            {
                if (!File.Exists(LogFolder + Path.GetFileName(FileName)))
                {
                    File.Copy(FileName, LogFolder + Path.GetFileName(FileName), false);
                }
            }
            else
            {
                LogWarning("File Not Found: " + FileName);
            }
        }

        static void DisplayText(string Text)
        {
            Console.WriteLine(Text);
            File.AppendAllText(LogFolder + "cscguard.txt", Text + crlf);
        }

        static void LogInfo(string Note)
        {
            if (Note.Contains("\t"))
            {
                DisplayText(Note);
            }
            else
            {
                DisplayText("[i] CSCGuard: " + Note);  
            }
        }

        static void DebugInfo(string Note)
        {
            if (DEBUGMODE)
            {
                if (Note.Contains("\t"))
                {
                    DisplayText(Note);
                }
                else
                {
                    DisplayText("[i] CSCGuard Debug: " + Note);
                }
            }
            else
            {
                if (Note.Contains("\t"))
                {
                    LogData += Note + crlf; ;
                }
                else
                {
                    LogData += "[i] CSCGuard Debug: " + Note + crlf; ;
                }
            }
            
        }

        static void LogWarning(string Note)
        {
            ConsoleColor oldColor = Console.ForegroundColor;
            Console.ForegroundColor = ConsoleColor.Red;
            DisplayText("[!] CSCGuard: " + Note);
            Console.ForegroundColor = oldColor;
        }

        static void DebugWarning(string Note)
        {
            if (DEBUGMODE)
            {
                ConsoleColor oldColor = Console.ForegroundColor;
                Console.ForegroundColor = ConsoleColor.Red;
                DisplayText("[!] CSCGuard Debug: " + Note);
                Console.ForegroundColor = oldColor;
            }
        }

        static void LogEventInfo(string Event)
        {
            try
            {
                if (!EventLog.SourceExists("CSCGuard"))
                {
                    EventLog.CreateEventSource("CSCGuard", "CSCGuard");
                }
                EventLog.WriteEntry("CSCGuard", Event, EventLogEntryType.Information, 1000);
            }
            catch(Exception Ex)
            {
                Console.WriteLine("Error Could Not Write To Windows Event Log: " + Ex.Message);
            }

            
        }

        static void LogEventWarning(string Event)
        {
            try
            {
                if (!EventLog.SourceExists("CSCGuard"))
                {
                    EventLog.CreateEventSource("CSCGuard", "CSCGuard");
                }
                EventLog.WriteEntry("CSCGuard", Event, EventLogEntryType.Warning, 9001);
            }
            catch (Exception Ex)
            {
                Console.WriteLine("Error Could Not Write To Windows Event Log: " + Ex.Message);
            }
        }


        public struct ParentProcessUtilities
        {
            // PROCESS_BASIC_INFORMATION
            internal IntPtr Reserved1;
            internal IntPtr PebBaseAddress;
            internal IntPtr Reserved2_0;
            internal IntPtr Reserved2_1;
            internal IntPtr UniqueProcessId;
            internal IntPtr InheritedFromUniqueProcessId;

            [DllImport("ntdll.dll")]
            private static extern int NtQueryInformationProcess(IntPtr processHandle, int processInformationClass, ref ParentProcessUtilities processInformation, int processInformationLength, out int returnLength);


            public static void GetParentProcessInfo()
            {
                Process Parent =  GetParentProcess(Process.GetCurrentProcess().Handle);
                Heuristic.ParentProcess.Id = Parent.Id.ToString();
                Heuristic.ParentProcess.Name = Parent.ProcessName.ToString();
                Heuristic.ParentProcess.Filename = Parent.MainModule.FileName;
            }


            /// <summary>
            /// Gets the parent process of specified process.
            /// </summary>
            /// <param name="id">The process id.</param>
            /// <returns>An instance of the Process class.</returns>
            public static Process GetParentProcess(int id)
            {
                try
                {
                    Process process = Process.GetProcessById(id);
                    return GetParentProcess(process.Handle);
                }
                catch (Exception Ex)
                {
                    Console.WriteLine(Ex);
                }
                return null;
            }

            /// <summary>
            /// Gets the parent process of a specified process.
            /// </summary>
            /// <param name="handle">The process handle.</param>
            /// <returns>An instance of the Process class.</returns>
            public static Process GetParentProcess(IntPtr handle)
            {
                ParentProcessUtilities pbi = new ParentProcessUtilities();
                int returnLength;
                int status = NtQueryInformationProcess(handle, 0, ref pbi, Marshal.SizeOf(pbi), out returnLength);
                if (status != 0)
                    throw new Win32Exception(status);

                try
                {
                    return Process.GetProcessById(pbi.InheritedFromUniqueProcessId.ToInt32());
                }
                catch (ArgumentException)
                {
                    // not found
                    return null;
                }
            }
        }
    }
}
