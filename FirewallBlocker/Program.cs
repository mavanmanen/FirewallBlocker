using FirewallBlocker.Extensions;
using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Security.Principal;
using WindowsFirewallHelper;

namespace FirewallBlocker
{
    class Program
    {
        static void Main(string[] args)
        {
            RestartIfNotAdmin(args);

            if (args.Any())
            {
                AddFirewallRules(args[0], args[1], args[2]);
            }
            else
            {
                InstallContextMenu();
            }

            Console.Write("Press a key to exit.");
            Console.ReadKey();
        }

        private static void RestartIfNotAdmin(string[] args)
        {
            WindowsIdentity identity = WindowsIdentity.GetCurrent();
            var principal = new WindowsPrincipal(identity);

            if(principal.IsInRole(WindowsBuiltInRole.Administrator))
            {
                return;
            }

            var processInfo = new ProcessStartInfo(GetExecutableLocation())
            {
                UseShellExecute = true,
                Verb = "runas",
                Arguments = string.Join(" ", args)
            };

            try
            {
                Process.Start(processInfo);
            }
            catch (Exception)
            {
                Console.WriteLine("Failed to run as admin.");
                Console.Write("Press a key to exit.");
                Console.ReadKey();
                Environment.Exit(1);
            }

            Environment.Exit(0);
        }

        private static void AddFirewallRules(string action, string direction, string file)
        {
            if(direction == "Incoming" || direction == "Both")
            {
                FirewallManager.Instance.Rules.Add(CreateFirewallRule(action, FirewallDirection.Inbound, file));
            }

            if (direction == "Outgoing" || direction == "Both")
            {
                FirewallManager.Instance.Rules.Add(CreateFirewallRule(action, FirewallDirection.Outbound, file));
            }

            Console.WriteLine("Firewall rule added:");
            Console.WriteLine($"Action: {action}");
            Console.WriteLine($"Direction: {direction}");
            Console.WriteLine($"File: {file}");
        }

        private static IRule CreateFirewallRule(string action, FirewallDirection direction, string filename)
        {
            var file = new FileInfo(filename);
            var rule = FirewallManager.Instance.CreateApplicationRule(
                FirewallProfiles.Domain | FirewallProfiles.Private | FirewallProfiles.Public,
                $"{action} {file.Name}",
                action == "Allow" ? FirewallAction.Allow : FirewallAction.Block,
                filename);

            rule.Direction = direction;

            return rule;
        }

        private static string GetExecutableLocation() => Assembly.GetExecutingAssembly().Location;

        private static void InstallContextMenu()
        {
            RegistryKey firewall = Registry
                .ClassesRoot
                .OpenOrCreateSubKey(@"exefile\shell\firewall");

            firewall.SetValue("MUIVerb", "Firewall");

            RegistryKey commands = Registry
                .LocalMachine
                .OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\CommandStore\shell", true);

            const string baseCommandKey = "Custom.Firewall";
            List<string> commandNames = new List<string>();

            foreach(string commandName in new[] { "Allow", "Block" })
            {
                string fullCommandName = $"{baseCommandKey}.{commandName}";
                commandNames.Add(fullCommandName);

                RegistryKey command = commands.OpenOrCreateSubKey(fullCommandName);
                command.SetValue("MUIVerb", commandName);

                var subCommandVerbs = new List<string>();
                foreach(string subCommandName in new[] { "Both", "Incoming", "Outgoing" })
                {
                    string fullSubCommand = $"{fullCommandName}.{subCommandName}";
                    subCommandVerbs.Add(fullSubCommand);

                    RegistryKey subCommand = commands.OpenOrCreateSubKey(fullSubCommand);
                    subCommand.SetValue("MUIVerb", subCommandName);

                    RegistryKey subCommandCommand = subCommand.OpenOrCreateSubKey("command");
                    subCommandCommand.SetValue("", $"{GetExecutableLocation()} {commandName} {subCommandName} \"%1\"");
                }

                command.SetValue("SubCommands", string.Join(";", subCommandVerbs));
            }

            firewall.SetValue("SubCommands", string.Join(";", commandNames));

            Console.WriteLine("Explorer context menu commands installed/updated.");
        }
    }
}
