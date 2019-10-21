using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;
using System.Management;

namespace CyberPatriotInitiative
{
    public partial class Form1 : Form
    {
        public Form1()
        {
            InitializeComponent();
        }

        private void Form1_Load(object sender, EventArgs e)
        {

        }

        private void m1_disableGuestButton_Click(object sender, EventArgs e)
        {
            string strCmdText;
            strCmdText = "/C net user guest /active:no";
            System.Diagnostics.Process.Start("CMD.exe", strCmdText);
        }

        private void m1_enableFirewallButton_Click(object sender, EventArgs e)
        {
            string strCmdText;
            strCmdText = "/C NetSh Advfirewall set allprofiles state on";
            System.Diagnostics.Process.Start("CMD.exe", strCmdText);
        }

        private void m1_disableEvilServicesButton_Click(object sender, EventArgs e)
        {
            string strCmdText;
            strCmdText = "/C net stop telnet";
            System.Diagnostics.Process.Start("CMD.exe", strCmdText);
            strCmdText = "/C sc config tlntsvr start= disabled";
            System.Diagnostics.Process.Start("CMD.exe", strCmdText);
            strCmdText = "/C net stop RemoteRegistry";
            System.Diagnostics.Process.Start("CMD.exe", strCmdText);
            strCmdText = "/C sc config RemoteRegistry start= disabled";
            System.Diagnostics.Process.Start("CMD.exe", strCmdText);
        }

        private void m1_updateAutomaticallyButton_Click(object sender, EventArgs e)
        {
            string strCmdText;
            strCmdText = @"/C reg add ""HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update"" /v AUOptions /t REG_DWORD /d 0 /f";
            System.Diagnostics.Process.Start("CMD.exe", strCmdText);
        }

        private void m1_setPasswordPolicyButton_Click(object sender, EventArgs e)
        {

        }

        private void m1_setLockoutPolicyButton_Click(object sender, EventArgs e)
        {

        }

        private void m1_enableUAEButton_Click(object sender, EventArgs e)
        {
            string strCmdText;
            strCmdText = @"/C C:WindowsSystem32cmd.exe /k %windir%System32reg.exe ADD HKLMSOFTWAREMicrosoftWindowsCurrentVersionPoliciesSystem /v EnableLUA /t REG_DWORD /d 1 /f";
            System.Diagnostics.Process.Start("CMD.exe", strCmdText);
        }

        private void m1_setUniformPasswordsButton_Click(object sender, EventArgs e)
        {
            SelectQuery query = new SelectQuery("Win32_UserAccount");
            ManagementObjectSearcher searcher = new ManagementObjectSearcher(query);
            foreach (ManagementObject envVar in searcher.Get())
            {
                string strCmdText;
                strCmdText = "/C net user " + envVar["Name"] + " c00kies98";
                System.Diagnostics.Process.Start("CMD.exe", strCmdText);
            }
        }
    }
}
