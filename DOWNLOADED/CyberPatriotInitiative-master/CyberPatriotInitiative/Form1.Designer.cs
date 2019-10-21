namespace CyberPatriotInitiative
{
    partial class Form1
    {
        /// <summary>
        /// Required designer variable.
        /// </summary>
        private System.ComponentModel.IContainer components = null;

        /// <summary>
        /// Clean up any resources being used.
        /// </summary>
        /// <param name="disposing">true if managed resources should be disposed; otherwise, false.</param>
        protected override void Dispose(bool disposing)
        {
            if (disposing && (components != null))
            {
                components.Dispose();
            }
            base.Dispose(disposing);
        }

        #region Windows Form Designer generated code

        /// <summary>
        /// Required method for Designer support - do not modify
        /// the contents of this method with the code editor.
        /// </summary>
        private void InitializeComponent()
        {
            this.tableLayoutPanel1 = new System.Windows.Forms.TableLayoutPanel();
            this.flowLayoutPanel1 = new System.Windows.Forms.FlowLayoutPanel();
            this.m1_disableGuestButton = new System.Windows.Forms.Button();
            this.m1_enableFirewallButton = new System.Windows.Forms.Button();
            this.m1_disableEvilServicesButton = new System.Windows.Forms.Button();
            this.m1_setPasswordPolicyButton = new System.Windows.Forms.Button();
            this.m1_setLockoutPolicyButton = new System.Windows.Forms.Button();
            this.m1_enableUAEButton = new System.Windows.Forms.Button();
            this.m1_setUniformPasswordsButton = new System.Windows.Forms.Button();
            this.m1_updateAutomaticallyButton = new System.Windows.Forms.Button();
            this.tableLayoutPanel1.SuspendLayout();
            this.flowLayoutPanel1.SuspendLayout();
            this.SuspendLayout();
            // 
            // tableLayoutPanel1
            // 
            this.tableLayoutPanel1.ColumnCount = 2;
            this.tableLayoutPanel1.ColumnStyles.Add(new System.Windows.Forms.ColumnStyle(System.Windows.Forms.SizeType.Percent, 44.98141F));
            this.tableLayoutPanel1.ColumnStyles.Add(new System.Windows.Forms.ColumnStyle(System.Windows.Forms.SizeType.Percent, 55.01859F));
            this.tableLayoutPanel1.Controls.Add(this.flowLayoutPanel1, 0, 0);
            this.tableLayoutPanel1.Dock = System.Windows.Forms.DockStyle.Fill;
            this.tableLayoutPanel1.Location = new System.Drawing.Point(0, 0);
            this.tableLayoutPanel1.Name = "tableLayoutPanel1";
            this.tableLayoutPanel1.RowCount = 1;
            this.tableLayoutPanel1.RowStyles.Add(new System.Windows.Forms.RowStyle(System.Windows.Forms.SizeType.Percent, 73.80952F));
            this.tableLayoutPanel1.Size = new System.Drawing.Size(538, 462);
            this.tableLayoutPanel1.TabIndex = 0;
            // 
            // flowLayoutPanel1
            // 
            this.flowLayoutPanel1.Controls.Add(this.m1_disableGuestButton);
            this.flowLayoutPanel1.Controls.Add(this.m1_enableFirewallButton);
            this.flowLayoutPanel1.Controls.Add(this.m1_disableEvilServicesButton);
            this.flowLayoutPanel1.Controls.Add(this.m1_setPasswordPolicyButton);
            this.flowLayoutPanel1.Controls.Add(this.m1_setLockoutPolicyButton);
            this.flowLayoutPanel1.Controls.Add(this.m1_enableUAEButton);
            this.flowLayoutPanel1.Controls.Add(this.m1_setUniformPasswordsButton);
            this.flowLayoutPanel1.Controls.Add(this.m1_updateAutomaticallyButton);
            this.flowLayoutPanel1.Dock = System.Windows.Forms.DockStyle.Fill;
            this.flowLayoutPanel1.FlowDirection = System.Windows.Forms.FlowDirection.TopDown;
            this.flowLayoutPanel1.Location = new System.Drawing.Point(3, 3);
            this.flowLayoutPanel1.Name = "flowLayoutPanel1";
            this.flowLayoutPanel1.Size = new System.Drawing.Size(235, 456);
            this.flowLayoutPanel1.TabIndex = 0;
            // 
            // m1_disableGuestButton
            // 
            this.m1_disableGuestButton.AutoSize = true;
            this.m1_disableGuestButton.Location = new System.Drawing.Point(3, 3);
            this.m1_disableGuestButton.Name = "m1_disableGuestButton";
            this.m1_disableGuestButton.Size = new System.Drawing.Size(108, 23);
            this.m1_disableGuestButton.TabIndex = 0;
            this.m1_disableGuestButton.Text = "Disable Guest Acc.";
            this.m1_disableGuestButton.UseVisualStyleBackColor = true;
            this.m1_disableGuestButton.Click += new System.EventHandler(this.m1_disableGuestButton_Click);
            // 
            // m1_enableFirewallButton
            // 
            this.m1_enableFirewallButton.AutoSize = true;
            this.m1_enableFirewallButton.Location = new System.Drawing.Point(3, 32);
            this.m1_enableFirewallButton.Name = "m1_enableFirewallButton";
            this.m1_enableFirewallButton.Size = new System.Drawing.Size(88, 23);
            this.m1_enableFirewallButton.TabIndex = 1;
            this.m1_enableFirewallButton.Text = "Enable Firewall";
            this.m1_enableFirewallButton.UseVisualStyleBackColor = true;
            this.m1_enableFirewallButton.Click += new System.EventHandler(this.m1_enableFirewallButton_Click);
            // 
            // m1_disableEvilServicesButton
            // 
            this.m1_disableEvilServicesButton.AutoSize = true;
            this.m1_disableEvilServicesButton.Location = new System.Drawing.Point(3, 61);
            this.m1_disableEvilServicesButton.Name = "m1_disableEvilServicesButton";
            this.m1_disableEvilServicesButton.Size = new System.Drawing.Size(121, 23);
            this.m1_disableEvilServicesButton.TabIndex = 2;
            this.m1_disableEvilServicesButton.Text = "Disable (evil) Services";
            this.m1_disableEvilServicesButton.UseVisualStyleBackColor = true;
            this.m1_disableEvilServicesButton.Click += new System.EventHandler(this.m1_disableEvilServicesButton_Click);
            // 
            // m1_setPasswordPolicyButton
            // 
            this.m1_setPasswordPolicyButton.AutoSize = true;
            this.m1_setPasswordPolicyButton.Location = new System.Drawing.Point(3, 90);
            this.m1_setPasswordPolicyButton.Name = "m1_setPasswordPolicyButton";
            this.m1_setPasswordPolicyButton.Size = new System.Drawing.Size(94, 23);
            this.m1_setPasswordPolicyButton.TabIndex = 3;
            this.m1_setPasswordPolicyButton.Text = "Password Policy";
            this.m1_setPasswordPolicyButton.UseVisualStyleBackColor = true;
            this.m1_setPasswordPolicyButton.Click += new System.EventHandler(this.m1_setPasswordPolicyButton_Click);
            // 
            // m1_setLockoutPolicyButton
            // 
            this.m1_setLockoutPolicyButton.AutoSize = true;
            this.m1_setLockoutPolicyButton.Location = new System.Drawing.Point(3, 119);
            this.m1_setLockoutPolicyButton.Name = "m1_setLockoutPolicyButton";
            this.m1_setLockoutPolicyButton.Size = new System.Drawing.Size(87, 23);
            this.m1_setLockoutPolicyButton.TabIndex = 4;
            this.m1_setLockoutPolicyButton.Text = "Lockout Policy";
            this.m1_setLockoutPolicyButton.UseVisualStyleBackColor = true;
            this.m1_setLockoutPolicyButton.Click += new System.EventHandler(this.m1_setLockoutPolicyButton_Click);
            // 
            // m1_enableUAEButton
            // 
            this.m1_enableUAEButton.AutoSize = true;
            this.m1_enableUAEButton.Location = new System.Drawing.Point(3, 148);
            this.m1_enableUAEButton.Name = "m1_enableUAEButton";
            this.m1_enableUAEButton.Size = new System.Drawing.Size(75, 23);
            this.m1_enableUAEButton.TabIndex = 5;
            this.m1_enableUAEButton.Text = "Enable UAE";
            this.m1_enableUAEButton.UseVisualStyleBackColor = true;
            this.m1_enableUAEButton.Click += new System.EventHandler(this.m1_enableUAEButton_Click);
            // 
            // m1_setUniformPasswordsButton
            // 
            this.m1_setUniformPasswordsButton.AutoSize = true;
            this.m1_setUniformPasswordsButton.Location = new System.Drawing.Point(3, 177);
            this.m1_setUniformPasswordsButton.Name = "m1_setUniformPasswordsButton";
            this.m1_setUniformPasswordsButton.Size = new System.Drawing.Size(121, 23);
            this.m1_setUniformPasswordsButton.TabIndex = 6;
            this.m1_setUniformPasswordsButton.Text = "Set Uniform Password";
            this.m1_setUniformPasswordsButton.UseVisualStyleBackColor = true;
            this.m1_setUniformPasswordsButton.Click += new System.EventHandler(this.m1_setUniformPasswordsButton_Click);
            // 
            // m1_updateAutomaticallyButton
            // 
            this.m1_updateAutomaticallyButton.AutoSize = true;
            this.m1_updateAutomaticallyButton.Location = new System.Drawing.Point(3, 206);
            this.m1_updateAutomaticallyButton.Name = "m1_updateAutomaticallyButton";
            this.m1_updateAutomaticallyButton.Size = new System.Drawing.Size(117, 23);
            this.m1_updateAutomaticallyButton.TabIndex = 7;
            this.m1_updateAutomaticallyButton.Text = "Update Automatically";
            this.m1_updateAutomaticallyButton.UseVisualStyleBackColor = true;
            this.m1_updateAutomaticallyButton.Click += new System.EventHandler(this.m1_updateAutomaticallyButton_Click);
            // 
            // Form1
            // 
            this.AutoScaleDimensions = new System.Drawing.SizeF(6F, 13F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.ClientSize = new System.Drawing.Size(538, 462);
            this.Controls.Add(this.tableLayoutPanel1);
            this.Name = "Form1";
            this.Text = "CyberPatriot Blazing Fast Points: Easy As Counting To One";
            this.Load += new System.EventHandler(this.Form1_Load);
            this.tableLayoutPanel1.ResumeLayout(false);
            this.flowLayoutPanel1.ResumeLayout(false);
            this.flowLayoutPanel1.PerformLayout();
            this.ResumeLayout(false);

        }

        #endregion

        private System.Windows.Forms.TableLayoutPanel tableLayoutPanel1;
        private System.Windows.Forms.FlowLayoutPanel flowLayoutPanel1;
        private System.Windows.Forms.Button m1_disableGuestButton;
        private System.Windows.Forms.Button m1_enableFirewallButton;
        private System.Windows.Forms.Button m1_disableEvilServicesButton;
        private System.Windows.Forms.Button m1_setPasswordPolicyButton;
        private System.Windows.Forms.Button m1_setLockoutPolicyButton;
        private System.Windows.Forms.Button m1_enableUAEButton;
        private System.Windows.Forms.Button m1_setUniformPasswordsButton;
        private System.Windows.Forms.Button m1_updateAutomaticallyButton;
    }
}

