## Tutorial 3 Guide for Macs with Apple Silicon 

### Part 1: VirtualBox Network Configuration (No Changes)
This part is identical to the original tutorial as it's performed entirely within VirtualBox, not the guest OS.

#### Open VirtualBox Network Manager:
In VirtualBox, go to **File** -> **Tools** -> **Network Manager**.

#### Create the Developer Network:
1. Click the **NAT Networks** tab.
2. Click **Create**.
3. Select the new network, click **Properties**.
   * **Network Name:** `Developer Network`
   * **Network CIDR:** `192.168.56.0/24`
   * Uncheck **Enable DHCP**. This is critical.
4. Click **Apply**.

#### Create the Server Network:
1. Click **Create** again.
2. Select the new network, click **Properties**.
   * **Network Name:** `Server Network`
   * **Network CIDR:** `10.0.2.0/24`
   * Uncheck **Enable DHCP**.
3. Click **Apply**.

#### Configure OPNsense VM Network Adapters:
1. Select your OPNsense VM and go to **Settings** -> **Network**.
2. Ensure three adapters are enabled:
   * **Adapter 1 (WAN):** Bridged Adapter, attached to your MacBook's Wi-Fi or Ethernet.
   * **Adapter 2 (LAN - Developer Network):** NAT Network, Name: `Developer Network`.
   * **Adapter 3 (OPT1 - Server Network):** NAT Network, Name: `Server Network`.
3. Click **OK**.

---

### Part 2: OPNsense Initial Configuration (Console)

You can download the **aarch64 (ARM64)** version of OPNsense from the following link (the first link for us):
* [OPNsense VM Images Releases](https://github.com/maurice-w/opnsense-vm-images/releases)

The format of the download is not readable by VirtualBox directly, we need to extract it first and then convert it with the help of Terminal and VirtualBox commands.

Open a new Terminal window and type (make sure to include complete file paths in respective places):
```bash
VBoxManage clonemedium [source_file.qcow2] [destination_file.vdi] --format VDI

```

> **Important Note:** This process only converts the virtual disk image. It does not create a fully configured virtual machine. You will still need to:
> 1. Create a new virtual machine in the VirtualBox GUI.
> 2. When you get to the **Hard Disk** section of the wizard, choose **Use an existing virtual hard disk file**.
> 3. Browse to and select the `.vdi` file you just created.
> 
> 

We finally should have a working VM (*SIGH*). To access it, the defaults are:

* **Username:** `root`
* **Password:** `opnsense`

This is the initial setup from the OPNsense virtual machine console:

1. **Boot the OPNsense VM.**
2. **Assign Interfaces (Use option 1 using keyboard):**
* OPNsense will auto-detect the network adapters (e.g., `em0`, `em1`, `em2`). It will ask if you want to set up VLANs or LAGGs. Type `n` and press **Enter** (do not set something that is not required).
* **WAN interface:** Enter the name for Adapter 1 (likely `em0`).
* **LAN interface:** Enter the name for Adapter 2 (likely `em1`).
* **Optional 1 interface:** Enter the name for Adapter 3 (likely `em2`).
* Review the summary and type `y` to proceed.


3. **Set the LAN IP Address:**
* After the setup completes, you will see the OPNsense console menu.
* Choose option **2) Set interface(s) IP address**.
* Select the LAN interface (option **2**).
* **Configure IPv4 address LAN interface via DHCP?:** Type `n`.
* **Enter the new LAN IPv4 address:** `192.168.56.254`
* **Enter the new LAN IPv4 subnet bit count:** `24`
* **Upstream gateway:** Press **Enter** for none.
* **Configure IPv6:** Type `n`.
* **Enable DHCP server on LAN?:** Type `y`.
* **Enter the start address of the DHCP range:** `192.168.56.2`
* **Enter the end address of the DHCP range:** `192.168.56.253`
* **Revert to HTTP?:** Press **Enter** (default is no). You can still access it via HTTP.



---

### Part 3: OPNsense Web Configuration

Now, connect from the Kali VM to configure the rest of OPNsense.

#### Configure Kali VM Network:

1. In VirtualBox, go to your Kali VM **Settings** -> **Network**.
2. Set **Adapter 1** to **NAT Network** with the Name **Developer Network**.
3. Boot the Kali VM. It should get an IP address like `192.168.56.2`.

#### Access the Web Interface:

1. In your Kali VM, open a browser and navigate to `http://192.168.56.254`.
2. Log in with default credentials:
* **Username:** `root`
* **Password:** `opnsense`



#### Complete the Setup Wizard:

1. The wizard will start automatically. Click **Next**.
2. **General Information:** Leave defaults. Click **Next**.
3. **Time Server:** Leave defaults. Click **Next**.
4. **Configure WAN:** Leave DHCP selected. Click **Next**.
5. **Configure LAN:** Confirm the IP is `192.168.56.254`. Click **Next**.
6. **Set Root Password:** Change the default password. This is a critical security step (but not required for us).
7. Click **Reload** to apply the changes.

#### Configure the OPT1 (Server) Interface:

1. After reloading, log in with your new password.
2. Go to **Interfaces** -> **[OPT1]**.
3. Check the box for **Enable Interface**.
4. **Description:** `SERVER`
5. **IPv4 Configuration Type:** `Static IPv4`
6. Scroll to the Static IPv4 configuration section:
* **IPv4 address:** `10.0.2.1` and select `/24` from the dropdown.


7. Click **Save**, then **Apply Changes** at the top of the page.

#### Configure DHCP for the Server Network:

1. Go to **Services** -> **DHCPv4** -> **[SERVER]**.
2. Check **Enable DHCP server on SERVER interface**.
3. **Range:** Set the range from `10.0.2.100` to `10.0.2.200`.
4. Scroll down and click **Save**.

---

### Part 4: VM Configuration & Connectivity Check

#### Configure DVWA VM Network:

1. In VirtualBox, go to your DVWA (Ubuntu) VM **Settings** -> **Network**.
2. Set its adapter to **NAT Network** with the Name **Server Network**.
3. Boot the DVWA VM. Run `ip a` in a terminal to confirm it received an IP like `10.0.2.100`.

#### Add a Route on Kali:

Kali needs to know how to reach the SERVER network. Open a terminal on Kali and run:

```bash
sudo route add -net 10.0.2.0 netmask 255.255.255.0 gw 192.168.56.254

```

#### Create a Firewall Rule to Allow Traffic:

1. In the OPNsense web interface, go to **Firewall** -> **Rules** -> **LAN**.
2. Click the orange **+ Add** button:
* **Action:** Pass
* **Protocol:** any
* **Source:** LAN net
* **Destination:** any
* **Description:** Allow LAN to access other networks


3. Click **Save**, then **Apply Changes**.

#### Test Connectivity:

From your Kali VM, ping the DVWA VM's IP address:

```bash
ping 10.0.2.100

```

You should see successful replies.

---

### Part 5: Detect Intrusions with Suricata (IDS)

OPNsense has Suricata built-in, which serves the same purpose as Snort.

#### Enable and Update Suricata:

1. In the OPNsense GUI, go to **Services** -> **Intrusion Detection** -> **Administration**.
2. Click the **Download** tab. Click **Download & Update Rules**. This will take a moment.
3. Go back to the **Settings** tab. Check **Enable Intrusion Detection**.
4. In the **Interfaces** box, select **SERVER**.
5. Click **Apply** at the bottom of the page.

This method adds your custom rule through the web interface, which ensures it is correctly formatted and applied.

#### Step 1: Navigate to User-defined Rules

1. In your OPNsense web GUI, go to the top menu and click on **Services**.
2. From the dropdown, go to **Intrusion Detection** -> **Administration**.
3. Click on the **User-defined** sub-tab.
4. You should see an empty list of user-defined rules.

#### Step 2: Add the New ICMP Rule

1. Click the orange **+ Add** button on the right side of the page to create a new rule.
2. Fill out the form exactly as follows:
* **Enabled:** Make sure this box is checked.
* **Action:** Select `alert` from the dropdown menu.
* **Protocol:** Select `ICMP` from the dropdown (this is more specific and better practice for pings than using IP).
* **Source:** Leave this as `any`.
* **Destination:** Leave this as `any`.
* **Description:** Type in the alert message you want to see:
```text
ICMP packet detected!

```


* **SID:** Enter a unique ID for your rule. Custom rules should start from 1000001 to avoid conflicts with official rules:
```text
1000001

```


* **Revision:** Set this to `1`.


3. Click the **Save** button at the bottom of the form. Your new rule will now appear in the list on the User-defined rules page.

#### Step 3: Apply the Changes

This is the most important and often forgotten step. Creating the rule doesn't make it active until you apply it.

1. After saving, you will see a blue/orange **Apply** button appear at the top right of the page.
2. Click the **Apply** button.
3. OPNsense will now reload the Suricata engine with your new custom rule included.

#### Verification

Now, you can test if your new rule is working exactly as described in the tutorial:

1. From your Kali VM, ping your DVWA VM:
```bash
ping 10.0.2.100

```


2. Go back to your OPNsense web interface.
3. Navigate to **Services** -> **Intrusion Detection** -> **Alerts**.
4. You should now see new entries in the alert log with your custom description: `"ICMP packet detected!"`.

---

### Part 6: Block Traffic with Firewall Rules

#### Create a Block Rule:

1. Go to **Firewall** -> **Rules** -> **LAN**.
2. Click the orange **+ Add** button:
* **Action:** Block
* **Protocol:** ICMP
* **Source:** LAN net
* **Destination:** SERVER net
* **Description:** Block Pings from LAN to SERVER


3. Click **Save**.

#### Order the Rules:

1. On the **Firewall** -> **Rules** -> **LAN** page, you will see your new Block rule and the previous Pass rule.
2. Firewall rules are processed from top to bottom. You must drag the Block rule so it is **ABOVE** the Pass rule.
3. Click **Apply Changes**.

#### Verify the Block:

1. From your Kali VM, try to ping the DVWA VM again.
2. The ping should now fail, confirming your firewall rule is working.

---

### Part 7: Create a Short Screencast Video and Submit

Record a short video demonstrating completion. Ensure it includes (refer to the tutorial sheet):

* **Network Setup:** Show the DVWA VM's terminal with the output of `ip a` to prove it received an IP from OPNsense.
* **OPNsense Interfaces:** Show the OPNsense dashboard, which displays the WAN, LAN, and SERVER interfaces and their IPs.
* **DVWA Access:** Show that you can open a browser in the DVWA VM and access its own web server (e.g., `http://10.0.2.100/DVWA/login.php`).
* **Ping Detection:**
* Temporarily disable the firewall block rule.
* Show `tcpdump` running on DVWA.
* Show the Suricata Alerts page in OPNsense.
* Ping DVWA from Kali and show the pings appearing in `tcpdump` and new alerts appearing in Suricata.


* **Ping Blocking:**
* Re-enable the firewall block rule (and ensure it's at the top).
* Show that pinging from Kali to DVWA now fails.



```
