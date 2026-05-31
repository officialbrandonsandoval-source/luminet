# Local-first network foundation

This project is intentionally local-first.

Long-term vision:
- Let people create independent, private, local networks with minimal dependence on cloud providers or traditional ISPs.
- Keep local services useful even when upstream internet is missing, degraded, surveilled, expensive, or intentionally disconnected.
- Treat internet sharing as an optional bridge, not the center of the system.

Current test posture:
- source_mode: interface
- upstream_interface: en0
- wifi_interface: en1
- active SSID: Luminet
- main subnet target: 192.168.77.0/24
- guest subnet target: 192.168.78.0/24

Why interface mode is current:
- macOS Internet Sharing is most likely to enable cleanly through System Settings when sharing from a real active upstream interface.
- en0 is currently connected and active, so it is the safest first proof test for AP creation, DHCP, client join, and monitoring.
- This does not change the project identity. Internet is allowed during the first test only as a bootstrap path.

Long-term preferred architecture:
1. Prove main Luminet AP + DHCP + client discovery using interface mode.
2. Prove local dashboard, local services, and device monitoring on the LAN.
3. Prove guest profile as a separate switchable SSID with pf restrictions.
4. Revisit loopback/local-only mode after main AP behavior is proven.
5. Add optional local services that do not require cloud:
   - local web dashboard
   - local file drop
   - local DNS naming
   - local AI service endpoints
   - local status/beacon page
   - emergency offline docs
6. Treat upstream internet as a toggleable capability:
   - online bridge when needed
   - offline LAN when preferred
   - no public exposure by default

Safety rules:
- No open Wi-Fi.
- No cloud dependency for dashboard or monitoring.
- No public service exposure by default.
- Exact confirmation tokens required for network mutation.
- Secrets stay in chmod 600 config and are redacted by default.
- Guest firewall rules are prepared but should not be applied until main network behavior is verified.

Next validation milestone:
- Manually enable Internet Sharing for Luminet in System Settings.
- Connect one client.
- Verify status, leases/ARP, dashboard, and monitor output.
- Only after that, prepare a separate guest-mode test.
