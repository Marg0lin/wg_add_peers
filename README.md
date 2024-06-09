## WireGuard Peer Configuration Script for pfSense
A quick and dirty PHP script to add peers to Wireguard on pfSense and generate config files to setup tunnels.

This script automates the process of adding a new WireGuard peer on pfSense, generating the necessary keys, updating the server configuration, and creating a client configuration file.

Manual setup of tunnels between peers can be quite tedious and time-consuming, especially if you need to configure more than one connection. To simplify this process, here we are with a PHP script that, when run from the SSH console, uses pfSense mechanisms to modify the Wireguard module configuration. This script automates the process of adding new peers to existing WireGuard tunnels, generating private and public keys for the new peer, updating the server configuration, creating a client configuration file, and restarting the WireGuard service to apply the changes.

## What this script does:

1. **Key Generation:** The script generates a private and public key for the new peer.
2. **Configuration Update:** Adds the new peer to the selected WireGuard tunnel in the pfSense configuration.
3. **Configuration File Generation:** Creates a configuration file for the client that can be used to set up the connection on the endpoint device.
4. **Service Restart:** Automatically restarts the WireGuard service on pfSense to apply the changes.
5. **DNS Settings Retrieval:** Fetches DNS servers from the `resolv.conf` file and adds them to the client configuration.

## Instructions for Use

### Step 1: Save the Script

Save the script as `generate_wg_peer.php` in the directory `/usr/local/www/`.

### Step 2: Set Permissions

Ensure the script has executable permissions:
```sh
chmod +x /usr/local/www/wg_add_peers.php
```

## PHP Script: `wg_add_peers.php`

```php
#!/usr/local/bin/php
<?php
require_once("/etc/inc/config.inc");
require_once("/etc/inc/config.gui.inc");

// Function to generate WireGuard private and public keys
function generate_wireguard_keys() {
    $private_key = trim(shell_exec("wg genkey"));
    $public_key = trim(shell_exec("echo $private_key | wg pubkey"));
    return array('private_key' => $private_key, 'public_key' => $public_key);
}

// Function to read data from prompt
function prompt($message) {
    echo $message . ": ";
    return trim(fgets(STDIN));
}

// Function to fetch DNS servers from resolv.conf
function fetch_dns_servers() {
    $dns_servers = [];
    $resolv_conf = file_get_contents('/etc/resolv.conf');
    if ($resolv_conf !== false) {
        $start = strpos($resolv_conf, '# wireguard_hosts');
        $end = strpos($resolv_conf, '# end_wireguard');
        if ($start !== false && $end !== false) {
            $dns_block = substr($resolv_conf, $start, $end - $start);
            preg_match_all('/^nameserver\s+([^\s]+)$/m', $dns_block, $matches);
            if (!empty($matches[1])) {
                $dns_servers = $matches[1];
            }
        }
    }
    return implode(',', $dns_servers);
}

// Function to generate client configuration file
function generate_client_config($peer_name, $private_key, $server_public_key, $server_ip, $peer_ip, $dns_servers, $allowed_ips) {
    $config = <<<EOL
[Interface]
PrivateKey = $private_key
Address = $peer_ip
DNS = $dns_servers

[Peer]
PublicKey = $server_public_key
Endpoint = $server_ip:443
AllowedIPs = $allowed_ips
PersistentKeepalive = 25
EOL;

    $file_path = "/root/wg_peers_configs/{$peer_name}_wg0.conf";
    file_put_contents($file_path, $config);
    return $file_path;
}

// Function to calculate subnet address
function calculate_subnet_address($ip, $mask) {
    $ip_bin = ip2long($ip);
    $mask_bin = ~((1 << (32 - $mask)) - 1);
    $subnet_bin = $ip_bin & $mask_bin;
    return long2ip($subnet_bin) . '/' . $mask;
}

// Function to get LAN subnets
function get_lan_subnets() {
    global $config;
    $lan_subnets = [];
    if (isset($config['interfaces'])) {
        foreach ($config['interfaces'] as $interface) {
            if (isset($interface['ipaddr']) && $interface['ipaddr'] != 'dhcp' && isset($interface['subnet'])) {
                $lan_subnets[] = calculate_subnet_address($interface['ipaddr'], $interface['subnet']);
            }
        }
    }
    return $lan_subnets;
}

// Function to restart WireGuard service
function restart_wireguard() {
    mwexec('/usr/local/etc/rc.d/wireguard restart', true);
}

// Load global pfSense configuration
global $config;

// Check if WireGuard configuration exists
if (!isset($config['installedpackages']['wireguard']) || !is_array($config['installedpackages']['wireguard'])) {
    echo "No WireGuard configuration found.\n";
    exit(1);
}

// Get WireGuard configuration
$wg_config = &$config['installedpackages']['wireguard'];

// Check if there are any WireGuard tunnels
if (!isset($wg_config['tunnels']['item']) || !is_array($wg_config['tunnels']['item'])) {
    echo "No WireGuard tunnels found.\n";
    exit(1);
}

// Display available tunnels
echo "Available WireGuard interfaces:\n";
foreach ($wg_config['tunnels']['item'] as $idx => $tunnel) {
    echo ($idx + 1) . ") " . $tunnel['name'] . " - " . $tunnel['descr'] . "\n";
}

// Get tunnel number from prompt
$tunnel_index = prompt("Select interface (enter number)");

if (!is_numeric($tunnel_index) || $tunnel_index < 1 || $tunnel_index > count($wg_config['tunnels']['item'])) {
    echo "Invalid selection\n";
    exit(1);
}

$tunnel_index--;  // Convert number to array index
$selected_tunnel = &$wg_config['tunnels']['item'][$tunnel_index];

// Get peer data from prompt
$peer_name = prompt("Enter peer name");
$peer_ip = prompt("Enter peer IP (e.g., 10.10.98.2/32)");

if (empty($peer_name) || empty($peer_ip)) {
    echo "Invalid input. Please provide all required information.\n";
    exit(1);
}

// Display available LAN networks
$lan_subnets = get_lan_subnets();
echo "Available LAN networks:\n";
foreach ($lan_subnets as $idx => $subnet) {
    echo ($idx + 1) . ") " . $subnet . "\n";
}
echo (count($lan_subnets) + 1) . ") All\n";

// Get allowed networks from prompt
$subnet_index = prompt("Select network (enter number)");
if (!is_numeric($subnet_index) || $subnet_index < 1 || $subnet_index > (count($lan_subnets) + 1)) {
    echo "Invalid selection\n";
    exit(1);
}

if ($subnet_index == count($lan_subnets) + 1) {
    // Select all networks
    $allowed_ips = $lan_subnets;
} else {
    // Select single network
    $allowed_ips = [$lan_subnets[$subnet_index - 1]];
}

// Add WireGuard interface address to allowed IPs
$tunnel_ip = $selected_tunnel['addresses'];
$allowed_ips[] = $tunnel_ip;

$allowed_ips_str = implode(',', $allowed_ips);

// Generate keys for new peer
$keys = generate_wireguard_keys();
$private_key = $keys['private_key'];
$public_key = $keys['public_key'];

// Get server public key
$server_public_key = $selected_tunnel['publickey'];

// Get server WAN IP
$wan_interface = get_interface_ip('wan');

// Add new peer to tunnel
$new_peer = array(
    'allowedips' => array(
        'row' => array(
            array(
                'address' => explode('/', $peer_ip)[0],
                'mask' => '32',
                'descr' => "Added by script"
            )
        )
    ),
    'enabled' => 'yes',
    'tun' => $selected_tunnel['name'],
    'descr' => $peer_name,
    'persistentkeepalive' => 25,
    'publickey' => $public_key,
    'presharedkey' => '',
);

// Add new peer to WireGuard configuration
if (!isset($wg_config['peers']['item'])) {
    $wg_config['peers']['item'] = array();
}
$wg_config['peers']['item'][] = $new_peer;

// Debug: Display new peer configuration
echo "Added new peer:\n";
echo "Private Key (Client): $private_key\n";
echo "Public Key (Client): $public_key\n";
echo "Public Key (Server): $server_public_key\n";

// Save configuration
write_config("Added WireGuard peer $peer_name to tunnel " . $selected_tunnel['name']);

// Restart WireGuard service
restart_wireguard();

// Fetch DNS servers from resolv.conf
$dns_servers = fetch_dns_servers();

// Generate client configuration file
$config_file_path = generate_client_config($peer_name, $private_key, $server_public_key, $wan_interface, $peer_ip, $dns_servers, $allowed_ips_str);

echo "Peer $peer_name added to tunnel " . $selected_tunnel['name'] . "\n";
echo "Private Key: $private_key\n";
echo "Client configuration file saved to: $config_file_path\n";
?>
```
