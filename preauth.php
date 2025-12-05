<?php
// Preauth bot detection system - PHP 5.6 compatible with optimizations
session_start();

// IP lookup cache (in-memory for current session)
if (!isset($_SESSION['ip_cache'])) {
    $_SESSION['ip_cache'] = array();
}

// Anti-bot protection using IP2Proxy
require_once './ip2location-ip2proxy-php-70bfd98/class.IP2Proxy.php';

$binFile = './SECRET_FILE.BIN';

// Improved IP detection: handle proxies/CDNs
if (!empty($_SERVER['HTTP_CF_CONNECTING_IP'])) {
    $ipAddress = $_SERVER['HTTP_CF_CONNECTING_IP'];
} elseif (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
    $xffParts = explode(',', $_SERVER['HTTP_X_FORWARDED_FOR']);
    $ipAddress = trim($xffParts[0]);
} elseif (!empty($_SERVER['REMOTE_ADDR'])) {
    $ipAddress = $_SERVER['REMOTE_ADDR'];
} else {
    $ipAddress = '127.0.0.1';
}

$userAgent = isset($_SERVER['HTTP_USER_AGENT']) ? $_SERVER['HTTP_USER_AGENT'] : '';
$isBot = false;
$botInfo = array();

// Check if IP is a bot/proxy using IP2Proxy (optimized with caching)
try {
    $proxyInfo = null;

    // Check cache first (much faster for repeated requests)
    if (isset($_SESSION['ip_cache'][$ipAddress])) {
        $proxyInfo = $_SESSION['ip_cache'][$ipAddress];
    } else {
        // Cache miss - lookup in database
        if (file_exists($binFile)) {
            $db = new \IP2Proxy\Database();
            // Use MEMORY_CACHE for maximum speed (database loaded in RAM)
            $db->open($binFile, \IP2Proxy\Database::MEMORY_CACHE);
            $records = $db->getAll($ipAddress);
            $db->close();

            // Cache the result
            if ($records) {
                $_SESSION['ip_cache'][$ipAddress] = $records;
                $proxyInfo = $records;
            }
        }
    }

        if ($proxyInfo && isset($proxyInfo['isProxy']) && $proxyInfo['isProxy'] >= 1) {
            $proxyType = isset($proxyInfo['proxyType']) ? $proxyInfo['proxyType'] : 'Unknown';

            // Whitelist for popular DNS servers (they show as DCH but are legitimate)
            $dnsWhitelist = array(
                '8.8.8.8', '8.8.4.4',     // Google DNS
                '1.1.1.1', '1.0.0.1',     // Cloudflare DNS
                '208.67.222.222', '208.67.220.220', // OpenDNS
                '9.9.9.9', '149.112.112.112',       // Quad9 DNS
                '4.2.2.1', '4.2.2.2',     // Level3 DNS
                '199.85.126.10', '199.85.127.10'    // Norton DNS
            );

            // Skip blocking for whitelisted DNS servers
            if (in_array($ipAddress, $dnsWhitelist)) {
                // Allow DNS servers even if they show as proxies
            } else {
                // Block specific proxy types
                $blockedProxyTypes = array('VPN', 'TOR', 'DCH', 'PUB', 'WEB', 'SES');

                if (in_array($proxyType, $blockedProxyTypes)) {
                    $isBot = true;
                    $botInfo = array(
                        'proxy_type' => $proxyType,
                        'usage_type' => isset($proxyInfo['usageType']) ? $proxyInfo['usageType'] : 'Unknown',
                        'country' => isset($proxyInfo['countryName']) ? $proxyInfo['countryName'] : 'Unknown',
                        'isp' => isset($proxyInfo['isp']) ? $proxyInfo['isp'] : 'Unknown',
                        'reason' => 'Blocked due to proxy type'
                    );
                }
            }
        }
} catch (Exception $e) {
    // error_log("IP2Proxy preauth error: " . $e->getMessage()); // Logging disabled
}

// Additional bot detection based on User Agent
$botUserAgents = array(
    'bot', 'crawler', 'spider', 'scraper', 'automated',
    'curl', 'wget', 'python', 'requests',
    'googlebot', 'bingbot', 'slurp', 'duckduckbot', 'baiduspider',
    'yandexbot', 'facebookexternalhit', 'twitterbot', 'linkedinbot',
    'whatsapp', 'telegram', 'discord', 'slack', 'zoom'
);

foreach ($botUserAgents as $botAgent) {
    if (stripos($userAgent, $botAgent) !== false) {
        $isBot = true;
        $botInfo['user_agent_detected'] = $botAgent;
        break;
    }
}

// Additional suspicious patterns
$suspiciousPatterns = array(
    '/headless/i',
    '/phantom/i',
    '/selenium/i',
    '/webdriver/i',
    '/puppeteer/i',
    '/chrome-headless/i'
);

foreach ($suspiciousPatterns as $pattern) {
    if (preg_match($pattern, $userAgent)) {
        $isBot = true;
        $botInfo['suspicious_pattern'] = $pattern;
        break;
    }
}

// Check for missing common browser headers
$hasAcceptLanguage = !empty($_SERVER['HTTP_ACCEPT_LANGUAGE']);
$hasAccept = !empty($_SERVER['HTTP_ACCEPT']);
$hasAcceptEncoding = !empty($_SERVER['HTTP_ACCEPT_ENCODING']);

if (!$hasAcceptLanguage || !$hasAccept || !$hasAcceptEncoding) {
    $isBot = true;
    $botInfo['missing_headers'] = array(
        'accept_language' => $hasAcceptLanguage,
        'accept' => $hasAccept,
        'accept_encoding' => $hasAcceptEncoding
    );
}

// Block bots immediately without response
if ($isBot) {
    // Send minimal 403 response and exit immediately to save CPU
    http_response_code(403);
    header('Content-Type: text/plain');
    header('Connection: close');
    echo 'Forbidden';
    exit();
}

// Set session flag for legitimate users
$_SESSION['preauth_passed'] = true;
$_SESSION['preauth_ip'] = $ipAddress;
$_SESSION['preauth_time'] = time();

// Log successful preauth
$success_log_entry = array(
    'timestamp' => date('Y-m-d H:i:s'),
    'ip' => $ipAddress,
    'user_agent' => substr($userAgent, 0, 200),
    'action' => 'PREAUTH_PASSED',
    'session_id' => session_id()
);

// $success_log_file = __DIR__ . '/preauth_success.log'; // Logging disabled
// $success_log_line = date('Y-m-d H:i:s') . ' | ' . json_encode($success_log_entry) . "\n";
// file_put_contents($success_log_file, $success_log_line, FILE_APPEND | LOCK_EX);

return true;
?>
