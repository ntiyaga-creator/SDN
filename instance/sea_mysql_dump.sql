-- MySQL-compatible dump generated from SQLite instance/sea.db
SET NAMES utf8mb4;
SET FOREIGN_KEY_CHECKS = 0;

DROP TABLE IF EXISTS `alerts`;
DROP TABLE IF EXISTS `logs`;
DROP TABLE IF EXISTS `policies`;
DROP TABLE IF EXISTS `roles`;
DROP TABLE IF EXISTS `settings`;
DROP TABLE IF EXISTS `users`;

CREATE TABLE `alerts` (
  `id` VARCHAR(40) NOT NULL,
  `timestamp` VARCHAR(40) NOT NULL,
  `message` VARCHAR(500) NOT NULL,
  `severity` VARCHAR(20) NOT NULL,
  `source_ip` VARCHAR(50) NOT NULL,
  `destination_ip` VARCHAR(50) NOT NULL,
  `mitigated` INT,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE `logs` (
  `id` INT NOT NULL,
  `timestamp` VARCHAR(40) NOT NULL,
  `level` VARCHAR(10) NOT NULL,
  `message` VARCHAR(1000) NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE `policies` (
  `id` VARCHAR(50) NOT NULL,
  `name` VARCHAR(200),
  `description` VARCHAR(500),
  `action` VARCHAR(20) NOT NULL,
  `priority` INT,
  `enabled` INT,
  `match_json` TEXT,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE `roles` (
  `id` INT NOT NULL,
  `name` VARCHAR(50) NOT NULL,
  `description` VARCHAR(200),
  `permissions` TEXT,
  `is_builtin` INT,
  PRIMARY KEY (`id`), UNIQUE KEY `uq_roles_name` (`name`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE `settings` (
  `key` VARCHAR(100) NOT NULL,
  `value` VARCHAR(500) NOT NULL,
  PRIMARY KEY (`key`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE `users` (
  `id` INT NOT NULL,
  `username` VARCHAR(80) NOT NULL,
  `password` VARCHAR(200) NOT NULL,
  `created_at` VARCHAR(40) NOT NULL,
  `role_id` INT DEFAULT 1,
  PRIMARY KEY (`id`), UNIQUE KEY `uq_users_username` (`username`), KEY `fk_users_role_id` (`role_id`), CONSTRAINT `fk_users_role_id_ref_roles_id` FOREIGN KEY (`role_id`) REFERENCES `roles` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Data for table `alerts`
INSERT INTO `alerts` (`id`,`timestamp`,`message`,`severity`,`source_ip`,`destination_ip`,`mitigated`) VALUES ('adf4e617-91b4-47a7-8e83-16957502fc40', '2026-06-16T20:26:36.933679+00:00', 'Suspicious traffic pattern detected', 'MEDIUM', '10.0.0.10', '8.8.8.1', '0');

-- Data for table `logs`
INSERT INTO `logs` (`id`,`timestamp`,`level`,`message`) VALUES ('1', '2026-05-21T09:56:01.817056+00:00', 'INFO', 'Admin login: admin');
INSERT INTO `logs` (`id`,`timestamp`,`level`,`message`) VALUES ('2', '2026-05-21T09:57:53.400961+00:00', 'INFO', 'SEA Application starting with SQLite database...');
INSERT INTO `logs` (`id`,`timestamp`,`level`,`message`) VALUES ('3', '2026-05-21T09:57:55.793908+00:00', 'WARN', 'Ryu controller not reachable, running in standalone mode');
INSERT INTO `logs` (`id`,`timestamp`,`level`,`message`) VALUES ('4', '2026-05-21T09:58:09.917986+00:00', 'INFO', 'SEA Application starting with SQLite database...');
INSERT INTO `logs` (`id`,`timestamp`,`level`,`message`) VALUES ('5', '2026-05-21T09:58:12.002710+00:00', 'WARN', 'Ryu controller not reachable, running in standalone mode');
INSERT INTO `logs` (`id`,`timestamp`,`level`,`message`) VALUES ('6', '2026-05-21T09:59:31.403731+00:00', 'INFO', 'SEA Application starting with SQLite database...');
INSERT INTO `logs` (`id`,`timestamp`,`level`,`message`) VALUES ('7', '2026-05-21T09:59:33.547387+00:00', 'WARN', 'Ryu controller not reachable, running in standalone mode');
INSERT INTO `logs` (`id`,`timestamp`,`level`,`message`) VALUES ('8', '2026-05-21T10:05:01.256992+00:00', 'INFO', 'SEA Application starting with SQLite database...');
INSERT INTO `logs` (`id`,`timestamp`,`level`,`message`) VALUES ('9', '2026-05-21T10:05:03.310474+00:00', 'WARN', 'Ryu controller not reachable, running in standalone mode');
INSERT INTO `logs` (`id`,`timestamp`,`level`,`message`) VALUES ('10', '2026-05-21T10:08:29.457786+00:00', 'INFO', 'Admin login: admin');
INSERT INTO `logs` (`id`,`timestamp`,`level`,`message`) VALUES ('11', '2026-06-15T18:19:02.780754+00:00', 'INFO', 'Admin login: admin');
INSERT INTO `logs` (`id`,`timestamp`,`level`,`message`) VALUES ('12', '2026-06-15T18:30:11.117001+00:00', 'INFO', 'Login: admin (admin)');
INSERT INTO `logs` (`id`,`timestamp`,`level`,`message`) VALUES ('13', '2026-06-15T18:30:11.258382+00:00', 'INFO', 'User created: analyst1');
INSERT INTO `logs` (`id`,`timestamp`,`level`,`message`) VALUES ('14', '2026-06-15T18:30:11.594624+00:00', 'INFO', 'User created: viewer1');
INSERT INTO `logs` (`id`,`timestamp`,`level`,`message`) VALUES ('15', '2026-06-15T18:30:11.672597+00:00', 'INFO', 'Login: viewer1 (viewer)');
INSERT INTO `logs` (`id`,`timestamp`,`level`,`message`) VALUES ('16', '2026-06-15T18:30:11.758376+00:00', 'INFO', 'All alerts cleared');
INSERT INTO `logs` (`id`,`timestamp`,`level`,`message`) VALUES ('17', '2026-06-15T18:30:11.858180+00:00', 'INFO', 'Imported 2 policies');
INSERT INTO `logs` (`id`,`timestamp`,`level`,`message`) VALUES ('18', '2026-06-15T18:30:11.961317+00:00', 'INFO', 'Imported 1 roles');
INSERT INTO `logs` (`id`,`timestamp`,`level`,`message`) VALUES ('19', '2026-06-15T18:30:12.098136+00:00', 'INFO', 'User deleted: viewer1');
INSERT INTO `logs` (`id`,`timestamp`,`level`,`message`) VALUES ('20', '2026-06-15T18:30:48.957681+00:00', 'INFO', 'Login: admin (admin)');
INSERT INTO `logs` (`id`,`timestamp`,`level`,`message`) VALUES ('21', '2026-06-15T18:30:49.037880+00:00', 'INFO', 'User created: testuser');
INSERT INTO `logs` (`id`,`timestamp`,`level`,`message`) VALUES ('22', '2026-06-15T18:30:49.101119+00:00', 'INFO', 'Login: testuser (analyst)');
INSERT INTO `logs` (`id`,`timestamp`,`level`,`message`) VALUES ('23', '2026-06-15T18:30:49.149362+00:00', 'INFO', 'All alerts cleared');
INSERT INTO `logs` (`id`,`timestamp`,`level`,`message`) VALUES ('24', '2026-06-15T18:36:40.197667+00:00', 'INFO', 'Login: admin (admin)');
INSERT INTO `logs` (`id`,`timestamp`,`level`,`message`) VALUES ('25', '2026-06-15T18:37:57.962591+00:00', 'INFO', 'Login: admin (admin)');
INSERT INTO `logs` (`id`,`timestamp`,`level`,`message`) VALUES ('26', '2026-06-15T18:37:58.034243+00:00', 'INFO', 'User created: viewer1');
INSERT INTO `logs` (`id`,`timestamp`,`level`,`message`) VALUES ('27', '2026-06-15T18:37:58.086309+00:00', 'INFO', 'Login: viewer1 (viewer)');
INSERT INTO `logs` (`id`,`timestamp`,`level`,`message`) VALUES ('28', '2026-06-15T18:37:58.147376+00:00', 'INFO', 'Login: analyst1 (analyst)');
INSERT INTO `logs` (`id`,`timestamp`,`level`,`message`) VALUES ('29', '2026-06-15T18:37:58.234275+00:00', 'INFO', 'Imported 2 policies');
INSERT INTO `logs` (`id`,`timestamp`,`level`,`message`) VALUES ('30', '2026-06-15T18:37:58.284789+00:00', 'INFO', 'Imported 1 roles');
INSERT INTO `logs` (`id`,`timestamp`,`level`,`message`) VALUES ('31', '2026-06-15T18:37:58.350907+00:00', 'INFO', 'User deleted: viewer1');
INSERT INTO `logs` (`id`,`timestamp`,`level`,`message`) VALUES ('32', '2026-06-15T18:38:31.183655+00:00', 'INFO', 'Login: admin (admin)');
INSERT INTO `logs` (`id`,`timestamp`,`level`,`message`) VALUES ('33', '2026-06-15T18:38:31.264398+00:00', 'INFO', 'User created: viewer1');
INSERT INTO `logs` (`id`,`timestamp`,`level`,`message`) VALUES ('34', '2026-06-15T18:38:31.300213+00:00', 'INFO', 'Login: viewer1 (viewer)');
INSERT INTO `logs` (`id`,`timestamp`,`level`,`message`) VALUES ('35', '2026-06-15T18:38:31.365980+00:00', 'INFO', 'Login: analyst1 (analyst)');
INSERT INTO `logs` (`id`,`timestamp`,`level`,`message`) VALUES ('36', '2026-06-15T18:38:31.444554+00:00', 'INFO', 'Imported 2 policies');
INSERT INTO `logs` (`id`,`timestamp`,`level`,`message`) VALUES ('37', '2026-06-15T18:38:31.479815+00:00', 'INFO', 'Imported 1 roles');
INSERT INTO `logs` (`id`,`timestamp`,`level`,`message`) VALUES ('38', '2026-06-15T18:38:31.542623+00:00', 'INFO', 'User deleted: viewer1');
INSERT INTO `logs` (`id`,`timestamp`,`level`,`message`) VALUES ('39', '2026-06-15T18:38:51.039934+00:00', 'INFO', 'Login: admin (admin)');
INSERT INTO `logs` (`id`,`timestamp`,`level`,`message`) VALUES ('40', '2026-06-15T18:38:51.142098+00:00', 'INFO', 'User created: viewer1');
INSERT INTO `logs` (`id`,`timestamp`,`level`,`message`) VALUES ('41', '2026-06-15T18:39:50.556573+00:00', 'INFO', 'Login: admin (admin)');
INSERT INTO `logs` (`id`,`timestamp`,`level`,`message`) VALUES ('42', '2026-06-15T18:39:50.648787+00:00', 'INFO', 'User created: test123');
INSERT INTO `logs` (`id`,`timestamp`,`level`,`message`) VALUES ('43', '2026-06-16T19:41:55.432236+00:00', 'INFO', 'SEA Application starting with SQLite database...');
INSERT INTO `logs` (`id`,`timestamp`,`level`,`message`) VALUES ('44', '2026-06-16T19:41:58.409608+00:00', 'WARN', 'Ryu controller not reachable, running in standalone mode');
INSERT INTO `logs` (`id`,`timestamp`,`level`,`message`) VALUES ('45', '2026-06-16T19:41:59.065122+00:00', 'INFO', 'Loaded admin user, 18 active policies');
INSERT INTO `logs` (`id`,`timestamp`,`level`,`message`) VALUES ('46', '2026-06-16T19:43:04.171465+00:00', 'INFO', 'SEA Application starting with SQLite database...');
INSERT INTO `logs` (`id`,`timestamp`,`level`,`message`) VALUES ('47', '2026-06-16T19:43:06.922499+00:00', 'WARN', 'Ryu controller not reachable, running in standalone mode');
INSERT INTO `logs` (`id`,`timestamp`,`level`,`message`) VALUES ('48', '2026-06-16T19:43:07.844282+00:00', 'INFO', 'Loaded admin user, 18 active policies');
INSERT INTO `logs` (`id`,`timestamp`,`level`,`message`) VALUES ('49', '2026-06-16T19:45:18.374597+00:00', 'INFO', 'SEA Application starting with SQLite database...');
INSERT INTO `logs` (`id`,`timestamp`,`level`,`message`) VALUES ('50', '2026-06-16T19:45:20.641493+00:00', 'WARN', 'Ryu controller not reachable, running in standalone mode');
INSERT INTO `logs` (`id`,`timestamp`,`level`,`message`) VALUES ('51', '2026-06-16T19:45:20.791317+00:00', 'INFO', 'Loaded admin user, 18 active policies');
INSERT INTO `logs` (`id`,`timestamp`,`level`,`message`) VALUES ('52', '2026-06-16T19:45:43.146187+00:00', 'INFO', 'SEA Application starting with SQLite database...');
INSERT INTO `logs` (`id`,`timestamp`,`level`,`message`) VALUES ('53', '2026-06-16T19:45:45.355846+00:00', 'WARN', 'Ryu controller not reachable, running in standalone mode');
INSERT INTO `logs` (`id`,`timestamp`,`level`,`message`) VALUES ('54', '2026-06-16T19:45:45.512789+00:00', 'INFO', 'Loaded admin user, 18 active policies');
INSERT INTO `logs` (`id`,`timestamp`,`level`,`message`) VALUES ('55', '2026-06-16T19:46:06.469957+00:00', 'INFO', 'Login: admin (admin)');
INSERT INTO `logs` (`id`,`timestamp`,`level`,`message`) VALUES ('56', '2026-06-16T19:49:03.083556+00:00', 'INFO', 'All alerts cleared');
INSERT INTO `logs` (`id`,`timestamp`,`level`,`message`) VALUES ('57', '2026-06-16T19:49:33.040832+00:00', 'INFO', 'Admin logout: admin');
INSERT INTO `logs` (`id`,`timestamp`,`level`,`message`) VALUES ('58', '2026-06-16T20:25:58.851553+00:00', 'INFO', 'SEA Application starting with SQLite database...');
INSERT INTO `logs` (`id`,`timestamp`,`level`,`message`) VALUES ('59', '2026-06-16T20:26:00.947507+00:00', 'WARN', 'Ryu controller not reachable, running in standalone mode');
INSERT INTO `logs` (`id`,`timestamp`,`level`,`message`) VALUES ('60', '2026-06-16T20:26:00.965014+00:00', 'INFO', 'Loaded admin user, 18 active policies');

-- Data for table `policies`
INSERT INTO `policies` (`id`,`name`,`description`,`action`,`priority`,`enabled`,`match_json`) VALUES ('policy_c0c6c3e6', 'DDoS Mitigation', 'Block traffic from IPs exceeding DDoS threshold', 'BLOCK', '100', '1', '{"eth_type": 2048}');
INSERT INTO `policies` (`id`,`name`,`description`,`action`,`priority`,`enabled`,`match_json`) VALUES ('policy_394b745d', 'ICMP Flood Protection', 'Rate-limit ICMP echo requests to prevent ping flood', 'RATE_LIMIT', '95', '1', '{"eth_type": 2048, "ip_proto": 1}');
INSERT INTO `policies` (`id`,`name`,`description`,`action`,`priority`,`enabled`,`match_json`) VALUES ('policy_8215707a', 'Host Isolation', 'Isolate compromised hosts from network traffic', 'ISOLATE', '90', '0', '{}');
INSERT INTO `policies` (`id`,`name`,`description`,`action`,`priority`,`enabled`,`match_json`) VALUES ('policy_52bcd740', 'Port Scan Prevention', 'Block IPs scanning more than 20 ports in 2 seconds', 'BLOCK', '98', '1', '{"eth_type": 2048}');
INSERT INTO `policies` (`id`,`name`,`description`,`action`,`priority`,`enabled`,`match_json`) VALUES ('policy_8575eb55', 'SYN Flood Protection', 'Drop excessive TCP SYN packets', 'DROP', '97', '1', '{"eth_type": 2048, "ip_proto": 6, "tcp_flags": 2}');
INSERT INTO `policies` (`id`,`name`,`description`,`action`,`priority`,`enabled`,`match_json`) VALUES ('policy_83e9655f', 'Traffic Mirroring', 'Redirect suspicious traffic to monitoring/honeypot port', 'REDIRECT', '85', '0', '{}');
INSERT INTO `policies` (`id`,`name`,`description`,`action`,`priority`,`enabled`,`match_json`) VALUES ('policy_4a10134c', 'Malware Containment', 'Quarantine hosts exhibiting malware-like behavior', 'QUARANTINE', '92', '0', '{}');
INSERT INTO `policies` (`id`,`name`,`description`,`action`,`priority`,`enabled`,`match_json`) VALUES ('policy_9b4af571', 'Known Malicious IPs', 'Block traffic from blacklisted IP addresses', 'BLOCK', '99', '1', '{"eth_type": 2048}');
INSERT INTO `policies` (`id`,`name`,`description`,`action`,`priority`,`enabled`,`match_json`) VALUES ('policy_ec749a31', 'DNS Amplification Protection', 'Rate-limit DNS responses to prevent amplification attacks', 'RATE_LIMIT', '93', '1', '{"eth_type": 2048, "ip_proto": 17, "udp_dst": 53}');
INSERT INTO `policies` (`id`,`name`,`description`,`action`,`priority`,`enabled`,`match_json`) VALUES ('policy_753188cd', 'Suspicious Traffic Logging', 'Log all traffic matching suspicious patterns for analysis', 'LOG_ONLY', '80', '1', '{}');
INSERT INTO `policies` (`id`,`name`,`description`,`action`,`priority`,`enabled`,`match_json`) VALUES ('policy_57fb5632', 'ARP Spoofing Detection', 'Generate alert on ARP cache poisoning attempts', 'ALERT', '88', '1', '{"eth_type": 2054}');
INSERT INTO `policies` (`id`,`name`,`description`,`action`,`priority`,`enabled`,`match_json`) VALUES ('policy_38addef1', 'Invalid TCP Flags', 'Drop packets with invalid TCP flag combinations', 'DROP', '96', '1', '{"eth_type": 2048, "ip_proto": 6}');
INSERT INTO `policies` (`id`,`name`,`description`,`action`,`priority`,`enabled`,`match_json`) VALUES ('policy_121e5882', 'UDP Flood Protection', 'Rate-limit UDP traffic to prevent UDP flood attacks', 'RATE_LIMIT', '94', '1', '{"eth_type": 2048, "ip_proto": 17}');
INSERT INTO `policies` (`id`,`name`,`description`,`action`,`priority`,`enabled`,`match_json`) VALUES ('policy_ebde7977', 'Spoofed IP Protection', 'Block traffic from internal IP ranges on external interfaces', 'BLOCK', '99', '1', '{"eth_type": 2048}');
INSERT INTO `policies` (`id`,`name`,`description`,`action`,`priority`,`enabled`,`match_json`) VALUES ('policy_45a3d5ab', 'Rogue DHCP Server', 'Isolate unauthorized DHCP servers on the network', 'ISOLATE', '91', '1', '{"eth_type": 2048, "udp_src": 67}');
INSERT INTO `policies` (`id`,`name`,`description`,`action`,`priority`,`enabled`,`match_json`) VALUES ('policy_f2e0a6df', 'Test Policy 1', '', 'BLOCK', '50', '1', '{"eth_type": 2048}');
INSERT INTO `policies` (`id`,`name`,`description`,`action`,`priority`,`enabled`,`match_json`) VALUES ('policy_6f1701d7', 'Test Policy 2', '', 'LOG_ONLY', '40', '1', '{}');
INSERT INTO `policies` (`id`,`name`,`description`,`action`,`priority`,`enabled`,`match_json`) VALUES ('policy_bfc15db0', 'Test Policy 1', '', 'BLOCK', '50', '1', '{"eth_type": 2048}');
INSERT INTO `policies` (`id`,`name`,`description`,`action`,`priority`,`enabled`,`match_json`) VALUES ('policy_c479c90d', 'Test Policy 2', '', 'LOG_ONLY', '40', '1', '{}');
INSERT INTO `policies` (`id`,`name`,`description`,`action`,`priority`,`enabled`,`match_json`) VALUES ('policy_2f61c988', 'Test Policy 1', '', 'BLOCK', '50', '1', '{"eth_type": 2048}');
INSERT INTO `policies` (`id`,`name`,`description`,`action`,`priority`,`enabled`,`match_json`) VALUES ('policy_1b7f65b5', 'Test Policy 2', '', 'LOG_ONLY', '40', '1', '{}');

-- Data for table `roles`
INSERT INTO `roles` (`id`,`name`,`description`,`permissions`,`is_builtin`) VALUES ('1', 'admin', 'Full system access', '["alerts.view", "alerts.mitigate", "alerts.clear", "alerts.export", "policies.view", "policies.create", "policies.edit", "policies.delete", "policies.import", "stats.view", "topology.view", "logs.view", "logs.download", "settings.view", "settings.edit", "users.view", "users.create", "users.delete", "roles.view", "roles.import"]', '1');
INSERT INTO `roles` (`id`,`name`,`description`,`permissions`,`is_builtin`) VALUES ('2', 'analyst', 'Monitor alerts and apply mitigations', '["alerts.view", "alerts.mitigate", "alerts.export", "policies.view", "stats.view", "topology.view", "logs.view", "settings.view"]', '1');
INSERT INTO `roles` (`id`,`name`,`description`,`permissions`,`is_builtin`) VALUES ('3', 'viewer', 'Read-only access to dashboard', '["alerts.view", "policies.view", "stats.view", "topology.view", "logs.view"]', '1');
INSERT INTO `roles` (`id`,`name`,`description`,`permissions`,`is_builtin`) VALUES ('4', 'custom_role', 'Test role', '["alerts.view", "stats.view"]', '0');

-- Data for table `settings`
INSERT INTO `settings` (`key`,`value`) VALUES ('packet_rate', '1000');
INSERT INTO `settings` (`key`,`value`) VALUES ('byte_rate', '1000000');
INSERT INTO `settings` (`key`,`value`) VALUES ('ddos_packets', '10000');

-- Data for table `users`
INSERT INTO `users` (`id`,`username`,`password`,`created_at`,`role_id`) VALUES ('1', 'admin', 'ntiyaga@1234', '2026-05-21T09:55:38.808916+00:00', '1');
INSERT INTO `users` (`id`,`username`,`password`,`created_at`,`role_id`) VALUES ('2', 'analyst1', 'test1234', '2026-06-15T18:30:11.243017+00:00', '2');
INSERT INTO `users` (`id`,`username`,`password`,`created_at`,`role_id`) VALUES ('3', 'testuser', 'test1234', '2026-06-15T18:30:49.018610+00:00', '2');
INSERT INTO `users` (`id`,`username`,`password`,`created_at`,`role_id`) VALUES ('4', 'viewer1', 'test1234', '2026-06-15T18:38:51.078819+00:00', '3');
INSERT INTO `users` (`id`,`username`,`password`,`created_at`,`role_id`) VALUES ('5', 'test123', 'test1234', '2026-06-15T18:39:50.583724+00:00', '2');

SET FOREIGN_KEY_CHECKS = 1;
