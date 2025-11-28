USE myconnector;

-- Create the tables your Python app expects
CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    oid VARCHAR(128) UNIQUE,
    email VARCHAR(256) UNIQUE,
    name VARCHAR(256),
    is_admin BOOLEAN DEFAULT FALSE
) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS cards (
    id INT AUTO_INCREMENT PRIMARY KEY,
    card_id VARCHAR(128) UNIQUE NOT NULL,
    owner VARCHAR(256),
    active BOOLEAN DEFAULT TRUE
) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS access_rules (
    id INT AUTO_INCREMENT PRIMARY KEY,
    card_id VARCHAR(128) NOT NULL,
    access_from TIME NULL,
    access_to TIME NULL,
    attributes TEXT,
    FOREIGN KEY (card_id) REFERENCES cards(card_id) ON DELETE CASCADE
) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS access_logs (
    id INT AUTO_INCREMENT PRIMARY KEY,
    card_id VARCHAR(128),
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    result VARCHAR(64),
    reason TEXT
) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS connection_logs (
    id INT AUTO_INCREMENT PRIMARY KEY,
    numtag VARCHAR(128),
    tagencre VARCHAR(20),
    last_connection DATETIME DEFAULT CURRENT_TIMESTAMP
) CHARACTER SET utf8mb4 COLLATE c;

CREATE TABLE IF NOT EXISTS pi_devices (
    id INT AUTO_INCREMENT PRIMARY KEY,
    device_id VARCHAR(128) UNIQUE,
    api_key_hash VARCHAR(256),
    description VARCHAR(256),
    enabled BOOLEAN DEFAULT TRUE
) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS encre_devices (
    id INT AUTO_INCREMENT PRIMARY KEY,
    encre_name VARCHAR(256) UNIQUE,
    encre_id VARCHAR(128) UNIQUE,
    description VARCHAR(256),
    active BOOLEAN DEFAULT TRUE
) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci

