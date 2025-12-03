DROP DATABASE IF EXISTS myconnector;
CREATE DATABASE IF NOT EXISTS myconnector CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE myconnector;

-- Users table
CREATE TABLE users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    oid VARCHAR(128) UNIQUE,
    email VARCHAR(256) UNIQUE,
    name VARCHAR(256),
    is_admin BOOLEAN DEFAULT FALSE
) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;


-- Encre devices table (doors) - must be created before access_rules
CREATE TABLE encre_devices (
    id INT AUTO_INCREMENT PRIMARY KEY,
    encre_id VARCHAR(128) UNIQUE NOT NULL,
    encre_name VARCHAR(256) UNIQUE NOT NULL,
    description TEXT,
    active BOOLEAN DEFAULT TRUE
) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- Cards table (FIXED: added account_type column and corrected foreign key)
CREATE TABLE cards (
    id INT AUTO_INCREMENT PRIMARY KEY,
    card_id VARCHAR(128) UNIQUE NOT NULL,
    owner VARCHAR(256),
    account_type VARCHAR(128) DEFAULT 'visitor',
    active BOOLEAN DEFAULT TRUE
) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- Access rules table (links cards to encres with time windows)
CREATE TABLE access_rules (
    id INT AUTO_INCREMENT PRIMARY KEY,
    card_id VARCHAR(128) NULL,
    account_type VARCHAR(128) NULL,
    encre_id VARCHAR(128) NULL,
    access_from TIME NULL,
    access_to TIME NULL,
    FOREIGN KEY (card_id) REFERENCES cards(card_id) ON DELETE CASCADE,
    FOREIGN KEY (encre_id) REFERENCES encre_devices(encre_id) ON DELETE SET NULL
) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- Access logs table
CREATE TABLE access_logs (
    id INT AUTO_INCREMENT PRIMARY KEY,
    card_id VARCHAR(128),
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    result VARCHAR(64),
    reason TEXT
) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- Connection logs table
CREATE TABLE connection_logs (
    id INT AUTO_INCREMENT PRIMARY KEY,
    numTag VARCHAR(128),
    tagEncre VARCHAR(20),
    last_connection DATETIME DEFAULT CURRENT_TIMESTAMP,
    result VARCHAR(20)
) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- Pi devices table
CREATE TABLE pi_devices (
    id INT AUTO_INCREMENT PRIMARY KEY,
    device_id VARCHAR(128) UNIQUE,
    api_key_hash VARCHAR(256),
    description VARCHAR(256),
    enabled BOOLEAN DEFAULT TRUE
) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;



USE myconnector;
INSERT INTO access_rules (card_id, account_type, encre_id, access_from, access_to)
VALUES 
    (NULL, 'engineer', NULL, '06:00:00', '18:00:00'),
    (NULL, 'manager', NULL, '07:00:00', '23:59:59'),
    (NULL, 'visitor', NULL, '08:00:00', '16:00:00');