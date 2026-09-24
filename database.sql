-- =======================================================
-- Database: login_security_db
-- Description: Database schema for Login Security Monitoring System
-- Compatible with: MySQL / MariaDB (XAMPP phpMyAdmin)
-- =======================================================

-- Create Database if it does not exist
CREATE DATABASE IF NOT EXISTS `login_security_db`;
USE `login_security_db`;

-- -------------------------------------------------------
-- Table 1: users
-- Stores user credentials with securely hashed passwords
-- -------------------------------------------------------
CREATE TABLE IF NOT EXISTS `users` (
    `id` INT AUTO_INCREMENT PRIMARY KEY,
    `username` VARCHAR(50) NOT NULL UNIQUE,
    `password` VARCHAR(255) NOT NULL,
    `created_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- -------------------------------------------------------
-- Table 2: login_logs
-- Tracks every login attempt (Success / Failed) and IP
-- -------------------------------------------------------
CREATE TABLE IF NOT EXISTS `login_logs` (
    `id` INT AUTO_INCREMENT PRIMARY KEY,
    `username` VARCHAR(50) NOT NULL,
    `status` VARCHAR(20) NOT NULL, -- 'SUCCESS' or 'FAILED'
    `ip_address` VARCHAR(45) NOT NULL,
    `login_time` TIMESTAMP DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- -------------------------------------------------------
-- Table 3: security_events
-- Stores cybersecurity incident logs with severity levels
-- -------------------------------------------------------
CREATE TABLE IF NOT EXISTS `security_events` (
    `id` INT AUTO_INCREMENT PRIMARY KEY,
    `event_type` VARCHAR(100) NOT NULL,
    `description` TEXT NOT NULL,
    `severity` VARCHAR(20) NOT NULL, -- 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'
    `created_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- -------------------------------------------------------
-- Sample Initial Data (Optional for testing)
-- -------------------------------------------------------
INSERT INTO `security_events` (`event_type`, `description`, `severity`) VALUES
('Multiple Failed Logins', 'Detected 3 consecutive failed login attempts for admin account.', 'MEDIUM'),
('Unrecognized IP Access', 'Access attempt from unwhitelisted IP address 192.168.1.105.', 'LOW'),
('SQL Injection Attempt', 'Detected suspicious query characters in login username field.', 'HIGH');
