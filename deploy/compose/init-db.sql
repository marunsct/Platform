-- Roles for the control-plane database. maturad runs as matura_app, which cannot bypass row-level security;
-- migrations run as matura_owner. Change the passwords for anything but local development.
CREATE ROLE matura_owner LOGIN NOSUPERUSER NOBYPASSRLS PASSWORD 'matura-owner-dev';
CREATE ROLE matura_app   LOGIN NOSUPERUSER NOBYPASSRLS PASSWORD 'matura-app-dev';
CREATE DATABASE matura OWNER matura_owner;
CREATE ROLE keycloak LOGIN PASSWORD 'keycloak-dev';
CREATE DATABASE keycloak OWNER keycloak;
