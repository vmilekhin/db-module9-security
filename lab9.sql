-- Модуль 9. Безопасность баз данных.
-- Скрипт создания среды и проведения негативных тестов.

DROP DATABASE IF EXISTS db_security_lab;
CREATE DATABASE db_security_lab;
\c db_security_lab

-- 1. Создаем роли
CREATE ROLE owner_role;
CREATE ROLE app_rw LOGIN PASSWORD 'app_pass';
CREATE ROLE analyst_ro LOGIN PASSWORD 'analyst_pass';
CREATE ROLE tenant_a LOGIN PASSWORD 'tenant_a_pass';
CREATE ROLE tenant_b LOGIN PASSWORD 'tenant_b_pass';

-- 2. Создаем схему и назначаем владельца
CREATE SCHEMA app_schema AUTHORIZATION owner_role;

-- 3. Переключаемся на владельца, чтобы создать таблицы
SET ROLE owner_role;

CREATE TABLE app_schema.orders (
    id SERIAL PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    amount NUMERIC NOT NULL
);

INSERT INTO app_schema.orders (tenant_id, amount) VALUES 
('tenant_a', 100), ('tenant_a', 200),
('tenant_b', 300), ('tenant_b', 400);

-- 4. Выдаем права
GRANT USAGE ON SCHEMA app_schema TO app_rw, analyst_ro, tenant_a, tenant_b;
GRANT SELECT, INSERT, UPDATE ON ALL TABLES IN SCHEMA app_schema TO app_rw;
GRANT SELECT ON ALL TABLES IN SCHEMA app_schema TO analyst_ro;
GRANT SELECT ON ALL TABLES IN SCHEMA app_schema TO tenant_a, tenant_b;
GRANT USAGE ON ALL SEQUENCES IN SCHEMA app_schema TO app_rw;

-- 5. Негативные тесты прав
SET ROLE analyst_ro;
DELETE FROM app_schema.orders WHERE id = 1; -- Ожидаем ERROR
SET ROLE app_rw;
CREATE TABLE app_schema.hack (id int); -- Ожидаем ERROR

-- 6. Включаем RLS
RESET ROLE;
ALTER TABLE app_schema.orders ENABLE ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation ON app_schema.orders
    FOR ALL
    TO PUBLIC
    USING (tenant_id = current_setting('app.current_tenant', true));

-- 7. Имитация атаки на архитектуру
SET ROLE app_rw;
SET app.current_tenant = 'tenant_a';
SELECT * FROM app_schema.orders; -- Видит только A
SET app.current_tenant = 'tenant_b';
SELECT * FROM app_schema.orders; -- Видит данные B!

-- 8. Проверка TLS
RESET ROLE;
SELECT pid, ssl, version, cipher FROM pg_stat_ssl;
