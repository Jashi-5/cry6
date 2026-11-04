-- Initialize test database alongside main database
CREATE DATABASE ebcp_guard_test_db OWNER ebcp_user;
GRANT ALL PRIVILEGES ON DATABASE ebcp_guard_test_db TO ebcp_user;
