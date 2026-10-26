INSERT INTO users (username, password, role) VALUES
('admin', '$2a$10$abcdefghijklmnopqrstuv', 'ADMIN'),
('user1', 'password123', 'USER'),
('user2', 'qwerty', 'USER'),
('user', 'password123', 'USER');  -- BF 시나리오 AUTH_SUCCESS 검증용

INSERT INTO products (name, description, price, stock) VALUES
('Smartphone', 'Latest model phone', 800000, 50),
('Laptop', 'Gaming laptop', 1500000, 20),
('Headphone', 'Wireless headphone', 200000, 100),
('Tablet', '10 inch tablet', 600000, 30);